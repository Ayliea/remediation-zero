# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""The local workspace layout and its per-stage write boundary."""
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from tools.idempotency import CompletedCall, derive_record
from tools.local_layout import AGENT_FILES, SHARED, STAGE_WRITES, Workspace

REPO_ROOT = Path(__file__).resolve().parents[1]
ALL = [c for names in AGENT_FILES.values() for c in names] + list(SHARED)


@pytest.fixture
def ws(tmp_path):
    return Workspace(tmp_path / "workspace")


def test_report_stage_cannot_write_tickets(ws):
    store = ws.docs_for("report")
    try:
        with pytest.raises(PermissionError):
            store.collection("tickets").document("T-1").set({"a": 1})
    finally:
        store.close()


def test_report_stage_ticket_file_is_readonly_in_sqlite(ws):
    store = ws.docs_for("report")
    try:
        conn, alias = store._conn_of("tickets")
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            conn.execute(f"INSERT INTO {alias}.docs (collection, id, data, revision) "
                         "VALUES ('tickets', 'T-1', '{}', 1)")
    finally:
        store.close()


def test_chase_cannot_write_decisions(ws):
    store = ws.docs_for("chase")
    try:
        with pytest.raises(PermissionError):
            store.collection("decisions").document("D-1").set({"a": 1})
        store.collection("tickets").document("T-1").set({"a": 1})
    finally:
        store.close()


def test_dashboard_stage_writes_nothing(ws):
    """Ruling 43: the dashboard reads every collection and holds no write access."""
    assert STAGE_WRITES["dashboard"] == set()
    store = ws.docs_for("dashboard")
    try:
        for name in ALL:
            ref = store.collection(name).document("X-1")
            with pytest.raises(PermissionError):
                ref.set({"a": 1})
            with pytest.raises(PermissionError):
                ref.create({"a": 1})
            batch = store.batch()
            with pytest.raises(PermissionError):
                batch.set(ref, {"a": 1})
                batch.commit()
            conn, alias = store._conn_of(name)
            with pytest.raises(sqlite3.OperationalError, match="readonly"):
                conn.execute(f"INSERT INTO {alias}.docs (collection, id, data, revision) "
                             f"VALUES ('{name}', 'X-1', '{{}}', 1)")
    finally:
        store.close()


@pytest.mark.parametrize("stage", sorted(STAGE_WRITES))
def test_every_stage_reads_every_collection(ws, stage):
    store = ws.docs_for(stage)
    try:
        for name in ALL:
            assert list(store.collection(name).stream()) == []
    finally:
        store.close()


def test_init_creates_missing_files(ws):
    ws.init()
    target = ws.file_for("tickets")
    assert target.name == "chase.sqlite3"
    target.unlink()
    store = ws.docs_for("report")
    store.close()
    assert target.exists()
    assert target.stat().st_mode & 0o777 == 0o600


def test_init_is_idempotent_and_keeps_data(ws):
    store = ws.docs_for("chase")
    store.collection("tickets").document("T-1").set({"a": 1})
    store.close()
    ws.init()
    store = ws.docs_for("report")
    try:
        assert store.collection("tickets").document("T-1").get().to_dict() == {"a": 1}
    finally:
        store.close()


def test_file_layout(ws):
    assert ws.file_for("cycles") == ws.root / "orchestrator.sqlite3"
    assert ws.file_for("human_queue") == ws.root / "shared.sqlite3"
    assert ws.file_for("approvals") == ws.root / "approvals.sqlite3"
    assert ws.file_for("findings") == ws.root / "references.sqlite3"


def test_unknown_stage_and_collection_raise_key_error(ws):
    with pytest.raises(KeyError):
        ws.docs_for("nope")
    with pytest.raises(KeyError):
        ws.file_for("nope")


def test_journal_shared_across_stages(ws):
    record = derive_record("RZ-1", "nudge", 1)
    first = ws.journal()
    claim = first.acquire(record)
    assert claim.acquired
    first.complete(claim, CompletedCall(record, {"ok": True}))
    second = ws.journal()
    done = second.get(record.key)
    assert done is not None and done.result == {"ok": True}


def test_readonly_stage_can_still_write_journal(ws):
    record = derive_record("RZ-2", "report", 1)
    store = ws.docs_for("report")
    try:
        assert list(store.collection("human_queue").stream()) == []
        journal = ws.journal()
        claim = journal.acquire(record)
        journal.complete(claim, CompletedCall(record, {"ok": 1}))
        assert journal.get(record.key) is not None
        with pytest.raises(PermissionError):
            store.collection("human_queue").document("H-1").set({"a": 1})
    finally:
        store.close()


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_workspace_files_are_private(ws):
    store = ws.docs_for("report")
    store.close()
    ws.journal().get("x")
    assert ws.root.stat().st_mode & 0o777 == 0o700
    files = sorted(ws.root.glob("*"))
    assert {f.name for f in files} >= {"shared.sqlite3", "references.sqlite3"}
    for f in files:
        assert f.stat().st_mode & 0o777 == 0o600, f.name


def test_stage_writes_reference_known_collections():
    owners = {}
    for agent, names in AGENT_FILES.items():
        for name in names:
            owners.setdefault(name, []).append(agent)
    for name in SHARED:
        owners.setdefault(name, []).append("shared")
    assert all(len(v) == 1 for v in owners.values())
    for stage, writes in STAGE_WRITES.items():
        assert writes <= set(owners), stage


def test_init_refuses_nonempty_foreign_directory(tmp_path):
    root = tmp_path / "myproject"
    root.mkdir()
    root.chmod(0o755)
    (root / "notes.txt").write_text("hi")
    with pytest.raises(ValueError, match="not a Remediation Zero workspace"):
        Workspace(root).init()
    assert sorted(p.name for p in root.iterdir()) == ["notes.txt"]
    if os.name == "posix":
        assert root.stat().st_mode & 0o777 == 0o755


def test_init_adopts_empty_directory(tmp_path):
    root = tmp_path / "empty"
    root.mkdir()
    root.chmod(0o755)
    Workspace(root).init()
    assert (root / "shared.sqlite3").exists() and (root / "chase.sqlite3").exists()
    if os.name == "posix":
        assert root.stat().st_mode & 0o777 == 0o700


def test_init_reopens_existing_workspace(ws):
    store = ws.docs_for("chase")
    store.collection("tickets").document("T-1").set({"a": 1})
    store.close()
    (ws.root / "extra.txt").write_text("x")  # a workspace may hold other files
    ws.init()
    store = ws.docs_for("report")
    try:
        assert store.collection("tickets").document("T-1").get().to_dict() == {"a": 1}
    finally:
        store.close()


@pytest.mark.skipif(os.name != "posix", reason="POSIX symlinks and modes")
def test_init_refuses_symlinked_database_file(ws, tmp_path):
    ws.init()
    target = tmp_path / "scratch.sqlite3"
    target.write_bytes(b"")
    target.chmod(0o644)
    link = ws.file_for("tickets")
    link.unlink()
    link.symlink_to(target)
    with pytest.raises(OSError):
        ws.init()
    assert target.stat().st_mode & 0o777 == 0o644


def test_private_file_works_without_fchmod(tmp_path, monkeypatch):
    monkeypatch.delattr(os, "fchmod", raising=False)
    ws = Workspace(tmp_path / "ws")
    ws.init()
    assert ws.file_for("tickets").exists() and ws.file_for("human_queue").exists()


def test_local_layout_is_stdlib_only():
    subprocess.run([sys.executable, "-S", "-c", "import tools.local_layout"],
                   cwd=REPO_ROOT, check=True)


def test_approve_stage_findings_file_is_readonly_in_sqlite(ws):
    # Approvals have their own file, so the approve command reaches findings
    # only through a read-only attachment, not the code check alone.
    store = ws.docs_for("approve")
    try:
        conn, alias = store._conn_of("findings")
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            conn.execute(f"INSERT INTO {alias}.docs (collection, id, data, revision) "
                         "VALUES ('findings', 'F-1', '{}', 1)")
    finally:
        store.close()


def _put_old_layout_approval(ws, doc_id, data):
    """An approval where workspaces before approvals.sqlite3 kept it."""
    conn = sqlite3.connect(ws.root / "references.sqlite3")
    try:
        conn.execute("INSERT INTO docs (collection, id, data, revision) VALUES (?, ?, ?, 1)",
                     ("approvals", doc_id, data))
        conn.commit()
    finally:
        conn.close()


def _rows(path, collection):
    conn = sqlite3.connect(path)
    try:
        return conn.execute("SELECT id, data FROM docs WHERE collection = ?",
                            (collection,)).fetchall()
    finally:
        conn.close()


def test_init_moves_old_layout_approvals_once(ws):
    ws.init()
    _put_old_layout_approval(ws, "RZ-1-c001", '{"approved_by": "Synthetic Owner"}')

    ws.init()
    ws.init()  # a repeat finds nothing left to move

    assert _rows(ws.root / "references.sqlite3", "approvals") == []
    assert _rows(ws.root / "approvals.sqlite3", "approvals") == [
        ("RZ-1-c001", '{"approved_by": "Synthetic Owner"}')]
    store = ws.docs_for("dashboard")
    try:
        assert store.collection("approvals").document("RZ-1-c001").get().to_dict() == {
            "approved_by": "Synthetic Owner"}
    finally:
        store.close()


def test_move_keeps_the_new_file_copy_after_an_interrupted_move(ws):
    # A move that copied but never deleted leaves a row in both files. The
    # copy already in approvals.sqlite3 wins; the stale one is dropped.
    ws.init()
    _put_old_layout_approval(ws, "RZ-1-c001", '{"approved_by": "old"}')
    conn = sqlite3.connect(ws.root / "approvals.sqlite3")
    try:
        conn.execute("INSERT INTO docs (collection, id, data, revision) VALUES "
                     "('approvals', 'RZ-1-c001', '{\"approved_by\": \"new\"}', 1)")
        conn.commit()
    finally:
        conn.close()

    ws.init()

    assert _rows(ws.root / "references.sqlite3", "approvals") == []
    assert _rows(ws.root / "approvals.sqlite3", "approvals") == [
        ("RZ-1-c001", '{"approved_by": "new"}')]


def test_scanner_state_is_written_only_by_import_and_enrichment_stages(ws):
    writers = {"enrichment_refresh", "scanner_import"}
    assert {s for s, writes in STAGE_WRITES.items() if "scanner_state" in writes} == writers
    assert STAGE_WRITES["scanner_import"] == {"assets", "findings", "scans", "scanner_state"}
    assert ws.file_for("scanner_state").name == "scanner.sqlite3"
    for stage in STAGE_WRITES:
        store = ws.docs_for(stage)
        try:
            ref = store.collection("scanner_state").document("X-1")
            if stage in writers:
                ref.set({"a": 1})
            else:
                with pytest.raises(PermissionError):
                    ref.set({"a": 1})
        finally:
            store.close()


def test_an_older_workspace_gains_the_scanner_file_on_open(ws):
    ws.init()
    ws.file_for("scanner_state").unlink()
    ws.docs_for("dashboard").close()
    assert ws.file_for("scanner_state").exists()


def _journal_keys(ws):
    conn = sqlite3.connect(ws.root / "shared.sqlite3")
    try:
        return [row[0] for row in conn.execute("SELECT key FROM journal")]
    finally:
        conn.close()


def test_one_transaction_spans_documents_and_the_journal(ws):
    journal = ws.journal()
    store = ws.docs_for("scanner_import")
    record = derive_record("RZ-1", "ingest_finding", 1)
    try:
        with pytest.raises(RuntimeError, match="stop"):
            with store.transaction(journal=Path(journal.path), clock=journal.clock) as bound:
                store.collection("findings").document("RZ-1").set({"a": 1})
                store.collection("scanner_state").document("T").set({"b": 2})
                bound.put(CompletedCall(record=record, result="ok"))
                # Reads inside see the transaction's own writes.
                assert store.collection("findings").document("RZ-1").get().exists
                raise RuntimeError("stop")
        assert not store.collection("findings").document("RZ-1").get().exists
        assert not store.collection("scanner_state").document("T").get().exists
        assert _journal_keys(ws) == []

        with store.transaction(journal=Path(journal.path), clock=journal.clock) as bound:
            store.collection("findings").document("RZ-1").set({"a": 1})
            bound.put(CompletedCall(record=record, result="ok"))
        assert store.collection("findings").document("RZ-1").get().to_dict() == {"a": 1}
        assert _journal_keys(ws) == [record.key]
        # The journal file is detached again: an ordinary write still commits alone.
        store.collection("findings").document("RZ-2").set({"a": 2})
    finally:
        store.close()


def test_a_failed_batch_inside_a_transaction_undoes_only_itself(ws):
    store = ws.docs_for("scanner_import")
    try:
        with store.transaction():
            store.collection("findings").document("RZ-1").set({"a": 1})
            batch = store.batch()
            batch.set(store.collection("findings").document("RZ-2"), {"a": 2})
            batch.update(store.collection("findings").document("missing"), {"a": 3})
            with pytest.raises(Exception):
                batch.commit()
        assert {s.id for s in store.collection("findings").stream()} == {"RZ-1"}
    finally:
        store.close()
