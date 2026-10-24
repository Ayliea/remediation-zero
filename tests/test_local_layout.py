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
    assert ws.file_for("approvals") == ws.root / "references.sqlite3"


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


def test_local_layout_is_stdlib_only():
    subprocess.run([sys.executable, "-S", "-c", "import tools.local_layout"],
                   cwd=REPO_ROOT, check=True)
