# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""The scanner_import stage: Greenbone reports in, task by task, through the rescan path.

Synthetic fixtures only: documentation IPs, `.invalid` hostnames, synthetic UUIDs.
"""
import dataclasses
import json
import logging
import sqlite3
from pathlib import Path

import pytest

from engine.ports import NoDelivery, NoTelemetry, Ports
from engine.scanner_import import (
    GreenboneSource, ImportRefused, import_scan, import_upload, pull,
)
from engine.scanner_source import normalise_greenbone
from engine.seed import SeedRefused, seed
from engine.snapshot import snapshot
from tools.clock import ClockMode, SimClock
from tools.gmp import GmpError
from tools.greenbone_report import ScannedHost, parse_report
from tools.guardrail import NoGuard
from tools.local_layout import Workspace

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures" / "greenbone"
TASK = "11111111-1111-4111-8111-111111111111"
TASK_B = "44444444-4444-4444-8444-444444444444"
WEB = "gb-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
LOG4J_OID = "1.3.6.1.4.1.25623.1.0.117850"
LOG4J = f"{WEB}:{LOG4J_OID}:8080/tcp"


def rid(n):
    return f"33333333-3333-4333-8333-{n:012d}"


def FIX(name):
    return (FIXTURES / name).read_bytes()


def BASIC():
    """report_basic.xml without its malformed result, so coverage is intact."""
    return dataclasses.replace(parse_report(FIX("report_basic.xml")), rejected=())


def report(n, *, with_log4j=True, status="Done", task=TASK, hosts=None, **changes):
    base = BASIC()
    results = base.results if with_log4j else tuple(
        r for r in base.results if r.nvt_oid != LOG4J_OID)
    fields = dict(report_id=rid(n), scan_status=status, task_id=task, results=results,
                  hosts=base.hosts if hosts is None else hosts)
    fields.update(changes)
    return dataclasses.replace(base, **fields)


def scan(n, **kw):
    return normalise_greenbone(report(n, **kw))


@pytest.fixture
def ws(tmp_path):
    workspace = Workspace(tmp_path / "workspace")
    workspace.init()
    return workspace


def ports_for(ws, stage="scanner_import"):
    return Ports(docs=ws.docs_for(stage), journal=ws.journal(), clock=SimClock(ClockMode.REAL),
                 roles=None, guard=NoGuard(), delivery=NoDelivery(), memory=None,
                 telemetry=NoTelemetry())


@pytest.fixture
def ports(ws):
    p = ports_for(ws)
    yield p
    p.docs.close()


def everything(ws):
    """Every stored row in every workspace file, journal included, with revisions."""
    out = {}
    for path in sorted(ws.root.glob("*.sqlite3")):
        conn = sqlite3.connect(path)
        try:
            out[path.name] = sorted(conn.execute(
                "SELECT collection, id, data, revision FROM docs").fetchall())
            if path.name == "shared.sqlite3":
                out["journal"] = sorted(conn.execute(
                    "SELECT key, state FROM journal").fetchall())
        finally:
            conn.close()
    return out


def docs(ws, collection):
    """Documents by id; findings by their `finding_id` field.

    The rescan writer files a finding under the idempotency layer's case-folded
    id, so the field, not the document id, carries the finding's own key.
    """
    store = ws.docs_for("dashboard")
    try:
        rows = [(s.id, s.to_dict()) for s in store.collection(collection).stream()]
    finally:
        store.close()
    if collection == "findings":
        return {data["finding_id"]: data for _, data in rows}
    return dict(rows)


class FakeSource:
    """A ScannerSource serving NormalisedScans by report id."""

    def __init__(self, listing=None, fail=None):
        self.listing = listing or {}   # task_id -> [meta, ...] oldest first
        self.scans = {}
        self.fail = fail or {}         # task_id -> exception to raise from finished_reports
        self.listed, self.fetched = [], []

    def add(self, n, *, status="Done", task=TASK, **kw):
        self.listing.setdefault(task, []).append(
            {"report_id": rid(n), "task_id": task, "status": status,
             "timestamp": f"2026-10-{n:02d}T01:00:00Z"})
        self.scans[rid(n)] = scan(n, status=status, task=task, **kw)

    def list_tasks(self):
        return [{"task_id": t, "name": "x"} for t in self.listing]

    def finished_reports(self, task_id):
        self.listed.append(task_id)
        if task_id in self.fail:
            raise self.fail[task_id]
        return list(self.listing.get(task_id, []))

    def fetch(self, report_id):
        self.fetched.append(report_id)
        return self.scans[report_id]


# --- import_scan refusals -----------------------------------------------------------


def test_unchosen_task_is_refused_and_nothing_written(ws, ports):
    before = everything(ws)
    with pytest.raises(ImportRefused, match="not chosen"):
        import_scan(ports, 1, scan(1), chosen_task_ids=[TASK_B])
    assert everything(ws) == before


def test_refused_report_writes_nothing(ws, ports):
    before = everything(ws)
    stopped = normalise_greenbone(parse_report(FIX("report_stopped.xml")))
    with pytest.raises(ImportRefused, match="Stopped"):
        import_scan(ports, 1, stopped, chosen_task_ids=[TASK])
    assert everything(ws) == before


# --- pull ---------------------------------------------------------------------------


def test_first_pull_imports_only_the_newest_done_report(ws, ports):
    source = FakeSource()
    source.add(1)
    source.add(2)
    source.add(3, status="Stopped")
    source.add(4)
    source.add(5, status="Interrupted")
    result = pull(ports, 1, source, chosen_task_ids=[TASK])
    assert source.fetched == [rid(4)]
    assert set(docs(ws, "scans")) == {rid(4)}
    state = docs(ws, "scanner_state")[TASK]
    assert state["last_result"] == "imported"
    assert state["last_imported_report_id"] == rid(4)
    assert state["last_imported_cycle"] == 1
    assert state["baseline_not_imported"] == 2
    assert state["skipped"] == [{"report_id": rid(3), "status": "Stopped"},
                                {"report_id": rid(5), "status": "Interrupted"}]
    assert result["pulled"][0]["result"] == "imported"


def test_one_report_per_task_per_cycle(ws, ports):
    source = FakeSource()
    source.add(1)
    pull(ports, 1, source, chosen_task_ids=[TASK])
    source.add(2)
    source.add(3)
    again = pull(ports, 1, source, chosen_task_ids=[TASK])
    assert again["pulled"][0]["result"] == "already_imported_this_cycle"
    assert set(docs(ws, "scans")) == {rid(1)}
    pull(ports, 2, source, chosen_task_ids=[TASK])
    assert set(docs(ws, "scans")) == {rid(1), rid(2)}        # oldest first, one only
    pull(ports, 3, source, chosen_task_ids=[TASK])
    assert set(docs(ws, "scans")) == {rid(1), rid(2), rid(3)}
    assert source.fetched == [rid(1), rid(2), rid(3)]


def test_resolved_regressed_resolved_across_three_reports(ws, ports):
    # Baseline in cycle 1, then three follow-up reports in cycles 2, 3, 4: the
    # second resolve must not be suppressed by the first one's idempotency key.
    source = FakeSource()
    source.add(1)
    pull(ports, 1, source, chosen_task_ids=[TASK])
    assert docs(ws, "findings")[LOG4J]["status"] == "open"
    for cycle, n, present, expected in ((2, 2, False, "resolved"), (3, 3, True, "open"),
                                        (4, 4, False, "resolved")):
        source.add(n, with_log4j=present)
        pull(ports, cycle, source, chosen_task_ids=[TASK])
        assert docs(ws, "findings")[LOG4J]["status"] == expected, cycle
    finding = docs(ws, "findings")[LOG4J]
    assert finding["resolved_by_scan"] == rid(4)
    assert finding["regressed_in_scan"] == rid(3)


def test_unfinished_host_closes_nothing(ws, ports):
    base = BASIC().hosts
    finished = tuple(dataclasses.replace(h, finished=True) for h in base)
    unfinished = tuple(dataclasses.replace(h, finished=(h.ip != "192.0.2.10")) for h in base)
    import_scan(ports, 1, scan(1, hosts=finished), chosen_task_ids=[TASK])
    assert docs(ws, "findings")[LOG4J]["status"] == "open"
    # The web host is unfinished and reports nothing: absence proves nothing.
    result = import_scan(ports, 2, scan(2, hosts=unfinished, results=()),
                         chosen_task_ids=[TASK])
    assert result["counts"]["resolved"] == 0
    assert result["counts"]["unverifiable"] == 3
    assert all(f["status"] == "open" for f in docs(ws, "findings").values())


def test_assets_keep_first_seen_and_never_lose_owner(ws, ports):
    import_scan(ports, 1, scan(1), chosen_task_ids=[TASK])
    first = docs(ws, "assets")[WEB]
    assert first["first_seen_scan"] == rid(1) and first["last_seen_scan"] == rid(1)
    assert "owner_id" not in first and "criticality" not in first
    person = ws.docs_for("seed")
    try:
        person.collection("assets").document(WEB).update({
            "owner_id": "OWN-1", "criticality": "high", "environment": "production",
            "internet_facing": True, "notes": "set by a person"})
    finally:
        person.close()
    moved = tuple(dataclasses.replace(h, hostname="web2.example.invalid", os_cpe="cpe:/o:debian:debian_linux:13",
                                      open_ports=("22/tcp",))
                  if h.ip == "192.0.2.10" else h for h in BASIC().hosts)
    import_scan(ports, 2, scan(2, hosts=moved), chosen_task_ids=[TASK])
    asset = docs(ws, "assets")[WEB]
    assert asset["first_seen_scan"] == rid(1)
    assert asset["first_seen_real_ts"] == first["first_seen_real_ts"]
    assert asset["first_seen_sim_ts"] == first["first_seen_sim_ts"]
    assert asset["last_seen_scan"] == rid(2)
    assert asset["last_seen_real_ts"] >= first["last_seen_real_ts"]
    assert asset["hostname"] == "web2.example.invalid"
    assert asset["os_cpe"] == "cpe:/o:debian:debian_linux:13"
    assert asset["open_ports"] == ["22/tcp"]
    assert (asset["owner_id"], asset["criticality"], asset["environment"],
            asset["internet_facing"], asset["notes"]) == (
        "OWN-1", "high", "production", True, "set by a person")


def test_failed_pull_records_failure_only(ws, ports):
    source = FakeSource()
    source.add(1)
    pull(ports, 1, source, chosen_task_ids=[TASK])
    before = everything(ws)
    source.fail[TASK] = GmpError("gvmd closed the connection before the response was complete")
    result = pull(ports, 2, source, chosen_task_ids=[TASK])
    assert result["pulled"][0] == {"task_id": TASK, "result": "failed", "error_class": "GmpError"}
    state = docs(ws, "scanner_state")[TASK]
    assert state["last_result"] == "failed"
    assert state["last_error_class"] == "GmpError"
    assert state["last_imported_report_id"] == rid(1)
    assert state["last_imported_cycle"] == 1
    assert "gvmd closed" not in json.dumps(state)
    after = everything(ws)
    changed = [name for name in after if after[name] != before[name]]
    assert changed == ["scanner.sqlite3"]


def test_empty_choice_pulls_nothing(ws, ports):
    source = FakeSource()
    source.add(1)
    before = everything(ws)
    assert pull(ports, 1, source, chosen_task_ids=[]) == {"pulled": [], "reason": "no tasks chosen"}
    assert source.listed == [] and source.fetched == []
    assert everything(ws) == before


def test_demo_and_real_never_mix_either_way(tmp_path):
    demo = Workspace(tmp_path / "demo")
    demo.init()
    seeding = ports_for(demo, "seed")
    try:
        seed(seeding, ROOT / "data")
    finally:
        seeding.docs.close()
    before = everything(demo)
    importing = ports_for(demo)
    try:
        with pytest.raises(ImportRefused, match="seeded demo findings"):
            import_scan(importing, 1, scan(1), chosen_task_ids=[TASK])
        source = FakeSource()
        source.add(1)
        with pytest.raises(ImportRefused, match="seeded demo findings"):
            pull(importing, 1, source, chosen_task_ids=[TASK])
        assert source.listed == []
    finally:
        importing.docs.close()
    assert everything(demo) == before

    real = Workspace(tmp_path / "real")
    real.init()
    importing = ports_for(real)
    try:
        import_scan(importing, 1, scan(1), chosen_task_ids=[TASK])
    finally:
        importing.docs.close()
    before = everything(real)
    seeding = ports_for(real, "seed")
    try:
        with pytest.raises(SeedRefused, match="Greenbone findings"):
            seed(seeding, ROOT / "data")
    finally:
        seeding.docs.close()
    assert everything(real) == before


def test_seed_command_says_why_it_refused(ws, ports):
    import os
    import subprocess
    import sys
    import_scan(ports, 1, scan(1), chosen_task_ids=[TASK])
    before = everything(ws)
    env = {k: v for k, v in os.environ.items() if not k.startswith(("RZ_", "GITHUB_"))}
    result = subprocess.run([sys.executable, "-S", "-m", "scripts.local", "--database",
                             str(ws.root), "seed"], cwd=ROOT, capture_output=True, text=True,
                            timeout=60, env=env)
    assert result.returncode == 1
    assert "holds Greenbone findings" in result.stderr
    assert "demo and real data never mix" in result.stderr
    assert everything(ws) == before


def test_repeated_pull_writes_nothing(ws, ports):
    source = FakeSource()
    source.add(1)
    pull(ports, 1, source, chosen_task_ids=[TASK])
    before = everything(ws)
    pull(ports, 1, source, chosen_task_ids=[TASK])
    assert everything(ws) == before
    # A later cycle with nothing new touches only the pull state.
    result = pull(ports, 2, source, chosen_task_ids=[TASK])
    assert result["pulled"][0]["result"] == "nothing_new"
    after = everything(ws)
    assert [name for name in after if after[name] != before[name]] == ["scanner.sqlite3"]
    assert docs(ws, "scanner_state")[TASK]["last_result"] == "nothing_new"


def test_upload_from_unchosen_task_needs_add_task(ws, ports):
    data = FIX("report_basic.xml")
    before = everything(ws)
    with pytest.raises(ImportRefused) as refused:
        import_upload(ports, 1, data, chosen_task_ids=[], qod_floor=70)
    assert str(refused.value) == (f"report is from task Weekly Example Scan ({TASK}), "
                                  "which is not chosen for this install")
    assert everything(ws) == before
    result = import_upload(ports, 1, data, chosen_task_ids=[], qod_floor=70, add_task=True)
    assert result["task_added"] is True
    assert set(docs(ws, "scans")) == {"22222222-2222-4222-8222-222222222222"}
    assert docs(ws, "scanner_state")[TASK]["last_import_via"] == "upload"


# --- atomicity, coverage and per-task isolation --------------------------------------


def test_report_that_uncovers_everything_closes_nothing_and_says_so(ws, ports):
    import_scan(ports, 1, scan(1), chosen_task_ids=[TASK])
    # Nothing on any host, but one rejected result that names no host: the
    # whole report is untrusted, so nothing may close.
    untrusted = normalise_greenbone(report(2, results=(), rejected=(("?", "bad severity", None),)))
    assert untrusted.covered_asset_ids == ()
    result = import_scan(ports, 2, untrusted, chosen_task_ids=[TASK])
    assert result["counts"]["resolved"] == 0
    assert result["uncovered_all"] is True
    assert all(f["status"] == "open" for f in docs(ws, "findings").values())
    state = docs(ws, "scanner_state")[TASK]
    assert state["last_uncovered_all"] is True
    assert state["last_skipped"] == {"log": 0, "below_qod": 0, "rejected": 1, "not_finished": 0}


def test_failure_after_first_write_leaves_nothing(ws, ports, monkeypatch):
    import_scan(ports, 1, scan(1), chosen_task_ids=[TASK])
    before = everything(ws)
    import engine.scanner_import as module

    def boom(*args, **kwargs):
        raise RuntimeError("disk full")

    # The pull state is the last write; assets, scan record, resolutions and
    # journal keys have all been written by then.
    monkeypatch.setattr(module, "_write_state", boom)
    with pytest.raises(RuntimeError, match="disk full"):
        import_scan(ports, 2, scan(2, with_log4j=False), chosen_task_ids=[TASK])
    assert everything(ws) == before
    monkeypatch.undo()
    # And the same report imports cleanly afterwards: no stale journal key suppresses it.
    result = import_scan(ports, 2, scan(2, with_log4j=False), chosen_task_ids=[TASK])
    assert result["newly_resolved"] == 1
    assert docs(ws, "findings")[LOG4J]["status"] == "resolved"


class FakeClient:
    """Stands in for GmpClient: one session, poisoned by its first failure."""

    def __init__(self, reports=None, fail=False, refused=()):
        self.reports = reports or {}
        self.fail = fail
        self.refused_reports = list(refused)
        self.skipped_tasks = 0
        self.entered = self.closed = False

    def __enter__(self):
        self.entered = True
        return self

    def __exit__(self, *exc):
        self.closed = True

    def finished_reports(self, task_id):
        if self.fail:
            raise GmpError("reading from gvmd failed (ConnectionResetError)")
        return [{"report_id": r.report_id, "task_id": task_id, "status": r.scan_status,
                 "timestamp": "2026-10-20T01:00:00Z"} for r in self.reports.get(task_id, [])]

    def report_xml(self, report_id):
        return FIX("report_basic.xml")


def test_one_failing_task_does_not_hide_the_next(ws, ports, caplog):
    good = parse_report(FIX("report_basic.xml"))
    clients = [FakeClient(fail=True),
               FakeClient(reports={TASK: [good]},
                          refused=[("?", "bad report id"), ("x", "bad status")])]
    made = []

    def factory():
        made.append(clients[len(made)])
        return made[-1]

    source = GreenboneSource(factory, qod_floor=70)
    with caplog.at_level(logging.INFO, logger="remediation_zero.scanner_import"):
        result = pull(ports, 1, source, chosen_task_ids=[TASK_B, TASK])
    assert [p["result"] for p in result["pulled"]] == ["failed", "imported"]
    assert len(made) == 2 and all(c.entered and c.closed for c in made)
    state = docs(ws, "scanner_state")
    assert state[TASK_B]["last_result"] == "failed"
    assert state[TASK]["last_result"] == "imported"
    assert state[TASK]["last_refused_reports"] == 2
    assert state[TASK]["last_refused_reasons"] == ["bad report id", "bad status"]
    assert state[TASK_B]["last_refused_reports"] == 0
    lines = [json.loads(r.getMessage()) for r in caplog.records
             if r.name == "remediation_zero.scanner_import"]
    per_task = [line for line in lines if line["event"] == "scanner_pull"]
    assert [(line["task_id"], line["result"]) for line in per_task] == [
        (TASK_B, "failed"), (TASK, "imported")]
    assert all(line["cycle_id"] == "cycle-001" for line in per_task)
    assert per_task[0]["error_class"] == "GmpError"
    assert "ConnectionResetError" not in caplog.text


def test_already_imported_this_cycle_does_not_download(ws, ports):
    source = FakeSource()
    source.add(1)
    pull(ports, 1, source, chosen_task_ids=[TASK])
    source.add(2)
    source.listed.clear()
    pull(ports, 1, source, chosen_task_ids=[TASK])
    assert source.listed == [] and source.fetched == [rid(1)]


def test_snapshot_includes_pull_state(ws, ports):
    source = FakeSource()
    source.add(1)
    pull(ports, 1, source, chosen_task_ids=[TASK])
    store = ws.docs_for("dashboard")
    try:
        view = snapshot(store)
    finally:
        store.close()
    assert [row["task_id"] for row in view["scanner_state"]] == [TASK]


def test_pull_state_fields_are_replaced_not_merged(ws, ports):
    from engine.scanner_import import _write_state
    _write_state(ports.docs, TASK, {"last_counts": {"new": 1, "foreign": 2}, "kept": "yes"})
    _write_state(ports.docs, TASK, {"last_counts": {"new": 0}})
    assert docs(ws, "scanner_state")[TASK] == {"task_id": TASK, "last_counts": {"new": 0},
                                               "kept": "yes"}
