# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""The chase, sweep, report, rescan and seed stages, run against a local workspace.

Everything here is synthetic: owners, assets and findings are invented, emails
end in .invalid and CVE identifiers are placeholders or real public ones. No
stage here needs a model; the report stage writes its marker without one.
"""
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from engine.ports import NoDelivery, NoTelemetry, Ports
from tools.clock import ClockMode, SimClock
from tools.enrichment import Enrichment
from tools.guardrail import NoGuard
from tools.local_layout import AGENT_FILES, SHARED, STAGE_WRITES, Workspace
from tools.local_memory import LocalMemory
from tools.model_roles import ModelRoles
from tools.reports import NO_SUMMARIZER

ROOT = Path(__file__).resolve().parents[1]
DAY = 86400
COLLECTIONS = sorted({c for names in AGENT_FILES.values() for c in names} | set(SHARED))


class ForbiddenModels:
    """Stands in for `ports.roles` where a stage must not touch models at all."""

    def __getattr__(self, name):
        raise AssertionError(f"this stage must not use model roles ({name})")


@pytest.fixture
def ws(tmp_path):
    return Workspace(tmp_path / "workspace")


def ports_for(ws, stage, clock, roles=None, delivery=None):
    docs = ws.docs_for(stage)
    return Ports(docs=docs, journal=ws.journal(), clock=clock, roles=roles,
                 guard=NoGuard(), delivery=delivery or NoDelivery(),
                 memory=LocalMemory(docs), telemetry=NoTelemetry())


def seed_reference(ws, clock):
    docs = ws.docs_for("seed")
    docs.collection("owners").document("own-1").set(
        {"owner_id": "own-1", "email": "ada.abara@example.invalid"})
    for fid, asset, status in (("RZ-0001", "ast-001", "open"), ("RZ-0002", "ast-001", "open"),
                               ("RZ-0003", "ast-002", "open"), ("RZ-0004", "ast-009", "open")):
        docs.collection("findings").document(fid).set(
            {"finding_id": fid, "asset_id": asset, "status": status,
             "cve_id": "CVE-2021-44228"})
    return docs


def start_clock(ws, finding_id, clock, sla_days=7):
    now = clock.now().sim_ts
    ws.docs_for("chase").collection("sla_clocks").document(finding_id).set(
        {"finding_id": finding_id, "owner_id": "own-1", "status": "open",
         "started_sim_ts": now, "due_sim_ts": now + sla_days * DAY, "sla_days": sla_days})


def dump(ws):
    """Every document in every collection, plus every journal row."""
    docs = ws.docs_for("report")
    out = {name: {s.id: s.to_dict() for s in docs.collection(name).stream()}
           for name in COLLECTIONS}
    conn = sqlite3.connect(ws.file_for("human_queue"))
    try:
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        out["_journal"] = {t: conn.execute(f"SELECT * FROM {t} ORDER BY rowid").fetchall()
                           for t in tables}
    finally:
        conn.close()
    return out


# --- chase ----------------------------------------------------------------------

def test_chase_escalates_after_sla_breach(ws):
    from engine.chase import run_chase
    clock = SimClock(mode=ClockMode.SIM)
    wall_before = clock.now().real_ts
    seed_reference(ws, clock)
    start_clock(ws, "RZ-0001", clock)

    first = run_chase(ports_for(ws, "chase", clock, roles=ForbiddenModels()), cycle=1)
    assert first == {"open_ticket": 1}

    # Past the SLA, in memory. real_ts is never moved, only simulated time.
    clock.advance(seconds=8 * DAY)
    ports = ports_for(ws, "chase", clock)
    assert run_chase(ports, cycle=2) == {"escalate": 1}

    docs = ws.docs_for("report")
    ticket = docs.collection("tickets").document("RZ-0001").get().to_dict()
    assert ticket["status"] == "escalated" and ticket["escalated"] is True
    assert ticket["escalated_cycle"] == 2
    assert docs.collection("sla_clocks").document("RZ-0001").get().to_dict()["status"] == "breached"
    stamps = [entry["real_ts"] for entry in ticket["history"]]
    assert [entry["action"] for entry in ticket["history"]] == ["open_ticket", "escalate"]
    assert all(wall_before <= ts <= clock.now().real_ts for ts in stamps)
    assert ticket["history"][1]["sim_ts"] - ticket["history"][1]["real_ts"] >= 8 * DAY - 60


def test_local_chase_records_no_delivery(ws):
    from engine.chase import run_chase
    assert NoDelivery.external is False
    clock = SimClock(mode=ClockMode.SIM)
    seed_reference(ws, clock)
    start_clock(ws, "RZ-0001", clock)

    assert run_chase(ports_for(ws, "chase", clock), cycle=1) == {"open_ticket": 1}

    ticket = ws.docs_for("report").collection("tickets").document("RZ-0001").get().to_dict()
    assert ticket["status"] == "open"
    assert "delivery" not in ticket
    assert "github_issue" not in ticket


def test_chase_stage_never_imports_rescan():
    """Only scripts/rescan.py (and the local CLI) resolve findings; agents never do."""
    source = (ROOT / "engine" / "chase.py").read_text()
    assert "engine.rescan" not in source and "import run_rescan" not in source


# --- sweep ----------------------------------------------------------------------

def test_sweep_reopens_expired_exception(ws):
    from engine.sweep import accept, run_sweep
    clock = SimClock(mode=ClockMode.SIM)
    seed_reference(ws, clock)
    enrichment = type("E", (), {"enrich": lambda self, cve: Enrichment(cve_id=cve, in_kev=False)})()

    accepted = accept(ports_for(ws, "exception_accept", clock, roles=ForbiddenModels()),
                      "RZ-0002", 30, "own-1", "Isolated pending decommission", 10,
                      enrichment=enrichment)
    assert accepted == "accepted:RZ-0002"

    ports = ports_for(ws, "sweep", clock, roles=ForbiddenModels())
    assert run_sweep(ports, cycle=11) == {"none": 1}

    clock.advance(seconds=31 * DAY)
    assert run_sweep(ports, cycle=12) == {"reopen": 1}

    docs = ws.docs_for("report")
    exception = docs.collection("exceptions").document("RZ-0002").get().to_dict()
    assert exception["status"] == "expired" and exception["reopened"] is True
    assert docs.collection("sla_clocks").document("RZ-0002").get().to_dict()["status"] == \
        "reopened_pending_triage"
    queued = docs.collection("human_queue").document("reopened-RZ-0002").get().to_dict()
    assert queued["kind"] == "acceptance_expired"

    # Reopened once; the next sweep leaves it alone.
    assert run_sweep(ports, cycle=13) == {"none": 1}


def test_accept_refuses_kev_without_a_person(ws):
    from engine.sweep import accept
    clock = SimClock(mode=ClockMode.SIM)
    seed_reference(ws, clock)
    kev = type("E", (), {"enrich": lambda self, cve: Enrichment(cve_id=cve, in_kev=True)})()
    with pytest.raises(ValueError, match="KEV"):
        accept(ports_for(ws, "exception_accept", clock), "RZ-0001", 30, "own-1", "x", 10,
               enrichment=kev)
    docs = ws.docs_for("report")
    assert docs.collection("exceptions").document("RZ-0001").get().to_dict() is None
    assert docs.collection("human_queue").document(
        "acceptance-refused-RZ-0001-c010").get().to_dict()["kind"] == "acceptance_refused"


def test_accept_unknown_finding_raises_no_such_finding(ws):
    from engine.sweep import NoSuchFinding, accept
    clock = SimClock(mode=ClockMode.SIM)
    with pytest.raises(NoSuchFinding):
        accept(ports_for(ws, "exception_accept", clock), "RZ-9999", 30, "own-1", "x", 10)


# --- report ---------------------------------------------------------------------

@pytest.mark.parametrize("roles", [None, ModelRoles()], ids=["no-roles", "no-summarizer"])
def test_report_without_summarizer_writes_marker(ws, roles):
    from engine.report import run_report
    clock = SimClock(mode=ClockMode.SIM)
    seed_reference(ws, clock)

    summary = run_report(ports_for(ws, "report", clock, roles=roles), cycle=30)

    assert summary == NO_SUMMARIZER
    report = ws.docs_for("report").collection("reports").document("report-c030").get().to_dict()
    assert report["summary"] == NO_SUMMARIZER
    assert report["cycle"] == 30 and "real_ts" in report and "sim_ts" in report
    assert report["metrics"]["decisions_total"] == 0


def test_report_cannot_write_tickets(ws):
    from engine.report import run_report
    clock = SimClock(mode=ClockMode.SIM)
    ports = ports_for(ws, "report", clock)

    assert run_report(ports, cycle=1) == NO_SUMMARIZER
    with pytest.raises(PermissionError):
        ports.docs.collection("tickets").document("RZ-0001").set({"status": "open"})
    assert "tickets" not in STAGE_WRITES["report"]


# --- rescan ---------------------------------------------------------------------

SCAN = {"scan_id": "rescan-synthetic", "covered_asset_ids": ["ast-001", "ast-002"],
        "findings": [
            {"finding_id": "RZ-0002", "asset_id": "ast-001", "cve_id": "CVE-2021-44228"},
            {"finding_id": "RZ-0100", "asset_id": "ast-002", "cve_id": "CVE-2021-44228",
             "scanner_comment": "synthetic", "injection_planted": False}]}


def test_rescan_dry_run_writes_nothing(ws):
    from engine.rescan import run_rescan
    clock = SimClock(mode=ClockMode.SIM)
    seed_reference(ws, clock)
    before = dump(ws)

    result = run_rescan(ports_for(ws, "rescan", clock, roles=ForbiddenModels()), 12, SCAN,
                        dry_run=True)

    assert result == {"cycle": "cycle-012", "scan_id": "rescan-synthetic",
                      "counts": {"new": 1, "persisting": 1, "regressed": 0, "resolved": 2,
                                 "unverifiable": 1},
                      "written": False}
    after = dump(ws)
    assert {k: len(v) for k, v in after.items()} == {k: len(v) for k, v in before.items()}
    assert after == before


def test_rescan_closes_verified_finding(ws):
    from engine.rescan import run_rescan
    clock = SimClock(mode=ClockMode.SIM)
    seed_reference(ws, clock)
    ports = ports_for(ws, "rescan", clock, roles=ForbiddenModels())

    result = run_rescan(ports, 12, SCAN, dry_run=False)

    assert result["written"] is True
    assert (result["newly_resolved"], result["newly_reopened"], result["newly_ingested"]) == (2, 0, 1)
    findings = ws.docs_for("report").collection("findings")
    closed = findings.document("RZ-0001").get().to_dict()
    assert closed["status"] == "resolved" and closed["resolved_by_scan"] == "rescan-synthetic"
    assert findings.document("RZ-0002").get().to_dict()["status"] == "open"   # still reported
    assert findings.document("RZ-0004").get().to_dict()["status"] == "open"   # not covered
    new = findings.document("RZ-0100").get().to_dict()
    assert new["status"] == "open" and "injection_planted" not in new
    scan = ws.docs_for("report").collection("scans").document("rescan-synthetic").get().to_dict()
    assert scan["covered_asset_ids"] == ["ast-001", "ast-002"]

    # A repeat run of the same cycle changes nothing and reports zero new work.
    before = dump(ws)
    again = run_rescan(ports, 12, SCAN, dry_run=False)
    assert (again["newly_resolved"], again["newly_reopened"], again["newly_ingested"]) == (0, 0, 0)
    assert dump(ws) == before


# --- seed -----------------------------------------------------------------------

def _unstamped(snapshot):
    return {name: {doc_id: {k: v for k, v in doc.items() if k not in ("real_ts", "sim_ts")}
                   for doc_id, doc in rows.items()}
            for name, rows in snapshot.items() if name in ("findings", "assets", "owners")}


def test_seed_is_idempotent(ws):
    from engine.seed import seed
    clock = SimClock(mode=ClockMode.SIM)
    ports = ports_for(ws, "seed", clock, roles=ForbiddenModels())

    first = seed(ports, ROOT / "data")
    snapshot = dump(ws)
    second = seed(ports, ROOT / "data")
    again = dump(ws)

    corpus = {kind: len(json.loads((ROOT / "data" / f"{kind}.json").read_text()))
              for kind in ("findings", "assets", "owners")}
    assert first == second == corpus
    assert {k: len(v) for k, v in again.items()} == {k: len(v) for k, v in snapshot.items()}
    assert _unstamped(again) == _unstamped(snapshot)
    for rows in _unstamped(again).values():
        for doc in rows.values():
            assert "injection_planted" not in doc
    assert all("real_ts" in d and "sim_ts" in d for d in again["findings"].values())


# --- standard library only --------------------------------------------------------

STAGE_RUN = r"""
import json, sys
from pathlib import Path
from engine.chase import run_chase
from engine.ports import NoDelivery, NoTelemetry, Ports
from engine.report import run_report
from engine.rescan import run_rescan
from engine.seed import seed
from engine.sweep import accept, run_sweep
from tools.clock import ClockMode, SimClock
from tools.guardrail import NoGuard
from tools.local_layout import Workspace
from tools.local_memory import LocalMemory

ws = Workspace(Path(sys.argv[1]))
clock = SimClock(mode=ClockMode.SIM)
def ports(stage):
    docs = ws.docs_for(stage)
    return Ports(docs, ws.journal(), clock, None, NoGuard(), NoDelivery(),
                 LocalMemory(docs), NoTelemetry())
counts = seed(ports("seed"), Path("data"))
now = clock.now().sim_ts
ws.docs_for("chase").collection("sla_clocks").document("RZ-0001").set(
    {"finding_id": "RZ-0001", "owner_id": "own-001", "status": "open",
     "started_sim_ts": now, "due_sim_ts": now + 7 * 86400})
chased = run_chase(ports("chase"), 1)
accepted = accept(ports("exception_accept"), "RZ-0002", 30, "own-001", "synthetic", 1,
                  approved_by_human=True)
clock.advance(seconds=31 * 86400)
swept = run_sweep(ports("sweep"), 2)
summary = run_report(ports("report"), 3)
scan = {"scan_id": "rescan-stdlib", "covered_asset_ids": [], "findings": []}
dry = run_rescan(ports("rescan"), 4, scan, dry_run=True)
applied = run_rescan(ports("rescan"), 4, scan, dry_run=False)
loaded = sorted(m for m in sys.modules
                if m.split(".")[0] in ("google", "scripts", "httpx") or m == "tools.store")
print(json.dumps({"counts": counts, "chased": chased, "accepted": accepted, "swept": swept,
                  "summary": summary, "dry": dry["written"], "applied": applied["written"],
                  "loaded": loaded}))
"""


def test_stages_stdlib_only(tmp_path):
    ran = subprocess.run([sys.executable, "-S", "-c", STAGE_RUN, str(tmp_path / "ws")],
                         cwd=ROOT, capture_output=True, text=True, timeout=120)
    assert ran.returncode == 0, ran.stderr
    result = json.loads(ran.stdout.strip().splitlines()[-1])
    assert result["loaded"] == []
    assert result["chased"] == {"open_ticket": 1}
    assert result["accepted"] == "accepted:RZ-0002"
    assert result["swept"] == {"reopen": 1}
    assert result["summary"] == NO_SUMMARIZER
    assert (result["dry"], result["applied"]) == (False, True)
    assert result["counts"]["findings"] > 0


def test_installed_local_edition_can_import_the_stages(tmp_path):
    from scripts.build_local_installer import build
    installer = build(tmp_path / "install.py")
    destination = tmp_path / "app"
    installed = subprocess.run([sys.executable, "-S", str(installer), "--directory",
                                str(destination), "--yes", "--no-start"],
                               capture_output=True, text=True, timeout=30)
    assert installed.returncode == 0, installed.stderr
    imported = subprocess.run(
        [sys.executable, "-S", "-c",
         "import engine.chase, engine.sweep, engine.report, engine.rescan, engine.seed"],
        cwd=destination, capture_output=True, text=True, timeout=30)
    assert imported.returncode == 0, imported.stderr


def test_rescan_apply_without_journal_refuses_before_writing(ws):
    from dataclasses import replace
    from engine.rescan import run_rescan
    clock = SimClock(mode=ClockMode.SIM)
    seed_reference(ws, clock)
    ports = replace(ports_for(ws, "rescan", clock), journal=None)
    before = dump(ws)

    with pytest.raises(ValueError, match="rescan apply needs a journal"):
        run_rescan(ports, 12, SCAN, dry_run=False)

    after = dump(ws)
    assert {k: len(v) for k, v in after.items()} == {k: len(v) for k, v in before.items()}
    assert after == before


def test_scan_manifest_records_source_and_task(ws):
    from engine.rescan import run_rescan
    clock = SimClock(mode=ClockMode.SIM)
    seed_reference(ws, clock)
    scan = {**SCAN, "scan_id": "gb-1", "task_id": "T1", "source": "greenbone",
            "report_status": "Done", "withheld_finding_ids": []}

    run_rescan(ports_for(ws, "rescan", clock, roles=ForbiddenModels()), 12, scan,
               dry_run=False)

    stored = ws.docs_for("report").collection("scans").document("gb-1").get().to_dict()
    assert stored["source"] == "greenbone"
    assert stored["task_id"] == "T1"
    assert stored["report_status"] == "Done"


def test_untasked_scan_manifest_has_no_task_fields(ws):
    from engine.rescan import run_rescan
    clock = SimClock(mode=ClockMode.SIM)
    seed_reference(ws, clock)
    run_rescan(ports_for(ws, "rescan", clock, roles=ForbiddenModels()), 12, SCAN,
               dry_run=False)
    stored = ws.docs_for("report").collection("scans").document("rescan-synthetic").get().to_dict()
    assert not {"source", "task_id", "report_status"} & set(stored)


def test_withheld_finding_status_is_unchanged_by_a_scan(ws):
    from engine.rescan import run_rescan
    clock = SimClock(mode=ClockMode.SIM)
    seed_reference(ws, clock)
    findings = ws.docs_for("report").collection("findings")
    before = findings.document("RZ-0001").get().to_dict()
    assert before["status"] == "open"
    # RZ-0001 is absent and covered (test_rescan_closes_verified_finding shows
    # it resolves); withheld, it must not.
    scan = {**SCAN, "withheld_finding_ids": ["RZ-0001"]}

    result = run_rescan(ports_for(ws, "rescan", clock, roles=ForbiddenModels()), 12, scan,
                        dry_run=False)

    assert findings.document("RZ-0001").get().to_dict() == before
    assert result["newly_resolved"] == 1   # only the other covered, absent finding


def test_greenbone_scan_without_withheld_list_is_refused(ws):
    from engine.rescan import run_rescan
    clock = SimClock(mode=ClockMode.SIM)
    seed_reference(ws, clock)
    before = dump(ws)
    scan = {**SCAN, "scan_id": "gb-2", "task_id": "T1", "source": "greenbone",
            "report_status": "Done"}

    with pytest.raises(ValueError, match="missing withheld_finding_ids"):
        run_rescan(ports_for(ws, "rescan", clock, roles=ForbiddenModels()), 12, scan,
                   dry_run=False)

    assert dump(ws) == before


def test_greenbone_scan_without_task_id_is_refused(ws):
    from engine.rescan import run_rescan
    clock = SimClock(mode=ClockMode.SIM)
    seed_reference(ws, clock)
    before = dump(ws)
    for task in (None, ""):
        scan = {**SCAN, "scan_id": "gb-3", "source": "greenbone", "report_status": "Done",
                "withheld_finding_ids": []}
        if task is not None:
            scan["task_id"] = task
        with pytest.raises(ValueError, match="missing task_id"):
            run_rescan(ports_for(ws, "rescan", clock, roles=ForbiddenModels()), 12, scan,
                       dry_run=False)
    assert dump(ws) == before


def test_greenbone_scan_with_string_withheld_list_is_refused(ws):
    from engine.rescan import run_rescan
    clock = SimClock(mode=ClockMode.SIM)
    seed_reference(ws, clock)
    before = dump(ws)
    scan = {**SCAN, "scan_id": "gb-4", "task_id": "T1", "source": "greenbone",
            "report_status": "Done", "withheld_finding_ids": "RZ-0001"}
    with pytest.raises(ValueError, match="list of strings"):
        run_rescan(ports_for(ws, "rescan", clock, roles=ForbiddenModels()), 12, scan,
                   dry_run=False)
    assert dump(ws) == before
