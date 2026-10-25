# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""The local lifecycle end to end, over many cycles, in one process.

One scenario runs twice: against a local `Workspace` (one SQLite file per
agent, a store per stage) and, when an emulator is configured, against
`FirestoreDocStore` on the Firestore emulator. Firestore is never faked: with
no `FIRESTORE_EMULATOR_HOST` that half is skipped and says so.

Simulated time is advanced in memory through `SimClock` in SIM mode. `real_ts`
is never moved, faked or injected: every stamp is checked against the wall
clock (`SimClock.now().real_ts`) read before and after the run.

Synthetic data only: invented findings, assets and owners on .invalid hosts.
CVE-2021-44228 is real and public; CVE-2099-0004 is a placeholder outside the
cached KEV list. The fake adapters answer from canned text, so the real
parsing, journalling and idempotency paths run unmodified.
"""
import json
import os
import sqlite3
from pathlib import Path

import pytest

from engine.approve import approve
from engine.ports import NoDelivery, NoTelemetry, Ports
from engine.report import run_report
from engine.rescan import run_rescan
from engine.seed import seed
from engine.sweep import accept
from engine.triage_cycle import run_triage_cycle
from scripts.local import run_local_cycle
from tools.clock import ClockMode, SimClock
from tools.enrichment import EnrichmentCache
from tools.guardrail import NoGuard, guard_for
from tools.local_layout import AGENT_FILES, SHARED, Workspace
from tools.local_memory import LocalMemory
from tools.reports import NO_SUMMARIZER
from tests.test_local_commands import PROPOSAL_JSON, RATIFY, FakeAdapter, roles_with

DAY = 86400
A, B, C, D, E = "RZ-0001", "RZ-0002", "RZ-0003", "RZ-0004", "RZ-0005"
COLLECTIONS = sorted({c for names in AGENT_FILES.values() for c in names} | set(SHARED))
SKIP_REASON = "FIRESTORE_EMULATOR_HOST not set: Firestore lifecycle not run"

# Ruling 37: the stamp pair each lifecycle collection carries today. Most use
# `real_ts`/`sim_ts`; three name the pair for the event that created the row.
STAMPS = {
    "decisions": ("real_ts", "sim_ts"),
    "assignments": ("real_ts", "sim_ts"),
    "tickets": ("opened_real_ts", "opened_sim_ts"),
    "exceptions": ("accepted_real_ts", "accepted_sim_ts"),
    "reports": ("real_ts", "sim_ts"),
    "cycles": ("started_real_ts", "started_sim_ts"),
    "human_queue": ("real_ts", "sim_ts"),
    "approvals": ("real_ts", "sim_ts"),
    "failed_runs": ("real_ts", "sim_ts"),
    "scans": ("real_ts", "sim_ts"),
    "memories": ("real_ts", "sim_ts"),
}


def write_corpus(folder, findings, assets, owners):
    folder.mkdir(parents=True, exist_ok=True)
    for name, rows in (("findings", findings), ("assets", assets), ("owners", owners)):
        (folder / f"{name}.json").write_text(json.dumps(rows), encoding="utf-8")
    return folder


def finding(finding_id, asset_id, cve_id="CVE-2021-44228"):
    return {"finding_id": finding_id, "asset_id": asset_id, "cve_id": cve_id,
            "status": "open", "scanner_comment": "Synthetic scanner note.",
            "injection_planted": False}


CORPUS = {
    "findings": [finding(A, "ast-01"), finding(B, "ast-02"), finding(C, "ast-02"),
                 finding(D, "ast-02", "CVE-2099-0004")],
    "assets": [{"asset_id": "ast-01", "hostname": "app-01.corp.invalid", "owner_id": "own-01"},
               {"asset_id": "ast-02", "hostname": "app-02.corp.invalid", "owner_id": "own-01"}],
    "owners": [{"owner_id": "own-01", "email": "owner@example.invalid",
                "display_name": "Synthetic Owner", "team": "synthetic"}],
}


def cross_family():
    return roles_with(FakeAdapter(PROPOSAL_JSON), FakeAdapter(RATIFY))


def same_family():
    return roles_with(FakeAdapter(PROPOSAL_JSON), FakeAdapter(RATIFY), reviewer_family="gpt")


def no_reviewer():
    return roles_with(FakeAdapter(PROPOSAL_JSON))


def calls(roles):
    return {role: len(adapter.calls) for role, adapter in roles._fakes.items() if adapter}


# --- the two storage backends ----------------------------------------------------


class SQLiteHarness:
    """A local workspace: `docs_for(stage)` enforces each stage's write boundary."""

    def __init__(self, root, clock):
        self.ws = Workspace(root)
        self.ws.init()

    def docs_for(self, stage):
        return self.ws.docs_for(stage)

    def journal(self):
        return self.ws.journal()

    def dump(self):
        docs = self.ws.docs_for("report")
        try:
            out = {name: {s.id: s.to_dict() for s in docs.collection(name).stream()}
                   for name in COLLECTIONS}
        finally:
            docs.close()
        conn = sqlite3.connect(self.ws.file_for("human_queue"))
        try:
            tables = [r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
            out["_journal"] = {t: conn.execute(f"SELECT * FROM {t} ORDER BY rowid").fetchall()
                               for t in tables}
        finally:
            conn.close()
        return out


class FirestoreHarness:
    """One `FirestoreDocStore` on the emulator serves every stage.

    It stands in for the `Workspace` that `run_local_cycle` is given: that
    function only calls `docs_for(stage)` and `journal()` on it. Per-stage
    write boundaries are a SQLite property and are not exercised here.
    """

    def __init__(self, client, clock):
        from tools.docstore import FirestoreDocStore

        class Docs(FirestoreDocStore):
            def close(self):
                pass  # the one client is closed by the test

        self._client, self._clock = client, clock
        self._docs = Docs(client)
        self.ws = self

    def docs_for(self, stage):
        return self._docs

    def journal(self):
        from tools.store import FirestoreIdempotencyStore
        return FirestoreIdempotencyStore(client=self._client, clock=self._clock)

    def dump(self):
        from tools.store import COLLECTION
        out = {name: {s.id: s.to_dict() for s in self._docs.collection(name).stream()}
               for name in COLLECTIONS}
        out["_journal"] = {s.id: s.to_dict() for s in self._client.collection(COLLECTION).stream()}
        return out


# --- the scenario ------------------------------------------------------------------


def ports(h, stage, clock, *, roles=None, journal=True):
    docs = h.docs_for(stage)
    return Ports(docs=docs, journal=h.journal() if journal else None, clock=clock, roles=roles,
                 guard=guard_for(roles) if roles else NoGuard(),
                 delivery=NoDelivery(), memory=LocalMemory(docs), telemetry=NoTelemetry(),
                 record_failed_runs=True)


def triage(h, cycle, roles, finding_ids, clock):
    """One engine triage call with `roles`: how a cycle gets a given review mode."""
    return run_triage_cycle(ports(h, "triage_cycle", clock, roles=roles), cycle,
                            finding_ids=finding_ids, enrichment=EnrichmentCache())


def local_cycle(h, cycle, roles, clock):
    return run_local_cycle(h.ws, cycle, roles=roles, clock=clock, environ={})


def run_lifecycle(h, clock, tmp_path):
    wall_before = clock.now().real_ts  # wall clock: SimClock never moves real_ts

    def get(name):
        return h.dump()[name]

    # 1. Seed loads the corpus.
    corpus = write_corpus(tmp_path / "corpus", **CORPUS)
    assert seed(ports(h, "seed", clock), corpus) == {"findings": 4, "assets": 2, "owners": 1}
    assert sorted(get("findings")) == [A, B, C, D]

    # 2. One review mode per triage call, since a run has one set of roles:
    #    A cross-family (cycle 1), B same-family with the default `wait`
    #    (cycle 2), C (and D) with no reviewer at all (cycle 3). Each cycle
    #    record then describes exactly the run it came from.
    cross, same, alone = cross_family(), same_family(), no_reviewer()
    assert triage(h, 1, cross, [A], clock)["outcomes"] == {"ratified": 1}
    assert triage(h, 2, same, [B], clock)["outcomes"] == {"held_for_approval": 1}
    assert triage(h, 3, alone, [C, D], clock)["outcomes"] == {"unreviewed": 2}
    decisions = get("decisions")
    assert {k: (v["outcome"], v["review_independence"]) for k, v in decisions.items()} == {
        f"{A}-c001": ("ratified", "cross_family"),
        f"{B}-c002": ("held_for_approval", "same_family"),
        f"{C}-c003": ("unreviewed", "unreviewed"),
        f"{D}-c003": ("unreviewed", "unreviewed")}
    assert calls(alone) == {"proposer": 2}  # no reviewer adapter was ever called
    queue = get("human_queue")
    assert queue[f"held-{B}-c002"]["kind"] == "same_family_review"
    assert queue[f"unreviewed-{C}-c003"]["kind"] == "unreviewed"
    cycles = get("cycles")
    assert [cycles[f"cycle-00{n}"]["reruns"] for n in (1, 2, 3)] == [0, 0, 0]

    # 3. Only A is assigned and gets an SLA clock.
    assert sorted(get("assignments")) == [f"{A}-c001"]
    clocks = get("sla_clocks")
    assert sorted(clocks) == [A] and clocks[A]["status"] == "open"
    assert clocks[A]["due_sim_ts"] - clocks[A]["started_sim_ts"] == 7 * DAY

    # 4. Past A's SLA, chase escalates exactly once across two chase runs.
    later = cross_family()
    first = local_cycle(h, 4, later, clock)
    assert first["outcomes"] == {} and first["chase"] == {"open_ticket": 1}
    assert calls(later) == {"proposer": 0, "reviewer": 0}  # decided findings are not re-triaged
    clock.advance(seconds=8 * DAY)
    assert local_cycle(h, 5, later, clock)["chase"].get("escalate") == 1
    second = local_cycle(h, 6, later, clock)
    assert "escalate" not in second["chase"]
    ticket = get("tickets")[A]
    assert ticket["escalated"] is True
    assert [e["action"] for e in ticket["history"]].count("escalate") == 1
    assert get("sla_clocks")[A]["status"] == "breached"

    # 5. `approve B`, then the next cycle assigns B. The decision is unchanged.
    approval_ports = ports(h, "approve", clock)
    assert approve(approval_ports, B, 2, "Synthetic Approver") == f"{B}-c002"
    assert f"{B}-c002" not in get("assignments")  # the approval alone assigns nothing
    held_before = get("decisions")[f"{B}-c002"]
    assert local_cycle(h, 7, later, clock)["approved"] == [f"{B}-c002"]
    assert f"{B}-c002" in get("assignments")
    assert get("sla_clocks")[B]["status"] == "open"
    assert get("decisions")[f"{B}-c002"] == held_before
    assert get("approvals")[f"{B}-c002"]["approved_by"] == "Synthetic Approver"

    # 6. A 7-day acceptance on D reopens once 8 simulated days have passed.
    result = accept(ports(h, "exception_accept", clock), D, 7, "own-01",
                    "Synthetic: host isolated pending decommission", 7)
    assert result == f"accepted:{D}"
    stub = get("sla_clocks")[D]  # D was never assigned: the pause makes a stub
    assert stub["status"] == "accepted" and "paused_sim_ts" in stub
    clock.advance(seconds=8 * DAY)
    assert local_cycle(h, 8, later, clock)["sweep"] == {"reopen": 1}
    exception = get("exceptions")[D]
    assert exception["status"] == "expired" and exception["reopened"] is True
    assert get("sla_clocks")[D]["status"] == "reopened_pending_triage"
    assert get("human_queue")[f"reopened-{D}"]["kind"] == "acceptance_expired"

    # 7. A rescan dry run writes nothing; the real rescan resolves A.
    scan = {"scan_id": "rescan-lifecycle", "covered_asset_ids": ["ast-01"], "findings": []}
    before = h.dump()
    dry = run_rescan(ports(h, "rescan", clock, journal=False), 9, scan, dry_run=True)
    assert dry["written"] is False and dry["counts"]["resolved"] == 1
    assert h.dump() == before
    applied = run_rescan(ports(h, "rescan", clock), 9, scan, dry_run=False)
    assert applied["written"] is True and applied["newly_resolved"] == 1
    findings = get("findings")
    assert findings[A]["status"] == "resolved"
    assert findings[A]["resolved_by_scan"] == "rescan-lifecycle"
    assert {f: findings[f]["status"] for f in (B, C, D)} == {B: "open", C: "open", D: "open"}
    assert "rescan-lifecycle" in get("scans")

    # 8. The report counts each review outcome; with no summarizer it says so.
    assert run_report(ports(h, "report", clock, roles=later), 9) == NO_SUMMARIZER
    report = get("reports")["report-c009"]
    assert report["summary"] == NO_SUMMARIZER
    assert (report["metrics"]["ratified"], report["metrics"]["held_for_approval"],
            report["metrics"]["unreviewed"]) == (1, 1, 2)

    # A corpus record with no asset stops the next cycle (a finding with no CVE
    # is valid now, so the malformation is the missing asset). The failure is
    # kept (class only) and the reopened D is re-triaged once before it.
    extra = write_corpus(tmp_path / "corpus-2", [{"finding_id": E, "cve_id": "CVE-2021-44228",
                                                  "status": "open"}], [], [])
    seed(ports(h, "seed", clock), extra)
    with pytest.raises(KeyError):
        local_cycle(h, 10, later, clock)
    assert get("failed_runs")[f"{E}-c010"]["error_class"] == "KeyError"
    assert get("decisions")[f"{D}-c010"]["outcome"] == "ratified"

    # 9. Every lifecycle document carries both clocks, and every real_ts is
    #    the wall clock at the time of writing: never moved, never backdated.
    wall_after = clock.now().real_ts
    everything = h.dump()
    for name, (real, sim) in STAMPS.items():
        rows = everything[name]
        assert rows, f"{name} was never written, so its stamps were not checked"
        for doc_id, doc in rows.items():
            assert real in doc and sim in doc, (name, doc_id, sorted(doc))
            assert wall_before <= doc[real] <= wall_after, (name, doc_id)
            assert doc[sim] >= doc[real] - 1, (name, doc_id)
    # Derived sla_clocks: every assigned clock carries its start pair.
    for doc_id, doc in everything["sla_clocks"].items():
        assert "started_real_ts" in doc and "started_sim_ts" in doc, (doc_id, sorted(doc))
        assert wall_before <= doc["started_real_ts"] <= wall_after
    # Every ticket history entry carries both clocks too.
    for doc_id, doc in everything["tickets"].items():
        for entry in doc["history"]:
            assert "real_ts" in entry and "sim_ts" in entry, (doc_id, entry)
    # Simulated time ran 16 days ahead of real time; real time did not.
    assert clock.now().sim_ts - clock.now().real_ts >= 16 * DAY - 1
    assert wall_after - wall_before < 16 * DAY


def test_lifecycle_local(tmp_path):
    clock = SimClock(mode=ClockMode.SIM)
    run_lifecycle(SQLiteHarness(tmp_path / "workspace", clock), clock, tmp_path)


def test_lifecycle_firestore_emulator(tmp_path):
    if not os.environ.get("FIRESTORE_EMULATOR_HOST"):
        pytest.skip(SKIP_REASON)
    from google.cloud import firestore

    from tools.store import COLLECTION

    client = firestore.Client(project="rz-lifecycle")
    for name in (*COLLECTIONS, COLLECTION):
        for doc in client.collection(name).stream():
            doc.reference.delete()
    clock = SimClock(mode=ClockMode.SIM)
    try:
        run_lifecycle(FirestoreHarness(client, clock), clock, tmp_path)
    finally:
        client.close()
