# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""A finding left unassigned is looked at again in every later cycle.

An owner recorded after the finding was ratified is picked up by the next
cycle: a new assignment in that cycle, and the SLA clock started then, never
backdated to the decision. With still no owner, nothing new is written. The
original "unassigned" queue entry stays as history and is shown as resolved.

Synthetic data only: invented findings, assets and owners on .invalid hosts.
"""
import json
import logging

from engine.snapshot import snapshot
from tools.metrics import compute_metrics
from tools.ownership import owner_found_cycle
from tests.test_engine_triage_cycle import (FINDING_ID, PROPOSAL_JSON, RATIFY, FakeAdapter,
                                            FakeCache, everything, journal_rows, ports_for,
                                            roles_with, ws)  # noqa: F401  (ws is a fixture)


def cycle(ports, number, finding_ids):
    from engine.triage_cycle import run_triage_cycle
    return run_triage_cycle(ports, number, finding_ids=finding_ids, enrichment=FakeCache())


def unowned_then_ratified(ws):
    """Cycle 1 ratifies the finding while its asset has no owner."""
    seed = ws.docs_for("seed")
    seed.collection("findings").document(FINDING_ID).update({"status": "open"})
    seed.collection("assets").document("ast-01").update({"owner_id": None})
    proposer, reviewer = FakeAdapter(PROPOSAL_JSON), FakeAdapter(RATIFY)
    roles = roles_with(proposer, reviewer)
    cycle(ports_for(ws, roles), 1, [FINDING_ID])
    return roles, proposer, reviewer


def events(caplog):
    return [json.loads(r.getMessage()) for r in caplog.records
            if r.name == "remediation_zero.cycle"]


def test_an_owner_recorded_later_is_picked_up_by_the_next_cycle(ws, caplog):
    roles, proposer, reviewer = unowned_then_ratified(ws)
    state = everything(ws)
    assert state["assignments"]["RZ-0001-c001"][0]["needs_human"] is True
    assert list(state["human_queue"]) == ["unassigned-RZ-0001-c001"]
    assert state["sla_clocks"] == {}

    ws.docs_for("seed").collection("assets").document("ast-01").update({"owner_id": "own-01"})
    caplog.set_level(logging.INFO, logger="remediation_zero.cycle")
    record = cycle(ports_for(ws, roles), 2, [])

    state = everything(ws)
    assigned = state["assignments"]["RZ-0001-c002"][0]
    assert assigned["owner_id"] == "own-01" and assigned["needs_human"] is False
    clock = state["sla_clocks"][FINDING_ID][0]
    assert clock["cycle_started"] == 2 and clock["sla_days"] == 7
    # Started now, not at the decision: nobody was told before an owner existed.
    assert clock["started_sim_ts"] >= state["decisions"]["RZ-0001-c001"][0]["sim_ts"]
    assert clock["started_real_ts"] == assigned["real_ts"]
    assert list(state["human_queue"]) == ["unassigned-RZ-0001-c001"]
    assert len(proposer.calls) == 1 and len(reviewer.calls) == 1
    assert record["outcomes"] == {}
    found = [e for e in events(caplog) if e["event"] == "owner_found_on_recheck"]
    assert len(found) == 1
    assert found[0]["finding_id"] == FINDING_ID and found[0]["cycle_id"] == "cycle-002"
    assert found[0]["owner_id"] == "own-01" and found[0]["unassigned_since_cycle"] == 1


def test_still_no_owner_writes_nothing_new(ws, caplog):
    roles, _, _ = unowned_then_ratified(ws)
    before, before_journal = everything(ws), journal_rows(ws)
    caplog.set_level(logging.INFO, logger="remediation_zero.cycle")

    cycle(ports_for(ws, roles), 2, [])

    after = everything(ws)
    assert {n: r for n, r in after.items() if n not in ("cycles", "memories")} == \
        {n: r for n, r in before.items() if n not in ("cycles", "memories")}
    assert journal_rows(ws) == before_journal
    still = [e for e in events(caplog) if e["event"] == "still_unassigned_on_recheck"]
    assert [(e["finding_id"], e["cycle_id"]) for e in still] == [(FINDING_ID, "cycle-002")]


def test_rerunning_the_cycle_that_found_the_owner_writes_nothing_new(ws):
    roles, _, _ = unowned_then_ratified(ws)
    ws.docs_for("seed").collection("assets").document("ast-01").update({"owner_id": "own-01"})
    cycle(ports_for(ws, roles), 2, [])
    before, before_journal = everything(ws), journal_rows(ws)

    cycle(ports_for(ws, roles), 2, [])

    after = everything(ws)
    assert {n: r for n, r in after.items() if n != "cycles"} == \
        {n: r for n, r in before.items() if n != "cycles"}
    assert journal_rows(ws) == before_journal


def test_a_later_cycle_does_not_reassign_a_finding_that_has_an_owner(ws):
    proposer, reviewer = FakeAdapter(PROPOSAL_JSON), FakeAdapter(RATIFY)
    roles = roles_with(proposer, reviewer)
    ws.docs_for("seed").collection("findings").document(FINDING_ID).update({"status": "open"})
    cycle(ports_for(ws, roles), 1, [FINDING_ID])
    before = everything(ws)

    cycle(ports_for(ws, roles), 2, [])

    after = everything(ws)
    assert list(after["assignments"]) == ["RZ-0001-c001"]
    assert after["sla_clocks"] == before["sla_clocks"]


def test_a_resolved_finding_is_not_rechecked(ws):
    roles, _, _ = unowned_then_ratified(ws)
    seed = ws.docs_for("seed")
    seed.collection("findings").document(FINDING_ID).update({"status": "resolved"})
    seed.collection("assets").document("ast-01").update({"owner_id": "own-01"})

    cycle(ports_for(ws, roles), 2, [])

    assert list(everything(ws)["assignments"]) == ["RZ-0001-c001"]


def test_the_old_queue_entry_is_shown_as_resolved_and_not_counted(ws):
    roles, _, _ = unowned_then_ratified(ws)
    ws.docs_for("seed").collection("assets").document("ast-01").update({"owner_id": "own-01"})
    cycle(ports_for(ws, roles), 2, [])

    queue = snapshot(ws.docs_for("report"))["human_queue"]
    assert [row.get("owner_found_cycle") for row in queue] == [2]

    docs = ws.docs_for("report")
    rows = {name: [d.to_dict() for d in docs.collection(name).stream()]
            for name in ("decisions", "tickets", "sla_clocks", "human_queue", "exceptions",
                         "findings", "scans", "assets")}
    metrics = compute_metrics(rows["decisions"], rows["tickets"], rows["sla_clocks"],
                              rows["human_queue"], rows["exceptions"], rows["findings"],
                              rows["scans"], rows["assets"])
    assert metrics["human_queue_total"] == 0 and metrics["human_queue_by_kind"] == {}
    assert metrics["human_queue_owner_found"] == 1


def test_owner_found_cycle_needs_a_later_clock_with_an_owner():
    entry = {"kind": "unassigned", "finding_id": "RZ-1", "cycle": 1}
    assert owner_found_cycle(entry, {"owner_id": "own-1", "cycle_started": 2}) == 2
    assert owner_found_cycle(entry, {"owner_id": "own-1", "cycle_started": 1}) is None
    assert owner_found_cycle(entry, {"owner_id": None, "cycle_started": 2}) is None
    assert owner_found_cycle(entry, None) is None
    assert owner_found_cycle(dict(entry, kind="adjudication"),
                             {"owner_id": "own-1", "cycle_started": 2}) is None


def test_the_actions_view_marks_the_entry_resolved(ws):
    from ui.dashboard_view import render
    roles, _, _ = unowned_then_ratified(ws)
    ws.docs_for("seed").collection("assets").document("ast-01").update({"owner_id": "own-01"})
    cycle(ports_for(ws, roles), 2, [])

    page = render(snapshot(ws.docs_for("report")), "actions")

    assert "an owner was found in cycle 2; this no longer waits on anyone." in page
