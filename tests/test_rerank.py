# Copyright 2026 Daviyon Daniels
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""When the owner changes a host's business context, its open findings are re-ranked on the
next cycle and their deadlines move, keeping the clock's original start."""
import json

import pytest

from engine.ports import NoTelemetry, Ports
from engine.triage_cycle import pending_findings, run_triage_cycle
from tests.test_engine_triage_cycle import (FINDING_ID, FakeAdapter, FakeCache, ForbiddenDelivery,
                                            RATIFY, RecordingGuard, roles_with)
from tests.test_engine_triage_cycle import ws as base_ws  # noqa: F401
from tools.clock import ClockMode, SimClock
from tools.context_store import ContextWriter
from tools.local_memory import LocalMemory

DAY = 86400
OWNER = "owner@example.invalid"
REJECT = "INJECTION: none\nVERDICT: REJECT\nREASON: not enough evidence"


def proposal(sla, severity="high"):
    return json.dumps({"severity": severity, "sla_days": sla, "remediation": "Apply the vendor patch.",
                       "evidence": ["in CISA KEV"], "rationale": "Exploited."})


@pytest.fixture
def ws(base_ws):
    base_ws.docs_for("seed").collection("findings").document(FINDING_ID).update({"status": "open"})
    return base_ws


@pytest.fixture
def clock():
    return SimClock(ClockMode.SIM)


def cycle(ws, clock, n, sla, reviewer=RATIFY):
    docs = ws.docs_for("triage_cycle")
    ports = Ports(docs=docs, journal=ws.journal(), clock=clock,
                  roles=roles_with(FakeAdapter(proposal(sla)), FakeAdapter(reviewer)),
                  guard=RecordingGuard(), delivery=ForbiddenDelivery(), memory=LocalMemory(docs),
                  telemetry=NoTelemetry(), record_failed_runs=True)
    return run_triage_cycle(ports, n, finding_ids=pending_findings(docs), enrichment=FakeCache())


def label(ws, clock, **facts):
    return ContextWriter(ws.docs_for("context"), clock).set_facts(
        ["ast-01"], facts, source="direct", account=OWNER)


def read(ws, collection, doc_id):
    return ws.docs_for("dashboard").collection(collection).document(doc_id).get().to_dict()


def moves(ws):
    return {s.id: s.to_dict() for s in ws.docs_for("dashboard").collection("deadline_moves").stream()}


def test_unchanged_host_not_rerun(ws, clock):
    cycle(ws, clock, 1, 30)
    assert pending_findings(ws.docs_for("dashboard")) == []


def test_label_change_reranks_open_findings_once(ws, clock):
    cycle(ws, clock, 1, 30)
    clock.advance(60)
    label(ws, clock, criticality="high")
    clock.advance(60)
    label(ws, clock, environment="production")
    assert pending_findings(ws.docs_for("dashboard")) == [FINDING_ID]
    cycle(ws, clock, 2, 30)
    assert pending_findings(ws.docs_for("dashboard")) == []
    assert read(ws, "decisions", "RZ-0001-c002") is not None


def test_deadline_shortened_keeps_original_start(ws, clock):
    cycle(ws, clock, 1, 30)
    started = read(ws, "sla_clocks", FINDING_ID)["started_sim_ts"]
    clock.advance(2 * DAY)
    label(ws, clock, criticality="high")
    cycle(ws, clock, 2, 7)
    sla = read(ws, "sla_clocks", FINDING_ID)
    assert sla["started_sim_ts"] == started and sla["due_sim_ts"] == started + 7 * DAY
    assert sla["sla_days"] == 7 and sla["status"] == "open" and sla["last_move_id"] == "RZ-0001-c002"
    move = moves(ws)["RZ-0001-c002"]
    assert (move["old_due_sim_ts"], move["new_due_sim_ts"]) == (started + 30 * DAY, started + 7 * DAY)
    assert move["changed_by"] == OWNER and move["change_summary"] == ["Criticality: not known → high"]
    assert move["asset_id"] == "ast-01" and move["real_ts"] > 0 and move["sim_ts"] > started
    assert move["outcome"] == "moved"


def test_deadline_never_less_than_one_day_away(ws, clock):
    cycle(ws, clock, 1, 30)
    clock.advance(5 * DAY)
    label(ws, clock, criticality="high")
    now = clock.now().sim_ts
    cycle(ws, clock, 2, 2)
    assert read(ws, "sla_clocks", FINDING_ID)["due_sim_ts"] == pytest.approx(now + DAY, abs=5)


def test_deadline_can_lengthen(ws, clock):
    cycle(ws, clock, 1, 7)
    started = read(ws, "sla_clocks", FINDING_ID)["started_sim_ts"]
    clock.advance(60)
    label(ws, clock, environment="development")
    cycle(ws, clock, 2, 60)
    assert read(ws, "sla_clocks", FINDING_ID)["due_sim_ts"] == started + 60 * DAY


def test_same_due_writes_no_move(ws, clock):
    cycle(ws, clock, 1, 30)
    clock.advance(60)
    label(ws, clock, environment="production")
    cycle(ws, clock, 2, 30)
    assert moves(ws) == {} and "last_move_id" not in read(ws, "sla_clocks", FINDING_ID)


def test_breached_clock_not_moved(ws, clock):
    cycle(ws, clock, 1, 30)
    ws.docs_for("triage_cycle").collection("sla_clocks").document(FINDING_ID).update({"status": "breached"})
    before = read(ws, "sla_clocks", FINDING_ID)
    clock.advance(60)
    label(ws, clock, criticality="high")
    cycle(ws, clock, 2, 3)
    assert read(ws, "sla_clocks", FINDING_ID) == before
    assert moves(ws)["RZ-0001-c002"]["outcome"] == "already overdue, not moved"


def test_resumed_cycle_moves_once(ws, clock):
    cycle(ws, clock, 1, 30)
    clock.advance(60)
    label(ws, clock, criticality="high")
    cycle(ws, clock, 2, 7)
    first = read(ws, "sla_clocks", FINDING_ID)
    clock.advance(60)
    docs = ws.docs_for("triage_cycle")
    run_triage_cycle(Ports(docs=docs, journal=ws.journal(), clock=clock,
                           roles=roles_with(FakeAdapter(proposal(3)), FakeAdapter(RATIFY)),
                           guard=RecordingGuard(), delivery=ForbiddenDelivery(),
                           memory=LocalMemory(docs), telemetry=NoTelemetry(), record_failed_runs=True),
                     2, finding_ids=[FINDING_ID], enrichment=FakeCache())
    assert read(ws, "sla_clocks", FINDING_ID) == first and list(moves(ws)) == ["RZ-0001-c002"]


def test_held_finding_is_not_reranked(ws, clock):
    cycle(ws, clock, 1, 30, reviewer=REJECT)
    assert read(ws, "decisions", "RZ-0001-c001")["outcome"] == "human_queue"
    clock.advance(60)
    label(ws, clock, criticality="high")
    assert pending_findings(ws.docs_for("dashboard")) == []
