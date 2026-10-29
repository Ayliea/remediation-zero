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
"""Triage sees the owner's business context, and Crown jewels under active exploitation is never below High."""
import json
from datetime import datetime, timedelta, timezone

from tests.test_engine_triage_cycle import (FINDING_ID, FakeAdapter, RATIFY, everything, ports_for, ws,  # noqa: F401
                                            roles_with)
from tools import inference
from tools.adjudication import Adjudication, AdjudicationOutcome, Proposal, Verdict
from tools.clock import ClockMode, SimClock
from tools.context_floor import FLOOR_SLA_DAYS, apply_floor
from tools.decisions import DecisionWriter, effective_severity, effective_sla_days
from tools.enrichment import Enrichment

NOW = 1_800_000_000.0


def adj(severity="medium", sla=60):
    proposal = Proposal("RZ-1", severity, sla, "Patch it.", ("evidence",), "Because.")
    return Adjudication("RZ-1", AdjudicationOutcome.RATIFIED, proposal, (Verdict(True, "ok"),), 1)


def enr(in_kev=True, kev_due_date=None, kev_checked=True, cve="CVE-2021-44228"):
    return Enrichment(cve_id=cve, in_kev=in_kev, kev_due_date=kev_due_date, kev_checked=kev_checked)


def date_in_days(now, days):
    return (datetime.fromtimestamp(now, tz=timezone.utc) + timedelta(days=days)).strftime("%Y-%m-%d")


def test_floor_raises_medium_to_high_with_14_days():
    out = apply_floor(adj("medium", 60), {"criticality": "high"}, enr(kev_due_date="2020-01-01"), NOW)
    assert FLOOR_SLA_DAYS == 14
    assert out.floor == {"applied": True, "severity": "high", "sla_days": 14,
                         "reason": "raised to High: Crown jewels and actively exploited"}
    assert out.proposal == adj("medium", 60).proposal


def test_future_kev_due_date_tightens_sla():
    out = apply_floor(adj("critical", 30), {"criticality": "high"}, enr(kev_due_date=date_in_days(NOW, 5)), NOW)
    assert out.floor["severity"] == "critical" and out.floor["sla_days"] == 5


def test_floor_keeps_a_shorter_proposed_sla():
    out = apply_floor(adj("high", 3), {"criticality": "high"}, enr(), NOW)
    assert out.floor == {"applied": True, "severity": "high", "sla_days": 3,
                         "reason": "within the floor for Crown jewels and actively exploited"}


def test_no_floor_when_kev_unknown():
    out = apply_floor(adj("low", 90), {"criticality": "high"}, enr(in_kev=False, kev_checked=False), NOW)
    assert out.floor == {"applied": False, "reason": "KEV list not available"}


def test_no_floor_without_crown_jewels():
    assert apply_floor(adj(), {"criticality": None}, enr(), NOW).floor is None
    assert apply_floor(adj(), {"criticality": "medium"}, enr(), NOW).floor is None


def test_no_cve_crown_jewel_is_not_floored():
    assert apply_floor(adj(), {"criticality": "high"},
                       Enrichment(cve_id="", applicable=False), NOW).floor is None


def test_no_proposal_is_not_floored():
    held = Adjudication("RZ-1", AdjudicationOutcome.HUMAN_QUEUE, None)
    assert apply_floor(held, {"criticality": "high"}, enr(), NOW).floor is None


def test_effective_values_read_the_floor():
    doc = {"proposed_severity": "medium", "proposed_sla_days": 60}
    assert (effective_severity(doc), effective_sla_days(doc)) == ("medium", 60)
    doc["floor"] = {"applied": True, "severity": "high", "sla_days": 14, "reason": "r"}
    assert (effective_severity(doc), effective_sla_days(doc)) == ("high", 14)
    doc["floor"] = {"applied": False, "reason": "KEV list not available"}
    assert effective_severity(doc) == "medium"


def test_floor_survives_restore(tmp_path):
    from tools.local_layout import Workspace
    ws = Workspace(tmp_path / "ws")
    writer = DecisionWriter(store=ws.journal(), client=ws.docs_for("triage_cycle"),
                            clock=SimClock(ClockMode.REAL))
    floored = apply_floor(adj(), {"criticality": "high"}, enr(), NOW)
    writer.record(floored, cycle=1)
    restored = writer.restore("RZ-1", 1)
    assert restored.floor == floored.floor
    stored = ws.docs_for("dashboard").collection("decisions").document("RZ-1-c001").get().to_dict()
    assert stored["floor"]["severity"] == "high" and stored["proposed_severity"] == "medium"


def test_render_shows_context_for_the_new_render():
    asset = {"hostname": "files.example.invalid", "context_facts": {"sensitive_data": True},
             "context_labels": ["lbl-1", "lbl-2"]}
    labels = {"lbl-1": {"name": "Billing", "effect": "crown_jewels"},
              "lbl-2": {"name": "bad\nname", "effect": "grouping"}}
    text = inference.render_finding({"finding_id": "F", "cve_ids": ["CVE-2021-44228"], "nvt_name": "x"},
                                    inference.with_context(asset, labels), enr())
    assert "  criticality: high" in text and "  sensitive_data: True" in text
    assert "  environment: not known" in text
    assert "  business_labels: Billing\n" in text


def test_context_guidance_only_for_the_new_render():
    new = inference.triage_instruction(False)
    legacy = inference.triage_instruction(True)
    assert "not known is missing context" in new and "not known is missing context" not in legacy


class KevCache:
    def enrich(self, cve_id):
        return Enrichment(cve_id=cve_id, in_kev=True, kev_due_date="2020-01-01")


def test_cycle_floors_and_assigns_with_the_floored_sla(ws):
    ctx = ws.docs_for("context")
    ctx.collection("assets").document("ast-01").update({"context_facts": {"criticality": "high"}})
    proposal = json.dumps({"severity": "medium", "sla_days": 60, "remediation": "Apply the vendor patch.",
                           "evidence": ["in CISA KEV"], "rationale": "Exploited."})
    proposer = FakeAdapter(proposal)
    from engine.triage_cycle import run_triage_cycle
    run_triage_cycle(ports_for(ws, roles_with(proposer, FakeAdapter(RATIFY))), 1,
                     finding_ids=[FINDING_ID], enrichment=KevCache())
    state = everything(ws)
    decision = state["decisions"]["RZ-0001-c001"][0]
    assert decision["floor"]["applied"] is True and decision["proposed_severity"] == "medium"
    assert state["sla_clocks"][FINDING_ID][0]["sla_days"] == 14
    assert "criticality: high" in proposer.calls[0]
