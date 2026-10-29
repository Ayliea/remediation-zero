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
"""Business context on the dashboard: the nudge for unlabeled hosts, and on a finding its
host's labels, the floor and each moved deadline. Synthetic data only."""
from engine.snapshot import snapshot
from scripts import local
from tools.clock import ClockMode, SimClock
from tools.context_store import ContextWriter
from ui.dashboard_view import decision_card, render

DAY = 86400
T = 1_790_000_000.0
OWNER = "owner@client.example"


def workspace(tmp_path):
    ws = local.open_workspace(tmp_path / "ws")
    seed = ws.docs_for("seed")
    seed.collection("assets").document("ast-01").set({"hostname": "files.client.example"})
    seed.collection("assets").document("ast-02").set({"hostname": "web.client.example"})
    seed.collection("findings").document("RZ-0001").set({"asset_id": "ast-01", "status": "open"})
    return ws


def account(role):
    return {"email": f"{role}@client.example", "role": role, "token": "t" * 32}


def test_nudge_counts_unknown_hosts(tmp_path):
    ws = workspace(tmp_path)
    data = snapshot(ws.docs_for("dashboard"))
    assert data["context_unknown_hosts"] == 2
    ContextWriter(ws.docs_for("context"), SimClock(ClockMode.SIM)).set_facts(
        ["ast-01"], {"criticality": "high"}, source="direct", account=OWNER)
    data = snapshot(ws.docs_for("dashboard"))
    assert data["context_unknown_hosts"] == 1
    page = render(data, account=account("owner"))
    assert "1 host has no business context — label them" in page
    assert 'href="/?view=settings&amp;section=context"' in page
    page = render(data, account=account("tech"))
    assert "1 host has no business context. Ask the owner to label them." in page
    assert "section=context" not in page


def test_no_nudge_when_every_host_has_context():
    page = render({"context_unknown_hosts": 0, "counts": {}}, account=account("owner"))
    assert "no business context" not in page


def test_finding_view_shows_floor_and_moves(tmp_path):
    ws = workspace(tmp_path)
    ContextWriter(ws.docs_for("context"), SimClock(ClockMode.SIM)).set_facts(
        ["ast-01"], {"criticality": "high", "environment": "production"}, source="direct", account=OWNER)
    triage = ws.docs_for("triage_cycle")
    triage.collection("decisions").document("RZ-0001-c002").set(
        {"finding_id": "RZ-0001", "cycle": 2, "outcome": "ratified", "proposed_severity": "medium",
         "proposed_sla_days": 30, "proposed_remediation": "Apply the vendor patch.",
         "floor": {"applied": True, "severity": "high", "sla_days": 14,
                   "reason": "raised to High: Crown jewels and actively exploited"},
         "real_ts": T, "sim_ts": T})
    triage.collection("deadline_moves").document("RZ-0001-c002").set(
        {"finding_id": "RZ-0001", "cycle": 2, "asset_id": "ast-01", "outcome": "moved",
         "old_due_sim_ts": T + 30 * DAY, "new_due_sim_ts": T + 14 * DAY, "changed_by": OWNER,
         "change_summary": ["Criticality: not known → high"], "real_ts": T, "sim_ts": T})
    (row,) = [r for r in snapshot(ws.docs_for("dashboard"))["decisions"] if r["cycle"] == 2]
    assert row["host"] == "files.client.example" and row["labels"] == ["Crown jewels", "Production"]
    assert [m["outcome"] for m in row["deadline_moves"]] == ["moved"]
    card = decision_card(row)
    reason = card.index("This is files.client.example, labeled Crown jewels, Production.")
    assert reason < card.index("Your next step")
    assert "Recorded priority: high" in card
    assert "Raised to High: Crown jewels and actively exploited." in card
    assert ("Deadline moved from 2026-10-21 to 2026-10-05 after Criticality: not known → high "
            f"({OWNER}).") in card


def test_overdue_move_is_said_plainly():
    row = {"finding_id": "RZ-0001", "outcome": "ratified", "host": "files.client.example", "labels": [],
           "deadline_moves": [{"outcome": "already overdue, not moved", "old_due_sim_ts": T,
                               "new_due_sim_ts": T, "changed_by": OWNER,
                               "change_summary": ["Criticality: low → high"]}]}
    card = decision_card(row)
    assert "Already overdue, so the deadline was not moved, after Criticality: low → high" in card
    assert "labeled" not in card  # no labels, no business reason line


def test_cloud_rows_render_unchanged():
    row = {"finding_id": "RZ-0001", "outcome": "ratified", "proposed_severity": "high"}
    card = decision_card(row)
    assert "This is" not in card and "Deadline moved" not in card and "Raised to" not in card
