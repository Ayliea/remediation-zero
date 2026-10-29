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
"""Business context is stored in its own file, written only by the owner's actions, and audited."""
import json

import pytest

from tools import access
from tools.accounts import AccountRefused
from tools.clock import ClockMode, SimClock
from tools.context_store import ContextWriter
from tools.local_layout import Workspace

OWNER = "owner@example.invalid"


@pytest.fixture
def workspace(tmp_path):
    ws = Workspace(tmp_path / "ws")
    seed = ws.docs_for("seed")
    for n in (1, 2):
        seed.collection("assets").document(f"ast-00{n}").set(
            {"asset_id": f"ast-00{n}", "hostname": f"host-{n}.example.invalid"})
    return ws


@pytest.fixture
def writer(workspace):
    return ContextWriter(workspace.docs_for("context"), SimClock(mode=ClockMode.SIM))


def asset(workspace, asset_id):
    return workspace.docs_for("dashboard").collection("assets").document(asset_id).get().to_dict()


def test_tech_may_not_manage_context():
    assert access.allowed("owner", "manage_context") is True
    assert access.allowed("tech", "manage_context") is False


def test_only_context_stage_writes_context_collections(workspace):
    with pytest.raises(PermissionError):
        workspace.docs_for("dashboard").collection("context_labels").document("x").set({"a": 1})
    workspace.docs_for("context").collection("context_labels").document("x").set({"a": 1})
    with pytest.raises(PermissionError):
        workspace.docs_for("context").collection("findings").document("x").set({"a": 1})


def test_deadline_moves_written_by_the_triage_cycle_only(workspace):
    workspace.docs_for("triage_cycle").collection("deadline_moves").document("m").set({"a": 1})
    with pytest.raises(PermissionError):
        workspace.docs_for("context").collection("deadline_moves").document("m").set({"a": 1})


def test_context_file_is_private(workspace):
    path = workspace.file_for("context_labels")
    assert path.name == "context.sqlite3" and (path.stat().st_mode & 0o777) == 0o600


def test_set_facts_bumps_marker_only_on_change(workspace, writer):
    assert writer.set_facts(["ast-001"], {"criticality": "high"}, source="direct", account=OWNER) == ["ast-001"]
    first = asset(workspace, "ast-001")
    assert first["context_facts"] == {"criticality": "high"}
    assert first["context_provenance"]["criticality"]["account"] == OWNER
    assert writer.set_facts(["ast-001"], {"criticality": "high"}, source="direct", account=OWNER) == []
    assert asset(workspace, "ast-001")["context_changed_sim_ts"] == first["context_changed_sim_ts"]


def test_set_facts_refuses_an_unknown_asset(writer):
    with pytest.raises(KeyError):
        writer.set_facts(["ast-404"], {"criticality": "high"}, source="direct", account=OWNER)


def test_custom_label_effect_and_removal_mark_hosts(workspace, writer):
    label = writer.add_label("Billing", "crown_jewels", account=OWNER)
    assert writer.custom_labels() == {label: "crown_jewels"}
    assert writer.tag(["ast-001", "ast-002"], label, account=OWNER) == ["ast-001", "ast-002"]
    tagged = asset(workspace, "ast-001")
    assert tagged["context_labels"] == [label]
    assert tagged["context_last_change"]["summary"] == ["Criticality: not known → high"]
    writer.set_facts(["ast-002"], {"criticality": "low"}, source="direct", account=OWNER)
    assert writer.remove_label(label, account=OWNER) == ["ast-001"]
    assert asset(workspace, "ast-001")["context_labels"] == []
    assert asset(workspace, "ast-001")["context_last_change"]["summary"] == ["Criticality: high → not known"]
    assert writer.custom_labels() == {}


def test_add_label_checks_name_and_effect(writer):
    with pytest.raises(ValueError):
        writer.add_label("bad<name>", "grouping", account=OWNER)
    with pytest.raises(ValueError):
        writer.add_label("Billing", "production", account=OWNER)
    writer.add_label("Billing", "grouping", account=OWNER)
    with pytest.raises(ValueError):
        writer.add_label("billing", "grouping", account=OWNER)


def test_untag_removes_the_label(workspace, writer):
    label = writer.add_label("Front desk", "sensitive_data", account=OWNER)
    writer.tag(["ast-001"], label, account=OWNER)
    assert writer.untag(["ast-001"], label, account=OWNER) == ["ast-001"]
    assert asset(workspace, "ast-001")["context_labels"] == []


def test_record_context_change_is_owner_only_and_stamped(signed_in):
    owner = signed_in.accounts.session(signed_in.owner_token).account_id
    tech = signed_in.accounts.session(signed_in.tech_token).account_id
    signed_in.accounts.record_context_change(owner, "context_facts_set",
                                             detail={"assets": 2, "facts": ["criticality"]},
                                             via="dashboard", source="192.0.2.10")
    row = dict(signed_in.accounts.store.events(1)[0])
    assert row["event"] == "context_facts_set" and json.loads(row["detail"]) == {
        "assets": 2, "facts": ["criticality"]}
    with pytest.raises(AccountRefused):
        signed_in.accounts.record_context_change(tech, "context_facts_set", detail={"assets": 1},
                                                 via="dashboard", source=None)


def test_context_audit_detail_has_no_host_names(signed_in):
    owner = signed_in.accounts.session(signed_in.owner_token).account_id
    with pytest.raises(ValueError):
        signed_in.accounts.record_context_change(owner, "context_facts_set",
                                                 detail={"host": "host-1.example.invalid"},
                                                 via="dashboard", source=None)
    with pytest.raises(ValueError):
        signed_in.accounts.record_context_change(owner, "connection_added", detail={"assets": 1},
                                                 via="dashboard", source=None)
