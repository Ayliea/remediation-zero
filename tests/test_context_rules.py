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
"""Rules suggest business context; the owner approves or denies each host. Nothing applies itself."""
import pytest

from tools.clock import ClockMode, SimClock
from tools.context_import import ColumnMapping, preview
from tools.context_rules import Rule, Suggestion, validate_rule
from tools.context_store import ContextWriter
from tools.local_layout import Workspace

OWNER = "owner@example.invalid"
HOSTS = [{"asset_id": "ast-001", "hostname": "db.files.example.invalid", "ip": "192.0.2.10"},
         {"asset_id": "ast-002", "hostname": "web.example.invalid", "ip": "192.0.2.11"},
         {"asset_id": "ast-003", "hostname": "laptop.example.invalid", "ip": "198.51.100.5"}]


@pytest.fixture
def clock():
    return SimClock(mode=ClockMode.SIM)


@pytest.fixture
def ws(tmp_path):
    ws = Workspace(tmp_path / "ws")
    seed = ws.docs_for("seed")
    for host in HOSTS:
        seed.collection("assets").document(host["asset_id"]).set(dict(host))
    return ws


@pytest.fixture
def writer(ws, clock):
    return ContextWriter(ws.docs_for("context"), clock)


def facts_of(ws, asset_id):
    return ws.docs_for("dashboard").collection("assets").document(asset_id).get().to_dict().get("context_facts")


def test_validate_rule_normalises_patterns():
    assert validate_rule("cidr", "192.0.2.7/24", {"environment": "production"}) == (
        "cidr", "192.0.2.0/24", {"environment": "production"})
    assert validate_rule("suffix", "*.Files.Example.invalid.", {"criticality": "high"}) == (
        "suffix", "files.example.invalid", {"criticality": "high"})


@pytest.mark.parametrize("kind,pattern,facts", [("cidr", "not-an-ip", {"environment": "production"}),
                                                ("suffix", "", {"criticality": "high"}),
                                                ("regex", ".*", {"criticality": "high"}),
                                                ("cidr", "192.0.2.0/24", {}),
                                                ("cidr", "192.0.2.0/24", {"criticality": "urgent"})])
def test_bad_rules_refused(kind, pattern, facts):
    with pytest.raises(ValueError):
        validate_rule(kind, pattern, facts)


def test_rule_never_applies_itself(ws, writer, clock):
    writer.save_rule("cidr", "192.0.2.0/24", {"environment": "production"}, account=OWNER)
    assert facts_of(ws, "ast-001") is None and facts_of(ws, "ast-002") is None
    found = writer.suggestions(clock.now().sim_ts)
    assert sorted(s.asset_id for s in found) == ["ast-001", "ast-002"]
    assert all(s.facts == {"environment": "production"} for s in found)


def test_suffix_rule_matches_the_name_and_below(writer, clock):
    rule_id = writer.save_rule("suffix", "files.example.invalid", {"criticality": "high"}, account=OWNER)
    assert writer.suggestions(clock.now().sim_ts) == [Suggestion(rule_id, "ast-001", {"criticality": "high"})]


def test_each_host_approved_or_denied(ws, writer, clock):
    rule_id = writer.save_rule("cidr", "192.0.2.0/24", {"environment": "production"}, account=OWNER)
    assert writer.decide(rule_id, "ast-001", True, account=OWNER) == ["ast-001"]
    assert facts_of(ws, "ast-001") == {"environment": "production"}
    prov = ws.docs_for("dashboard").collection("assets").document("ast-001").get().to_dict()["context_provenance"]
    assert prov["environment"]["source"] == "rule"
    writer.decide(rule_id, "ast-002", False, account=OWNER)
    assert facts_of(ws, "ast-002") is None
    assert writer.suggestions(clock.now().sim_ts) == []


def test_denied_host_stays_denied_after_the_rule_is_edited(writer, clock):
    rule_id = writer.save_rule("cidr", "192.0.2.0/24", {"environment": "production"}, account=OWNER)
    writer.decide(rule_id, "ast-002", False, account=OWNER)
    writer.save_rule("cidr", "192.0.2.0/25", {"environment": "production"}, account=OWNER, rule_id=rule_id)
    assert [s.asset_id for s in writer.suggestions(clock.now().sim_ts)] == ["ast-001"]


def test_removing_a_rule_removes_its_suggestions_and_denials(ws, writer, clock):
    rule_id = writer.save_rule("cidr", "192.0.2.0/24", {"environment": "production"}, account=OWNER)
    writer.decide(rule_id, "ast-002", False, account=OWNER)
    writer.remove_rule(rule_id, account=OWNER)
    assert writer.suggestions(clock.now().sim_ts) == []
    kinds = [s.to_dict()["kind"] for s in ws.docs_for("dashboard").collection("context_suggestions").stream()]
    assert kinds == []


def test_host_already_matching_is_not_suggested(writer, clock):
    writer.set_facts(["ast-001"], {"environment": "production"}, source="direct", account=OWNER)
    writer.save_rule("cidr", "192.0.2.0/24", {"environment": "production"}, account=OWNER)
    assert [s.asset_id for s in writer.suggestions(clock.now().sim_ts)] == ["ast-002"]


def upload_unmatched(writer, hosts, key="new.example.invalid"):
    mapping = ColumnMapping("Host", {"environment": "Env", "criticality": "Importance"})
    writer.apply_upload(preview(["Host", "Env", "Importance"], [[key, "dev", "high"]], mapping, hosts),
                        mapping, account=OWNER)


def test_row_suggestion_appears_when_host_is_scanned(ws, writer, clock):
    upload_unmatched(writer, HOSTS)
    assert writer.suggestions(clock.now().sim_ts) == []
    ws.docs_for("seed").collection("assets").document("ast-004").set(
        {"asset_id": "ast-004", "hostname": "new.example.invalid", "ip": "203.0.113.4"})
    (found,) = writer.suggestions(clock.now().sim_ts)
    assert found.asset_id == "ast-004" and found.facts == {"environment": "development", "criticality": "high"}
    assert found.source_id.startswith("row-")
    writer.decide(found.source_id, "ast-004", True, account=OWNER)
    assert facts_of(ws, "ast-004") == {"environment": "development", "criticality": "high"}
    assert writer.suggestions(clock.now().sim_ts) == []


def test_expired_row_not_suggested(ws, writer, clock):
    upload_unmatched(writer, HOSTS)
    ws.docs_for("seed").collection("assets").document("ast-004").set(
        {"asset_id": "ast-004", "hostname": "new.example.invalid"})
    clock.advance(90 * 86400 + 1)
    assert writer.suggestions(clock.now().sim_ts) == []


def test_hand_set_fact_supersedes_row(ws, writer, clock):
    upload_unmatched(writer, HOSTS)
    ws.docs_for("seed").collection("assets").document("ast-004").set(
        {"asset_id": "ast-004", "hostname": "new.example.invalid"})
    clock.advance(60)
    writer.set_facts(["ast-004"], {"environment": "production"}, source="direct", account=OWNER)
    (found,) = writer.suggestions(clock.now().sim_ts)
    assert found.facts == {"criticality": "high"}


def test_denying_a_row_drops_it(ws, writer, clock):
    upload_unmatched(writer, HOSTS)
    ws.docs_for("seed").collection("assets").document("ast-004").set(
        {"asset_id": "ast-004", "hostname": "new.example.invalid"})
    (found,) = writer.suggestions(clock.now().sim_ts)
    writer.decide(found.source_id, "ast-004", False, account=OWNER)
    assert writer.suggestions(clock.now().sim_ts) == []
    assert facts_of(ws, "ast-004") is None


def test_decide_refuses_a_host_the_rule_does_not_cover(writer):
    rule_id = writer.save_rule("cidr", "192.0.2.0/24", {"environment": "production"}, account=OWNER)
    with pytest.raises(ValueError):
        writer.decide(rule_id, "ast-003", True, account=OWNER)


def test_rule_is_a_value():
    assert Rule("r", "cidr", "192.0.2.0/24", {"environment": "production"}).covers(HOSTS[0])
    assert not Rule("r", "cidr", "192.0.2.0/24", {"environment": "production"}).covers(HOSTS[2])
