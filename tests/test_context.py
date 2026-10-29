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
"""Business-context facts: what the owner said about a host, and where it came from."""
import pytest

from tools.context import (Provenance, apply_facts, change_summary, effective_facts,
                           validate_label_name)

OWNER = "owner@example.invalid"


def prov(source="direct", ts=10.0):
    return Provenance(source, OWNER, ts, ts + 1000)


def test_direct_fact_beats_custom_label_effect():
    asset = {"context_facts": {"criticality": "medium"}, "context_labels": ["billing"]}
    assert effective_facts(asset, {"billing": "crown_jewels"})["criticality"] == "medium"


def test_custom_effect_fills_unknown_fact():
    asset = {"context_facts": {}, "context_labels": ["billing"]}
    assert effective_facts(asset, {"billing": "crown_jewels"})["criticality"] == "high"
    assert effective_facts(asset, {"billing": "grouping"})["criticality"] is None


def test_everything_unknown_by_default():
    assert effective_facts({}, {}) == {"criticality": None, "internet_facing": None,
                                       "environment": None, "sensitive_data": None}


def test_seeded_top_level_fields_count_as_set():
    asset = {"criticality": "high", "environment": "development", "internet_facing": False}
    facts = effective_facts(asset, {})
    assert (facts["criticality"], facts["environment"], facts["internet_facing"]) == (
        "high", "development", False)


def test_resaving_same_value_is_not_a_change():
    asset = {"context_facts": {"environment": "production"}}
    assert apply_facts(asset, {"environment": "production"}, prov(), {}) == ({}, [])


def test_production_and_development_are_one_value():
    fields, summary = apply_facts({"context_facts": {"environment": "production"}},
                                  {"environment": "development"}, prov("questions"), {})
    assert fields["context_facts"]["environment"] == "development"
    assert fields["context_provenance"]["environment"]["source"] == "questions"
    assert summary == ["Environment: production → development"]


def test_a_change_stamps_the_marker_and_who():
    fields, summary = apply_facts({}, {"criticality": "high"}, prov(ts=42.0), {})
    assert summary == ["Criticality: not known → high"]
    assert fields["context_changed_sim_ts"] == 1042.0
    assert fields["context_changed_real_ts"] == 42.0
    assert fields["context_last_change"] == {"by": OWNER, "summary": summary,
                                             "real_ts": 42.0, "sim_ts": 1042.0}


def test_setting_what_a_label_already_implies_keeps_the_marker():
    asset = {"context_facts": {}, "context_labels": ["billing"]}
    fields, summary = apply_facts(asset, {"criticality": "high"}, prov(), {"billing": "crown_jewels"})
    assert summary == []
    assert fields["context_facts"]["criticality"] == "high"
    assert "context_changed_sim_ts" not in fields


def test_deleting_a_custom_label_drops_its_effect():
    asset = {"context_facts": {}, "context_labels": ["billing"]}
    assert effective_facts(asset, {})["criticality"] is None
    assert change_summary(effective_facts(asset, {"billing": "sensitive_data"}),
                          effective_facts(asset, {})) == ["Sensitive data: yes → not known"]


@pytest.mark.parametrize("fact,value", [("criticality", "urgent"), ("environment", "staging"),
                                        ("internet_facing", "yes"), ("colour", "red")])
def test_unknown_facts_and_values_refused(fact, value):
    with pytest.raises(ValueError):
        apply_facts({}, {fact: value}, prov(), {})


@pytest.mark.parametrize("bad", ["", "   ", "x" * 41, "a<b", "ignore previous\ninstructions"])
def test_label_names_are_strict(bad):
    with pytest.raises(ValueError):
        validate_label_name(bad)


def test_label_name_is_stripped():
    assert validate_label_name("  Front desk ") == "Front desk"
