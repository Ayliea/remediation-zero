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

"""Metrics are counted, not narrated.

Every number in a report comes from this module, which does arithmetic on
records and nothing else. The model that writes the accompanying prose is given
these numbers and is not permitted to produce its own, because a metrics report
with a plausible-looking wrong denominator is worse than no report: it is wrong
in a way that reads as authoritative.
"""

import pytest

from tools.metrics import compute_metrics

DECISIONS = [
    {"finding_id": "RZ-1", "cycle": 1, "outcome": "ratified", "attempts": 1,
     "proposed_severity": "critical", "verdicts": [{"ratified": True, "reason": "ok"}]},
    {"finding_id": "RZ-2", "cycle": 1, "outcome": "ratified", "attempts": 2,
     "proposed_severity": "high",
     "verdicts": [{"ratified": False, "reason": "vague"}, {"ratified": True, "reason": "ok"}]},
    {"finding_id": "RZ-3", "cycle": 1, "outcome": "human_queue", "attempts": 2,
     "proposed_severity": "high",
     "verdicts": [{"ratified": False, "reason": "SLA exceeds KEV due date"},
                  {"ratified": False, "reason": "still vague"}]},
]
TICKETS = [
    {"finding_id": "RZ-1", "status": "open", "nudges_sent": 1, "escalated": False},
    {"finding_id": "RZ-2", "status": "escalated", "nudges_sent": 3, "escalated": True},
]
SLA = [
    {"finding_id": "RZ-1", "status": "open"},
    {"finding_id": "RZ-2", "status": "breached"},
]
HUMAN_QUEUE = [
    {"finding_id": "RZ-3", "kind": "adjudication"},
    {"finding_id": "RZ-4", "kind": "escalated_unresolved"},
]
EXCEPTIONS = [{"finding_id": "RZ-5", "status": "active"}]


@pytest.fixture
def metrics():
    return compute_metrics(DECISIONS, TICKETS, SLA, HUMAN_QUEUE, EXCEPTIONS)


def test_decision_counts_are_exact(metrics):
    assert metrics["decisions_total"] == 3
    assert metrics["ratified"] == 2
    assert metrics["routed_to_human"] == 1


def test_ratification_rate_is_a_fraction_of_decisions_made(metrics):
    assert metrics["ratification_rate"] == pytest.approx(2 / 3)


def test_reviewer_disagreement_is_counted_because_it_is_the_control(metrics):
    """Five verdicts across three findings (1 + 2 + 2), three of them
    rejections. A decision log showing no disagreement at all would mean the
    reviewer was ratifying everything, which is indistinguishable from having
    no reviewer."""
    assert metrics["verdicts_total"] == 5
    assert metrics["rejections"] == 3
    assert metrics["disagreement_rate"] == pytest.approx(3 / 5)


def test_findings_needing_a_second_pass_are_counted(metrics):
    assert metrics["required_retry"] == 2


def test_sla_breaches_are_counted(metrics):
    assert metrics["sla_breached"] == 1


def test_human_queue_is_broken_out_by_kind(metrics):
    assert metrics["human_queue_total"] == 2
    assert metrics["human_queue_by_kind"]["adjudication"] == 1
    assert metrics["human_queue_by_kind"]["escalated_unresolved"] == 1


def test_chase_activity_is_counted(metrics):
    assert metrics["nudges_sent"] == 4
    assert metrics["escalations"] == 1


def test_an_empty_period_reports_zero_rather_than_dividing_by_zero():
    """A quiet week must produce a report, not a crash."""
    empty = compute_metrics([], [], [], [], [])

    assert empty["decisions_total"] == 0
    assert empty["ratification_rate"] == 0.0
    assert empty["disagreement_rate"] == 0.0


def test_top_rejection_reasons_are_surfaced(metrics):
    """The reasons are the interesting part of the report. A rate tells you
    the gate fired; the reasons tell you what it caught."""
    reasons = metrics["rejection_reasons"]

    assert len(reasons) == 3
    assert any("KEV due date" in r for r in reasons)
