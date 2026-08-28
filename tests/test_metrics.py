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


FINDINGS = [
    {"finding_id": "RZ-1", "asset_id": "ast-01", "status": "resolved",
     "resolved_by_scan": "rescan-01"},
    {"finding_id": "RZ-2", "asset_id": "ast-01", "status": "open"},
    {"finding_id": "RZ-3", "asset_id": "ast-02", "status": "open"},
    {"finding_id": "RZ-4", "asset_id": "ast-09", "status": "open"},
]

ASSETS = [{"asset_id": f"ast-{n:02d}"} for n in range(1, 11)]

SCANS = [
    {"scan_id": "rescan-00", "real_ts": 100.0, "covered_asset_ids": ["ast-01"],
     "counts": {"resolved": 99, "persisting": 1, "unverifiable": 0,
                "new": 0, "regressed": 0}},
    {"scan_id": "rescan-01", "real_ts": 200.0,
     "covered_asset_ids": ["ast-01", "ast-02"],
     "counts": {"resolved": 1, "persisting": 1, "unverifiable": 1,
                "new": 1, "regressed": 1}},
]


@pytest.fixture
def metrics():
    return compute_metrics(DECISIONS, TICKETS, SLA, HUMAN_QUEUE, EXCEPTIONS,
                           FINDINGS, SCANS, ASSETS)


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
    empty = compute_metrics([], [], [], [], [], [], [], [])

    assert empty["decisions_total"] == 0
    assert empty["ratification_rate"] == 0.0
    assert empty["disagreement_rate"] == 0.0


def test_top_rejection_reasons_are_surfaced(metrics):
    """The reasons are the interesting part of the report. A rate tells you
    the gate fired; the reasons tell you what it caught."""
    reasons = metrics["rejection_reasons"]

    assert len(reasons) == 3
    assert any("KEV due date" in r for r in reasons)


# ---------------------------------------------------------------------------
# Remediation: the outcome, not the activity
# ---------------------------------------------------------------------------

def test_resolved_findings_are_counted(metrics):
    """Every other number in this dict measures how hard the fleet worked.
    None of them say whether anything actually got fixed."""
    assert metrics["findings_total"] == 4
    assert metrics["findings_resolved"] == 1
    assert metrics["findings_open"] == 3


def test_the_rate_is_taken_over_what_was_actually_scanned(metrics):
    """resolved / (resolved + persisting), not resolved / everything.

    The latest scan resolved 1 and saw 1 persist, so half of what it examined
    is fixed. Dividing by the whole estate would report 25% and quietly credit
    the fleet for findings on hosts nobody looked at.
    """
    assert metrics["remediated_of_scanned"] == pytest.approx(0.5)


def test_the_rate_is_not_named_as_a_bare_remediation_rate(metrics):
    """A bare `remediation_rate` can be quoted without its denominator, and
    the denominator is the whole story: examine a tenth of the estate, close
    everything you see, report 100%. The name carries the qualification so it
    cannot be separated from it."""
    assert "remediation_rate" not in metrics
    assert "remediated_of_scanned" in metrics


def test_what_cannot_be_vouched_for_is_reported_beside_the_rate(metrics):
    """The honest counterpart. A rate with no unverifiable count next to it
    invites exactly the reading the coverage gate exists to prevent."""
    assert metrics["unverifiable"] == 1
    assert metrics["coverage_rate"] == pytest.approx(0.2)
    assert metrics["assets_covered"] == 2
    assert metrics["assets_total"] == 10


def test_only_the_most_recent_scan_sets_the_period_numbers(metrics):
    """An older scan resolved 99 of 100. Reporting that this week would be a
    straightforward lie told by taking the wrong row."""
    assert metrics["latest_scan"] == "rescan-01"
    assert metrics["remediated_of_scanned"] != pytest.approx(0.99)
    assert metrics["scans_recorded"] == 2


def test_regressions_and_new_findings_are_surfaced(metrics):
    assert metrics["regressions"] == 1
    assert metrics["newly_discovered"] == 1


def test_a_period_with_no_scan_reports_zero_rather_than_failing():
    """Before the first rescan there is nothing to divide by, and the report
    still has to render."""
    empty = compute_metrics(DECISIONS, TICKETS, SLA, HUMAN_QUEUE, EXCEPTIONS,
                            FINDINGS, [], ASSETS)
    assert empty["remediated_of_scanned"] == 0
    assert empty["unverifiable"] == 0
    assert empty["latest_scan"] is None
    assert empty["coverage_rate"] == 0
    # The findings themselves are still countable without a scan.
    assert empty["findings_resolved"] == 1


def test_the_reporting_prompt_forbids_stating_the_rate_alone():
    """The prompt is the only thing standing between a correct number and a
    misleading sentence. A model handed `remediated_of_scanned` with no
    instruction will quote it as a remediation percentage, which is the
    misreading the coverage gate exists to prevent."""
    from pathlib import Path
    prompt = (Path(__file__).resolve().parents[1] / "prompts" / "reporting.md").read_text()

    assert "remediated_of_scanned" in prompt
    assert "unverifiable" in prompt
    assert "coverage_rate" in prompt


def test_every_remediation_metric_the_prompt_relies_on_actually_exists(metrics):
    """A prompt naming a key the block does not carry tells the model to state
    a number it was never given, which the one rule forbids it from inventing
    -- so it says nothing, and the section quietly disappears."""
    from pathlib import Path
    import re
    prompt = (Path(__file__).resolve().parents[1] / "prompts" / "reporting.md").read_text()

    for key in re.findall(r"`([a-z_]+)`", prompt):
        if key in ("remediated_of_scanned", "unverifiable", "coverage_rate"):
            assert key in metrics, f"the prompt names {key}, the block has no such key"
