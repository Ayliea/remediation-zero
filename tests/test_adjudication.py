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

"""The triage/review adjudication loop.

The loop is where the architecture's failure rules live, so it is tested
independently of the models. The model is injected as a callable: these tests
are about what the loop does with an answer, not about what either model says.
Whether the models themselves behave is proven by running them, not here.
"""

import pytest

from tools.adjudication import (
    AdjudicationOutcome,
    CapacityError,
    Proposal,
    Verdict,
    adjudicate,
)

FINDING = {"finding_id": "RZ-0001", "cve_id": "CVE-2021-44228", "asset_id": "ast-001"}

PROPOSAL = Proposal(
    finding_id="RZ-0001",
    severity="critical",
    sla_days=7,
    remediation="Upgrade log4j-core to 2.17.1 or later.",
    evidence=("CISA KEV catalog", "FIRST EPSS"),
    rationale="Known exploited, EPSS 0.99999.",
)


def _triage(_finding):
    return PROPOSAL


def test_a_ratified_proposal_is_adjudicated_on_the_first_pass():
    result = adjudicate(
        FINDING,
        triage=_triage,
        review=lambda f, p: Verdict(ratified=True, reason="Evidence supports it."),
    )

    assert result.outcome is AdjudicationOutcome.RATIFIED
    assert result.attempts == 1
    assert result.proposal == PROPOSAL


def test_a_rejection_is_retried_exactly_once():
    """One retry, then the human queue. Never a loop."""
    seen = []

    def review(_finding, proposal):
        seen.append(proposal)
        return Verdict(ratified=False, reason="SLA too generous for a KEV entry.")

    result = adjudicate(FINDING, triage=_triage, review=review)

    assert len(seen) == 2
    assert result.attempts == 2
    assert result.outcome is AdjudicationOutcome.HUMAN_QUEUE


def test_a_rejection_then_ratification_is_accepted():
    verdicts = [
        Verdict(ratified=False, reason="Cite EPSS explicitly."),
        Verdict(ratified=True, reason="Now cited."),
    ]

    result = adjudicate(
        FINDING, triage=_triage, review=lambda f, p: verdicts.pop(0)
    )

    assert result.outcome is AdjudicationOutcome.RATIFIED
    assert result.attempts == 2


def test_every_rejection_reason_is_retained():
    """Disagreements are the evidence that the control is real. Discarding the
    first reason on retry would throw away the interesting half."""
    reasons = ["First objection.", "Second objection."]

    def review(_finding, _proposal):
        return Verdict(ratified=False, reason=reasons.pop(0))

    result = adjudicate(FINDING, triage=_triage, review=review)

    assert [v.reason for v in result.verdicts] == [
        "First objection.",
        "Second objection.",
    ]


def test_capacity_pressure_is_never_recorded_as_a_rejection():
    """Gemma MaaS returns 429 under load. Reading that as 'the reviewer
    rejected this triage' would write a decision no model ever made into the
    adjudication record."""

    def review(_finding, _proposal):
        raise CapacityError("429 The request queue is full")

    result = adjudicate(FINDING, triage=_triage, review=review, max_capacity_retries=2)

    assert result.outcome is AdjudicationOutcome.UNAVAILABLE
    assert result.verdicts == ()


def test_capacity_pressure_retries_then_succeeds():
    """A 429 is transient. It should cost a retry, not the decision."""
    calls = []

    def review(_finding, _proposal):
        calls.append(1)
        if len(calls) < 3:
            raise CapacityError("429 The request queue is full")
        return Verdict(ratified=True, reason="Fine.")

    result = adjudicate(FINDING, triage=_triage, review=review, max_capacity_retries=3)

    assert result.outcome is AdjudicationOutcome.RATIFIED
    assert len(calls) == 3


def test_the_loop_cannot_run_away():
    """A reviewer that always rejects must still terminate."""
    calls = []

    def review(_finding, _proposal):
        calls.append(1)
        return Verdict(ratified=False, reason="No.")

    adjudicate(FINDING, triage=_triage, review=review)

    assert len(calls) <= 2


# --- reviewer response parsing ---------------------------------------------

def test_a_fenced_reviewer_response_does_not_leak_backticks_into_the_reason():
    """Gemma wraps the requested format in a code fence often enough that the
    closing fence was ending up inside stored reasons, which then appear in the
    decision record a judge reads."""
    from tools.review_models import _strip_fences

    fenced = "```\nVERDICT: REJECT\nREASON: The remediation is vague.\n```"
    assert "```" not in _strip_fences(fenced)


def test_an_unparseable_reviewer_response_is_not_a_ratification():
    """Defaulting to ratify on confusion would make the gate decorative."""
    from tools.review_models import VERDICT_PATTERN

    assert VERDICT_PATTERN.search("I think this looks fine to me") is None


def test_capacity_backoff_is_bounded():
    """A stuck model must not stall a cycle indefinitely. Retries are capped
    and the last failure is reported as unavailability, never as a verdict."""
    from tools.review_models import MAX_MODEL_ATTEMPTS, _with_backoff

    calls = []

    def always_429():
        calls.append(1)
        raise RuntimeError("429 RESOURCE_EXHAUSTED")

    with pytest.raises(CapacityError, match="unavailable after"):
        _with_backoff(always_429, what="test model")

    assert len(calls) == MAX_MODEL_ATTEMPTS


def test_a_non_capacity_error_is_not_retried():
    """Backing off from a bug wastes time and hides it."""
    from tools.review_models import _with_backoff

    calls = []

    def bad_request():
        calls.append(1)
        raise ValueError("malformed prompt")

    with pytest.raises(ValueError):
        _with_backoff(bad_request, what="test model")

    assert len(calls) == 1
