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

"""The adjudication record.

This is the evidence that the reviewer exists and disagreed. If a verdict is
dropped here, the disagreement rate the report leans on becomes a number
nobody can check, and a rejection that was never written is indistinguishable
from a reviewer that ratified everything.
"""

import pytest

from tools.adjudication import (
    Adjudication,
    AdjudicationOutcome,
    Proposal,
    Verdict,
)
from tools.clock import ClockMode, SimClock
from tools.decisions import (
    COLLECTION,
    HUMAN_QUEUE,
    DecisionWriter,
    to_decision_document,
)
from tools.idempotency import InMemoryIdempotencyStore


class FakeDoc:
    def __init__(self, docs, key, log):
        self._docs, self._key, self._log = docs, key, log

    def set(self, data):
        self._log.append(self._key)
        self._docs[self._key] = dict(data)


class FakeCollection:
    def __init__(self, docs, name, log):
        self._docs, self._name, self._log = docs, name, log

    def document(self, doc_id):
        return FakeDoc(self._docs, (self._name, doc_id), self._log)


class FakeClient:
    def __init__(self):
        self.docs, self.writes = {}, []

    def collection(self, name):
        return FakeCollection(self.docs, name, self.writes)


PROPOSAL = Proposal(finding_id="RZ-1", severity="high", sla_days=7,
                    remediation="Apply the vendor patch.",
                    evidence=("in CISA KEV", "EPSS 0.71"),
                    rationale="Internet facing and exploited in the wild.")


def adjudication(outcome=AdjudicationOutcome.RATIFIED, verdicts=None,
                 attempts=1, note="", proposal=PROPOSAL):
    return Adjudication(
        finding_id="RZ-1", outcome=outcome, proposal=proposal,
        verdicts=verdicts if verdicts is not None
        else (Verdict(ratified=True, reason="Severity matches the evidence."),),
        attempts=attempts, note=note,
    )


@pytest.fixture
def client():
    return FakeClient()


@pytest.fixture
def writer(client):
    return DecisionWriter(store=InMemoryIdempotencyStore(), client=client,
                          clock=SimClock(mode=ClockMode.REAL))


# --- the document ------------------------------------------------------------

def test_every_verdict_is_kept_not_just_the_last(client, writer):
    """The first objection has to survive the retry. Keeping only the final
    verdict would turn "rejected once, then ratified" into "ratified", which
    is the reviewer's contribution being erased from its own record."""
    verdicts = (Verdict(ratified=False, reason="Severity understates KEV."),
                Verdict(ratified=True, reason="Re-proposal is defensible."))
    writer.record(adjudication(verdicts=verdicts, attempts=2), cycle=3)

    stored = client.docs[(COLLECTION, "RZ-1-c003")]["verdicts"]
    assert len(stored) == 2
    assert stored[0]["ratified"] is False
    assert "understates" in stored[0]["reason"]


def test_the_cited_evidence_is_recorded(writer, client):
    """A decision without its evidence is an assertion."""
    writer.record(adjudication(), cycle=3)
    document = client.docs[(COLLECTION, "RZ-1-c003")]
    assert document["cited_evidence"] == ["in CISA KEV", "EPSS 0.71"]
    assert document["proposed_severity"] == "high"


def test_both_stamps_are_recorded(writer, client):
    writer.record(adjudication(), cycle=3)
    document = client.docs[(COLLECTION, "RZ-1-c003")]
    assert "real_ts" in document and "sim_ts" in document


def test_an_unavailable_reviewer_is_not_recorded_as_a_rejection():
    """Capacity pressure is never a verdict. Collapsing the two would corrupt
    the adjudication record with a disagreement that never happened."""
    document = to_decision_document(
        adjudication(outcome=AdjudicationOutcome.UNAVAILABLE, verdicts=(),
                     note="reviewer unavailable after 4 attempts"),
        SimClock(mode=ClockMode.REAL), cycle=3)

    assert document["outcome"] == "unavailable"
    assert document["verdicts"] == []


def test_a_decision_with_no_proposal_still_records(writer, client):
    """The reviewer can be unreachable before triage produced anything."""
    writer.record(adjudication(outcome=AdjudicationOutcome.UNAVAILABLE,
                               proposal=None, verdicts=()), cycle=3)

    document = client.docs[(COLLECTION, "RZ-1-c003")]
    assert document["proposed_severity"] is None
    assert document["cited_evidence"] == []


# --- the human queue ---------------------------------------------------------

def test_a_twice_rejected_finding_reaches_the_human_queue(writer, client):
    verdicts = (Verdict(ratified=False, reason="Severity understates KEV."),
                Verdict(ratified=False, reason="Still understates it."))
    writer.record(adjudication(outcome=AdjudicationOutcome.HUMAN_QUEUE,
                               verdicts=verdicts, attempts=2,
                               note="rejected twice"), cycle=3)

    entry = client.docs[(HUMAN_QUEUE, "RZ-1-c003")]
    assert entry["finding_id"] == "RZ-1"
    assert entry["reason"] == "rejected twice"
    assert len(entry["verdicts"]) == 2


def test_a_ratified_finding_does_not_reach_the_human_queue(writer, client):
    writer.record(adjudication(), cycle=3)
    assert (HUMAN_QUEUE, "RZ-1-c003") not in client.docs


def test_a_queued_finding_without_a_note_still_says_something(writer, client):
    """An empty reason in the human queue is a row a person cannot action."""
    writer.record(adjudication(outcome=AdjudicationOutcome.HUMAN_QUEUE,
                               verdicts=(), note=""), cycle=3)

    assert client.docs[(HUMAN_QUEUE, "RZ-1-c003")]["reason"].strip()


# --- once -------------------------------------------------------------------

def test_recording_the_same_decision_twice_writes_once(writer, client):
    writer.record(adjudication(), cycle=3)
    writes = len(client.writes)
    writer.record(adjudication(), cycle=3)
    assert len(client.writes) == writes


def test_the_document_id_is_the_natural_key(writer, client):
    """Even a store failure cannot produce two decisions for one finding in
    one cycle, because the second would overwrite the first rather than
    landing beside it."""
    writer.record(adjudication(), cycle=3)
    assert (COLLECTION, "RZ-1-c003") in client.docs


def test_a_later_cycle_records_separately(writer, client):
    writer.record(adjudication(), cycle=3)
    writer.record(adjudication(), cycle=4)
    assert (COLLECTION, "RZ-1-c003") in client.docs
    assert (COLLECTION, "RZ-1-c004") in client.docs
