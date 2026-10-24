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
from types import SimpleNamespace
from google.api_core.exceptions import AlreadyExists

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

    def get(self):
        data = self._docs.get(self._key)
        return SimpleNamespace(exists=data is not None, to_dict=lambda: data)

    def create(self, data):
        if self._key in self._docs:
            raise AlreadyExists("exists")
        self.set(data)


class FakeCollection:
    def __init__(self, docs, name, log):
        self._docs, self._name, self._log = docs, name, log

    def document(self, doc_id):
        return FakeDoc(self._docs, (self._name, doc_id), self._log)

    def stream(self):
        return [FakeDoc(self._docs, key, self._log).get()
                for key in self._docs if key[0] == self._name]


class FakeClient:
    def __init__(self):
        self.docs, self.writes = {}, []

    def collection(self, name):
        return FakeCollection(self.docs, name, self.writes)

    def batch(self):
        return FakeBatch(self)


class FakeBatch:
    """Atomic-create contract double, not a substitute for emulator checks."""
    def __init__(self, client):
        self.client, self.pending = client, []

    def create(self, ref, data):
        self.pending.append((ref, data))

    def commit(self):
        if any(ref._key in self.client.docs for ref, _ in self.pending):
            raise AlreadyExists("exists")
        for ref, data in self.pending:
            ref.create(data)


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


# --- review independence -----------------------------------------------------

def test_document_carries_independence_models_and_policy(writer, client):
    result = Adjudication(
        "RZ-1", AdjudicationOutcome.HELD_FOR_APPROVAL, PROPOSAL,
        (Verdict(True, "ok"),), 1, "same-family review: needs a person's approval",
        review_independence="same_family",
        models={"proposer": {"format": "openai_chat", "model": "qwen-a", "family": "qwen"}},
        same_family_policy="wait")
    writer.record(result, cycle=3)

    document = client.docs[(COLLECTION, "RZ-1-c003")]
    assert document["review_independence"] == "same_family"
    assert document["models"]["proposer"]["family"] == "qwen"
    assert document["same_family_policy"] == "wait"


def test_old_decision_document_restores_with_defaults(writer, client):
    document = to_decision_document(adjudication(), SimClock(mode=ClockMode.REAL), 3)
    for name in ("review_independence", "models", "same_family_policy"):
        del document[name]
    client.docs[(COLLECTION, "RZ-1-c003")] = document

    restored = writer.restore("RZ-1", 3)

    assert restored.outcome is AdjudicationOutcome.RATIFIED
    assert restored.review_independence == "cross_family"
    assert restored.models == {}
    assert restored.same_family_policy == "wait"


def test_unreviewed_writes_its_own_queue_document_once(writer, client):
    result = adjudication(outcome=AdjudicationOutcome.UNREVIEWED, verdicts=(),
                          note="needs a person's review: no reviewer configured")
    writer.record(result, cycle=3)
    writer.record(result, cycle=3)

    entry = client.docs[(HUMAN_QUEUE, "unreviewed-RZ-1-c003")]
    assert entry["kind"] == "unreviewed"
    assert entry["decision_id"] == "RZ-1-c003"
    assert (HUMAN_QUEUE, "RZ-1-c003") not in client.docs
    assert len([k for k in client.docs if k[0] == HUMAN_QUEUE]) == 1


def test_held_writes_its_own_queue_document_once(writer, client):
    result = adjudication(outcome=AdjudicationOutcome.HELD_FOR_APPROVAL,
                          note="same-family review: needs a person's approval")
    writer.record(result, cycle=3)
    writer.record(result, cycle=3)

    entry = client.docs[(HUMAN_QUEUE, "held-RZ-1-c003")]
    assert entry["kind"] == "same_family_review"
    assert entry["reason"] == "same-family review: needs a person's approval"
    assert len([k for k in client.docs if k[0] == HUMAN_QUEUE]) == 1


def test_a_missing_held_queue_document_is_repaired_without_duplicates(writer, client):
    result = adjudication(outcome=AdjudicationOutcome.HELD_FOR_APPROVAL, note="held")
    client.docs[(COLLECTION, "RZ-1-c003")] = to_decision_document(
        result, SimClock(mode=ClockMode.REAL), 3)

    writer.restore("RZ-1", 3)
    writer.restore("RZ-1", 3)

    assert [k for k in client.docs if k[0] == HUMAN_QUEUE] == [(HUMAN_QUEUE, "held-RZ-1-c003")]


def _roles(env):
    from tools.model_roles import ModelRoles
    return ModelRoles.from_env(env)


def test_cloud_decision_records_cross_family(writer, client):
    roles = _roles({"REASONING_MODEL": "gemini-3.5-flash",
                    "REVIEWER_MODEL": "gemma-4-26b-a4b-it-maas"})
    writer.adjudicate_once(
        {"finding_id": "RZ-1"}, lambda _f: PROPOSAL,
        lambda _f, _p: Verdict(True, "ok"), cycle=3, roles=roles)

    document = client.docs[(COLLECTION, "RZ-1-c003")]
    assert document["outcome"] == "ratified"
    assert document["review_independence"] == "cross_family"
    assert document["same_family_policy"] == "wait"
    assert {"proposer", "reviewer"} <= set(document["models"])
    assert document["models"] == roles.provenance()
    assert not [k for k in client.docs if k[0] == HUMAN_QUEUE]


def test_adjudicate_once_without_a_reviewer_never_calls_review(writer, client):
    roles = _roles({"REASONING_MODEL": "gemini-3.5-flash"})
    assert roles.independence() == "unreviewed"

    result = writer.adjudicate_once(
        {"finding_id": "RZ-1"}, lambda _f: PROPOSAL, None, cycle=3, roles=roles)

    assert result.outcome is AdjudicationOutcome.UNREVIEWED
    document = client.docs[(COLLECTION, "RZ-1-c003")]
    assert document["review_independence"] == "unreviewed"
    assert document["models"] == roles.provenance()
    assert "reviewer" not in document["models"]
    assert (HUMAN_QUEUE, "unreviewed-RZ-1-c003") in client.docs


def test_adjudicate_once_without_roles_refuses(writer, client):
    calls = []
    with pytest.raises(ValueError, match="roles are required: independence cannot be assumed"):
        writer.adjudicate_once(
            {"finding_id": "RZ-1"}, lambda _f: calls.append("triage") or PROPOSAL,
            lambda _f, _p: calls.append("review") or Verdict(True, "ok"), cycle=3)
    assert calls == []
    assert not client.docs


def test_decision_document_carries_screening_flags_only_when_given():
    from tools.clock import ClockMode, SimClock
    from tools.decisions import to_decision_document
    from tools.model_armor import ArmorVerdict
    adjudication = Adjudication(finding_id="RZ-1", outcome=AdjudicationOutcome.UNAVAILABLE,
                                proposal=None, verdicts=(), attempts=0, note="n")
    clock = SimClock(ClockMode.REAL)
    verdict = ArmorVerdict(blocked=True, screened=False, reasons=("quoted payload",))

    with_flags = to_decision_document(adjudication, clock, 1, screening=verdict)
    assert with_flags["screening"] == {"screened": False, "blocked": True}
    assert "quoted payload" not in repr(with_flags)
    # Absent, not invented: a caller that cannot say leaves it unknown.
    assert "screening" not in to_decision_document(adjudication, clock, 1)
