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

"""Writing adjudicated decisions.

`decisions` holds both halves of the record: what triage proposed, and what the
reviewer said about it. Rejections are kept, not just ratifications, because
the disagreements are the evidence that the gate does anything at all. A
decision log containing only agreements would be indistinguishable from one
produced without a reviewer.

Every write goes through the idempotency guard. A resumed cycle recomputes the
same key from the finding, the action and the cycle number, finds the completed
call, and does not write a second decision.
"""

from dataclasses import replace as _replace
from typing import Any, Mapping, Optional

from tools.adjudication import Adjudication, AdjudicationFailure, AdjudicationOutcome, Proposal, Verdict, adjudicate
from tools.clock import SimClock
from tools.docstore import AlreadyExists, as_docstore, firestore_client
from tools.idempotency import IdempotencyGuard, derive_record

#: Owned by the triage and reviewer agents. No other agent writes it.
COLLECTION = "decisions"

#: Terminal state for anything the fleet could not resolve safely. Any agent
#: may append; nothing reads it except the console.
HUMAN_QUEUE = "human_queue"


def to_decision_document(
    adjudication: Adjudication, clock: SimClock, cycle: int, screening: Any = None
) -> dict[str, Any]:
    """Flatten an adjudication into a Firestore document.

    `screening` is the guard's verdict on the untrusted text. Only its two
    flags are kept: its reasons can quote the text they describe. A caller
    that has no verdict leaves the field out, which reads as unknown rather
    than as a claim either way.
    """
    stamp = clock.now()
    proposal = adjudication.proposal
    document = {
        "finding_id": adjudication.finding_id,
        "cycle": cycle,
        "outcome": adjudication.outcome.value,
        "attempts": adjudication.attempts,
        "note": adjudication.note,
        "proposed_severity": proposal.severity if proposal else None,
        "proposed_sla_days": proposal.sla_days if proposal else None,
        "proposed_remediation": proposal.remediation if proposal else None,
        "cited_evidence": list(proposal.evidence) if proposal else [],
        "rationale": proposal.rationale if proposal else None,
        # Every verdict, in order. The first objection survives the retry.
        "verdicts": [
            {"ratified": v.ratified, "reason": v.reason}
            for v in adjudication.verdicts
        ],
        # How independent the review was, and which models took part.
        "review_independence": adjudication.review_independence,
        "models": dict(adjudication.models),
        "same_family_policy": adjudication.same_family_policy,
        "real_ts": stamp.real_ts,
        "sim_ts": stamp.sim_ts,
    }
    if screening is not None:
        document["screening"] = {"screened": bool(screening.screened),
                                 "blocked": bool(screening.blocked)}
        if getattr(screening, "nvt_name_unscreened_strict", False) is True:
            # Local edition, no guard: the test name was shown under the strict
            # plain-text rule. Absent everywhere else, so other records are unchanged.
            document["screening"]["nvt_name_unscreened_strict"] = True
    return document


class DecisionWriter:
    """Writes adjudications, once each."""

    def __init__(
        self,
        store,
        client: Optional[Any] = None,
        clock: Optional[SimClock] = None,
    ) -> None:
        self._db = as_docstore(client if client is not None else firestore_client())
        self._clock = clock or SimClock.from_env()
        self._store = store
        self._guard = IdempotencyGuard(store)

    def restore(self, finding_id: str, cycle: int) -> Optional[Adjudication]:
        """Restore canonical evidence; create-only repair of missing escalation."""
        key = derive_record(finding_id, "decision", cycle)
        document_id = f"{key.finding_id}-c{cycle:03d}"
        snapshot = self._db.collection(COLLECTION).document(document_id).get()
        if not snapshot.exists:
            if self._store.get(key.key) is not None:
                raise RuntimeError("completed decision ledger has no decision; reconciliation required")
            return None
        doc = snapshot.to_dict()
        if doc["finding_id"].strip().upper() != key.finding_id or doc["cycle"] != cycle:
            raise ValueError("stored decision identity does not match request")
        proposal = None
        if doc["proposed_severity"] is not None:
            proposal = Proposal(key.finding_id, doc["proposed_severity"], doc["proposed_sla_days"],
                                doc["proposed_remediation"], tuple(doc["cited_evidence"]), doc["rationale"])
        result = Adjudication(key.finding_id, AdjudicationOutcome(doc["outcome"]), proposal,
                              tuple(Verdict(**v) for v in doc["verdicts"]), doc["attempts"], doc["note"],
                              # Documents written before these fields existed were
                              # all reviewed by one family against another.
                              doc.get("review_independence", "cross_family"),
                              dict(doc.get("models") or {}),
                              doc.get("same_family_policy", "wait"))
        if result.outcome is not AdjudicationOutcome.RATIFIED:
            @self._guard.protects(action="decision_queue_repair")
            def repair(*, finding_id: str, cycle: int):
                ref, payload = self._queue_document(result, cycle, document_id)
                try:
                    ref.create(payload)
                except AlreadyExists:
                    pass
            repair(finding_id=key.finding_id, cycle=cycle)
        return result

    def adjudicate_once(self, finding, triage, review, *, cycle: int, context: str = "",
                        roles=None, screening=None) -> Adjudication:
        """Adjudicate once. `roles` supplies independence, provenance and policy.

        `roles` is required: a record must never claim an independence nobody
        established (hard constraint 3), so there is no default to fall back to.
        """
        if roles is None:
            raise ValueError("roles are required: independence cannot be assumed")
        from tools.inference_journal import InferenceJournal
        finding_id = finding["finding_id"]
        restored = self.restore(finding_id, cycle)
        if restored is not None:
            return restored
        journal = InferenceJournal(self._store, finding_id, cycle, context=context)
        independence = roles.independence()
        provenance = dict(roles.provenance())
        policy = roles.same_family_policy
        counts = {"triage": 0, "review": 0}
        def checked(phase, expected, fn):
            def invoke(*args):
                terminal = self.restore(finding_id, cycle)
                if terminal is not None:
                    raise AdjudicationFailure(terminal)
                counts[phase] += 1
                return journal.call(f"{phase}_{counts[phase]}", expected, lambda: fn(*args))
            return invoke
        try:
            result = adjudicate(finding, checked("triage", Proposal, triage),
                                None if independence == "unreviewed"
                                else checked("review", Verdict, review),
                                max_capacity_retries=1,
                                independence=independence, same_family_policy=policy)
        except AdjudicationFailure as exc:
            result = exc.adjudication
        result = _replace(result, review_independence=independence,
                          models=provenance, same_family_policy=policy)
        self.record(result, cycle, screening=screening)
        return self.restore(finding_id, cycle)

    def record(self, adjudication: Adjudication, cycle: int, screening=None) -> str:
        """Atomically create decision and escalation; first durable result wins."""
        key = derive_record(adjudication.finding_id, "decision", cycle)
        document_id = f"{key.finding_id}-c{cycle:03d}"
        if self.restore(key.finding_id, cycle) is not None:
            return document_id

        @self._guard.protects(action="decision")
        def _write(*, finding_id: str, cycle: int) -> str:
            document = to_decision_document(adjudication, self._clock, cycle, screening)
            document["finding_id"] = finding_id
            batch = self._db.batch()
            batch.create(self._db.collection(COLLECTION).document(document_id), document)
            if adjudication.outcome is not AdjudicationOutcome.RATIFIED:
                ref, payload = self._queue_document(adjudication, cycle, document_id)
                payload["finding_id"] = finding_id
                batch.create(ref, payload)
            try:
                batch.commit()
            except AlreadyExists:
                if self.restore(finding_id, cycle) is None:
                    raise RuntimeError("queue exists without a decision; manual reconciliation required")
            return document_id

        return _write(finding_id=adjudication.finding_id, cycle=cycle)

    def _queue_document(
        self, adjudication: Adjudication, cycle: int, decision_id: str
    ):
        stamp = self._clock.now()
        unavailable = adjudication.outcome is AdjudicationOutcome.UNAVAILABLE
        outcome = adjudication.outcome
        if unavailable:
            queue_id = f"reviewer-unavailable-{decision_id}"
        elif outcome is AdjudicationOutcome.UNREVIEWED:
            queue_id = f"unreviewed-{decision_id}"
        elif outcome is AdjudicationOutcome.HELD_FOR_APPROVAL:
            queue_id = f"held-{decision_id}"
        else:
            queue_id = decision_id
        payload = {
                "finding_id": adjudication.finding_id,
                "cycle": cycle,
                "reason": adjudication.note or "unresolved after review",
                "decision_id": decision_id,
                "verdicts": [
                    {"ratified": v.ratified, "reason": v.reason}
                    for v in adjudication.verdicts
                ],
                "real_ts": stamp.real_ts,
                "sim_ts": stamp.sim_ts,
            }
        if unavailable:
            payload["kind"] = "reviewer_unavailable"
        elif outcome is AdjudicationOutcome.UNREVIEWED:
            payload["kind"] = "unreviewed"
        elif outcome is AdjudicationOutcome.HELD_FOR_APPROVAL:
            payload["kind"] = "same_family_review"
        return self._db.collection(HUMAN_QUEUE).document(queue_id), payload
