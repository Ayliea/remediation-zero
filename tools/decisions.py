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

from typing import Any, Mapping, Optional

from google.cloud import firestore

from tools.adjudication import Adjudication
from tools.clock import SimClock
from tools.idempotency import IdempotencyGuard

#: Owned by the triage and reviewer agents. No other agent writes it.
COLLECTION = "decisions"

#: Terminal state for anything the fleet could not resolve safely. Any agent
#: may append; nothing reads it except the console.
HUMAN_QUEUE = "human_queue"


def to_decision_document(
    adjudication: Adjudication, clock: SimClock, cycle: int
) -> dict[str, Any]:
    """Flatten an adjudication into a Firestore document."""
    stamp = clock.now()
    proposal = adjudication.proposal
    return {
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
        "real_ts": stamp.real_ts,
        "sim_ts": stamp.sim_ts,
    }


class DecisionWriter:
    """Writes adjudications, once each."""

    def __init__(
        self,
        store,
        client: Optional[firestore.Client] = None,
        clock: Optional[SimClock] = None,
    ) -> None:
        self._client = client or firestore.Client()
        self._clock = clock or SimClock.from_env()
        self._guard = IdempotencyGuard(store)

    def record(self, adjudication: Adjudication, cycle: int) -> str:
        """Record one adjudication. Repeating this call has no second effect."""

        @self._guard.protects(action="decision")
        def _write(*, finding_id: str, cycle: int) -> str:
            document = to_decision_document(adjudication, self._clock, cycle)
            # The document ID is the natural key, so even a store failure
            # cannot produce two decisions for one finding in one cycle.
            document_id = f"{finding_id}-c{cycle:03d}"
            self._client.collection(COLLECTION).document(document_id).set(document)

            if adjudication.outcome.value == "human_queue":
                self._append_human_queue(adjudication, cycle, document_id)
            return document_id

        return _write(finding_id=adjudication.finding_id, cycle=cycle)

    def _append_human_queue(
        self, adjudication: Adjudication, cycle: int, decision_id: str
    ) -> None:
        stamp = self._clock.now()
        self._client.collection(HUMAN_QUEUE).document(decision_id).set(
            {
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
        )
