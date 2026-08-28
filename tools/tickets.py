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

"""Ticket, nudge and escalation writes.

Every one of these is a side effect that must not happen twice. The
idempotency key is derived from the finding, the action and the cycle, so a
resumed agent that recomputes it finds the completed call and sends nothing.

Nudges are keyed per cycle rather than per finding, deliberately. Week three's
nudge is not week two's nudge and must still send; what must never happen is
week three's nudge going out twice because the process restarted between the
send and the write.
"""

import json
import logging
from typing import Any, Optional

from google.cloud import firestore

from tools.chase import ChaseAction, ChaseState
from tools.clock import SimClock
from tools.idempotency import IdempotencyGuard

logger = logging.getLogger("remediation_zero.tickets")

COLLECTION = "tickets"
SLA_COLLECTION = "sla_clocks"
HUMAN_QUEUE = "human_queue"


class TicketWriter:
    """Performs chase's side effects, once each."""

    def __init__(
        self,
        store,
        client: Optional[firestore.Client] = None,
        clock: Optional[SimClock] = None,
        delivery: Optional[Any] = None,
    ) -> None:
        self._client = client or firestore.Client()
        self._clock = clock or SimClock.from_env()
        self._guard = IdempotencyGuard(store)
        #: Where the ticket is delivered so a person sees it. Optional: the
        #: fleet runs without it and the record is unchanged either way.
        self._delivery = delivery

    def _deliver(self, event: str, finding_id: str, ticket_ref, **fields) -> None:
        """Deliver one chase action to the tracker.

        Never raises. Firestore is the record and the tracker is a delivery of
        it: a cycle whose deadline, nudge count and escalation were written
        correctly has done its work, and an unreachable tracker is a delivery
        to retry rather than a cycle to fail. The inverse would be worse —
        refusing to record that a nudge was due because a network call failed
        loses the fact itself.
        """
        if self._delivery is None:
            return
        try:
            number = self._delivery.deliver(
                event=event, finding_id=finding_id, **fields)
            if number is not None:
                ticket_ref.update({"github_issue": number})
        except Exception as exc:  # noqa: BLE001 - deliberately broad
            logger.warning(json.dumps({
                "event": "delivery_failed", "finding_id": finding_id,
                "cycle_id": "-", "action": event,
                "error": type(exc).__name__, "detail": str(exc)[:200],
            }, sort_keys=True))

    def act(
        self,
        action: ChaseAction,
        state: ChaseState,
        cycle: int,
        owner: dict[str, Any],
        now_sim_ts: float,
    ) -> Optional[str]:
        """Carry out one chase action. Repeating the call has no second effect."""
        if action in (ChaseAction.WAIT, ChaseAction.DONE):
            return None

        @self._guard.protects(action=action.value)
        def _perform(*, finding_id: str, cycle: int) -> str:
            stamp = self._clock.now()
            ticket_ref = self._client.collection(COLLECTION).document(finding_id)

            if action is ChaseAction.OPEN_TICKET:
                ticket_ref.set(
                    {
                        "finding_id": finding_id,
                        "status": "open",
                        "owner_id": owner.get("owner_id"),
                        "owner_email": owner.get("email"),
                        "opened_cycle": cycle,
                        "opened_real_ts": stamp.real_ts,
                        "opened_sim_ts": now_sim_ts,
                        "nudges_sent": 0,
                        "escalated": False,
                        "last_contact_sim_ts": now_sim_ts,
                        "history": [
                            {"action": "open_ticket", "cycle": cycle,
                             "real_ts": stamp.real_ts, "sim_ts": now_sim_ts}
                        ],
                    }
                )
                self._deliver("open_ticket", finding_id, ticket_ref,
                              owner=owner, cycle=cycle, now_sim_ts=now_sim_ts,
                              state=state)
                return f"ticket:{finding_id}"

            entry = {"action": action.value, "cycle": cycle,
                     "real_ts": stamp.real_ts, "sim_ts": now_sim_ts}

            if action is ChaseAction.NUDGE:
                ticket_ref.update(
                    {
                        "nudges_sent": firestore.Increment(1),
                        "last_contact_sim_ts": now_sim_ts,
                        "history": firestore.ArrayUnion([entry]),
                    }
                )
                self._deliver("nudge", finding_id, ticket_ref, owner=owner,
                              cycle=cycle, now_sim_ts=now_sim_ts, state=state)
                return f"nudge:{finding_id}:c{cycle}"

            if action is ChaseAction.ESCALATE:
                ticket_ref.update(
                    {
                        "escalated": True,
                        "status": "escalated",
                        "escalated_cycle": cycle,
                        "last_contact_sim_ts": now_sim_ts,
                        "history": firestore.ArrayUnion([entry]),
                    }
                )
                self._client.collection(SLA_COLLECTION).document(finding_id).update(
                    {"status": "breached"}
                )
                self._deliver("escalate", finding_id, ticket_ref, owner=owner,
                              cycle=cycle, now_sim_ts=now_sim_ts, state=state)
                return f"escalate:{finding_id}"

            if action is ChaseAction.CLOSE_TICKET:
                # The ticket keeps its history rather than being deleted. What
                # the fleet did about a finding stays readable after the
                # finding stops being a problem, which is what makes the
                # closure auditable instead of merely tidy.
                ticket_ref.update(
                    {
                        "status": "resolved",
                        "resolved_cycle": cycle,
                        "resolved_real_ts": stamp.real_ts,
                        "resolved_sim_ts": now_sim_ts,
                        "resolved_by_scan": getattr(state, "resolved_by_scan", None),
                        "last_contact_sim_ts": now_sim_ts,
                        "history": firestore.ArrayUnion([entry]),
                    }
                )
                self._deliver("close_ticket", finding_id, ticket_ref, owner=owner,
                              cycle=cycle, now_sim_ts=now_sim_ts, state=state)
                return f"close_ticket:{finding_id}"

            if action is ChaseAction.HUMAN_QUEUE:
                self._client.collection(HUMAN_QUEUE).document(
                    f"unresolved-{finding_id}"
                ).set(
                    {
                        "finding_id": finding_id,
                        "cycle": cycle,
                        "kind": "escalated_unresolved",
                        "reason": (
                            f"Escalated and still unresolved "
                            f"{state.days_overdue(now_sim_ts):.0f} simulated days "
                            f"past the SLA. The fleet has no further action that "
                            f"does not involve a person."
                        ),
                        "owner_id": owner.get("owner_id"),
                        "real_ts": stamp.real_ts,
                        "sim_ts": now_sim_ts,
                    }
                )
                ticket_ref.update({"status": "with_human",
                                   "history": firestore.ArrayUnion([entry])})
                self._deliver("human_queue", finding_id, ticket_ref, owner=owner,
                              cycle=cycle, now_sim_ts=now_sim_ts, state=state)
                return f"human_queue:{finding_id}"

            return "noop"

        return _perform(finding_id=state.finding_id, cycle=cycle)
