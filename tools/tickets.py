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

Every authoritative state transition is protected against a repeated cycle.
Tracker calls are a recoverable, at-least-once delivery: issue creation has a
lookup recovery path, while comments can repeat in the narrow case where
GitHub accepted a request but the acknowledgement was lost.

Nudges are keyed per cycle rather than per finding, deliberately. Week three's
nudge is not week two's nudge and must still send; what must never happen is
week three's nudge going out twice because the process restarted between the
send and the write.
"""

import json
import logging
import secrets
from dataclasses import dataclass
from typing import Any, Optional

from google.cloud import firestore

from tools.chase import ChaseAction, ChaseState
from tools.clock import SimClock
from tools.idempotency import IdempotencyGuard
from tools.telemetry import cycle_id

logger = logging.getLogger("remediation_zero.tickets")

COLLECTION = "tickets"
SLA_COLLECTION = "sla_clocks"
HUMAN_QUEUE = "human_queue"


@dataclass(frozen=True)
class _DeliveryState:
    started_sim_ts: float = 0.0
    due_sim_ts: float = 0.0
    nudges_sent: int = 0
    resolved_by_scan: Optional[str] = None

    def days_overdue(self, now_sim_ts: float) -> float:
        return max(0.0, (now_sim_ts - self.due_sim_ts) / 86400)


class TicketWriter:
    """Performs chase state transitions once and delivers them best-effort."""

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

    def _pending_delivery(
        self, event: str, finding_id: str, owner: dict[str, Any], cycle: int,
        now_sim_ts: float, state: ChaseState,
    ) -> Optional[dict[str, Any]]:
        if self._delivery is None:
            return None
        return {
            # Persisted before egress. Unlike a public deterministic marker,
            # this cannot be pre-forged by a commenter to suppress delivery.
            "delivery_id": secrets.token_urlsafe(18),
            "status": "pending",
            "event": event,
            "finding_id": finding_id,
            "owner": dict(owner),
            "cycle": cycle,
            "now_sim_ts": now_sim_ts,
            "state": {
                "started_sim_ts": state.started_sim_ts,
                "due_sim_ts": state.due_sim_ts,
                "nudges_sent": state.nudges_sent,
                "resolved_by_scan": getattr(state, "resolved_by_scan", None),
            },
            "attempts": 0,
        }

    def _deliver(self, ticket_ref, pending: Optional[dict[str, Any]]) -> bool:
        """Deliver one chase action to the tracker.

        Never raises. The pending event is already in Firestore beside the
        ticket state, so failure leaves durable work for the next cycle rather
        than relying on a log line to become a retry mechanism.
        """
        if pending is None:
            return True
        event = str(pending["event"])
        finding_id = str(pending["finding_id"])
        fields = {
            "owner": pending.get("owner") or {},
            "cycle": int(pending["cycle"]),
            "now_sim_ts": float(pending["now_sim_ts"]),
            "state": _DeliveryState(**(pending.get("state") or {})),
            "delivery_id": pending.get("delivery_id"),
        }
        if self._delivery is None:
            return False
        try:
            number = self._delivery.deliver(
                event=event, finding_id=finding_id, **fields)
            stamp = self._clock.now()
            delivered = {
                **pending,
                "status": "delivered",
                "attempts": int(pending.get("attempts", 0)) + 1,
                "delivered_real_ts": stamp.real_ts,
                "delivered_sim_ts": stamp.sim_ts,
            }
            update = {"delivery": delivered}
            if number is not None:
                update["github_issue"] = number
            ticket_ref.update(update)
            return True
        except Exception as exc:  # noqa: BLE001 - deliberately broad
            failed = {
                **pending,
                "status": "pending",
                "attempts": int(pending.get("attempts", 0)) + 1,
                "last_error": f"{type(exc).__name__}: {str(exc)[:160]}",
            }
            ticket_ref.update({"delivery": failed})
            logger.warning(json.dumps({
                "event": "delivery_failed", "finding_id": finding_id,
                "cycle_id": cycle_id(fields.get("cycle")), "action": event,
                "error": type(exc).__name__, "detail": str(exc)[:200],
            }, sort_keys=True))
            return False

    def retry_pending(self, finding_id: str, ticket: dict[str, Any]) -> bool:
        """Replay the exact oldest undelivered event before newer work."""
        pending = ticket.get("delivery")
        if not isinstance(pending, dict) or pending.get("status") != "pending":
            return True
        ref = self._client.collection(COLLECTION).document(finding_id)
        return self._deliver(ref, pending)

    def cancel_pending(
        self, finding_id: str, ticket: dict[str, Any], reason: str
    ) -> bool:
        """Cancel an undelivered event whose premise no longer holds.

        Delivery is deliberately retried from durable state, but a retry is
        not allowed to outrank newer authoritative state. A reminder that was
        due before a rescan or risk acceptance must not reach an owner after
        the fleet has learned to stop chasing it.
        """
        pending = ticket.get("delivery")
        if not isinstance(pending, dict) or pending.get("status") != "pending":
            return False
        stamp = self._clock.now()
        cancelled = {
            **pending,
            "status": "cancelled",
            "cancel_reason": reason,
            "cancelled_real_ts": stamp.real_ts,
            "cancelled_sim_ts": stamp.sim_ts,
        }
        self._client.collection(COLLECTION).document(finding_id).update(
            {"delivery": cancelled}
        )
        return True

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
            pending = self._pending_delivery(
                action.value, finding_id, owner, cycle, now_sim_ts, state
            )
            delivery_field = {"delivery": pending} if pending is not None else {}

            if action is ChaseAction.OPEN_TICKET:
                # merge, not replace. This branch opens a ticket that has
                # never existed and reopens one a rescan regressed, and the
                # second case only became reachable when CLOSE_TICKET landed.
                # A plain set() served the first case correctly and silently
                # destroyed the second: nudges, escalation, the whole history
                # and the tracker issue number all replaced by a fresh
                # document, so the console showed a finding the fleet had
                # chased for weeks as though it had just been found.
                #
                # The counters do reset. A regression is a new problem and the
                # owner gets the same three nudges before escalation as they
                # would on any other ticket; inheriting nudges_sent would trip
                # the MAX_NUDGES gate in chase.next_action immediately and
                # escalate without ever asking. What is preserved is the
                # record of what happened, which is the part that cannot be
                # reconstructed later.
                batch = self._client.batch()
                batch.set(
                    ticket_ref,
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
                        **delivery_field,
                        # A resolution that no longer holds must not sit
                        # beside status "open" contradicting it. Same
                        # treatment scan_store.reopen gives the finding.
                        "resolved_cycle": firestore.DELETE_FIELD,
                        "resolved_real_ts": firestore.DELETE_FIELD,
                        "resolved_sim_ts": firestore.DELETE_FIELD,
                        "resolved_by_scan": firestore.DELETE_FIELD,
                    },
                    merge=True,
                )
                # Appended rather than assigned, so a reopen extends the trail
                # instead of starting it over. ArrayUnion creates the field
                # when the ticket is genuinely new.
                batch.update(
                    ticket_ref,
                    {"history": firestore.ArrayUnion([
                        {"action": "open_ticket", "cycle": cycle,
                         "real_ts": stamp.real_ts, "sim_ts": now_sim_ts}
                    ])}
                )
                batch.commit()
                self._deliver(ticket_ref, pending)
                return f"ticket:{finding_id}"

            entry = {"action": action.value, "cycle": cycle,
                     "real_ts": stamp.real_ts, "sim_ts": now_sim_ts}

            if action is ChaseAction.NUDGE:
                ticket_ref.update(
                    {
                        "nudges_sent": firestore.Increment(1),
                        "last_contact_sim_ts": now_sim_ts,
                        "history": firestore.ArrayUnion([entry]),
                        **delivery_field,
                    }
                )
                self._deliver(ticket_ref, pending)
                return f"nudge:{finding_id}:c{cycle}"

            if action is ChaseAction.ESCALATE:
                batch = self._client.batch()
                batch.update(
                    ticket_ref,
                    {
                        "escalated": True,
                        "status": "escalated",
                        "escalated_cycle": cycle,
                        "last_contact_sim_ts": now_sim_ts,
                        "history": firestore.ArrayUnion([entry]),
                        **delivery_field,
                    }
                )
                batch.update(
                    self._client.collection(SLA_COLLECTION).document(finding_id),
                    {"status": "breached"}
                )
                batch.commit()
                self._deliver(ticket_ref, pending)
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
                        **delivery_field,
                    }
                )
                self._deliver(ticket_ref, pending)
                return f"close_ticket:{finding_id}"

            if action is ChaseAction.HUMAN_QUEUE:
                batch = self._client.batch()
                batch.set(
                    self._client.collection(HUMAN_QUEUE).document(
                    f"unresolved-{finding_id}"
                    ),
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
                batch.update(
                    ticket_ref,
                    {"status": "with_human",
                     "history": firestore.ArrayUnion([entry]),
                     **delivery_field},
                )
                batch.commit()
                self._deliver(ticket_ref, pending)
                return f"human_queue:{finding_id}"

            return "noop"

        return _perform(finding_id=state.finding_id, cycle=cycle)
