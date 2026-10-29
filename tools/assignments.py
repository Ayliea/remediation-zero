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

"""Writing assignments and starting SLA clocks.

`assignments` is owned by the ownership agent. `sla_clocks` is derived state:
it exists so that the chase agent has something to read that does not require
recomputing an SLA from the decision every time it wakes up.

An SLA clock is started in simulated time and recorded in both. That is the
whole reason there are two stamps: a six-week SLA can elapse in three minutes
of demonstration without anyone claiming six weeks passed, because `real_ts`
sits next to `sim_ts` on every record and disagrees with it honestly.
"""

from typing import Any, Mapping, Optional

from tools.clock import SimClock
from tools.docstore import as_docstore, firestore_client
from tools.idempotency import IdempotencyGuard
from tools.ownership import Assignment

COLLECTION = "assignments"
SLA_COLLECTION = "sla_clocks"
#: Each deadline a business-context change moved (or would have, for a breached clock).
MOVES_COLLECTION = "deadline_moves"
HUMAN_QUEUE = "human_queue"


class AssignmentWriter:
    """Records who is accountable, and starts their clock."""

    def __init__(
        self,
        store,
        client: Optional[Any] = None,
        clock: Optional[SimClock] = None,
    ) -> None:
        self._db = as_docstore(client if client is not None else firestore_client())
        self._clock = clock or SimClock.from_env()
        self._guard = IdempotencyGuard(store)

    def record(
        self, assignment: Assignment, cycle: int, sla_days: Optional[int] = None,
        context_change: Optional[Mapping[str, Any]] = None,
    ) -> str:
        """Record one assignment. Repeating this call has no second effect.

        `context_change` is the asset's `context_last_change` (tools.context). With it, an
        SLA clock that is already open is moved rather than restarted (`_move_sla`), and a
        breached one is left alone; both are recorded in `deadline_moves`. Without it, or
        for a clock in any other state, the clock starts as it always has.
        """

        @self._guard.protects(action="assignment")
        def _write(*, finding_id: str, cycle: int) -> str:
            stamp = self._clock.now()
            document_id = f"{finding_id}-c{cycle:03d}"

            self._db.collection(COLLECTION).document(document_id).set(
                {
                    "finding_id": finding_id,
                    "cycle": cycle,
                    "asset_id": assignment.asset_id,
                    "owner_id": assignment.owner_id,
                    "owner_email": assignment.owner_email,
                    "owner_name": assignment.owner_name,
                    "team": assignment.team,
                    "needs_human": assignment.needs_human,
                    "reason": assignment.reason,
                    "real_ts": stamp.real_ts,
                    "sim_ts": stamp.sim_ts,
                }
            )

            if assignment.needs_human:
                self._db.collection(HUMAN_QUEUE).document(
                    f"unassigned-{document_id}"
                ).set(
                    {
                        "finding_id": finding_id,
                        "cycle": cycle,
                        "reason": assignment.reason,
                        "kind": "unassigned",
                        "real_ts": stamp.real_ts,
                        "sim_ts": stamp.sim_ts,
                    }
                )
            elif sla_days is not None:
                clock = (self._db.collection(SLA_COLLECTION).document(finding_id).get().to_dict()
                         if context_change is not None else None)
                if clock and clock.get("status") in ("open", "breached"):
                    self._move_sla(finding_id, assignment, cycle, sla_days, stamp, clock,
                                   context_change)
                else:
                    self._start_sla(finding_id, assignment, cycle, sla_days, stamp)

            return document_id

        return _write(finding_id=assignment.finding_id, cycle=cycle)

    def _move_sla(self, finding_id: str, assignment: Assignment, cycle: int, sla_days: int,
                  stamp: Any, clock: Mapping[str, Any], change: Mapping[str, Any]) -> None:
        """Move an open clock's deadline after a business-context change.

        The clock keeps its original start: new due = start + new SLA days, but never sooner
        than a day from now, so a raised finding is not born overdue, and a shorter SLA never
        lands later than the deadline it already had. A clock that is overdue (breached, or
        open past its due time: chase marks it breached only when it escalates) is not
        moved. An unchanged due time writes nothing.
        """
        old_due = clock["due_sim_ts"]
        if clock.get("status") == "breached" or old_due <= stamp.sim_ts:
            new_due, outcome = old_due, "already overdue, not moved"
        else:
            new_due = max(clock["started_sim_ts"] + sla_days * 86400, stamp.sim_ts + 86400)
            if sla_days < (clock.get("sla_days") or sla_days + 1):
                new_due = min(new_due, old_due)
            if new_due == old_due:
                return
            outcome = "moved"
        move_id = f"{finding_id}-c{cycle:03d}"
        self._db.collection(MOVES_COLLECTION).document(move_id).set(
            {"finding_id": finding_id, "cycle": cycle, "asset_id": assignment.asset_id,
             "old_due_sim_ts": old_due, "new_due_sim_ts": new_due, "outcome": outcome,
             "changed_by": change.get("by"), "change_summary": list(change.get("summary") or []),
             "changed_sim_ts": change.get("sim_ts"),
             "real_ts": stamp.real_ts, "sim_ts": stamp.sim_ts})
        if outcome == "moved":
            self._db.collection(SLA_COLLECTION).document(finding_id).update(
                {"due_sim_ts": new_due, "sla_days": sla_days, "last_move_id": move_id})

    def _start_sla(
        self,
        finding_id: str,
        assignment: Assignment,
        cycle: int,
        sla_days: int,
        stamp: Any,
    ) -> None:
        """Start the clock in simulated time.

        `due_sim_ts` is what the chase agent compares against, so an
        accelerated demonstration moves the deadline. `started_real_ts` records
        when this actually happened and is never adjusted to match.
        """
        self._db.collection(SLA_COLLECTION).document(finding_id).set(
            {
                "finding_id": finding_id,
                "cycle_started": cycle,
                "owner_id": assignment.owner_id,
                "sla_days": sla_days,
                "started_real_ts": stamp.real_ts,
                "started_sim_ts": stamp.sim_ts,
                "due_sim_ts": stamp.sim_ts + sla_days * 86400,
                "status": "open",
            }
        )
