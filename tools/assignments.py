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

from typing import Any, Optional

from google.cloud import firestore

from tools.clock import SimClock
from tools.idempotency import IdempotencyGuard
from tools.ownership import Assignment

COLLECTION = "assignments"
SLA_COLLECTION = "sla_clocks"
HUMAN_QUEUE = "human_queue"


class AssignmentWriter:
    """Records who is accountable, and starts their clock."""

    def __init__(
        self,
        store,
        client: Optional[firestore.Client] = None,
        clock: Optional[SimClock] = None,
    ) -> None:
        self._client = client or firestore.Client()
        self._clock = clock or SimClock.from_env()
        self._guard = IdempotencyGuard(store)

    def record(
        self, assignment: Assignment, cycle: int, sla_days: Optional[int] = None
    ) -> str:
        """Record one assignment. Repeating this call has no second effect."""

        @self._guard.protects(action="assignment")
        def _write(*, finding_id: str, cycle: int) -> str:
            stamp = self._clock.now()
            document_id = f"{finding_id}-c{cycle:03d}"

            self._client.collection(COLLECTION).document(document_id).set(
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
                self._client.collection(HUMAN_QUEUE).document(
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
                self._start_sla(finding_id, assignment, cycle, sla_days, stamp)

            return document_id

        return _write(finding_id=assignment.finding_id, cycle=cycle)

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
        self._client.collection(SLA_COLLECTION).document(finding_id).set(
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
