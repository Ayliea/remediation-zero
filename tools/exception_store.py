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

"""Recording risk acceptances and re-opening them at expiry."""

from typing import Any, Optional

from google.cloud import firestore

from tools.clock import SimClock
from tools.exceptions import Exception_, validate_acceptance
from tools.idempotency import IdempotencyGuard

COLLECTION = "exceptions"
SLA_COLLECTION = "sla_clocks"
HUMAN_QUEUE = "human_queue"


class ExceptionWriter:
    """Accepts risks, and brings them back when the acceptance lapses."""

    def __init__(
        self,
        store,
        client: Optional[firestore.Client] = None,
        clock: Optional[SimClock] = None,
    ) -> None:
        self._client = client or firestore.Client()
        self._clock = clock or SimClock.from_env()
        self._guard = IdempotencyGuard(store)

    def accept(
        self,
        finding_id: str,
        cycle: int,
        accepted_by: str,
        reason: str,
        ttl_days: int,
        in_kev: bool,
        approved_by_human: bool = False,
    ) -> str:
        """Record a risk acceptance.

        Refuses before writing anything if the acceptance is one the fleet is
        not permitted to make. A refused acceptance goes to a person rather
        than being silently dropped, because the request itself is a signal.
        """
        try:
            validate_acceptance(
                ttl_days=ttl_days,
                reason=reason,
                in_kev=in_kev,
                approved_by_human=approved_by_human,
            )
        except ValueError as exc:
            stamp = self._clock.now()
            self._client.collection(HUMAN_QUEUE).document(
                f"acceptance-refused-{finding_id}-c{cycle:03d}"
            ).set(
                {
                    "finding_id": finding_id,
                    "cycle": cycle,
                    "kind": "acceptance_refused",
                    "reason": str(exc),
                    "requested_by": accepted_by,
                    "requested_ttl_days": ttl_days,
                    "real_ts": stamp.real_ts,
                    "sim_ts": stamp.sim_ts,
                }
            )
            raise

        @self._guard.protects(action="accept_risk")
        def _write(*, finding_id: str, cycle: int) -> str:
            stamp = self._clock.now()
            expires = stamp.sim_ts + ttl_days * 86400
            self._client.collection(COLLECTION).document(finding_id).set(
                {
                    "finding_id": finding_id,
                    "accepted_by": accepted_by,
                    "reason": reason,
                    "ttl_days": ttl_days,
                    "accepted_cycle": cycle,
                    "accepted_real_ts": stamp.real_ts,
                    "accepted_sim_ts": stamp.sim_ts,
                    "expires_sim_ts": expires,
                    "approved_by_human": approved_by_human,
                    "in_kev": in_kev,
                    "reopened": False,
                    "status": "active",
                }
            )
            # Chase must not pursue an accepted finding, so the clock is
            # paused rather than left running against an owner who has been
            # told to stand down.
            self._client.collection(SLA_COLLECTION).document(finding_id).set(
                {"status": "accepted", "paused_sim_ts": stamp.sim_ts}, merge=True
            )
            return f"accepted:{finding_id}"

        return _write(finding_id=finding_id, cycle=cycle)

    def reopen(self, exception: Exception_, cycle: int, now_sim_ts: float) -> str:
        """Bring back a finding whose acceptance has lapsed.

        The finding was never fixed, only deferred, so it returns for
        re-adjudication rather than resuming its old SLA: the evidence may
        have moved while it was parked, and a stale severity is not a decision.
        """

        @self._guard.protects(action="reopen_exception")
        def _write(*, finding_id: str, cycle: int) -> str:
            stamp = self._clock.now()
            self._client.collection(COLLECTION).document(finding_id).set(
                {
                    "reopened": True,
                    "status": "expired",
                    "reopened_cycle": cycle,
                    "reopened_real_ts": stamp.real_ts,
                    "reopened_sim_ts": now_sim_ts,
                },
                merge=True,
            )
            self._client.collection(SLA_COLLECTION).document(finding_id).set(
                {"status": "reopened_pending_triage"}, merge=True
            )
            self._client.collection(HUMAN_QUEUE).document(
                f"reopened-{finding_id}"
            ).set(
                {
                    "finding_id": finding_id,
                    "cycle": cycle,
                    "kind": "acceptance_expired",
                    "reason": (
                        f"Risk acceptance lapsed after {exception.ttl_days} "
                        f"simulated days. Accepted by {exception.accepted_by} "
                        f"because: {exception.reason} The finding was never "
                        f"remediated and returns for re-adjudication."
                    ),
                    "real_ts": stamp.real_ts,
                    "sim_ts": now_sim_ts,
                }
            )
            return f"reopened:{finding_id}"

        return _write(finding_id=exception.finding_id, cycle=cycle)
