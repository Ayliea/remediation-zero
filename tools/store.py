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

"""Firestore-backed idempotency store.

The in-memory store is for tests. This is the one that makes a resumed agent
safe across process restarts, which is the only kind of resume that matters:
an agent that crashes and comes back has lost its memory, so the record of what
it already did has to outlive it.

Completed calls are written under the idempotency key itself. The key is opaque,
so the document carries the components that explain it, which is what keeps an
opaque key traceable.
"""

import uuid
from typing import Optional

from google.cloud import firestore
from google.api_core.exceptions import AlreadyExists, FailedPrecondition

from tools.clock import SimClock
from tools.idempotency import (
    CallClaim, CompletedCall, IdempotencyInProgress, IdempotencyRecord,
)

#: Where completed side effects are remembered. Not owned by any agent: it is
#: infrastructure, and every agent writes its own effects here.
COLLECTION = "idempotency"
CLAIM_LEASE_SECONDS = 600


class FirestoreIdempotencyStore:
    """Remembers completed side effects across process restarts."""

    def __init__(
        self,
        client: Optional[firestore.Client] = None,
        clock: Optional[SimClock] = None,
        collection: str = COLLECTION,
    ) -> None:
        self._client = client or firestore.Client()
        self._clock = clock or SimClock.from_env()
        self._collection = self._client.collection(collection)

    def get(self, key: str) -> Optional[CompletedCall]:
        snapshot = self._collection.document(key).get()
        if not snapshot.exists:
            return None

        data = snapshot.to_dict() or {}
        # Pre-claim records have no status and are completed by definition.
        if data.get("status", "completed") != "completed":
            return None
        return self._completed(key, data)

    @staticmethod
    def _completed(key: str, data: dict) -> CompletedCall:
        return CompletedCall(
            record=IdempotencyRecord(
                key=key,
                finding_id=data.get("finding_id", ""),
                action=data.get("action", ""),
                cycle=int(data.get("cycle", 0)),
                scheme=data.get("scheme", ""),
            ),
            result=data.get("result"),
        )

    def put(self, completed: CompletedCall) -> None:
        stamp = self._clock.now()
        self._collection.document(completed.key).set(
            {
                # The components that explain an otherwise opaque key.
                "finding_id": completed.finding_id,
                "action": completed.action,
                "cycle": completed.cycle,
                "scheme": completed.record.scheme,
                "result": completed.result,
                "status": "completed",
                "real_ts": stamp.real_ts,
                "sim_ts": stamp.sim_ts,
            }
        )

    def acquire(self, record: IdempotencyRecord) -> CallClaim:
        """Atomically acquire a bounded lease for one effect.

        Firestore `create` is an atomic create-if-absent. Reclaiming an expired
        lease uses the snapshot update-time as a precondition, so two rescuers
        cannot both take ownership.
        """
        ref = self._collection.document(record.key)
        token = uuid.uuid4().hex

        for _attempt in range(3):
            stamp = self._clock.now()
            payload = {
                "finding_id": record.finding_id,
                "action": record.action,
                "cycle": record.cycle,
                "scheme": record.scheme,
                "status": "in_progress",
                "claim_token": token,
                "claim_expires_real_ts": stamp.real_ts + CLAIM_LEASE_SECONDS,
                "real_ts": stamp.real_ts,
                "sim_ts": stamp.sim_ts,
            }
            snapshot = ref.get()
            if not snapshot.exists:
                try:
                    ref.create(payload)
                    return CallClaim(record=record, acquired=True, token=token)
                except AlreadyExists:
                    continue

            data = snapshot.to_dict() or {}
            if data.get("status", "completed") == "completed":
                return CallClaim(
                    record=record, acquired=False,
                    existing=self._completed(record.key, data),
                )
            if float(data.get("claim_expires_real_ts", 0) or 0) > stamp.real_ts:
                return CallClaim(record=record, acquired=False)

            try:
                option = (
                    firestore.LastUpdateOption(snapshot.update_time)
                    if getattr(snapshot, "update_time", None) is not None else None
                )
                if option is None:
                    ref.update(payload)
                else:
                    ref.update(payload, option=option)
                return CallClaim(record=record, acquired=True, token=token)
            except FailedPrecondition:
                continue

        return CallClaim(record=record, acquired=False)

    def complete(self, claim: CallClaim, completed: CompletedCall) -> None:
        ref = self._collection.document(completed.key)
        snapshot = ref.get()
        data = snapshot.to_dict() or {}
        if not snapshot.exists or data.get("claim_token") != claim.token:
            raise IdempotencyInProgress("idempotency claim was lost before completion")

        stamp = self._clock.now()
        payload = {
            "finding_id": completed.finding_id,
            "action": completed.action,
            "cycle": completed.cycle,
            "scheme": completed.record.scheme,
            "result": completed.result,
            "status": "completed",
            "claim_token": firestore.DELETE_FIELD,
            "claim_expires_real_ts": firestore.DELETE_FIELD,
            "real_ts": stamp.real_ts,
            "sim_ts": stamp.sim_ts,
        }
        option = (
            firestore.LastUpdateOption(snapshot.update_time)
            if getattr(snapshot, "update_time", None) is not None else None
        )
        try:
            if option is None:
                ref.update(payload)
            else:
                ref.update(payload, option=option)
        except FailedPrecondition as exc:
            raise IdempotencyInProgress(
                "idempotency claim changed before completion"
            ) from exc

    def abandon(self, claim: CallClaim) -> None:
        if not claim.acquired:
            return
        ref = self._collection.document(claim.record.key)
        snapshot = ref.get()
        data = snapshot.to_dict() or {}
        if not snapshot.exists or data.get("claim_token") != claim.token:
            return
        option = (
            firestore.LastUpdateOption(snapshot.update_time)
            if getattr(snapshot, "update_time", None) is not None else None
        )
        try:
            if option is None:
                ref.delete()
            else:
                ref.delete(option=option)
        except FailedPrecondition:
            return
