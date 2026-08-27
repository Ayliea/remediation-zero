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

from typing import Optional

from google.cloud import firestore

from tools.clock import SimClock
from tools.idempotency import CompletedCall, IdempotencyRecord

#: Where completed side effects are remembered. Not owned by any agent: it is
#: infrastructure, and every agent writes its own effects here.
COLLECTION = "idempotency"


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
                "real_ts": stamp.real_ts,
                "sim_ts": stamp.sim_ts,
            }
        )
