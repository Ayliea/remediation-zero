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

"""Turn corpus records into Firestore documents.

Ingest is the boundary where invented scenario data becomes system state, so it
is where two things have to be got right.

The planted injection label is stripped here and nowhere else. `injection_planted`
exists so `verify-controls.sh` knows which finding to assert on, and it is read
from the committed corpus file for that purpose. If it reached Firestore, every
agent downstream could see a field telling it which finding carries an attack,
and the two-layer defence claim would be worth nothing: the agent would be
reading a label rather than recognising a payload. The payload itself is
preserved byte for byte, because Model Armor and the reviewer need something
real to catch.

Both stamps are attached here, from `SimClock`. `discovered_on_day` stays as it
is: it is invented scenario colour, and conflating it with `real_ts` would put a
fabricated timestamp into system state.
"""

from typing import Any, Mapping

from tools.clock import SimClock

#: Collections the seed script owns. Agents never write these.
REFERENCE_COLLECTIONS = ("findings", "assets", "owners")

#: Fields that exist for the verification path and must never become state.
TEST_ONLY_FIELDS = ("injection_planted",)

#: Which field carries the natural key for each collection. Using the natural
#: key as the document ID is what makes re-ingest overwrite rather than
#: duplicate.
ID_FIELDS = {
    "findings": "finding_id",
    "assets": "asset_id",
    "owners": "owner_id",
}


def to_document(
    record: Mapping[str, Any], clock: SimClock, kind: str
) -> dict[str, Any]:
    """Build the Firestore document for one corpus record.

    Args:
        record: one entry from the committed corpus.
        clock: the system clock. Both stamps come from here, never from
            `time.time()` or a server timestamp.
        kind: the target collection. Must be a reference collection: a typo
            would write reference data into a collection an agent owns and
            quietly break the separation of concerns.

    Returns:
        The document, with `_document_id` naming the ID it should be written
        under. The caller strips that key before writing.
    """
    if kind not in REFERENCE_COLLECTIONS:
        raise ValueError(
            f"kind must be one of {REFERENCE_COLLECTIONS}, got {kind!r}. "
            f"Ingest only writes read-only reference collections."
        )

    document = {k: v for k, v in record.items() if k not in TEST_ONLY_FIELDS}

    stamp = clock.now()
    document["real_ts"] = stamp.real_ts
    document["sim_ts"] = stamp.sim_ts
    document["_document_id"] = record[ID_FIELDS[kind]]
    return document
