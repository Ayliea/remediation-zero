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

"""Load the committed corpus into the read-only reference collections.

Safe to re-run. Documents are written under their natural keys, so a second run
overwrites in place rather than producing a second copy of every finding.

Writes `findings`, `assets` and `owners` only. No agent writes these
collections; they are reference data and the seed script owns them.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dotenv import load_dotenv
from google.cloud import firestore

from tools.clock import SimClock
from tools.ingest import REFERENCE_COLLECTIONS, to_document

REPO_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = REPO_ROOT / "data"

#: Firestore caps a batched write at 500 operations.
BATCH_LIMIT = 450


def main() -> int:
    load_dotenv(REPO_ROOT / ".env")
    clock = SimClock.from_env()
    client = firestore.Client()

    print(f"clock mode: {clock.mode.value}")
    total = 0

    for kind in REFERENCE_COLLECTIONS:
        path = DATA_DIR / f"{kind}.json"
        records = json.loads(path.read_text(encoding="utf-8"))
        collection = client.collection(kind)

        written = 0
        batch = client.batch()
        pending = 0

        for record in records:
            document = to_document(record, clock=clock, kind=kind)
            document_id = document.pop("_document_id")
            batch.set(collection.document(document_id), document)
            pending += 1
            written += 1

            if pending >= BATCH_LIMIT:
                batch.commit()
                batch = client.batch()
                pending = 0

        if pending:
            batch.commit()

        print(f"  {kind}: {written} documents")
        total += written

    print(f"\n{total} documents written. Re-running overwrites in place.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
