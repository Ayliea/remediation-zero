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

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dotenv import load_dotenv
from google.cloud import firestore

from engine.ports import NoDelivery, NoTelemetry, Ports
from engine.seed import BATCH_LIMIT, seed  # noqa: F401  (BATCH_LIMIT re-exported)
from tools.clock import SimClock
from tools.docstore import FirestoreDocStore
from tools.guardrail import NoGuard
from tools.ingest import REFERENCE_COLLECTIONS

REPO_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = REPO_ROOT / "data"


def main() -> int:
    load_dotenv(REPO_ROOT / ".env")
    clock = SimClock.from_env()
    client = firestore.Client()

    print(f"clock mode: {clock.mode.value}")

    # The cloud parts. Seeding writes reference data under natural keys and
    # holds no idempotency journal, model, tracker or memory.
    ports = Ports(docs=FirestoreDocStore(client), journal=None, clock=clock,
                  roles=None, guard=NoGuard(), delivery=NoDelivery(), memory=None,
                  telemetry=NoTelemetry())
    counts = seed(ports, DATA_DIR, kinds=REFERENCE_COLLECTIONS,
                  progress=lambda kind, written: print(f"  {kind}: {written} documents"))
    total = sum(counts.values())

    print(f"\n{total} documents written. Re-running overwrites in place.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
