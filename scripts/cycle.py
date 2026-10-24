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

"""Run one remediation cycle.

Reads findings from Firestore, enriches them from the local cache, puts each
through triage and adversarial review, and records the adjudication. The
lifecycle itself is `engine.triage_cycle`; this script supplies the cloud parts.

Safe to re-run. Every decision write is keyed on the finding, the action and
the cycle number, so running the same cycle twice produces the same decisions
rather than a second copy of each.
"""

import argparse
import json
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dotenv import load_dotenv
from google.cloud import firestore

from engine.ports import NoDelivery, NoTelemetry, Ports
from engine.triage_cycle import _log, run_triage_cycle  # noqa: F401  (_log re-exported)
from scripts import quiet_sdk_logging
from tools import review_models as rm
from tools.model_roles import ModelRoles
from tools.clock import SimClock
from tools.docstore import FirestoreDocStore
from tools.fleet_memory import FleetMemory
from tools.enrichment import EnrichmentCache
from tools.guardrail import ModelArmorGuard
from tools.model_armor import ModelArmor
from tools.store import FirestoreIdempotencyStore

REPO_ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cycle", type=int, required=True, help="cycle number")
    parser.add_argument("--limit", type=int, default=5, help="findings this cycle")
    parser.add_argument("--start", type=int, default=1, help="first finding index")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, stream=sys.stdout, format="%(message)s")
    quiet_sdk_logging()
    load_dotenv(REPO_ROOT / ".env")

    import os

    clock = SimClock.from_env()
    client = firestore.Client()
    cache = EnrichmentCache()
    genai_client = rm._client()
    roles = ModelRoles.from_env(os.environ)

    armor = ModelArmor()
    import subprocess
    armor_token = subprocess.run(
        ["gcloud", "auth", "application-default", "print-access-token"],
        capture_output=True, text=True, check=False).stdout.strip()

    # The cloud parts. The stage builds its writers over these, so every
    # decision and assignment key is exactly what it was. This path emits no
    # spans and delivers nothing; delivery belongs to chase.
    ports = Ports(
        docs=FirestoreDocStore(client),
        journal=FirestoreIdempotencyStore(client=client, clock=clock),
        clock=clock,
        roles=roles,
        guard=ModelArmorGuard(armor, lambda: armor_token),
        delivery=NoDelivery(),
        memory=FleetMemory(),
        telemetry=NoTelemetry(),
    )

    finding_ids = [f"RZ-{i:04d}" for i in range(args.start, args.start + args.limit)]
    record = run_triage_cycle(ports, args.cycle, finding_ids=finding_ids,
                              enrichment=cache, vertex_client=genai_client)
    print(json.dumps({"cycle": record["cycle_id"], "outcomes": record["outcomes"]},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
