#!/usr/bin/env python3
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

"""Apply a follow-up scan to what the fleet is already chasing.

    ./scripts/rescan.sh --cycle 12
    ./scripts/rescan.sh --cycle 12 --dry-run

This is the only path that can mark a finding resolved, and therefore the only
thing that can ever stop a chase for a good reason rather than by escalating
it to a person. Everything it concludes it concludes from two inputs: what the
scan reported, and which assets the scan actually examined.

`--dry-run` reconciles and prints, and writes nothing. Run it first. The
summary it prints is the same summary the real run produces, so the closures
can be read before they happen rather than audited after.

`--cycle` is required and has no default. It is half of every idempotency key
written here, so a default would let two different runs share keys and let the
second silently do nothing.
"""

import argparse
import json
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dotenv import load_dotenv
from google.cloud import firestore

from engine import rescan as engine_rescan
from engine.ports import NoDelivery, NoTelemetry, Ports
from engine.rescan import _log, load_scan  # noqa: F401  (re-exported)
from scripts import quiet_sdk_logging
from tools.clock import SimClock
from tools.docstore import FirestoreDocStore
from tools.guardrail import NoGuard
from tools.store import FirestoreIdempotencyStore

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SCAN = REPO_ROOT / "data" / "rescan-01.json"


def run_rescan(cycle: int, scan_path: Path, dry_run: bool) -> dict:
    scan = load_scan(scan_path)

    client = firestore.Client()
    clock = SimClock.from_env()

    # The cloud parts. A dry run is given no journal: it writes nothing, so
    # it has no idempotency store to build.
    ports = Ports(
        docs=FirestoreDocStore(client),
        journal=None if dry_run else FirestoreIdempotencyStore(client=client, clock=clock),
        clock=clock, roles=None, guard=NoGuard(), delivery=NoDelivery(),
        memory=None, telemetry=NoTelemetry(),
    )
    return engine_rescan.run_rescan(ports, cycle, scan, dry_run)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cycle", type=int, required=True)
    parser.add_argument("--file", type=Path, default=DEFAULT_SCAN,
                        help="the scan to apply. Defaults to data/rescan-01.json.")
    parser.add_argument("--dry-run", action="store_true",
                        help="reconcile and print; write nothing.")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, stream=sys.stdout, format="%(message)s")
    quiet_sdk_logging()
    load_dotenv(REPO_ROOT / ".env")

    if args.cycle < 0:
        print("--cycle must not be negative", file=sys.stderr)
        return 2

    result = run_rescan(cycle=args.cycle, scan_path=args.file,
                        dry_run=args.dry_run)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
