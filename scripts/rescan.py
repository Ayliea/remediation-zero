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

from scripts import quiet_sdk_logging
from tools.clock import SimClock
from tools.rescan import Outcome, reconcile
from tools.scan_store import ScanWriter
from tools.store import FirestoreIdempotencyStore

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SCAN = REPO_ROOT / "data" / "rescan-01.json"

logger = logging.getLogger("remediation_zero.rescan")


def _log(event: str, cycle_id: str, finding_id: str, **fields) -> None:
    logger.info(json.dumps(
        {"event": event, "cycle_id": cycle_id, "finding_id": finding_id, **fields},
        sort_keys=True, default=str))


def load_scan(path: Path) -> dict:
    """Read a scan file, refusing one that cannot support a closure.

    A scan missing its coverage manifest is the dangerous shape: reconcile
    would read the absent key as an empty set, resolve nothing, and report
    success. That is the safe direction, but it is a silent no-op dressed as a
    clean run, and the next person concludes the fleet found nothing to close.
    """
    scan = json.loads(path.read_text(encoding="utf-8"))

    for key in ("scan_id", "covered_asset_ids", "findings"):
        if key not in scan:
            raise ValueError(f"{path.name} has no '{key}'. A scan without one "
                             f"cannot justify a closure.")
    return scan


def run_rescan(cycle: int, scan_path: Path, dry_run: bool) -> dict:
    cycle_id = f"cycle-{cycle:03d}"
    scan = load_scan(scan_path)

    client = firestore.Client()
    clock = SimClock.from_env()

    previous = [doc.to_dict() for doc in client.collection("findings").stream()]
    _log("rescan_started", cycle_id, "-", scan_id=scan["scan_id"],
         previous_findings=len(previous), reported=len(scan["findings"]),
         covered_assets=len(scan["covered_asset_ids"]), dry_run=dry_run)

    reconciliation = reconcile(
        previous=previous,
        scan=scan["findings"],
        covered_asset_ids=scan["covered_asset_ids"],
        scan_id=scan["scan_id"],
    )

    counts = reconciliation.counts

    if dry_run:
        for item in reconciliation.of(Outcome.RESOLVED)[:5]:
            _log("would_resolve", cycle_id, item.finding_id,
                 asset_id=item.asset_id, reason=item.reason)
        for item in reconciliation.of(Outcome.UNVERIFIABLE)[:5]:
            _log("would_leave_open", cycle_id, item.finding_id,
                 asset_id=item.asset_id, reason=item.reason)
        _log("rescan_dry_run", cycle_id, "-", scan_id=scan["scan_id"],
             counts=counts)
        return {"cycle": cycle_id, "scan_id": scan["scan_id"],
                "counts": counts, "written": False}

    writer = ScanWriter(
        store=FirestoreIdempotencyStore(client=client, clock=clock),
        client=client,
        clock=clock,
    )

    # The manifest first. A run that dies after this leaves coverage evidence
    # with fewer closures than it warrants, which re-running repairs. The
    # reverse leaves closures whose evidence was never stored, and nothing
    # remaining records what the scan actually looked at.
    writer.record_scan(reconciliation, cycle=cycle)
    resolved = writer.resolve(reconciliation, cycle=cycle)
    reopened = writer.reopen(reconciliation, cycle=cycle)
    added = writer.ingest_new(reconciliation, scan["findings"], cycle=cycle)

    _log("rescan_finished", cycle_id, "-", scan_id=scan["scan_id"],
         counts=counts, newly_resolved=resolved, newly_reopened=reopened,
         newly_ingested=added)

    return {"cycle": cycle_id, "scan_id": scan["scan_id"], "counts": counts,
            "newly_resolved": resolved, "newly_reopened": reopened,
            "newly_ingested": added, "written": True}


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
