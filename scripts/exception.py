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

"""Record risk acceptances, and sweep for lapsed ones.

    ./scripts/exception.sh --cycle 10 --accept RZ-0330 --ttl 90 \
        --by own-004 --reason "Isolated pending decommission"
    ./scripts/exception.sh --cycle 11 --sweep --advance-days 95

The sweep is what makes a TTL mean anything. Without it an acceptance expires
in a field nobody reads.
"""

import argparse
import json
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dotenv import load_dotenv
from google.cloud import firestore

from tools.clock import SimClock
from tools.enrichment import EnrichmentCache
from tools.exception_store import ExceptionWriter
from tools.exceptions import Exception_, ExceptionAction, next_action
from tools.store import FirestoreIdempotencyStore

REPO_ROOT = Path(__file__).resolve().parents[1]
logger = logging.getLogger("remediation_zero.exceptions")


def _log(event: str, cycle_id: str, finding_id: str, **fields) -> None:
    logger.info(json.dumps(
        {"event": event, "cycle_id": cycle_id, "finding_id": finding_id, **fields},
        sort_keys=True, default=str))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cycle", type=int, required=True)
    parser.add_argument("--accept", help="finding id to accept")
    parser.add_argument("--ttl", type=int, help="acceptance ttl in simulated days")
    parser.add_argument("--by", default="own-001", help="who is accepting")
    parser.add_argument("--reason", default="", help="why")
    parser.add_argument("--approved-by-human", action="store_true",
                        help="a person approved this. Required for a KEV entry.")
    parser.add_argument("--sweep", action="store_true", help="reopen lapsed acceptances")
    parser.add_argument("--advance-days", type=float, default=0.0)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, stream=sys.stdout, format="%(message)s")
    for noisy in ("httpx", "google_genai", "google.auth", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    load_dotenv(REPO_ROOT / ".env")

    clock = SimClock.from_env()
    if args.advance_days:
        clock.advance(seconds=args.advance_days * 86400)

    client = firestore.Client()
    store = FirestoreIdempotencyStore(client=client, clock=clock)
    writer = ExceptionWriter(store=store, client=client, clock=clock)
    cache = EnrichmentCache()

    cycle_id = f"cycle-{args.cycle:03d}"
    stamp = clock.now()

    if args.accept:
        finding = client.collection("findings").document(args.accept).get().to_dict()
        if not finding:
            print(f"no such finding: {args.accept}", file=sys.stderr)
            return 1
        in_kev = cache.enrich(finding["cve_id"]).in_kev
        try:
            result = writer.accept(
                finding_id=args.accept, cycle=args.cycle, accepted_by=args.by,
                reason=args.reason, ttl_days=args.ttl, in_kev=in_kev,
                approved_by_human=args.approved_by_human,
            )
            _log("risk_accepted", cycle_id, args.accept, ttl_days=args.ttl,
                 in_kev=in_kev, approved_by_human=args.approved_by_human,
                 result=result)
        except ValueError as exc:
            _log("acceptance_refused", cycle_id, args.accept, in_kev=in_kev,
                 reason=str(exc), routed_to="human_queue")
            print(json.dumps({"refused": args.accept, "reason": str(exc)}))
            return 2

    if args.sweep:
        _log("sweep_started", cycle_id, "-", sim_ts=stamp.sim_ts,
             sim_ahead_days=round((stamp.sim_ts - stamp.real_ts) / 86400, 2))
        actions = {}
        for snapshot in client.collection("exceptions").stream():
            data = snapshot.to_dict()
            exception = Exception_(
                finding_id=data["finding_id"],
                accepted_by=data.get("accepted_by", "unknown"),
                reason=data.get("reason", ""),
                accepted_sim_ts=data["accepted_sim_ts"],
                ttl_days=int(data["ttl_days"]),
                reopened=bool(data.get("reopened", False)),
            )
            action = next_action(exception, stamp.sim_ts)
            actions[action.value] = actions.get(action.value, 0) + 1
            if action is ExceptionAction.REOPEN:
                result = writer.reopen(exception, cycle=args.cycle,
                                       now_sim_ts=stamp.sim_ts)
                _log("acceptance_expired", cycle_id, exception.finding_id,
                     ttl_days=exception.ttl_days,
                     accepted_by=exception.accepted_by, result=result)
        _log("sweep_finished", cycle_id, "-", actions=actions)
        print(json.dumps({"cycle": cycle_id, "sweep": actions}, sort_keys=True))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
