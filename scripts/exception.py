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

from engine import sweep as engine_sweep
from engine.ports import NoDelivery, NoTelemetry, Ports
from engine.sweep import _log  # noqa: F401  (re-exported; same logger and shape)
from scripts import quiet_sdk_logging
from tools.clock import SimClock
from tools.docstore import FirestoreDocStore
from tools.enrichment import EnrichmentCache
from tools.guardrail import NoGuard
from tools.store import FirestoreIdempotencyStore

REPO_ROOT = Path(__file__).resolve().parents[1]


def _ports(client, store, clock: SimClock) -> Ports:
    """The cloud parts. The exception stage reasons with no model, delivers
    nothing and remembers nothing."""
    return Ports(docs=FirestoreDocStore(client), journal=store, clock=clock,
                 roles=None, guard=NoGuard(), delivery=NoDelivery(), memory=None,
                 telemetry=NoTelemetry())


def run_sweep(
    cycle: int,
    advance_days: float = 0.0,
    clock: SimClock | None = None,
) -> dict[str, int]:
    """Reopen every risk acceptance whose TTL has lapsed, and report what it did.

    Separated from main() so the scheduled worker can call it. An acceptance
    that expires while nobody is looking is the failure this agent exists to
    prevent, which makes it exactly the work that should run on a schedule
    rather than when someone remembers.

    An already-advanced clock can be passed in. Two independently constructed
    clocks advanced by the same number of days do agree, so building a second
    one here would not corrupt anything today — but it would leave the caller
    and this function each holding a clock and no statement of which one is
    authoritative. Passing it makes the answer explicit.
    """
    if clock is None:
        clock = SimClock.from_env()
        if advance_days:
            clock.advance(seconds=advance_days * 86400)

    client = firestore.Client()
    store = FirestoreIdempotencyStore(client=client, clock=clock)
    return engine_sweep.run_sweep(_ports(client, store, clock), cycle)


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
    quiet_sdk_logging()
    load_dotenv(REPO_ROOT / ".env")

    clock = SimClock.from_env()
    if args.advance_days:
        clock.advance(seconds=args.advance_days * 86400)

    client = firestore.Client()
    store = FirestoreIdempotencyStore(client=client, clock=clock)
    cache = EnrichmentCache()

    cycle_id = f"cycle-{args.cycle:03d}"

    if args.accept:
        try:
            engine_sweep.accept(
                _ports(client, store, clock), args.accept, args.ttl, args.by,
                args.reason, args.cycle,
                approved_by_human=args.approved_by_human, enrichment=cache,
            )
        except engine_sweep.NoSuchFinding:
            print(f"no such finding: {args.accept}", file=sys.stderr)
            return 1
        except ValueError as exc:
            print(json.dumps({"refused": args.accept, "reason": str(exc)}))
            return 2

    if args.sweep:
        actions = run_sweep(cycle=args.cycle, clock=clock)
        print(json.dumps({"cycle": cycle_id, "sweep": actions}, sort_keys=True))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
