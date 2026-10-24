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

"""Run the chase agent over every open SLA clock.

    ./scripts/chase.sh --cycle 4 --advance-days 8

`--advance-days` moves simulated time forward by that many days from now. It
does not move `real_ts`, which is read from the wall clock on every write and
is never adjusted to match. That is the entire point of carrying both stamps:
a six-week remediation lifecycle can be demonstrated in three minutes, and the
record shows honestly that three minutes is what actually elapsed.

Advancing requires SIM_CLOCK_MODE=sim. In real mode SimClock refuses, because
in real mode there is no supported way to move time at all.
"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dotenv import load_dotenv
from google.cloud import firestore

from engine import chase as engine_chase
from engine.chase import _log  # noqa: F401  (re-exported; same logger and shape)
from engine.ports import NoDelivery, NoTelemetry, Ports
from scripts import quiet_sdk_logging
from tools.clock import SimClock
from tools.docstore import FirestoreDocStore
from tools.guardrail import NoGuard
from tools.store import FirestoreIdempotencyStore
from tools.delivery import GitHubDelivery
from tools.github_tickets import GitHubTickets, GitHubUnavailable

REPO_ROOT = Path(__file__).resolve().parents[1]


def run_chase(
    cycle: int,
    advance_days: float = 0.0,
    clock: SimClock | None = None,
) -> dict[str, int]:
    """Run the chase agent over every SLA clock once, and report what it did.

    Separated from main() so the scheduled worker can call it. The worker
    receives a Pub/Sub push rather than a command line, but it must do exactly
    what the command does — a scheduled path that quietly diverges from the one
    a person can run is a path nobody has actually tested.

    Takes the same optional pre-advanced clock as run_sweep, so the worker can
    hold both runners behind one signature rather than special-casing which
    agent it is about to call.
    """
    if clock is None:
        clock = SimClock.from_env()
        if advance_days:
            # Raises in real mode. Deliberately: the elapsed-time claim depends
            # on there being no way to move time when the clock says it is real.
            clock.advance(seconds=advance_days * 86400)

    client = firestore.Client()
    store = FirestoreIdempotencyStore(client=client, clock=clock)
    cycle_id = f"cycle-{cycle:03d}"

    # Delivery is optional and its absence is stated rather than silent. The
    # fleet's decisions are identical either way — what changes is whether the
    # accountable person ever sees them.
    delivery = None
    repo = os.environ.get("GITHUB_TICKET_REPO", "").strip()
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if repo and token:
        try:
            delivery = GitHubDelivery(
                GitHubTickets(repo=repo, token=token), client=client)
            _log("delivery_enabled", cycle_id, "-", tracker=repo)
        except GitHubUnavailable as exc:
            _log("delivery_unavailable", cycle_id, "-", reason=str(exc)[:160])
    else:
        _log("delivery_disabled", cycle_id, "-",
             reason="GITHUB_TICKET_REPO and GITHUB_TOKEN are not both set")

    # The cloud parts. Chase is the only stage handed a tracker: GitHub when
    # it is configured and reachable, otherwise NoDelivery, which the stage
    # treats as no delivery at all, exactly as before.
    ports = Ports(
        docs=FirestoreDocStore(client),
        journal=store,
        clock=clock,
        roles=None,
        guard=NoGuard(),
        delivery=delivery if delivery is not None else NoDelivery(),
        memory=None,  # chase neither remembers nor recalls
        telemetry=NoTelemetry(),
    )
    return engine_chase.run_chase(ports, cycle, advance_days=advance_days)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cycle", type=int, required=True)
    parser.add_argument("--advance-days", type=float, default=0.0,
                        help="move simulated time forward. Requires SIM_CLOCK_MODE=sim.")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, stream=sys.stdout, format="%(message)s")
    quiet_sdk_logging()
    load_dotenv(REPO_ROOT / ".env")

    taken = run_chase(cycle=args.cycle, advance_days=args.advance_days)
    print(json.dumps({"cycle": f"cycle-{args.cycle:03d}", "actions": taken},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
