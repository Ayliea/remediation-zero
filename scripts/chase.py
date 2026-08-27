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
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dotenv import load_dotenv
from google.cloud import firestore

from tools.chase import ChaseAction, ChaseState, next_action
from tools.clock import SimClock
from tools.store import FirestoreIdempotencyStore
from tools.tickets import TicketWriter

REPO_ROOT = Path(__file__).resolve().parents[1]
logger = logging.getLogger("remediation_zero.chase")


def _log(event: str, cycle_id: str, finding_id: str, **fields) -> None:
    logger.info(json.dumps(
        {"event": event, "cycle_id": cycle_id, "finding_id": finding_id, **fields},
        sort_keys=True, default=str))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cycle", type=int, required=True)
    parser.add_argument("--advance-days", type=float, default=0.0,
                        help="move simulated time forward. Requires SIM_CLOCK_MODE=sim.")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, stream=sys.stdout, format="%(message)s")
    for noisy in ("httpx", "google_genai", "google.auth", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    load_dotenv(REPO_ROOT / ".env")

    clock = SimClock.from_env()
    if args.advance_days:
        # Raises in real mode. Deliberately: the elapsed-time claim depends on
        # there being no way to move time when the clock says it is real.
        clock.advance(seconds=args.advance_days * 86400)

    client = firestore.Client()
    store = FirestoreIdempotencyStore(client=client, clock=clock)
    writer = TicketWriter(store=store, client=client, clock=clock)

    cycle_id = f"cycle-{args.cycle:03d}"
    stamp = clock.now()
    _log("chase_started", cycle_id, "-", clock_mode=clock.mode.value,
         advanced_days=args.advance_days,
         real_ts=stamp.real_ts, sim_ts=stamp.sim_ts,
         sim_ahead_days=round((stamp.sim_ts - stamp.real_ts) / 86400, 2))

    owners = {o["owner_id"]: o for o in
              (d.to_dict() for d in client.collection("owners").stream())}
    tickets = {t["finding_id"]: t for t in
               (d.to_dict() for d in client.collection("tickets").stream())}
    # An accepted risk is not chased. Nudging an owner who has been told to
    # stand down destroys the credibility of every other nudge.
    accepted = {
        e["finding_id"]
        for e in (d.to_dict() for d in client.collection("exceptions").stream())
        if e.get("status") == "active" and e.get("expires_sim_ts", 0) > 0
    }

    taken: dict[str, int] = {}

    for snapshot in client.collection(SLA := "sla_clocks").stream():
        sla = snapshot.to_dict()
        finding_id = sla["finding_id"]
        if finding_id in accepted and sla.get("expires_check", True):
            _log("skipped_accepted", cycle_id, finding_id,
                 reason="risk acceptance is active")
            taken["skipped_accepted"] = taken.get("skipped_accepted", 0) + 1
            continue
        ticket = tickets.get(finding_id, {})

        state = ChaseState(
            finding_id=finding_id,
            started_sim_ts=sla["started_sim_ts"],
            due_sim_ts=sla["due_sim_ts"],
            ticket_open=bool(ticket),
            nudges_sent=int(ticket.get("nudges_sent", 0)),
            last_contact_sim_ts=ticket.get("last_contact_sim_ts"),
            escalated=bool(ticket.get("escalated", False)),
            resolved=ticket.get("status") == "resolved",
        )

        action = next_action(state, now_sim_ts=stamp.sim_ts)
        owner = owners.get(sla.get("owner_id"), {})
        result = writer.act(action, state, cycle=args.cycle, owner=owner,
                            now_sim_ts=stamp.sim_ts)

        taken[action.value] = taken.get(action.value, 0) + 1
        _log("chase_action", cycle_id, finding_id, action=action.value,
             nudges_sent=state.nudges_sent, escalated=state.escalated,
             days_overdue=round(state.days_overdue(stamp.sim_ts), 1),
             owner_id=sla.get("owner_id"), result=result)

    _log("chase_finished", cycle_id, "-", actions=taken)
    print(json.dumps({"cycle": cycle_id, "actions": taken}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
