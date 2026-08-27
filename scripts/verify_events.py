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

"""Prove the dead-letter queue by sending it something.

A dead-letter queue that has never caught anything is a configuration line, not
a control. Worse, the two ways it commonly fails are both silent: if the
Pub/Sub service agent lacks publisher on the dead-letter topic, the
subscription retries forever and the queue stays empty — which looks identical
to a queue that is empty because nothing has failed.

So this publishes a message the worker genuinely cannot process, waits for the
delivery attempts to be exhausted, and reads it back out of the dead-letter
subscription. Same three outcomes as verify-controls: a check that could not
run is inconclusive and exits non-zero, because "could not run" is not "passed".

    ./scripts/verify-events.sh
"""

import argparse
import base64
import json
import subprocess
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(REPO_ROOT / ".env")

import os  # noqa: E402

PROJECT = os.environ["GOOGLE_CLOUD_PROJECT"]
TOPIC = "remediation-tick"
DEAD_LETTER_SUB = "remediation-tick-dead-hold"

#: One tick fans out to one subscription per agent, and each dead-letters
#: independently, so a single published message becomes this many entries in
#: the queue. They do not arrive together: the two subscriptions exhaust their
#: delivery attempts seconds apart, so a check that stops at the first copy
#: leaves the second behind and slowly fills the queue it is verifying.
EXPECTED_COPIES = 2

#: How long to keep draining after the first copy shows up.
DRAIN_GRACE_SECONDS = 120

GREEN, RED, AMBER, DIM, RESET = (
    "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m")


def gcloud(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["gcloud", *args, "--project", PROJECT],
                          capture_output=True, text=True, check=False)


def _drain_remaining_copies(marker: str, already: int) -> int:
    """Acknowledge this run's other dead-letter copies as they arrive.

    Without this the check leaves its own test message in the queue every time
    it runs, which is a slow way to make a dead-letter queue meaningless: the
    next person to look at it finds it full of poison this script published.
    """
    drained = 0
    deadline = time.time() + DRAIN_GRACE_SECONDS

    while drained + already < EXPECTED_COPIES and time.time() < deadline:
        time.sleep(10)
        pulled = gcloud("pubsub", "subscriptions", "pull", DEAD_LETTER_SUB,
                        "--limit", "20", "--format", "json")
        if pulled.returncode != 0:
            break

        ack_ids = []
        for entry in json.loads(pulled.stdout or "[]"):
            encoded = entry.get("message", {}).get("data", "") or ""
            try:
                body = base64.b64decode(encoded).decode("utf-8", "replace")
            except (ValueError, TypeError):
                continue
            if marker in body and entry.get("ackId"):
                ack_ids.append(entry["ackId"])

        if ack_ids:
            gcloud("pubsub", "subscriptions", "ack", DEAD_LETTER_SUB,
                   "--ack-ids", ",".join(ack_ids))
            drained += len(ack_ids)

    return drained


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=int, default=420,
                        help="seconds to wait for the dead-letter to arrive")
    parser.add_argument("--marker", required=True,
                        help="unique tag for this run's poison message")
    args = parser.parse_args()

    print("\nRemediation Zero — event verification")
    print("The dead-letter queue is proved by sending it something.\n")

    # A cycle that is a string can never become a valid tick, so the worker
    # answers 400 on every delivery. It refuses rather than acknowledging,
    # which is the behaviour that lets the message reach the queue at all.
    poison = json.dumps({"cycle": f"poison-{args.marker}"})

    published = gcloud("pubsub", "topics", "publish", TOPIC, "--message", poison)
    if published.returncode != 0:
        print(f"  [{AMBER}INCONCLUSIVE{RESET}] could not publish to {TOPIC}")
        print(f"         {DIM}{published.stderr.strip()[:200]}{RESET}")
        return 1
    print(f"  published a message the worker cannot process")
    print(f"  {DIM}{poison}{RESET}\n")

    deadline = time.time() + args.timeout
    attempt = 0
    while time.time() < deadline:
        attempt += 1
        # Deliberately not --auto-ack. The first version of this script pulled
        # with auto-ack and matched the marker against the raw entry, but
        # Pub/Sub message data is base64, so the marker never matched and every
        # message pulled — including the one being looked for — was acknowledged
        # and discarded. The check reported FAIL against infrastructure that was
        # working. A verification that destroys its own evidence is worse than
        # no verification, because it produces a confident wrong answer.
        pulled = gcloud("pubsub", "subscriptions", "pull", DEAD_LETTER_SUB,
                        "--limit", "20", "--format", "json")
        if pulled.returncode != 0:
            print(f"  [{AMBER}INCONCLUSIVE{RESET}] could not pull {DEAD_LETTER_SUB}")
            print(f"         {DIM}{pulled.stderr.strip()[:200]}{RESET}")
            return 1

        # Every copy, not the first one. The tick fans out to two
        # subscriptions and each dead-letters independently, so one published
        # message becomes two entries here. An earlier version acknowledged
        # only the first match and left the other behind, so every run of this
        # check quietly added a message to the queue it was verifying.
        mine = []
        for entry in json.loads(pulled.stdout or "[]"):
            encoded = entry.get("message", {}).get("data", "") or ""
            try:
                body = base64.b64decode(encoded).decode("utf-8", "replace")
            except (ValueError, TypeError):
                body = str(encoded)
            if args.marker in body and entry.get("ackId"):
                mine.append(entry["ackId"])

        if mine:
            # Acknowledge only this run's own poison. Anything else in here is
            # a real failure a person still needs to find.
            gcloud("pubsub", "subscriptions", "ack", DEAD_LETTER_SUB,
                   "--ack-ids", ",".join(mine))
            waited = int(args.timeout - (deadline - time.time()))
            found = len(mine) + _drain_remaining_copies(args.marker, len(mine))

            print(f"  [{GREEN}PASS{RESET}] The dead-letter queue caught it")
            print(f"         {DIM}{found} of {EXPECTED_COPIES} expected copies, "
                  f"first after ~{waited}s and {attempt} poll(s), in "
                  f"{DEAD_LETTER_SUB}. One per subscription: each "
                  f"dead-letters independently.{RESET}")
            if found < EXPECTED_COPIES:
                # Not a failure of the control, but say it rather than leaving
                # the reader to assume the queue is empty afterwards.
                print(f"         {AMBER}{EXPECTED_COPIES - found} copy/copies "
                      f"had not arrived within {DRAIN_GRACE_SECONDS}s and "
                      f"remain in the queue.{RESET}")
            print(f"\n{GREEN}The queue holds what the fleet could not "
                  f"process.{RESET}")
            return 0

        remaining = int(deadline - time.time())
        print(f"  {DIM}not yet — {remaining}s left{RESET}", flush=True)
        time.sleep(20)

    print(f"  [{RED}FAIL{RESET}] nothing reached {DEAD_LETTER_SUB} in "
          f"{args.timeout}s")
    print(f"\n{RED}A message the worker refused did not reach the queue. "
          f"Check that the Pub/Sub service agent holds publisher on the "
          f"dead-letter topic.{RESET}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
