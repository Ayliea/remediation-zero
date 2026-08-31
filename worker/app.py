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

"""The Pub/Sub push endpoint that runs one agent on a schedule.

One image, two deployments. WORKER_AGENT selects which agent this instance
runs, and the service account it runs under is that agent's own. Running both
agents in one process would need one identity holding both agents' access,
which is the shared credential the architecture does not have.

On status codes, which are the whole contract with Pub/Sub:

    204   the tick ran, or had already run. Acknowledged, never redelivered.
    400   the message cannot be turned into a tick, ever.
    500   the tick could not be completed this time.

400 and 500 both leave the message unacknowledged, so Pub/Sub redelivers and
the dead-letter policy eventually catches it. They are distinguished because
the log has to separate a scheduler publishing nonsense from Firestore being
briefly unavailable, even though both end in the same place.

Nothing here returns 2xx on a message it did not process. A worker that
acknowledges what it could not handle has silently dropped it, and the
dead-letter queue it was supposed to reach never sees it.
"""

import json
import logging
import os
import sys

from fastapi import FastAPI, Request, Response

from scripts import quiet_sdk_logging
from scripts.chase import run_chase
from scripts.exception import run_sweep
from tools.clock import SimClock
from tools.idempotency import CompletedCall, derive_record
from tools.store import FirestoreIdempotencyStore
from tools.telemetry import cycle_id
from worker.envelope import (
    MalformedTick,
    Tick,
    cycle_for_day,
    parse_push_request,
)

logging.basicConfig(level=logging.INFO, stream=sys.stdout, format="%(message)s")
quiet_sdk_logging()
logger = logging.getLogger("remediation_zero.worker")

#: Which agent this instance is. No default: a worker that guesses its own
#: identity would run the wrong agent under the wrong service account.
AGENT = os.environ.get("WORKER_AGENT", "")

RUNNERS = {"chase": run_chase, "exception": run_sweep}

app = FastAPI(title="Remediation Zero worker")


def _log(event: str, cycle: int | None = None, **fields) -> None:
    """Emit one structured line in the same shape as every other agent's.

    cycle_id and finding_id are always present, because the convention is that
    a single finding's journey is greppable end to end. A scheduled run that
    logged its own dialect would break that trail at exactly the point where
    nobody was watching it happen.
    """
    logger.info(json.dumps(
        {
            "event": event,
            "agent": AGENT,
            "cycle_id": cycle_id(cycle),
            "finding_id": "-",  # the worker acts on the fleet, not one finding
            **({"cycle": cycle} if cycle is not None else {}),
            **fields,
        },
        sort_keys=True, default=str))


@app.get("/healthz")
def healthz() -> dict:
    """Report readiness, including whether this instance knows what it is."""
    return {"ok": AGENT in RUNNERS, "agent": AGENT}


@app.post("/tick")
async def tick(request: Request) -> Response:
    if AGENT not in RUNNERS:
        # Misconfiguration, not a bad message. Fail every delivery loudly
        # rather than acknowledging ticks this instance cannot run.
        _log("worker_misconfigured", known=sorted(RUNNERS))
        return Response(status_code=500)

    try:
        body = await request.json()
    except ValueError:
        _log("tick_malformed", reason="request body is not JSON")
        return Response(status_code=400)

    # The scheduler cannot put the date in its payload, so the cycle is derived
    # here from the clock. real_ts rather than sim_ts: a daily tick is a
    # wall-clock event, and two deliveries of one day's tick must agree even if
    # simulated time moved between them.
    try:
        parsed = parse_push_request(
            body, default_cycle=cycle_for_day(SimClock.from_env().now().real_ts)
        )
    except MalformedTick as exc:
        # 400 rather than 204. The message is unusable and will never become
        # usable, but acknowledging it here is how a tick disappears without
        # anyone deciding that it should. Let it reach the dead-letter queue.
        _log("tick_malformed", reason=str(exc))
        return Response(status_code=400)

    return _run(parsed)


def _store_for(clock: SimClock) -> FirestoreIdempotencyStore:
    """Build the idempotency store. Seam so the handler is testable."""
    from google.cloud import firestore

    return FirestoreIdempotencyStore(client=firestore.Client(), clock=clock)


def _run(parsed: Tick) -> Response:
    """Run this tick once, or recognise that it has already run."""
    record = derive_record(finding_id=f"tick-{parsed.cycle}", action=AGENT,
                           cycle=parsed.cycle)
    clock = SimClock.from_env()

    try:
        store = _store_for(clock)

        # Claim before work. Firestore creates the first lease atomically, so
        # two Cloud Run instances cannot both pass an empty read and run the
        # same tick concurrently.
        claim = store.acquire(record)
        if claim.existing is not None:
            _log("tick_already_ran", cycle=parsed.cycle, message_id=parsed.message_id)
            return Response(status_code=204)
        if not claim.acquired:
            _log("tick_in_progress", cycle=parsed.cycle,
                 message_id=parsed.message_id)
            # Keep this delivery unacknowledged. The current owner should
            # finish first; if it does not, the bounded lease can be reclaimed.
            return Response(status_code=500)

        _log("tick_started", cycle=parsed.cycle, message_id=parsed.message_id,
             advance_days=parsed.advance_days, clock_mode=clock.mode.value)

        try:
            if parsed.advance_days:
                clock.advance(seconds=parsed.advance_days * 86400)

            actions = RUNNERS[AGENT](cycle=parsed.cycle, clock=clock)
        except BaseException:
            # Nothing completed owns no permanent claim. Pub/Sub can retry the
            # same deterministic key instead of waiting for the lease timeout.
            store.abandon(claim)
            raise

        store.complete(
            claim,
            CompletedCall(
                record=record, result={"agent": AGENT, "actions": actions}
            ),
        )
        _log("tick_finished", cycle=parsed.cycle, actions=actions)
        return Response(status_code=204)

    except RuntimeError as exc:
        # advance() in real mode. A configuration error, not a transient one,
        # but still not something to acknowledge away.
        _log("tick_refused", cycle=parsed.cycle, reason=str(exc))
        return Response(status_code=400)

    except Exception as exc:  # noqa: BLE001 - deliberately broad
        # Anything else is treated as transient and retried. If it is not
        # transient, the dead-letter policy is what stops the retrying.
        _log("tick_failed", cycle=parsed.cycle, error=type(exc).__name__,
             detail=str(exc)[:300])
        return Response(status_code=500)
