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

"""Turning a Pub/Sub push request into a tick, or refusing to.

Nothing here touches Firestore, a model, or a clock, which is what lets the
whole envelope contract be tested without any of them.

The refusals are the point. Pub/Sub delivers at least once and retries what it
cannot deliver, so a worker that accepts a malformed message has thrown it
away: there is no second chance and no record. Every unusable message raises,
the endpoint answers with a failure, and the message is redelivered until the
dead-letter policy catches it. That is the only path on which a tick the fleet
could not process ends up somewhere a person can still find it.
"""

import base64
import binascii
import json
from dataclasses import dataclass
from typing import Any, Mapping

from tools.idempotency import derive_key


class MalformedTick(ValueError):
    """This push request cannot be turned into a tick.

    Deliberately not a subclass of anything the handler catches broadly. A
    malformed message and a Firestore outage both end in a non-2xx response,
    but they are different failures and the log has to be able to tell them
    apart.
    """


@dataclass(frozen=True)
class Tick:
    """One scheduled instruction to run one agent once."""

    cycle: int
    advance_days: float
    message_id: str

    def idempotency_key(self, agent: str) -> str:
        """Key this tick's work for one agent.

        Keyed on the cycle rather than the message id. Pub/Sub may assign a new
        id when it redelivers, so a key derived from the id would let the same
        tick run twice under two different keys — which is precisely the
        duplicate the guard exists to prevent.

        The agent name is the action component, so the two subscribers to a
        single tick never collide with each other.
        """
        return derive_key(finding_id=f"tick-{self.cycle}", action=agent,
                          cycle=self.cycle)


def _require_int(payload: Mapping[str, Any], field: str) -> int:
    value = payload.get(field)
    # bool is a subclass of int, so True would otherwise mint cycle 1.
    if isinstance(value, bool) or not isinstance(value, int):
        raise MalformedTick(f"{field} must be an integer, got {value!r}")
    if value < 0:
        raise MalformedTick(f"{field} must not be negative, got {value!r}")
    return value


def _optional_float(payload: Mapping[str, Any], field: str) -> float:
    value = payload.get(field, 0)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise MalformedTick(f"{field} must be a number, got {value!r}")
    if value < 0:
        # Simulated time moves forward or not at all. Nothing in the system
        # reads a negative advance as anything, and silently clamping it to
        # zero would hide a scheduler misconfiguration.
        raise MalformedTick(f"{field} must not be negative, got {value!r}")
    return float(value)


#: Manual cycles are small integers chosen by a person. A derived cycle is
#: days-since-epoch, which is five figures and cannot collide with them.
SCHEDULED_CYCLE_FLOOR = 10_000


def cycle_for_day(real_ts: float) -> int:
    """Derive a cycle number from a wall-clock timestamp.

    Cloud Scheduler publishes a fixed payload: it cannot template the date in,
    and it keeps no counter. A literal cycle in that payload would therefore be
    the same integer every day, and since the cycle is half the idempotency
    key, the guard would correctly skip every tick after the first. The
    schedule would silently stop doing anything on day two while continuing to
    report success.

    Days since the epoch gives the two properties the key actually needs:
    stable within a day, so a redelivery is absorbed; distinct across days, so
    tomorrow's tick is new work.

    Takes the timestamp rather than reading one. Every time read in this system
    goes through SimClock, and a module that quietly called the wall clock
    would be a hole in that rule as well as untestable.
    """
    if real_ts < 0:
        raise MalformedTick(f"timestamp must not be negative, got {real_ts!r}")
    return SCHEDULED_CYCLE_FLOOR + int(real_ts // 86400)


def parse_push_request(body: Any, default_cycle: int | None = None) -> Tick:
    """Read a Pub/Sub push request, or raise MalformedTick.

    `default_cycle` is used when the payload carries none, which is how the
    scheduled path works: the scheduler publishes no cycle and the worker
    supplies one derived from the day. A payload that does name a cycle wins,
    so a person can reproduce any past run by publishing it by hand.
    """
    if not isinstance(body, Mapping):
        raise MalformedTick("request body is not an object")

    message = body.get("message")
    if not isinstance(message, Mapping):
        raise MalformedTick("no message in the push request")

    encoded = message.get("data")
    if not isinstance(encoded, str) or not encoded:
        raise MalformedTick("message carries no data")

    try:
        raw = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise MalformedTick(f"data is not valid base64: {exc}") from exc

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise MalformedTick(f"data is not valid JSON: {exc}") from exc

    if not isinstance(payload, Mapping):
        raise MalformedTick("payload is not a JSON object")

    if "cycle" not in payload and default_cycle is not None:
        cycle = _require_int({"cycle": default_cycle}, "cycle")
    else:
        cycle = _require_int(payload, "cycle")

    return Tick(
        cycle=cycle,
        advance_days=_optional_float(payload, "advance_days"),
        message_id=str(message.get("messageId", "")),
    )
