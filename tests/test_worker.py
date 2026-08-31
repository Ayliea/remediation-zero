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

"""What the scheduled worker does with a Pub/Sub push.

Pub/Sub delivers at least once, so the same tick arrives twice often enough
that it has to be designed for rather than hoped about. These tests cover the
two halves of that: a redelivered tick must do nothing the second time, and a
tick that genuinely cannot be processed must fail loudly enough to reach the
dead-letter queue rather than being acknowledged away.
"""

import base64
import json

import pytest

from worker.envelope import (
    MalformedTick,
    Tick,
    cycle_for_day,
    parse_push_request,
)
from tools.idempotency import InMemoryIdempotencyStore


def push_body(payload: dict, message_id: str = "m-1") -> dict:
    """Shape a real Pub/Sub push request around a payload."""
    return {
        "subscription": "projects/p/subscriptions/chase-tick",
        "message": {
            "messageId": message_id,
            "publishTime": "2026-08-27T09:00:00Z",
            "data": base64.b64encode(json.dumps(payload).encode()).decode(),
        },
    }


# --- the happy path ---------------------------------------------------------

def test_a_well_formed_tick_parses():
    tick = parse_push_request(push_body({"cycle": 7, "advance_days": 2}))
    assert tick == Tick(cycle=7, advance_days=2.0, message_id="m-1")


def test_advance_days_defaults_to_zero_rather_than_being_required():
    """A tick that only says "run" is valid. Real mode cannot advance anyway."""
    assert parse_push_request(push_body({"cycle": 7})).advance_days == 0.0


# --- malformed input, which must never be quietly accepted ------------------
#
# Every one of these raises rather than returning a default. A worker that
# invents a cycle number for a message that did not carry one writes real
# state under a key nobody chose, and the idempotency guard is derived from
# that key.

@pytest.mark.parametrize("payload", [
    {},                                  # no cycle, and no default supplied
    {"cycle": None},
    {"cycle": "seven"},                  # not an integer
    {"cycle": -1},                       # negative
    {"cycle": True},                     # bool is a subclass of int
    {"cycle": 7, "advance_days": "two"},
    {"cycle": 7, "advance_days": -3},    # time never moves backwards
    {"cycle": 7, "advance_days": float("nan")},
    {"cycle": 7, "advance_days": float("inf")},
    {"cycle": 7, "advance_days": 366},   # bounded demo control, not a time machine
])
def test_an_unusable_payload_is_refused(payload):
    with pytest.raises(MalformedTick):
        parse_push_request(push_body(payload))


@pytest.mark.parametrize("body", [
    {},                                              # not a push request
    {"message": {}},                                 # no data
    {"message": {"data": "not-valid-base64!!"}},
    {"message": {"data": base64.b64encode(b"not json").decode()}},
    {"message": {"data": base64.b64encode(b"[1,2]").decode()}},  # not an object
])
def test_an_unusable_envelope_is_refused(body):
    with pytest.raises(MalformedTick):
        parse_push_request(body)


def test_the_message_id_is_carried_through():
    """The id is what makes a redelivery recognisable in the log."""
    assert parse_push_request(push_body({"cycle": 3}, "m-99")).message_id == "m-99"


# --- idempotency across redelivery ------------------------------------------

def test_the_same_tick_derives_the_same_key_twice():
    a = parse_push_request(push_body({"cycle": 7}, "m-1"))
    b = parse_push_request(push_body({"cycle": 7}, "m-2"))
    assert a.idempotency_key("chase") == b.idempotency_key("chase")


def test_a_redelivered_tick_keys_on_the_cycle_not_the_message_id():
    """Pub/Sub assigns a new id on some redeliveries, so keying on it would
    let the same tick run twice under two different keys."""
    a = parse_push_request(push_body({"cycle": 7}, "m-1"))
    b = parse_push_request(push_body({"cycle": 7}, "m-2"))
    assert a.message_id != b.message_id
    assert a.idempotency_key("chase") == b.idempotency_key("chase")


def test_different_cycles_derive_different_keys():
    a = parse_push_request(push_body({"cycle": 7}))
    b = parse_push_request(push_body({"cycle": 8}))
    assert a.idempotency_key("chase") != b.idempotency_key("chase")


def test_the_two_agents_never_share_a_key_for_the_same_tick():
    """One tick fans out to both workers. They must not collide."""
    tick = parse_push_request(push_body({"cycle": 7}))
    assert tick.idempotency_key("chase") != tick.idempotency_key("exception")


def test_the_key_is_opaque():
    """Same scheme as every other key in the system: a fixed-length digest.

    Asserting that the digit 7 is absent would be a broken test rather than a
    strict one — hex digests contain most digits by chance. What is actually
    checkable is the shape, and that no input survives as a readable substring.
    """
    key = parse_push_request(push_body({"cycle": 7})).idempotency_key("chase")
    assert len(key) == 64
    assert all(c in "0123456789abcdef" for c in key)
    assert "chase" not in key
    assert "tick-7" not in key


# --- the HTTP contract with Pub/Sub -----------------------------------------
#
# The status code IS the contract. 2xx acknowledges and the message is gone;
# anything else redelivers and eventually dead-letters. These tests exist
# because getting one of them backwards would silently discard a tick, and
# nothing downstream would ever report a gap.

import worker.app as worker_app
from fastapi.testclient import TestClient


class FakeStore(InMemoryIdempotencyStore):
    def __init__(self):
        super().__init__()
        self.puts = []

    def put(self, completed):
        self.puts.append(completed)
        super().put(completed)

    def complete(self, claim, completed):
        self.puts.append(completed)
        super().complete(claim, completed)


@pytest.fixture
def wired(monkeypatch):
    """A worker with the agent set and Firestore replaced."""
    store = FakeStore()
    ran = []

    monkeypatch.setattr(worker_app, "AGENT", "chase")
    monkeypatch.setattr(worker_app, "RUNNERS", {
        "chase": lambda cycle, clock=None: ran.append(cycle) or {"nudge": 1},
    })
    monkeypatch.setattr(worker_app, "_store_for",
                        lambda clock: store)
    return TestClient(worker_app.app), store, ran


def test_a_good_tick_is_acknowledged_and_runs_once(wired):
    client, store, ran = wired
    assert client.post("/tick", json=push_body({"cycle": 5})).status_code == 204
    assert ran == [5]
    assert len(store.puts) == 1


def test_a_redelivered_tick_is_acknowledged_without_running_again(wired):
    client, store, ran = wired
    client.post("/tick", json=push_body({"cycle": 5}, "m-1"))
    # Pub/Sub redelivers with a different message id.
    second = client.post("/tick", json=push_body({"cycle": 5}, "m-2"))
    assert second.status_code == 204
    assert ran == [5], "the agent ran a second time on a redelivery"
    assert len(store.puts) == 1


def test_a_malformed_tick_is_refused_rather_than_acknowledged(wired):
    """400 keeps it unacknowledged so the dead-letter policy can catch it.

    An empty payload is NOT the malformed case any more — the scheduler
    publishes one deliberately and the worker derives the cycle from the day.
    A cycle that is present but unusable still is.
    """
    client, _, ran = wired
    assert client.post("/tick", json=push_body({"cycle": "seven"})).status_code == 400
    assert client.post("/tick", json=push_body({"cycle": -1})).status_code == 400
    assert ran == []


def test_the_schedulers_empty_payload_runs(wired):
    """What Cloud Scheduler actually publishes, end to end through the handler."""
    client, _, ran = wired
    assert client.post("/tick", json=push_body({"advance_days": 0})).status_code == 204
    assert len(ran) == 1
    assert ran[0] > 1000, "the cycle should be derived from the day"


def test_a_failing_run_returns_500_so_pubsub_retries(wired, monkeypatch):
    client, _, _ = wired

    def explode(cycle, clock=None):
        raise ConnectionError("firestore unavailable")

    monkeypatch.setattr(worker_app, "RUNNERS", {"chase": explode})
    assert client.post("/tick", json=push_body({"cycle": 5})).status_code == 500


def test_an_unset_agent_never_acknowledges(monkeypatch):
    """A misconfigured worker must not eat the ticks it cannot run."""
    monkeypatch.setattr(worker_app, "AGENT", "")
    client = TestClient(worker_app.app)
    assert client.post("/tick", json=push_body({"cycle": 5})).status_code == 500
    assert client.get("/healthz").json()["ok"] is False


def test_no_failure_path_returns_a_2xx(wired, monkeypatch):
    """The one property that must hold across every refusal above."""
    client, _, _ = wired
    monkeypatch.setattr(worker_app, "RUNNERS",
                        {"chase": lambda cycle, clock=None: (_ for _ in ()).throw(
                            RuntimeError("advance() is not available in real mode"))})
    for body in [push_body({"cycle": "x"}), push_body({"cycle": -1}), push_body({"cycle": 5})]:
        assert client.post("/tick", json=body).status_code >= 400


# --- the cycle the scheduler cannot supply ----------------------------------
#
# Cloud Scheduler publishes a fixed payload. It cannot template the date in and
# keeps no counter, so a literal cycle would be the same integer every day.
# Since the cycle is half the idempotency key, the guard would then correctly
# skip every tick after the first: the schedule would stop doing anything on
# day two while still reporting success. These tests exist because that failure
# is invisible from the outside — a no-op tick and a successful tick look
# identical in the scheduler console.

DAY = 86400


def test_the_same_day_derives_the_same_cycle():
    """So a redelivery, or a second tick that day, is absorbed by the guard."""
    morning = 1787800000.0
    evening = morning + (6 * 3600)
    assert cycle_for_day(morning) == cycle_for_day(evening)


def test_consecutive_days_derive_different_cycles():
    """So tomorrow's tick is new work rather than a skip."""
    t = 1787800000.0
    assert cycle_for_day(t) != cycle_for_day(t + DAY)


def test_a_derived_cycle_cannot_collide_with_a_hand_chosen_one():
    """Manual cycles are small integers a person picked."""
    assert cycle_for_day(1787800000.0) > 1000


def test_a_payload_without_a_cycle_uses_the_supplied_default():
    tick = parse_push_request(push_body({}), default_cycle=20692)
    assert tick.cycle == 20692


def test_a_payload_with_a_cycle_overrides_the_default():
    """So a past run can be reproduced by publishing it by hand."""
    tick = parse_push_request(push_body({"cycle": 7}), default_cycle=20692)
    assert tick.cycle == 7


def test_a_bad_default_is_still_refused():
    """The default is not a way around validation."""
    with pytest.raises(MalformedTick):
        parse_push_request(push_body({}), default_cycle=-1)


def test_cycle_derivation_reads_no_clock_of_its_own():
    """Constraint 6: every time read goes through SimClock.

    cycle_for_day takes a timestamp rather than fetching one, so it cannot be
    the place the rule is quietly broken.
    """
    import inspect
    import worker.envelope as env
    source = inspect.getsource(env)
    for forbidden in ("datetime.now", "time.time", "utcnow", "date.today"):
        assert forbidden not in source
