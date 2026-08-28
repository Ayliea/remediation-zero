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

"""The store that makes a resume survive a restart.

The in-memory store is for tests. This one is what every side-effecting tool in
the fleet actually writes through, and it had no tests of its own -- which the
repository's own rule forbids for anything carrying an idempotency key.

The failure that matters is not losing a record. It is returning None for a
call that did happen, because the guard reads None as "never ran" and does the
work a second time: a second ticket, a second nudge, a second escalation.
"""

import pytest

from tools.clock import ClockMode, SimClock
from tools.idempotency import (
    CompletedCall,
    IdempotencyGuard,
    IdempotencyRecord,
    derive_record,
)
from tools.store import COLLECTION, FirestoreIdempotencyStore


# --- the smallest Firestore that can be wrong -------------------------------

class FakeSnapshot:
    def __init__(self, data):
        self._data = data

    @property
    def exists(self):
        return self._data is not None

    def to_dict(self):
        return self._data


class FakeDoc:
    def __init__(self, docs, key):
        self._docs, self._key = docs, key

    def get(self):
        return FakeSnapshot(self._docs.get(self._key))

    def set(self, data):
        self._docs[self._key] = dict(data)


class FakeCollection:
    def __init__(self, docs, name):
        self.docs, self.name = docs, name

    def document(self, doc_id):
        return FakeDoc(self.docs, doc_id)


class FakeClient:
    def __init__(self):
        self.docs = {}
        self.collections = []

    def collection(self, name):
        self.collections.append(name)
        return FakeCollection(self.docs, name)


@pytest.fixture
def client():
    return FakeClient()


@pytest.fixture
def store(client):
    return FirestoreIdempotencyStore(
        client=client, clock=SimClock(mode=ClockMode.REAL))


def completed(result="ticket:RZ-1", finding_id="RZ-1", action="open_ticket",
              cycle=4):
    return CompletedCall(
        record=derive_record(finding_id=finding_id, action=action, cycle=cycle),
        result=result,
    )


# --- round trip -------------------------------------------------------------

def test_a_key_that_was_never_written_is_absent(store):
    """Absent must mean absent. A store that invented a record here would
    suppress work that never happened."""
    assert store.get("a-key-nothing-ever-wrote") is None


def test_a_completed_call_survives_the_round_trip(store):
    call = completed()
    store.put(call)

    back = store.get(call.key)
    assert back is not None
    assert back.result == "ticket:RZ-1"
    assert back.finding_id == "RZ-1"
    assert back.action == "open_ticket"
    assert back.cycle == 4


def test_the_document_is_keyed_by_the_idempotency_key(store, client):
    """Not by finding id. Two actions on one finding in one cycle are two
    different effects and must not share a document."""
    call = completed()
    store.put(call)

    assert call.key in client.docs
    assert "RZ-1" not in client.docs


def test_the_components_that_explain_the_key_are_stored(store, client):
    """The key is an opaque hash. Without these the record cannot be traced
    back to the finding it belongs to."""
    call = completed()
    store.put(call)

    document = client.docs[call.key]
    assert document["finding_id"] == "RZ-1"
    assert document["action"] == "open_ticket"
    assert document["cycle"] == 4
    assert document["scheme"] == call.record.scheme


def test_both_stamps_are_written(store, client):
    """Constraint 6. Every persisted record carries both."""
    call = completed()
    store.put(call)

    document = client.docs[call.key]
    assert "real_ts" in document and "sim_ts" in document


def test_it_writes_to_the_idempotency_collection(client):
    FirestoreIdempotencyStore(client=client, clock=SimClock(mode=ClockMode.REAL))
    assert client.collections == [COLLECTION]


# --- the failure that would duplicate work ----------------------------------

def test_a_call_that_returned_none_is_still_remembered_as_having_run(store):
    """The subtle one, and the expensive one to get wrong.

    A tool that returns None has still had its effect. If `get` reported that
    as "never ran", the guard would redo it every cycle: a second ticket, a
    second nudge, a second escalation, each one a real message to a real
    person. The distinction is between a missing document and a stored None,
    not between a truthy result and a falsy one.
    """
    call = completed(result=None)
    store.put(call)

    back = store.get(call.key)
    assert back is not None, "a stored None was read as never having run"
    assert back.result is None


def test_a_falsy_result_is_not_mistaken_for_absence(store):
    """Same trap, other shapes. 0, "" and [] are all things a tool can
    legitimately return."""
    for falsy in (0, "", [], False):
        call = completed(result=falsy, action=f"act-{type(falsy).__name__}")
        store.put(call)
        assert store.get(call.key) is not None


# --- through the guard, which is how it is actually used --------------------

def test_the_guard_suppresses_a_repeat_through_this_store(store):
    """The store in isolation is not the claim. The claim is that a tool
    wrapped by the guard and backed by this store runs its effect once."""
    guard = IdempotencyGuard(store)
    calls = []

    @guard.protects(action="open_ticket")
    def open_ticket(*, finding_id, cycle):
        calls.append(finding_id)
        return f"ticket:{finding_id}"

    first = open_ticket(finding_id="RZ-9", cycle=3)
    second = open_ticket(finding_id="RZ-9", cycle=3)

    assert calls == ["RZ-9"], "the effect ran twice"
    assert first == second == "ticket:RZ-9"


def test_a_new_cycle_is_not_suppressed_through_this_store(store):
    """The store must not over-suppress either. Cycle 4 is new work."""
    guard = IdempotencyGuard(store)
    calls = []

    @guard.protects(action="nudge")
    def nudge(*, finding_id, cycle):
        calls.append(cycle)
        return f"nudge:{cycle}"

    nudge(finding_id="RZ-9", cycle=3)
    nudge(finding_id="RZ-9", cycle=4)

    assert calls == [3, 4]


def test_a_restart_does_not_lose_what_was_already_done(client):
    """The whole point of this store rather than the in-memory one. A fresh
    process, a fresh guard, the same Firestore: the effect stays done."""
    clock = SimClock(mode=ClockMode.REAL)
    calls = []

    def build():
        guard = IdempotencyGuard(
            FirestoreIdempotencyStore(client=client, clock=clock))

        @guard.protects(action="escalate")
        def escalate(*, finding_id, cycle):
            calls.append(finding_id)
            return "escalated"
        return escalate

    build()(finding_id="RZ-2", cycle=7)
    build()(finding_id="RZ-2", cycle=7)   # the process restarted

    assert calls == ["RZ-2"]
