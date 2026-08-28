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

"""Assignment, and the clock it starts.

Two things happen here that nothing else in the fleet does: a finding acquires
an accountable human, and its deadline begins. Both are load-bearing for
everything downstream -- chase paces its nudges against `due_sim_ts`, and a
finding with no owner is one the fleet cannot chase at all.
"""

import pytest

from tools.assignments import (
    COLLECTION,
    HUMAN_QUEUE,
    SLA_COLLECTION,
    AssignmentWriter,
)
from tools.clock import ClockMode, SimClock
from tools.idempotency import InMemoryIdempotencyStore
from tools.ownership import Assignment

DAY = 86400


class FakeDoc:
    def __init__(self, docs, key, log):
        self._docs, self._key, self._log = docs, key, log

    def set(self, data):
        self._log.append(self._key)
        self._docs[self._key] = dict(data)


class FakeCollection:
    def __init__(self, docs, name, log):
        self._docs, self._name, self._log = docs, name, log

    def document(self, doc_id):
        return FakeDoc(self._docs, (self._name, doc_id), self._log)


class FakeClient:
    def __init__(self):
        self.docs, self.writes = {}, []

    def collection(self, name):
        return FakeCollection(self.docs, name, self.writes)


OWNED = Assignment(finding_id="RZ-1", asset_id="ast-01", owner_id="own-1",
                   owner_email="dev@example.invalid", owner_name="Dev Garrow",
                   team="platform")

UNOWNED = Assignment(finding_id="RZ-2", asset_id="ast-99", needs_human=True,
                     reason="No owner is recorded for ast-99.")


@pytest.fixture
def client():
    return FakeClient()


@pytest.fixture
def writer(client):
    return AssignmentWriter(store=InMemoryIdempotencyStore(), client=client,
                            clock=SimClock(mode=ClockMode.REAL))


# --- the assignment ---------------------------------------------------------

def test_an_owned_finding_records_who_is_accountable(writer, client):
    writer.record(OWNED, cycle=3, sla_days=7)

    document = client.docs[(COLLECTION, "RZ-1-c003")]
    assert document["owner_id"] == "own-1"
    assert document["owner_email"] == "dev@example.invalid"
    assert document["needs_human"] is False


def test_an_unowned_finding_goes_to_a_person_with_its_reason(writer, client):
    """A dangling owner reference is worse than none, because it looks
    resolved. The queue entry has to say what is actually missing."""
    writer.record(UNOWNED, cycle=3, sla_days=7)

    entry = client.docs[(HUMAN_QUEUE, "unassigned-RZ-2-c003")]
    assert entry["kind"] == "unassigned"
    assert "ast-99" in entry["reason"]


# --- the clock --------------------------------------------------------------

def test_the_deadline_is_set_in_simulated_time(writer, client):
    """chase compares against due_sim_ts, so an accelerated demonstration has
    to move the deadline with it."""
    writer.record(OWNED, cycle=3, sla_days=7)

    clock = client.docs[(SLA_COLLECTION, "RZ-1")]
    assert clock["due_sim_ts"] == clock["started_sim_ts"] + 7 * DAY
    assert clock["sla_days"] == 7
    assert clock["status"] == "open"


def test_the_real_start_is_recorded_and_is_not_the_simulated_one(writer, client):
    """started_real_ts is wall clock and is never adjusted to match the
    scenario. It is the evidence the elapsed-time claim rests on."""
    writer.record(OWNED, cycle=3, sla_days=7)

    clock = client.docs[(SLA_COLLECTION, "RZ-1")]
    assert "started_real_ts" in clock
    assert clock["due_sim_ts"] != clock["started_real_ts"]


def test_a_finding_that_needs_a_person_starts_no_clock(writer, client):
    """Counting a deadline against nobody produces a breach that no owner can
    answer for, and it would show up in the report as a missed SLA."""
    writer.record(UNOWNED, cycle=3, sla_days=7)

    assert (SLA_COLLECTION, "RZ-2") not in client.docs


def test_no_sla_days_starts_no_clock(writer, client):
    """Triage may not have produced an SLA. A default here would invent a
    deadline nobody decided."""
    writer.record(OWNED, cycle=3, sla_days=None)

    assert (SLA_COLLECTION, "RZ-1") not in client.docs
    assert (COLLECTION, "RZ-1-c003") in client.docs


# --- once -------------------------------------------------------------------

def test_recording_the_same_assignment_twice_writes_once(writer, client):
    writer.record(OWNED, cycle=3, sla_days=7)
    writes = len(client.writes)
    writer.record(OWNED, cycle=3, sla_days=7)
    assert len(client.writes) == writes


def test_a_repeat_does_not_restart_the_clock(writer, client):
    """The dangerous half. Restarting the clock would silently extend every
    deadline the fleet is chasing, and nothing downstream would look wrong."""
    writer.record(OWNED, cycle=3, sla_days=7)
    first_due = client.docs[(SLA_COLLECTION, "RZ-1")]["due_sim_ts"]

    writer.record(OWNED, cycle=3, sla_days=7)

    assert client.docs[(SLA_COLLECTION, "RZ-1")]["due_sim_ts"] == first_due
