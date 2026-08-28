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

"""Chase's side effects, and the guarantee that each happens once.

This is the largest side-effecting surface in the fleet and it had no tests.
Every action here reaches a real person -- a ticket filed, a nudge sent, an
escalation raised -- so a repeat is not a wasted write, it is a second message
to someone who already got the first one.
"""

import pytest

from tools.chase import ChaseAction, ChaseState
from tools.clock import ClockMode, SimClock
from tools.idempotency import InMemoryIdempotencyStore
from tools.tickets import COLLECTION, HUMAN_QUEUE, SLA_COLLECTION, TicketWriter

DAY = 86400
OWNER = {"owner_id": "own-1", "email": "dev@example.invalid",
         "display_name": "Dev Garrow"}


# --- a Firestore that records what was asked of it --------------------------

class FakeDoc:
    def __init__(self, docs, key, log):
        self._docs, self._key, self._log = docs, key, log

    def set(self, data):
        self._log.append(("set", self._key))
        self._docs[self._key] = dict(data)

    def update(self, data):
        self._log.append(("update", self._key))
        self._docs.setdefault(self._key, {}).update(data)


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


class RecordingDelivery:
    def __init__(self, number=None, raises=None):
        self.events, self._number, self._raises = [], number, raises

    def deliver(self, event, finding_id, **fields):
        self.events.append(event)
        if self._raises:
            raise self._raises
        return self._number


@pytest.fixture
def client():
    return FakeClient()


@pytest.fixture
def writer(client):
    return TicketWriter(store=InMemoryIdempotencyStore(), client=client,
                        clock=SimClock(mode=ClockMode.REAL))


def state(**over):
    base = dict(finding_id="RZ-1", started_sim_ts=1000 * DAY,
                due_sim_ts=1007 * DAY, ticket_open=False)
    base.update(over)
    return ChaseState(**base)


def act(writer, action, st=None, cycle=5, now=1001 * DAY):
    return writer.act(action, st or state(), cycle=cycle, owner=OWNER,
                      now_sim_ts=now)


# --- opening ----------------------------------------------------------------

def test_opening_a_ticket_records_the_owner_and_the_deadline(writer, client):
    act(writer, ChaseAction.OPEN_TICKET)

    ticket = client.docs[(COLLECTION, "RZ-1")]
    assert ticket["status"] == "open"
    assert ticket["owner_id"] == "own-1"
    assert ticket["nudges_sent"] == 0
    assert ticket["escalated"] is False
    assert ticket["opened_cycle"] == 5


def test_every_write_carries_both_stamps(writer, client):
    act(writer, ChaseAction.OPEN_TICKET)
    ticket = client.docs[(COLLECTION, "RZ-1")]
    assert "opened_real_ts" in ticket and "opened_sim_ts" in ticket
    assert ticket["history"][0]["real_ts"] and ticket["history"][0]["sim_ts"]


# --- the actions that do nothing --------------------------------------------

def test_wait_writes_nothing(writer, client):
    assert act(writer, ChaseAction.WAIT) is None
    assert client.writes == []


def test_done_writes_nothing(writer, client):
    """DONE is reached only after CLOSE_TICKET has already run. Writing again
    would re-close a finished ticket on every subsequent cycle."""
    assert act(writer, ChaseAction.DONE) is None
    assert client.writes == []


# --- once, and only once ----------------------------------------------------

@pytest.mark.parametrize("action", [
    ChaseAction.OPEN_TICKET, ChaseAction.NUDGE, ChaseAction.ESCALATE,
    ChaseAction.CLOSE_TICKET, ChaseAction.HUMAN_QUEUE,
])
def test_repeating_an_action_in_one_cycle_has_no_second_effect(writer, client, action):
    """Constraint 5, on every action that reaches a person."""
    st = state(ticket_open=True)
    act(writer, action, st)
    writes_after_first = len(client.writes)

    act(writer, action, st)

    assert len(client.writes) == writes_after_first, f"{action.value} ran twice"


@pytest.mark.parametrize("action", [
    ChaseAction.OPEN_TICKET, ChaseAction.NUDGE, ChaseAction.ESCALATE,
])
def test_a_later_cycle_is_not_suppressed(writer, client, action):
    """Over-suppression is the invisible failure: a nudge that never sends."""
    st = state(ticket_open=True)
    act(writer, action, st, cycle=5)
    writes = len(client.writes)

    act(writer, action, st, cycle=6)

    assert len(client.writes) > writes, f"{action.value} was wrongly suppressed"


def test_two_actions_in_one_cycle_do_not_share_a_key(writer, client):
    """The key is derived from the action as well as the finding and cycle. A
    nudge must not be suppressed because an escalation already ran."""
    st = state(ticket_open=True)
    act(writer, ChaseAction.NUDGE, st)
    writes = len(client.writes)

    act(writer, ChaseAction.ESCALATE, st)

    assert len(client.writes) > writes


# --- escalation reaches beyond the ticket -----------------------------------

def test_escalation_marks_the_sla_clock_breached(writer, client):
    act(writer, ChaseAction.ESCALATE, state(ticket_open=True))

    assert client.docs[(COLLECTION, "RZ-1")]["status"] == "escalated"
    assert client.docs[(SLA_COLLECTION, "RZ-1")]["status"] == "breached"


def test_the_human_queue_entry_says_why_a_person_is_needed(writer, client):
    act(writer, ChaseAction.HUMAN_QUEUE, state(ticket_open=True),
        now=1020 * DAY)

    entry = client.docs[(HUMAN_QUEUE, "unresolved-RZ-1")]
    assert entry["kind"] == "escalated_unresolved"
    assert "past the SLA" in entry["reason"]
    assert entry["owner_id"] == "own-1"


# --- closing ----------------------------------------------------------------

def test_closing_keeps_the_history_rather_than_deleting_the_ticket(writer, client):
    """What the fleet did about a finding stays readable after the finding
    stops being a problem. That is the difference between an auditable
    closure and a tidy one."""
    st = state(ticket_open=True)
    act(writer, ChaseAction.OPEN_TICKET, st)
    act(writer, ChaseAction.CLOSE_TICKET, st)

    ticket = client.docs[(COLLECTION, "RZ-1")]
    assert ticket["status"] == "resolved"
    assert ticket["resolved_cycle"] == 5
    assert ticket["opened_cycle"] == 5, "the opening record was discarded"


def test_closing_records_the_scan_that_justified_it(writer, client):
    st = ChaseState(finding_id="RZ-1", started_sim_ts=1000 * DAY,
                    due_sim_ts=1007 * DAY, ticket_open=True,
                    resolved=True, resolved_by_scan="rescan-01")
    act(writer, ChaseAction.CLOSE_TICKET, st)

    assert client.docs[(COLLECTION, "RZ-1")]["resolved_by_scan"] == "rescan-01"


# --- delivery is a delivery, not the record ---------------------------------

def test_a_tracker_failure_does_not_fail_the_cycle(client):
    """Firestore is the record and the tracker is a delivery of it. Refusing
    to record that a nudge was due because a network call failed loses the
    fact itself."""
    writer = TicketWriter(
        store=InMemoryIdempotencyStore(), client=client,
        clock=SimClock(mode=ClockMode.REAL),
        delivery=RecordingDelivery(raises=RuntimeError("github is down")),
    )

    result = act(writer, ChaseAction.NUDGE, state(ticket_open=True))

    assert result is not None
    assert client.docs[(COLLECTION, "RZ-1")]["nudges_sent"] is not None


def test_an_issue_number_is_written_back_to_the_ticket(client):
    writer = TicketWriter(
        store=InMemoryIdempotencyStore(), client=client,
        clock=SimClock(mode=ClockMode.REAL),
        delivery=RecordingDelivery(number=42),
    )
    act(writer, ChaseAction.OPEN_TICKET)

    assert client.docs[(COLLECTION, "RZ-1")]["github_issue"] == 42


def test_the_fleet_runs_identically_with_no_tracker_configured(client):
    """Delivery is optional and its absence changes no decision."""
    writer = TicketWriter(store=InMemoryIdempotencyStore(), client=client,
                          clock=SimClock(mode=ClockMode.REAL), delivery=None)
    act(writer, ChaseAction.OPEN_TICKET)

    assert client.docs[(COLLECTION, "RZ-1")]["status"] == "open"


def test_each_action_delivers_its_own_event(client):
    delivery = RecordingDelivery()
    writer = TicketWriter(store=InMemoryIdempotencyStore(), client=client,
                          clock=SimClock(mode=ClockMode.REAL), delivery=delivery)
    st = state(ticket_open=True)

    for action in (ChaseAction.OPEN_TICKET, ChaseAction.NUDGE,
                   ChaseAction.ESCALATE, ChaseAction.CLOSE_TICKET,
                   ChaseAction.HUMAN_QUEUE):
        act(writer, action, st)

    assert delivery.events == ["open_ticket", "nudge", "escalate",
                               "close_ticket", "human_queue"]
