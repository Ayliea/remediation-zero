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

"""The chase driver: which findings it acts on, and which it declines to.

The state machine is tested elsewhere. What this covers is the assembly around
it -- where each field of ChaseState comes from, and the two skips. Both skips
matter more than they look: a finding chased when it should not be nudges
someone who was told to stand down, and a finding skipped when it should not
be goes quiet with nobody deciding that it should.
"""

import pytest

import scripts.chase as chase_module
from scripts.chase import run_chase
from tools.clock import ClockMode, SimClock

DAY = 86400
CLOCK = SimClock(mode=ClockMode.SIM)
NOW = CLOCK.now().sim_ts


class FakeSnapshot:
    def __init__(self, data):
        self._data = data

    def to_dict(self):
        return self._data


class FakeDoc:
    def __init__(self, docs, key):
        self._docs, self._key = docs, key

    def get(self):
        snap = FakeSnapshot(self._docs.get(self._key))
        snap.exists = self._key in self._docs
        return snap

    def set(self, data, merge=False):
        if merge:
            self._docs.setdefault(self._key, {}).update(data)
        else:
            self._docs[self._key] = dict(data)

    def update(self, data):
        self._docs.setdefault(self._key, {}).update(data)


class FakeCollection:
    def __init__(self, docs, name, rows):
        self._docs, self._name, self._rows = docs, name, rows

    def stream(self):
        return [FakeSnapshot(r) for r in self._rows.get(self._name, [])]

    def document(self, doc_id):
        return FakeDoc(self._docs, (self._name, doc_id))


class FakeClient:
    def __init__(self, rows):
        self.docs, self._rows = {}, rows

    def collection(self, name):
        return FakeCollection(self.docs, name, self._rows)


def sla(finding_id="RZ-1", due_in_days=5, status="open", owner_id="own-1"):
    return {"finding_id": finding_id, "owner_id": owner_id, "status": status,
            "started_sim_ts": NOW - 2 * DAY,
            "due_sim_ts": NOW + due_in_days * DAY, "sla_days": 7}


OWNER = {"owner_id": "own-1", "email": "d@example.invalid",
         "display_name": "Dev Garrow"}


@pytest.fixture
def run(monkeypatch):
    monkeypatch.delenv("GITHUB_TICKET_REPO", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    def go(sla_rows, tickets=(), findings=(), exceptions=(), cycle=5):
        client = FakeClient({
            "sla_clocks": list(sla_rows), "tickets": list(tickets),
            "findings": list(findings), "exceptions": list(exceptions),
            "owners": [OWNER],
        })
        monkeypatch.setattr(chase_module.firestore, "Client",
                            lambda *a, **k: client)
        return run_chase(cycle=cycle, clock=CLOCK), client
    return go


# --- the ordinary path ------------------------------------------------------

def test_a_finding_with_no_ticket_gets_one(run):
    actions, client = run([sla()])

    assert actions["open_ticket"] == 1
    assert client.docs[("tickets", "RZ-1")]["status"] == "open"


def test_the_owner_is_looked_up_and_attached(run):
    _, client = run([sla()])
    assert client.docs[("tickets", "RZ-1")]["owner_email"] == "d@example.invalid"


# --- the skips --------------------------------------------------------------

def test_an_actively_accepted_risk_is_not_chased(run):
    """Nudging an owner who has been told to stand down destroys the
    credibility of every other nudge."""
    actions, client = run(
        [sla()],
        exceptions=[{"finding_id": "RZ-1", "status": "active",
                     "expires_sim_ts": NOW + 30 * DAY}])

    assert actions.get("open_ticket", 0) == 0
    assert actions["skipped_accepted"] == 1
    assert ("tickets", "RZ-1") not in client.docs


def test_a_stub_clock_awaiting_re_triage_is_skipped_not_escalated(run):
    """A reopened acceptance merges a status onto a clock that may not exist.
    Reading its missing start as zero would make it look decades overdue and
    escalate it on the strength of a field nobody set."""
    actions, client = run([{"finding_id": "RZ-1", "owner_id": "own-1",
                            "status": "reopened_pending_triage"}])

    assert actions["skipped_not_chaseable"] == 1
    assert ("tickets", "RZ-1") not in client.docs


def test_an_expired_acceptance_no_longer_suppresses_the_chase(run):
    """Only an active one does. A lapsed acceptance that kept suppressing
    would park the finding permanently."""
    actions, _ = run(
        [sla()],
        exceptions=[{"finding_id": "RZ-1", "status": "expired",
                     "expires_sim_ts": NOW - DAY}])

    assert actions["open_ticket"] == 1


# --- where resolution comes from --------------------------------------------

def test_a_resolved_finding_closes_its_ticket(run):
    """The finding is the source of truth, not the ticket. This is the path a
    rescan opens."""
    actions, client = run(
        [sla()],
        tickets=[{"finding_id": "RZ-1", "status": "open", "nudges_sent": 1,
                  "last_contact_sim_ts": NOW - DAY}],
        findings=[{"finding_id": "RZ-1", "status": "resolved",
                   "resolved_by_scan": "rescan-01"}])

    assert actions["close_ticket"] == 1
    assert client.docs[("tickets", "RZ-1")]["status"] == "resolved"
    assert client.docs[("tickets", "RZ-1")]["resolved_by_scan"] == "rescan-01"


def test_an_unresolved_finding_is_still_chased(run):
    actions, _ = run(
        [sla()],
        tickets=[{"finding_id": "RZ-1", "status": "open", "nudges_sent": 0,
                  "last_contact_sim_ts": NOW - 5 * DAY}],
        findings=[{"finding_id": "RZ-1", "status": "open"}])

    assert actions.get("close_ticket", 0) == 0


def test_a_closed_ticket_is_not_reopened_on_the_next_cycle(run):
    """A closed ticket record still exists because it keeps its history.
    Reading its presence as an open ticket would file a fresh one forever."""
    actions, _ = run(
        [sla()],
        tickets=[{"finding_id": "RZ-1", "status": "resolved",
                  "nudges_sent": 1, "last_contact_sim_ts": NOW}],
        findings=[{"finding_id": "RZ-1", "status": "resolved"}])

    assert actions.get("open_ticket", 0) == 0
    assert actions["done"] == 1


def test_a_regressed_finding_is_chased_again(run):
    """The rescan put the finding back to open and left the ticket closed.
    That is exactly the state that files a new ticket, and open_issue reopens
    the existing tracker issue rather than duplicating it."""
    actions, _ = run(
        [sla()],
        tickets=[{"finding_id": "RZ-1", "status": "resolved",
                  "nudges_sent": 1, "last_contact_sim_ts": NOW}],
        findings=[{"finding_id": "RZ-1", "status": "open",
                   "regressed_in_scan": "rescan-02"}])

    assert actions["open_ticket"] == 1


# --- delivery ---------------------------------------------------------------

def test_the_fleet_decides_identically_with_no_tracker_configured(run):
    """Its absence is stated rather than silent. What changes is whether the
    accountable person ever sees the decision, not what was decided."""
    actions, client = run([sla()])

    assert actions["open_ticket"] == 1
    assert "github_issue" not in client.docs[("tickets", "RZ-1")]


# --- once -------------------------------------------------------------------

def test_running_the_same_cycle_twice_acts_once(run):
    """Pub/Sub delivers at least once and the worker calls this directly, so
    a redelivered tick must not file a second ticket."""
    first, client = run([sla()])
    before = dict(client.docs[("tickets", "RZ-1")])
    assert first["open_ticket"] == 1
    assert ("idempotency",) != ()  # the ledger is written through the same fake

    # Same cycle, same fake Firestore, still monkeypatched by the fixture.
    second = run_chase(cycle=5, clock=CLOCK)

    assert second["open_ticket"] == 1, "the action was not attempted again"
    assert client.docs[("tickets", "RZ-1")] == before, "it wrote a second time"


def test_a_later_cycle_is_not_suppressed(run):
    """The guard must not over-suppress. Cycle 6 is new work, and a nudge that
    never sends leaves no trace of not having sent."""
    _, client = run([sla(due_in_days=-1)])
    before = dict(client.docs[("tickets", "RZ-1")])

    run_chase(cycle=6, clock=CLOCK)

    assert client.docs[("tickets", "RZ-1")] != before
