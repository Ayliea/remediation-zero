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

"""The sweep that brings deferred risk back.

An acceptance that expires while nobody is looking is the failure this agent
exists to prevent, so the sweep runs on a schedule rather than when someone
remembers. That makes two directions dangerous: missing an expiry leaves a
live vulnerability parked forever, and reopening something twice resets a
finding's history and pages an owner about work that already came back.

The fake here is the database, not the writer. ExceptionWriter and the
idempotency store are the real ones, so the sweep is tested through the path
it actually takes.
"""

import pytest
from google.api_core.exceptions import AlreadyExists
from google.cloud import firestore

import scripts.exception as sweep_module
from scripts.exception import run_sweep
from tools.clock import ClockMode, SimClock

DAY = 86400


class FakeSnapshot:
    def __init__(self, data):
        self._data = data

    def to_dict(self):
        return self._data

    update_time = None


class FakeDoc:
    def __init__(self, docs, key):
        self._docs, self._key = docs, key

    def get(self):
        data = self._docs.get(self._key)
        snapshot = FakeSnapshot(data)
        snapshot.exists = data is not None
        return snapshot

    def set(self, data, merge=False):
        if merge:
            self._docs.setdefault(self._key, {}).update(data)
        else:
            self._docs[self._key] = dict(data)

    def create(self, data):
        if self._key in self._docs:
            raise AlreadyExists("already exists")
        self._docs[self._key] = dict(data)

    def update(self, data, option=None):
        current = self._docs.setdefault(self._key, {})
        for key, value in data.items():
            if value is firestore.DELETE_FIELD:
                current.pop(key, None)
            else:
                current[key] = value

    def delete(self, option=None):
        self._docs.pop(self._key, None)


class FakeCollection:
    def __init__(self, docs, name, rows):
        self._docs, self._name, self._rows = docs, name, rows

    def stream(self):
        return [FakeSnapshot(row) for row in self._rows.get(self._name, [])]

    def document(self, doc_id):
        return FakeDoc(self._docs, (self._name, doc_id))


class FakeClient:
    def __init__(self, rows):
        self.docs, self._rows = {}, rows

    def collection(self, name):
        return FakeCollection(self.docs, name, self._rows)


#: Sim time starts at wall clock and only moves forward -- advance() refuses a
#: negative delta, which is the guard that makes the elapsed-time claim
#: defensible. So an acceptance's age is expressed backwards from the clock's
#: present rather than by winding the clock to a chosen absolute moment.
CLOCK = SimClock(mode=ClockMode.SIM)
NOW = CLOCK.now().sim_ts


def acceptance(finding_id="RZ-1", age_days=31, ttl_days=30, reopened=False):
    """One acceptance, made `age_days` ago in simulated time."""
    return {"finding_id": finding_id, "accepted_by": "dev@example.invalid",
            "reason": "Change window is closed.",
            "accepted_sim_ts": NOW - age_days * DAY, "ttl_days": ttl_days,
            "reopened": reopened}


@pytest.fixture
def run(monkeypatch):
    """Run the sweep against a fake database, at the clock's present."""
    def go(rows, cycle=9):
        client = FakeClient({"exceptions": rows})
        monkeypatch.setattr(sweep_module.firestore, "Client", lambda *a, **k: client)
        actions = run_sweep(cycle=cycle, clock=CLOCK)
        return actions, client
    return go


# --- what the sweep does ----------------------------------------------------

def test_an_unexpired_acceptance_is_left_alone(run):
    actions, client = run([acceptance(age_days=10)])

    assert actions.get("reopen", 0) == 0
    assert ("exceptions", "RZ-1") not in client.docs


def test_a_lapsed_acceptance_is_reopened(run):
    actions, client = run([acceptance()])

    assert actions["reopen"] == 1
    assert client.docs[("exceptions", "RZ-1")]["reopened"] is True
    assert client.docs[("sla_clocks", "RZ-1")]["status"] == "reopened_pending_triage"


def test_an_already_reopened_acceptance_is_not_reopened_again(run):
    """Reopening every cycle after expiry would be noise, and would reset the
    finding's history repeatedly."""
    actions, client = run([acceptance(reopened=True)])

    assert actions.get("reopen", 0) == 0
    assert ("human_queue", "reopened-RZ-1") not in client.docs


def test_the_person_is_told_why_it_came_back(run):
    _, client = run([acceptance()])

    entry = client.docs[("human_queue", "reopened-RZ-1")]
    assert entry["kind"] == "acceptance_expired"
    assert "dev@example.invalid" in entry["reason"]


def test_each_acceptance_is_judged_on_its_own_ttl(run):
    """A short TTL that has lapsed and a long one that has not, in the same
    sweep. Judging them together would either miss one or reopen both."""
    actions, client = run(
        [acceptance("RZ-1", ttl_days=7), acceptance("RZ-2", ttl_days=90)])

    assert actions["reopen"] == 1
    assert ("exceptions", "RZ-1") in client.docs
    assert ("exceptions", "RZ-2") not in client.docs


def test_the_sweep_reports_what_it_did(run):
    actions, _ = run([acceptance("RZ-1"), acceptance("RZ-2", ttl_days=90)])

    assert actions["reopen"] == 1
    assert actions["none"] == 1


def test_an_empty_sweep_is_not_an_error(run):
    actions, _ = run([])
    assert actions == {}


# --- once -------------------------------------------------------------------

def test_sweeping_the_same_cycle_twice_reopens_once(monkeypatch):
    """Pub/Sub delivers at least once, and this runs on a schedule."""
    client = FakeClient({"exceptions": [acceptance()]})
    monkeypatch.setattr(sweep_module.firestore, "Client", lambda *a, **k: client)

    run_sweep(cycle=9, clock=CLOCK)
    first = dict(client.docs[("exceptions", "RZ-1")])
    run_sweep(cycle=9, clock=CLOCK)

    assert client.docs[("exceptions", "RZ-1")] == first


# --- whose clock ------------------------------------------------------------

def test_the_clock_it_is_given_is_the_one_it_uses(monkeypatch):
    """The function documents that passing a clock makes the answer explicit
    about which one is authoritative. A clock built inside would sit at wall
    clock and disagree with a caller who had advanced past an expiry."""
    advanced = SimClock(mode=ClockMode.SIM)
    advanced.advance(seconds=40 * DAY)
    client = FakeClient({"exceptions": [acceptance(age_days=0, ttl_days=30)]})
    monkeypatch.setattr(sweep_module.firestore, "Client", lambda *a, **k: client)

    actions = run_sweep(cycle=9, clock=advanced)

    assert actions["reopen"] == 1, "the caller's advanced clock was ignored"
