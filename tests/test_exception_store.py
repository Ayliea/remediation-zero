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

"""Risk acceptances, and the refusals that are also records.

An accepted risk is the one place the fleet deliberately stops chasing a live
vulnerability, so both directions matter: an acceptance it should not have made
is a vulnerability parked on the fleet's own authority, and a refusal that
vanishes silently is a request nobody ever sees.
"""

import pytest

from tools.clock import ClockMode, SimClock
from tools.exception_store import (
    COLLECTION,
    HUMAN_QUEUE,
    SLA_COLLECTION,
    ExceptionWriter,
)
from tools.exceptions import Exception_
from tools.idempotency import InMemoryIdempotencyStore

DAY = 86400


class FakeDoc:
    def __init__(self, docs, key, log):
        self._docs, self._key, self._log = docs, key, log

    def set(self, data, merge=False):
        self._log.append(self._key)
        if merge:
            self._docs.setdefault(self._key, {}).update(data)
        else:
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


@pytest.fixture
def client():
    return FakeClient()


@pytest.fixture
def writer(client):
    return ExceptionWriter(store=InMemoryIdempotencyStore(), client=client,
                           clock=SimClock(mode=ClockMode.REAL))


def accept(writer, **over):
    kwargs = dict(finding_id="RZ-1", cycle=3, accepted_by="dev@example.invalid",
                  reason="Change window is closed until the next release.",
                  ttl_days=30, in_kev=False)
    kwargs.update(over)
    return writer.accept(**kwargs)


# --- accepting ---------------------------------------------------------------

def test_an_acceptance_carries_its_own_expiry(writer, client):
    """A risk acceptance with no end is a decision to never fix something,
    made once and never revisited."""
    accept(writer)

    record = client.docs[(COLLECTION, "RZ-1")]
    assert record["status"] == "active"
    assert record["expires_sim_ts"] == record["accepted_sim_ts"] + 30 * DAY
    assert record["reopened"] is False


def test_accepting_pauses_the_clock_rather_than_leaving_it_running(writer, client):
    """Nudging an owner who has been told to stand down destroys the
    credibility of every other nudge."""
    accept(writer)
    assert client.docs[(SLA_COLLECTION, "RZ-1")]["status"] == "accepted"


def test_the_paused_clock_still_carries_its_finding_id(writer, client):
    """A finding can be accepted before it was ever assigned, so no clock
    exists and the merge creates one. A document identified only by its key is
    unreadable to anything that queries by field."""
    accept(writer)
    assert client.docs[(SLA_COLLECTION, "RZ-1")]["finding_id"] == "RZ-1"


# --- refusing ----------------------------------------------------------------

def test_an_exploited_vulnerability_cannot_be_accepted_by_the_fleet(writer):
    """A KEV finding is being exploited in the wild. The fleet may not park
    that on its own authority."""
    with pytest.raises(ValueError):
        accept(writer, in_kev=True)


def test_a_refusal_is_recorded_for_a_person_rather_than_dropped(writer, client):
    """The request itself is the signal: somebody wanted this parked."""
    with pytest.raises(ValueError):
        accept(writer, in_kev=True)

    entry = client.docs[(HUMAN_QUEUE, "acceptance-refused-RZ-1-c003")]
    assert entry["kind"] == "acceptance_refused"
    assert entry["requested_by"] == "dev@example.invalid"
    assert entry["reason"].strip()


def test_a_refused_acceptance_writes_no_exception(writer, client):
    """The refusal must not half-apply. A finding recorded as accepted and
    also refused is worse than either outcome."""
    with pytest.raises(ValueError):
        accept(writer, in_kev=True)

    assert (COLLECTION, "RZ-1") not in client.docs
    assert (SLA_COLLECTION, "RZ-1") not in client.docs


@pytest.mark.parametrize("bad", [
    {"ttl_days": 0}, {"ttl_days": -1}, {"ttl_days": 100000},
    {"reason": "   "},
])
def test_an_unusable_acceptance_is_refused(writer, bad):
    with pytest.raises(ValueError):
        accept(writer, **bad)


def test_a_kev_finding_can_be_accepted_when_a_human_approved_it(writer, client):
    """The control is that the fleet cannot do it alone, not that it can never
    happen."""
    accept(writer, in_kev=True, approved_by_human=True)
    assert client.docs[(COLLECTION, "RZ-1")]["approved_by_human"] is True


# --- expiry ------------------------------------------------------------------

def test_a_lapsed_acceptance_returns_the_finding_for_re_adjudication(writer, client):
    """Not to its old SLA. The evidence may have moved while it was parked,
    and a stale severity is not a decision."""
    lapsed = Exception_(finding_id="RZ-1", accepted_by="dev@example.invalid",
                        reason="Change window.", accepted_sim_ts=1000 * DAY,
                        ttl_days=30)
    writer.reopen(lapsed, cycle=9, now_sim_ts=1031 * DAY)

    assert client.docs[(COLLECTION, "RZ-1")]["status"] == "expired"
    assert client.docs[(COLLECTION, "RZ-1")]["reopened"] is True
    assert (client.docs[(SLA_COLLECTION, "RZ-1")]["status"]
            == "reopened_pending_triage")


def test_the_reopening_says_who_accepted_it_and_why(writer, client):
    """A person reading this months later needs the original justification,
    not just the fact that something came back."""
    lapsed = Exception_(finding_id="RZ-1", accepted_by="dev@example.invalid",
                        reason="Change window.", accepted_sim_ts=1000 * DAY,
                        ttl_days=30)
    writer.reopen(lapsed, cycle=9, now_sim_ts=1031 * DAY)

    entry = client.docs[(HUMAN_QUEUE, "reopened-RZ-1")]
    assert entry["kind"] == "acceptance_expired"
    assert "dev@example.invalid" in entry["reason"]
    assert "never remediated" in entry["reason"]


# --- once --------------------------------------------------------------------

def test_accepting_twice_writes_once(writer, client):
    accept(writer)
    writes = len(client.writes)
    accept(writer)
    assert len(client.writes) == writes


def test_reopening_twice_writes_once(writer, client):
    lapsed = Exception_(finding_id="RZ-1", accepted_by="a@example.invalid",
                        reason="r", accepted_sim_ts=1000 * DAY, ttl_days=30)
    writer.reopen(lapsed, cycle=9, now_sim_ts=1031 * DAY)
    writes = len(client.writes)
    writer.reopen(lapsed, cycle=9, now_sim_ts=1031 * DAY)
    assert len(client.writes) == writes


def test_accepting_and_reopening_do_not_share_a_key(writer, client):
    """Both act on one finding and can fall in one cycle. Sharing a key would
    make the reopen a no-op and leave the finding parked forever."""
    from tools.idempotency import derive_key
    assert derive_key("RZ-1", "accept_risk", 3) != derive_key(
        "RZ-1", "reopen_exception", 3)
