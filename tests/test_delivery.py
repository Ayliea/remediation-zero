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

"""What the accountable person reads when the fleet follows up.

These are the only words this system puts in front of a human who did not ask
for them, so being wrong here is worse than being wrong in a log. The first
version told every owner that "0 simulated days" remained regardless of the
deadline, and promised "two more nudges" on the second of three.
"""

from dataclasses import dataclass

from tools.chase import MAX_NUDGES
from tools.delivery import _comment

DAY = 86400
OWNER = {"display_name": "Dev Garrow"}


@dataclass
class State:
    due_sim_ts: float
    nudges_sent: int = 0

    def days_overdue(self, now):
        return (now - self.due_sim_ts) / DAY


def test_a_nudge_with_time_left_says_how_much():
    now = 1000 * DAY
    body = _comment("nudge", 5, now, State(due_sim_ts=now + 3 * DAY), OWNER)
    assert "3 simulated days remain" in body
    assert "0 simulated days" not in body


def test_a_nudge_past_the_deadline_does_not_claim_time_remains():
    now = 1000 * DAY
    body = _comment("nudge", 5, now, State(due_sim_ts=now - 2 * DAY), OWNER)
    assert "already passed" in body


def test_the_nudge_counts_down_honestly():
    now = 1000 * DAY
    first = _comment("nudge", 5, now, State(due_sim_ts=now + DAY, nudges_sent=0), OWNER)
    last = _comment("nudge", 5, now,
                    State(due_sim_ts=now + DAY, nudges_sent=MAX_NUDGES - 1), OWNER)
    assert f"Nudge 1 of {MAX_NUDGES}" in first
    assert f"Nudge {MAX_NUDGES} of {MAX_NUDGES}" in last
    assert "That was the last nudge" in last
    assert "more nudge" not in last


def test_a_single_remaining_day_reads_as_one_day():
    """It is in front of a person, so it agrees with itself."""
    now = 1000 * DAY
    body = _comment("nudge", 5, now, State(due_sim_ts=now + DAY), OWNER)
    assert "1 simulated day remains" in body
    assert "days remain" not in body


def test_the_second_of_three_promises_one_more_not_two():
    now = 1000 * DAY
    body = _comment("nudge", 5, now, State(due_sim_ts=now + DAY, nudges_sent=1), OWNER)
    assert "1 more nudge follows" in body


def test_escalation_says_it_happens_once():
    now = 1000 * DAY
    body = _comment("escalate", 5, now,
                    State(due_sim_ts=now - 2 * DAY, nudges_sent=3), OWNER)
    assert "once" in body
    assert "2 simulated days ago" in body


def test_the_human_handoff_is_framed_as_success():
    now = 1000 * DAY
    body = _comment("human_queue", 5, now,
                    State(due_sim_ts=now - 4 * DAY, nudges_sent=3), OWNER)
    assert "successful outcome" in body


# ---------------------------------------------------------------------------
# Closing a ticket a rescan confirmed
# ---------------------------------------------------------------------------

@dataclass
class ResolvedState:
    due_sim_ts: float
    nudges_sent: int = 0
    resolved_by_scan: str = "scan-02"

    def days_overdue(self, now):
        return (now - self.due_sim_ts) / DAY


def test_a_closure_names_the_scan_that_justified_it():
    """The closing comment is the only place an owner learns why their ticket
    went away. "Resolved" without the evidence is indistinguishable from a
    ticket someone quietly deleted."""
    now = 1000 * DAY
    body = _comment("close_ticket", 7, now, ResolvedState(due_sim_ts=now), OWNER)
    assert "scan-02" in body
    assert "Resolved" in body


def test_a_closure_explains_that_coverage_is_what_made_absence_evidence():
    """The distinction the whole design rests on, stated where a human sees
    it rather than only in the code that enforces it."""
    now = 1000 * DAY
    body = _comment("close_ticket", 7, now, ResolvedState(due_sim_ts=now), OWNER)
    assert "covered" in body
    assert "never examined" in body


def test_a_closure_without_a_named_scan_still_reads_sensibly():
    """resolved_by_scan is absent on any state built before the rescan path
    existed. The comment degrades rather than rendering None at a person."""
    now = 1000 * DAY
    body = _comment("close_ticket", 7, now, State(due_sim_ts=now), OWNER)
    assert "None" not in body
    assert "a later scan" in body


# ---------------------------------------------------------------------------
# The order the tracker sees
# ---------------------------------------------------------------------------

class RecordingTracker:
    """Records the sequence of tracker calls, which is the thing under test."""

    def __init__(self):
        self.calls = []

    def open_issue(self, finding_id, title, body, labels, cycle):
        self.calls.append(("open_issue", 42, finding_id))
        return 42

    def comment_once(self, number, body, marker):
        assert marker.startswith("<!-- remediation-zero-delivery:")
        self.calls.append(("comment", number, body))

    def close_issue(self, number):
        self.calls.append(("close_issue", number, None))


class _Doc:
    def __init__(self, data): self._data = data
    def to_dict(self): return self._data


class _Collection:
    def __init__(self, data): self._data = data
    def document(self, _id): return self
    def get(self): return _Doc(self._data)


class _DB:
    def __init__(self, ticket): self._ticket = ticket
    def collection(self, name): return _Collection(self._ticket)


def _delivery(ticket):
    from tools.delivery import GitHubDelivery
    tracker = RecordingTracker()
    return GitHubDelivery(tracker, _DB(ticket)), tracker


def test_the_closure_comment_is_posted_before_the_issue_closes():
    """Closing first would post the reason into an issue that is already out
    of every triage view and most notification settings, so the explanation a
    person most wants is the one they are least likely to ever see."""
    delivery, tracker = _delivery({"github_issue": 42})
    now = 1000 * DAY

    delivery.deliver(event="close_ticket", finding_id="RZ-1", owner=OWNER,
                     cycle=7, now_sim_ts=now,
                     state=ResolvedState(due_sim_ts=now))

    assert [call[0] for call in tracker.calls] == ["comment", "close_issue"]
    assert tracker.calls[0][1] == 42
    assert tracker.calls[1][1] == 42


def test_a_nudge_does_not_close_anything():
    """close_issue is reachable only from close_ticket. A dispatch that closed
    on any event would end the chase at the first nudge."""
    delivery, tracker = _delivery({"github_issue": 42})
    now = 1000 * DAY

    for event in ("nudge", "escalate", "human_queue"):
        delivery.deliver(event=event, finding_id="RZ-1", owner=OWNER, cycle=7,
                         now_sim_ts=now, state=ResolvedState(due_sim_ts=now))

    assert "close_issue" not in [call[0] for call in tracker.calls]


def test_a_closure_with_no_filed_issue_touches_the_tracker_at_all():
    """A finding whose issue never filed has nothing to close, and reaching
    for a None issue number would raise inside a delivery path that is
    documented never to fail a cycle."""
    delivery, tracker = _delivery({})
    now = 1000 * DAY

    delivery.deliver(event="close_ticket", finding_id="RZ-1", owner=OWNER,
                     cycle=7, now_sim_ts=now,
                     state=ResolvedState(due_sim_ts=now))

    assert tracker.calls == []


def test_a_later_nudge_recovers_an_issue_whose_opening_delivery_failed():
    delivery, tracker = _delivery({})
    delivery._latest_decision = lambda _finding_id: {}
    now = 1000 * DAY

    recovered = delivery.deliver(
        event="nudge", finding_id="RZ-1", owner=OWNER, cycle=6,
        now_sim_ts=now, state=State(due_sim_ts=now + DAY),
    )

    assert recovered == 42
    assert [call[0] for call in tracker.calls] == ["open_issue", "comment"]
