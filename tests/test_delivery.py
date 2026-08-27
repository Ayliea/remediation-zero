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
