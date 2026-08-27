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

"""What chase does next, given a clock and a ticket.

This is the agent that owns the six weeks after the scan, so its decisions are
almost entirely a function of elapsed simulated time. Keeping that logic pure
means the whole multi-week lifecycle can be tested in milliseconds without
waiting for it or faking a wall clock.
"""

import pytest

from tools.chase import (
    ChaseAction,
    ChaseState,
    MAX_NUDGES,
    NUDGE_INTERVAL_DAYS,
    next_action,
    unchaseable_reason,
)

DAY = 86400
STARTED = 1_000_000.0
DUE = STARTED + 14 * DAY


def state(**overrides) -> ChaseState:
    base = dict(
        finding_id="RZ-0001",
        started_sim_ts=STARTED,
        due_sim_ts=DUE,
        ticket_open=False,
        nudges_sent=0,
        last_contact_sim_ts=None,
        escalated=False,
        resolved=False,
    )
    base.update(overrides)
    return ChaseState(**base)


def test_a_finding_with_no_ticket_gets_one_opened():
    assert next_action(state(), now_sim_ts=STARTED) is ChaseAction.OPEN_TICKET


def test_nothing_happens_immediately_after_the_ticket_is_opened():
    """An owner who was just told is not nudged the same day."""
    current = state(ticket_open=True, last_contact_sim_ts=STARTED)

    assert next_action(current, now_sim_ts=STARTED + DAY) is ChaseAction.WAIT


def test_an_owner_is_nudged_once_the_interval_has_passed():
    current = state(ticket_open=True, last_contact_sim_ts=STARTED)
    later = STARTED + (NUDGE_INTERVAL_DAYS + 1) * DAY

    assert next_action(current, now_sim_ts=later) is ChaseAction.NUDGE


def test_nudging_stops_after_the_cap_and_escalates_instead():
    """Chasing forever is not chasing. After the cap it becomes someone
    else's problem, which is the point of escalation."""
    current = state(
        ticket_open=True,
        nudges_sent=MAX_NUDGES,
        last_contact_sim_ts=STARTED,
    )
    later = STARTED + (NUDGE_INTERVAL_DAYS + 1) * DAY

    assert next_action(current, now_sim_ts=later) is ChaseAction.ESCALATE


def test_a_breached_sla_escalates_even_if_nudges_remain():
    """The deadline outranks the cadence. An overdue finding is escalated
    rather than politely nudged again."""
    current = state(ticket_open=True, nudges_sent=1, last_contact_sim_ts=DUE - DAY)

    assert next_action(current, now_sim_ts=DUE + DAY) is ChaseAction.ESCALATE


def test_an_already_escalated_overdue_finding_goes_to_a_person():
    """Escalation happens once. After that a human owns it and the fleet
    stops acting, because a loop that re-escalates weekly is noise."""
    current = state(
        ticket_open=True, nudges_sent=2, escalated=True, last_contact_sim_ts=DUE
    )

    assert next_action(current, now_sim_ts=DUE + 7 * DAY) is ChaseAction.HUMAN_QUEUE


def test_a_resolved_finding_is_left_alone():
    current = state(ticket_open=True, resolved=True, nudges_sent=1)

    assert next_action(current, now_sim_ts=DUE + 30 * DAY) is ChaseAction.DONE


def test_the_lifecycle_terminates_within_a_bounded_number_of_actions():
    """Six weeks of chasing must converge. A chase loop that never ends is a
    chase loop that pages someone every cycle forever."""
    current = state()
    now = STARTED
    seen = []

    for _ in range(200):
        action = next_action(current, now_sim_ts=now)
        seen.append(action)
        if action in (ChaseAction.DONE, ChaseAction.HUMAN_QUEUE):
            break
        current = current.after(action, now_sim_ts=now)
        now += NUDGE_INTERVAL_DAYS * DAY

    assert seen[-1] is ChaseAction.HUMAN_QUEUE
    assert seen.count(ChaseAction.NUDGE) <= MAX_NUDGES
    assert seen.count(ChaseAction.ESCALATE) == 1


def test_nudge_cadence_scales_with_the_sla_window():
    """A fixed cadence lets a short SLA expire before the first nudge fires,
    so an urgent finding would be chased less than a relaxed one."""
    urgent = state(due_sim_ts=STARTED + 7 * DAY)
    relaxed = state(due_sim_ts=STARTED + 30 * DAY)

    assert urgent.nudge_interval_seconds < relaxed.nudge_interval_seconds
    assert urgent.nudge_interval_seconds == pytest.approx(7 * DAY / 4)


def test_a_short_sla_still_gets_nudged_before_it_expires():
    """The regression this fixes: with a fixed seven-day cadence and a
    seven-day SLA, the deadline arrived before any nudge was ever sent."""
    current = state(
        due_sim_ts=STARTED + 7 * DAY, ticket_open=True, last_contact_sim_ts=STARTED
    )

    assert next_action(current, now_sim_ts=STARTED + 2 * DAY) is ChaseAction.NUDGE


# --- clock records that are not chaseable yet -------------------------------
#
# These came from a real crash rather than from imagination. The exception
# agent reopens a lapsed acceptance by merging a status onto the finding's SLA
# clock, and merge=True creates the document when there was no clock to begin
# with. Chase then read that stub and died on the missing start time, halfway
# through a run that had already written tickets.
#
# The status on that stub says "reopened_pending_triage", which is chase
# answering its own question: a finding waiting to be re-triaged has no agreed
# deadline yet, so there is nothing to chase it against.


def test_a_clock_with_no_start_time_is_not_chaseable():
    assert unchaseable_reason({"finding_id": "RZ-0330"}) is not None


def test_the_reopened_stub_that_caused_the_crash_is_skipped_by_name():
    stub = {
        "finding_id": "RZ-0330",
        "status": "reopened_pending_triage",
        "paused_sim_ts": 1787800491.4873943,
    }
    reason = unchaseable_reason(stub)
    assert reason is not None
    assert "triage" in reason


def test_a_started_clock_is_chaseable():
    assert unchaseable_reason(
        {
            "finding_id": "RZ-0101",
            "started_sim_ts": 1787800000.0,
            "due_sim_ts": 1788400000.0,
        }
    ) is None


def test_a_clock_missing_only_the_due_date_is_not_chaseable():
    """A start with no deadline gives next_action no window to divide."""
    assert unchaseable_reason(
        {"finding_id": "RZ-0101", "started_sim_ts": 1787800000.0}
    ) is not None


def test_the_reason_is_reportable_rather_than_a_bare_boolean():
    """The driver logs why it skipped, the way it already does for acceptances."""
    reason = unchaseable_reason({"finding_id": "RZ-0330"})
    assert isinstance(reason, str) and reason
