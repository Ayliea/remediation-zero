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

"""The chase agent's decision logic.

This is the part of the system that owns the weeks after a scan: opening the
ticket, nudging the owner, escalating when the deadline passes, and knowing
when to stop and hand the finding to a person.

Every decision is a function of elapsed simulated time and what has already
been done, and nothing here reads a clock or writes anything. That is what lets
a six-week lifecycle be tested in milliseconds and replayed in a demonstration
without anyone waiting six weeks or pretending they did.

The rules, in priority order:

    resolved                 stop. The work is done.
    no ticket                open one. Nothing else can happen first.
    past due, escalated      hand it to a person. Escalation happens once, and
                             a loop that re-escalates every cycle is noise
                             rather than urgency.
    past due                 escalate. The deadline outranks the cadence: an
                             overdue finding is not politely nudged again.
    nudges exhausted         escalate. Chasing forever is not chasing.
    interval elapsed         nudge. The interval is the SLA window divided by
                             MAX_NUDGES + 1, so pressure stays proportional to
                             urgency instead of a fixed cadence letting a
                             short SLA expire un-nudged.
    otherwise                wait.
"""

from dataclasses import dataclass, replace
from enum import Enum
from typing import Optional

DAY_SECONDS = 86400

#: After this many nudges the fleet stops asking and escalates.
MAX_NUDGES = 3

#: Fallback cadence when an SLA window is not known, in simulated days.
NUDGE_INTERVAL_DAYS = 7


class ChaseAction(Enum):
    """What chase should do next for one finding."""

    OPEN_TICKET = "open_ticket"
    NUDGE = "nudge"
    ESCALATE = "escalate"
    #: Escalated and still unresolved. A person owns it; the fleet stops.
    HUMAN_QUEUE = "human_queue"
    #: Too soon to act. The common case, and doing nothing is a decision.
    WAIT = "wait"
    DONE = "done"


@dataclass(frozen=True)
class ChaseState:
    """What has already happened to one finding."""

    finding_id: str
    started_sim_ts: float
    due_sim_ts: float
    ticket_open: bool = False
    nudges_sent: int = 0
    last_contact_sim_ts: Optional[float] = None
    escalated: bool = False
    resolved: bool = False

    def after(self, action: ChaseAction, now_sim_ts: float) -> "ChaseState":
        """The state that follows from taking `action` at `now_sim_ts`.

        Used to replay a lifecycle without a database, and to reason about
        termination.
        """
        if action is ChaseAction.OPEN_TICKET:
            return replace(self, ticket_open=True, last_contact_sim_ts=now_sim_ts)
        if action is ChaseAction.NUDGE:
            return replace(
                self,
                nudges_sent=self.nudges_sent + 1,
                last_contact_sim_ts=now_sim_ts,
            )
        if action is ChaseAction.ESCALATE:
            return replace(self, escalated=True, last_contact_sim_ts=now_sim_ts)
        return self

    def days_overdue(self, now_sim_ts: float) -> float:
        return max(0.0, (now_sim_ts - self.due_sim_ts) / DAY_SECONDS)

    @property
    def nudge_interval_seconds(self) -> float:
        """Spread the nudges across the SLA window rather than using a fixed
        cadence.

        A fixed seven-day cadence against a seven-day SLA means the deadline
        arrives before the first nudge ever fires, so a critical finding gets
        chased less than a low one. Dividing the window by MAX_NUDGES + 1
        keeps the pressure proportional to the urgency: a 7-day SLA nudges
        roughly every 1.75 days, a 30-day SLA every 7.5.
        """
        window = self.due_sim_ts - self.started_sim_ts
        if window <= 0:
            return NUDGE_INTERVAL_DAYS * DAY_SECONDS
        return window / (MAX_NUDGES + 1)


def next_action(state: ChaseState, now_sim_ts: float) -> ChaseAction:
    """Decide what to do for one finding, at one moment in simulated time."""
    if state.resolved:
        return ChaseAction.DONE

    if not state.ticket_open:
        return ChaseAction.OPEN_TICKET

    overdue = now_sim_ts >= state.due_sim_ts

    if overdue and state.escalated:
        # Escalated and still not fixed. The fleet has run out of moves that
        # do not involve a person.
        return ChaseAction.HUMAN_QUEUE

    if overdue:
        return ChaseAction.ESCALATE

    since_contact = now_sim_ts - (state.last_contact_sim_ts or state.started_sim_ts)
    if since_contact < state.nudge_interval_seconds:
        return ChaseAction.WAIT

    if state.nudges_sent >= MAX_NUDGES:
        return ChaseAction.ESCALATE

    return ChaseAction.NUDGE
