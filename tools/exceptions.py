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

"""Risk acceptances with a TTL, and automatic re-opening at expiry.

The failure this exists to prevent is the one that actually happens in a real
programme. A risk gets accepted to clear a backlog, the expiry is recorded in a
spreadsheet nobody opens, and six months later the acceptance has quietly
become a decision never to fix it. Nobody made that decision. It happened by
default, which is the worst way for a security decision to get made.

So expiry is not advisory here. An acceptance carries a TTL, the TTL is bounded,
and when it lapses the finding comes back on its own.

Three things the fleet will not accept on its own:

    no TTL              a risk accepted with no expiry is a risk abandoned
    an unbounded TTL    ten years is not an acceptance, it is a decision
    a KEV entry         presence in CISA KEV means it is being exploited right
                        now. A person may still accept it, and that is the
                        control: a human decides, rather than it being
                        impossible

Expiry is measured in simulated time, so a ninety-day acceptance can lapse
inside a demonstration while `real_ts` records honestly that it did not really
take ninety days.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional

DAY_SECONDS = 86400

#: The longest acceptance the fleet will record without a human. Beyond this
#: it is not an acceptance, it is a decision not to remediate.
MAX_TTL_DAYS = 180


class ExceptionStatus(Enum):
    ACTIVE = "active"
    EXPIRED = "expired"


class ExceptionAction(Enum):
    #: Bring the finding back. It was never fixed, only deferred.
    REOPEN = "reopen"
    NONE = "none"


@dataclass(frozen=True)
class Exception_:
    """One recorded risk acceptance.

    Named with a trailing underscore so it does not shadow the builtin.
    """

    finding_id: str
    accepted_by: str
    reason: str
    accepted_sim_ts: float
    ttl_days: int
    reopened: bool = False

    @property
    def expires_sim_ts(self) -> float:
        return self.accepted_sim_ts + self.ttl_days * DAY_SECONDS


def validate_acceptance(
    ttl_days: Optional[int],
    reason: str,
    in_kev: bool,
    approved_by_human: bool,
) -> None:
    """Refuse an acceptance the fleet is not permitted to make.

    Raises:
        ValueError: naming which rule was broken, so the refusal is
            actionable rather than merely a denial.
    """
    if ttl_days is None:
        raise ValueError(
            "An acceptance requires a ttl_days. A risk accepted with no expiry "
            "is a risk abandoned."
        )
    if ttl_days <= 0 or ttl_days > MAX_TTL_DAYS:
        raise ValueError(
            f"ttl_days must be between 1 and {MAX_TTL_DAYS}, got {ttl_days}. "
            f"Longer than that is not an acceptance, it is a decision not to fix it."
        )
    if not reason.strip():
        raise ValueError(
            "An acceptance requires a reason. An unexplained acceptance cannot "
            "be reviewed later, which is the only thing separating it from "
            "ignoring the finding."
        )
    if in_kev and not approved_by_human:
        raise ValueError(
            "This CVE is in the CISA KEV catalog, meaning it is being exploited "
            "in the wild. The fleet does not accept that risk on its own. Route "
            "to a person for approval."
        )


def status_at(exception: Exception_, now_sim_ts: float) -> ExceptionStatus:
    """Whether the acceptance still stands at `now_sim_ts`."""
    if now_sim_ts >= exception.expires_sim_ts:
        return ExceptionStatus.EXPIRED
    return ExceptionStatus.ACTIVE


def next_action(exception: Exception_, now_sim_ts: float) -> ExceptionAction:
    """What to do about one acceptance now."""
    if exception.reopened:
        # Re-opening every cycle after expiry would be noise and would reset
        # the finding's history repeatedly.
        return ExceptionAction.NONE
    if status_at(exception, now_sim_ts) is ExceptionStatus.EXPIRED:
        return ExceptionAction.REOPEN
    return ExceptionAction.NONE
