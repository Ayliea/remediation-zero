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

"""Risk acceptances expire, and expiry is not optional.

The failure this guards against is the one that actually happens in a real
programme: a risk is accepted to clear a backlog, nobody diarises the expiry,
and the acceptance quietly becomes permanent. So most of these tests are about
what the exception agent refuses to do.
"""

import pytest

from tools.exceptions import (
    MAX_TTL_DAYS,
    Exception_,
    ExceptionAction,
    ExceptionStatus,
    next_action,
    status_at,
    validate_acceptance,
)

DAY = 86400
ACCEPTED_AT = 1_000_000.0


def exception(**overrides) -> Exception_:
    base = dict(
        finding_id="RZ-0001",
        accepted_by="own-001",
        reason="Compensating control: host is isolated pending decommission.",
        accepted_sim_ts=ACCEPTED_AT,
        ttl_days=90,
        reopened=False,
    )
    base.update(overrides)
    return Exception_(**base)


def test_an_acceptance_is_active_before_its_ttl():
    assert status_at(exception(), ACCEPTED_AT + 30 * DAY) is ExceptionStatus.ACTIVE


def test_an_acceptance_expires_at_its_ttl():
    assert status_at(exception(), ACCEPTED_AT + 91 * DAY) is ExceptionStatus.EXPIRED


def test_an_expired_acceptance_reopens_the_finding():
    """The whole point. An acceptance that lapses without reopening is an
    acceptance that silently became permanent."""
    assert next_action(exception(), ACCEPTED_AT + 91 * DAY) is ExceptionAction.REOPEN


def test_reopening_happens_once():
    """Re-opening every cycle after expiry would be noise, and would reset the
    finding's history repeatedly."""
    already = exception(reopened=True)

    assert next_action(already, ACCEPTED_AT + 200 * DAY) is ExceptionAction.NONE


def test_an_active_acceptance_does_nothing():
    assert next_action(exception(), ACCEPTED_AT + 1 * DAY) is ExceptionAction.NONE


# --- what cannot be accepted ------------------------------------------------

def test_an_acceptance_without_a_ttl_is_refused():
    """A risk accepted with no expiry is a risk abandoned."""
    with pytest.raises(ValueError, match="ttl"):
        validate_acceptance(ttl_days=None, reason="because", in_kev=False,
                            approved_by_human=False)


def test_an_unbounded_ttl_is_refused():
    """Ten years is not an acceptance, it is a decision not to fix it."""
    with pytest.raises(ValueError, match="ttl"):
        validate_acceptance(ttl_days=MAX_TTL_DAYS + 1, reason="because",
                            in_kev=False, approved_by_human=False)


def test_an_acceptance_without_a_reason_is_refused():
    """An unexplained acceptance cannot be reviewed later, which is the only
    thing that makes an acceptance different from ignoring the finding."""
    with pytest.raises(ValueError, match="reason"):
        validate_acceptance(ttl_days=30, reason="   ", in_kev=False,
                            approved_by_human=False)


def test_a_known_exploited_vulnerability_cannot_be_auto_accepted():
    """Presence in CISA KEV means it is being exploited right now. The fleet
    is not permitted to accept that risk on its own; a person must."""
    with pytest.raises(ValueError, match="KEV"):
        validate_acceptance(ttl_days=30, reason="mitigated", in_kev=True,
                            approved_by_human=False)


def test_a_human_may_accept_a_known_exploited_vulnerability():
    """The control is that a person decides, not that it is impossible."""
    validate_acceptance(ttl_days=30, reason="Isolated, decommission scheduled.",
                        in_kev=True, approved_by_human=True)
