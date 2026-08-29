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

"""What the identity probes are allowed to score as a denial.

These two jobs decide whether two of the six controls pass, and they decide it
by classifying an exception. Everything rests on that classification being
narrow: a probe that scores any failure as a denial reports a working boundary
whenever the network is down, whenever a request is malformed, whenever
impersonation fails. The earlier version of one of these did exactly that and
passed without exercising anything.

So the tests here are almost entirely about failures that must NOT count.
"""

import pytest

from ui.control_probe import attempt as control_attempt
from ui.secret_probe import attempt as secret_attempt

ATTEMPTS = [
    pytest.param(control_attempt, id="control_probe"),
    pytest.param(secret_attempt, id="secret_probe"),
]


class PermissionDenied(Exception):
    pass


class InvalidArgument(Exception):
    pass


class ServiceUnavailable(Exception):
    pass


def raiser(exc):
    def fn():
        raise exc
    return fn


# --- the two outcomes that are real ----------------------------------------

@pytest.mark.parametrize("attempt", ATTEMPTS)
def test_a_permission_denial_where_one_was_expected_is_a_pass(attempt):
    assert attempt("write a ticket", True,
                   raiser(PermissionDenied("caller lacks permission"))) is True


@pytest.mark.parametrize("attempt", ATTEMPTS)
def test_a_success_where_one_was_expected_is_a_pass(attempt):
    """Half of these checks expect ALLOWED. An identity that can do nothing
    proves only that it is broken; the control is that the boundary falls in
    a specific place."""
    assert attempt("read a finding", False, lambda: None) is True


@pytest.mark.parametrize("attempt", ATTEMPTS)
def test_a_success_where_a_denial_was_expected_is_a_failure(attempt):
    """The boundary is open. This is the finding the probe exists to make."""
    assert attempt("write a ticket", True, lambda: None) is False


@pytest.mark.parametrize("attempt", ATTEMPTS)
def test_a_denial_where_success_was_expected_is_a_failure(attempt):
    """Over-restriction is still wrong: the reporting agent has to be able to
    write its own reports, or it is simply broken rather than scoped."""
    assert attempt("write a report", False,
                   raiser(PermissionDenied("nope"))) is False


# --- failures that must never be scored as a denial ------------------------

@pytest.mark.parametrize("attempt", ATTEMPTS)
def test_a_malformed_request_is_not_a_denial(attempt):
    """The historical bug. An InvalidArgument means the probe never reached
    the boundary it was testing, so scoring it as DENIED reports a control
    that was never exercised."""
    assert attempt("write a ticket", True,
                   raiser(InvalidArgument("bad document path"))) is False


@pytest.mark.parametrize("attempt", ATTEMPTS)
def test_an_unrelated_failure_is_not_a_denial(attempt):
    """A network blip is not evidence of least privilege."""
    assert attempt("write a ticket", True,
                   raiser(ServiceUnavailable("connection reset"))) is False


@pytest.mark.parametrize("attempt", ATTEMPTS)
def test_a_400_is_not_a_denial(attempt):
    assert attempt("write a ticket", True,
                   raiser(Exception("400 malformed request body"))) is False


def test_an_impersonation_failure_is_not_a_denial():
    """Specific to the secret probe, and the reason it runs as the identity
    rather than borrowing it: a denial on getAccessToken is a denial of the
    impersonation, not of the action under test."""
    assert secret_attempt("read the token", True,
                          raiser(Exception("Failed to impersonate: 403"))) is False


# --- what the reader is told ------------------------------------------------

@pytest.mark.parametrize("attempt", ATTEMPTS)
def test_a_mismatch_explains_itself(attempt, capsys):
    """A mismatch that does not say why is a dead end for whoever reads it."""
    attempt("write a ticket", True, raiser(ServiceUnavailable("connection reset")))
    out = capsys.readouterr().out
    assert "MISMATCH" in out
    assert "connection reset" in out


@pytest.mark.parametrize("attempt", ATTEMPTS)
def test_a_malformed_request_is_labelled_as_one_not_as_an_error(attempt, capsys):
    """ERROR and INVALID REQUEST mean different things to whoever is reading.
    The first says the boundary held oddly; the second says the probe never
    got there. Collapsing them hides the failure mode this classifier exists
    to separate."""
    attempt("write a ticket", True, raiser(InvalidArgument("bad path")))
    assert "INVALID REQUEST" in capsys.readouterr().out


@pytest.mark.parametrize("attempt", ATTEMPTS)
def test_a_400_is_labelled_as_a_malformed_request_too(attempt, capsys):
    """Same condition reached by message rather than by exception type. It
    was classified correctly and then labelled ERROR anyway."""
    attempt("write a ticket", True, raiser(Exception("400 bad body")))
    assert "INVALID REQUEST" in capsys.readouterr().out
