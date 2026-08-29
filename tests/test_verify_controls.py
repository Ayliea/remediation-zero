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

"""The suite that reports on the other controls.

Everything this repository claims about least privilege, prompt injection and
resume safety is believed on the strength of what this script prints. So the
part worth testing is not the checks -- each of those performs a real action
against real infrastructure -- but the bookkeeping around them: the three
outcomes, and the selector that decides which checks run at all.

A control suite that collapses "could not run" into "passed" is how a control
ends up believed on the strength of a test that never exercised it.
"""

import os

import pytest

os.environ.setdefault("GOOGLE_CLOUD_PROJECT", "test-project")

import scripts.verify_controls as vc


@pytest.fixture(autouse=True)
def clean_results():
    """The module keeps its results in module-level lists."""
    vc.results.clear()
    vc.inconclusive_checks.clear()
    yield
    vc.results.clear()
    vc.inconclusive_checks.clear()


# --- three outcomes, not two ------------------------------------------------

def test_a_passing_check_is_recorded_as_passed():
    vc.record("a control", True, "detail")
    assert vc.results == [("a control", True, "detail")]


def test_a_failing_check_is_recorded_as_failed():
    vc.record("a control", False, "detail")
    assert vc.results[0][1] is False


def test_a_check_that_could_not_run_never_counts_as_passed():
    """The whole reason there are three outcomes. A check that could not run
    is not a check that passed, and collapsing the two is how a control gets
    believed on the strength of a test that never exercised it."""
    vc.record("a control", True, "no findings in Firestore", inconclusive=True)

    assert vc.results[0][1] is False, "an inconclusive check was scored as passed"
    assert vc.inconclusive_checks == ["a control"]


def test_an_inconclusive_check_is_named_so_it_can_be_chased():
    vc.record("first", True, "d", inconclusive=True)
    vc.record("second", True, "d")
    vc.record("third", True, "d", inconclusive=True)

    assert vc.inconclusive_checks == ["first", "third"]


def test_an_inconclusive_check_is_marked_differently_on_screen(capsys):
    """PASS, FAIL and unknown have to be distinguishable at a glance, because
    the demo shows this output rather than reading it aloud."""
    vc.record("a control", True, "detail", inconclusive=True)
    out = capsys.readouterr().out
    assert "PASS" not in out
    assert "????" in out


def test_the_detail_is_always_printed(capsys):
    """A result with no evidence beside it is an assertion."""
    vc.record("a control", True, "before={} after={}")
    assert "before={} after={}" in capsys.readouterr().out


# --- the selector -----------------------------------------------------------

def test_every_check_is_registered_with_a_name_and_a_callable():
    for key, (name, fn) in vc.CHECKS.items():
        assert isinstance(name, str) and name.strip(), key
        assert callable(fn), key


def test_the_six_claims_are_all_registered():
    """Six is the number the README, CLAUDE.md and the runbook all state. A
    check quietly dropped from this dict would take its claim with it while
    every document still promised it."""
    assert set(vc.CHECKS) == {
        "armor", "reviewer", "probe", "secret", "resume", "coverage"}


def test_no_two_checks_share_a_description():
    """The description is what the reader matches against the claim."""
    names = [name for name, _ in vc.CHECKS.values()]
    assert len(names) == len(set(names))


def test_the_slow_checks_are_separately_selectable():
    """probe and secret are Cloud Run jobs and cost minutes. The demo starts
    them in pre-flight, which is only possible because they can be named
    apart from the fast ones."""
    assert "probe" in vc.CHECKS and "secret" in vc.CHECKS


def test_the_coverage_check_is_not_bundled_into_a_slow_selector():
    """It reads Firestore and computes; it belongs with the fast set, and the
    runbook puts it there."""
    assert "coverage" in vc.CHECKS
