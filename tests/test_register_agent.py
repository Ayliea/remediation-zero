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

"""The registry publish had two faults that concealed each other.

The PATCH that publishes the agent card omitted `updateMask`. That is not an
error in this API: it returns a healthy long-running operation and changes
nothing. So the registry entry sat on a version eleven commits old.

The discoverability check that should have caught it broke out of its search
loop on any entry whose display name contained "Remediation Zero", without
comparing versions. It therefore matched the stale entry and reported success
in about two seconds. A check that cannot fail for the reason it claims to test
is worse than no check, because it is counted as evidence.

These are structural assertions against the script text rather than behavioural
ones, because the behaviour needs a live catalogue. They exist to stop the two
specific regressions, each of which was individually silent and jointly
invisible.
"""

import re
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "register-agent.sh"


@pytest.fixture(scope="module")
def source() -> str:
    return SCRIPT.read_text()


def test_patch_sends_an_update_mask(source: str) -> None:
    """Without updateMask the update is accepted and discarded."""
    patch_line = next(
        (ln for ln in source.splitlines() if "agentregistry.googleapis.com/v1/${EXISTING}" in ln),
        None,
    )
    assert patch_line is not None, "the PATCH target URL is no longer recognisable"
    assert "updateMask=" in patch_line, (
        "the PATCH omits updateMask, so it will report success and change nothing"
    )


def test_update_mask_names_every_mutable_field(source: str) -> None:
    """A field left out of the mask silently keeps its previous value."""
    patch_line = next(
        ln for ln in source.splitlines() if "agentregistry.googleapis.com/v1/${EXISTING}" in ln
    )
    # Take only the field names, stopping at whatever shell quoting follows.
    mask = re.match(r"[A-Za-z.,]+", patch_line.split("updateMask=", 1)[1]).group(0)
    named = {f for f in mask.split(",") if f}
    # These are the keys the request body sets; see the BODY construction above
    # it. agentSpec is the one that carries the version.
    assert {"displayName", "description", "agentSpec"} <= named, (
        f"updateMask={mask} does not cover every field BODY sets"
    )


def test_search_pins_to_the_published_version(source: str) -> None:
    """Matching on display name alone accepts a stale catalogue entry."""
    assert "RZ_WANT" in source, (
        "the search no longer passes the published version in for comparison"
    )
    assert "got == want" in source, (
        "the search no longer compares the found version against the published one"
    )


def test_a_stale_hit_is_reported_as_stale(source: str) -> None:
    """Found-but-wrong-version and not-found are different failures."""
    assert "FOUND, BUT STALE" in source
    assert "PUBLISHED, BUT NOT FOUND BY SEARCH" in source


def test_the_stale_path_still_exits_nonzero(source: str) -> None:
    """A stale entry must fail the script, not merely print a warning."""
    tail = source.split("FOUND, BUT STALE", 1)[1]
    assert "exit 1" in tail, "a stale catalogue entry no longer fails the run"


def test_version_drift_is_reported_but_not_fatal(source: str) -> None:
    """VERSION is HEAD; the card claims it is what the engine serves.

    Those coincide only when nothing has been committed since the last deploy.
    Nothing records the engine's build commit, so the script compares the
    engine's updateTime against the HEAD commit time and says so when they have
    drifted. It must not exit on it: a commit touching only docs or scripts
    legitimately leaves the engine current, and failing there would make the
    step unrunnable for the common case.
    """
    assert "DRIFT" in source, "the engine/HEAD drift check is gone"
    assert "the running engine was not built from" in source

    drift_branch = source.split('if [[ -n "${DRIFT}" ]]; then', 1)[1].split("fi", 1)[0]
    assert "exit" not in drift_branch, (
        "drift is informational; exiting here would block docs-only commits"
    )
