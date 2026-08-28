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

"""Deploys that report success while removing a capability.

deploy-worker.sh reads the tracker repository from the deploy-time shell. Run
from a terminal that never exported GITHUB_TICKET_REPO, it produced a deploy
that looked entirely healthy -- new revision, 100% traffic, no error -- whose
only symptom was `delivery_disabled` in a log line nobody reads. The worker
came back unable to file a ticket.

That happened on 2026-08-28 while redeploying the workers to pick up the
reopen fix, and it is the same shape as the registry PATCH that omitted
updateMask: an operation that succeeds and does not do the thing.

Losing a capability is not the same as never having had one. The guard
compares this invocation against what the running service can already do, and
refuses rather than quietly downgrading it.

Structural assertions. The behavioural check needs a live service to describe,
and is recorded in the commit that added the guard: run without the variable,
exit 1, no build submitted.
"""

from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "deploy-worker.sh"


@pytest.fixture(scope="module")
def source() -> str:
    return SCRIPT.read_text()


def test_the_guard_exists(source: str) -> None:
    assert "REFUSING" in source, "the delivery-drop guard is gone"


def test_the_guard_consults_the_running_service(source: str) -> None:
    """Comparing against the deployed state is the whole mechanism.

    Checking only whether the variable is set cannot tell a first deploy from a
    downgrade, and refusing the first deploy would be wrong.
    """
    assert "LIVE_REPO" in source
    assert "gcloud run services describe" in source.split("REFUSING")[0]


def test_the_guard_refuses_rather_than_warning(source: str) -> None:
    """Pinned to the guard's own line, not to any exit that follows it.

    The first version of this case asserted `"exit 1" in tail`. A different
    guard later in the same script also exits 1, so removing this one's refusal
    left the assertion passing -- a check that could not fail for the reason it
    claimed to test, which is the exact defect this suite keeps finding
    elsewhere. Caught by mutation, which is the only reason it is written this
    way.
    """
    guard = source.split("REFUSING", 1)[1].split("\nfi\n", 1)[0]
    refusals = [
        line.strip() for line in guard.splitlines()
        if "DROP_DELIVERY" in line and "exit 1" in line
    ]
    assert refusals, (
        "the guard prints REFUSING but no longer exits; a warning that still "
        "deploys is not a guard"
    )


def test_the_downgrade_can_still_be_asked_for_deliberately(source: str) -> None:
    """A guard with no way past it gets deleted the first time it is wrong."""
    assert "DROP_DELIVERY" in source


def test_the_guard_runs_before_the_build(source: str) -> None:
    """Refusing after a container build wastes money on a project with none."""
    guard_at = source.index("REFUSING")
    build_at = source.index("gcloud builds submit")
    assert guard_at < build_at, "the guard refuses only after paying for a build"
