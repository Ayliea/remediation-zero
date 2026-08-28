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

"""The failure-handling section of CLAUDE.md, checked against the code.

That section claimed a circuit breaker for most of this project's life. There
was never one. The claim survived because nothing compared it to anything: a
prose bullet in a document is not reachable from a test, so it cannot fail, and
a statement that cannot fail is not evidence of anything.

The bullets now name specific constants. These cases assert those constants
exist and hold the stated values, so changing a cap without changing the
sentence that describes it fails here rather than in front of a reader.

Deliberately narrow. This does not attempt to parse English out of the
document; it pins the three numbers the document commits to, and asserts that
the absence of a breaker is still stated as an absence.
"""

from pathlib import Path

import pytest

from tools.adjudication import MAX_REVIEW_ATTEMPTS, adjudicate

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def claude_md() -> str:
    return (REPO_ROOT / "CLAUDE.md").read_text()


def test_the_review_loop_cap_is_what_the_document_says() -> None:
    assert MAX_REVIEW_ATTEMPTS == 2


def test_the_capacity_retry_default_is_what_the_document_says() -> None:
    import inspect

    default = inspect.signature(adjudicate).parameters["max_capacity_retries"].default
    assert default == 3


def test_the_graph_retry_cap_is_what_the_document_says() -> None:
    source = (REPO_ROOT / "agents" / "orchestrator" / "graph.py").read_text()
    assert "RetryConfig(max_attempts=4" in source


def test_the_document_states_the_breaker_is_absent(claude_md: str) -> None:
    """If one is ever built, this fails and the sentence gets rewritten."""
    assert "There is no circuit breaker." in claude_md


def test_no_document_claims_a_breaker_that_exists(claude_md: str) -> None:
    """The claim may appear only as a denial, never as an assertion."""
    readme = (REPO_ROOT / "README.md").read_text()
    for name, text in (("CLAUDE.md", claude_md), ("README.md", readme)):
        for line in text.splitlines():
            low = line.lower()
            if "circuit breaker" not in low:
                continue
            assert "no circuit breaker" in low, (
                f"{name} asserts a circuit breaker that does not exist: {line[:90]}"
            )
