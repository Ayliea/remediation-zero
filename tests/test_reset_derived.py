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

"""What the reset script is allowed to delete.

This is the only script in the repository that removes anything, so its blast
radius is asserted rather than reviewed. The test reads the source: a guarantee
that depends on nobody adding a collection name later is not a guarantee.
"""

from pathlib import Path

import pytest

from scripts.reset_derived import CLEARABLE, PROTECTED, refuse_reason

SOURCE = (Path(__file__).resolve().parents[1] / "scripts" / "reset_derived.py").read_text()


def test_it_clears_exactly_the_two_derived_collections():
    """Derived state can be rebuilt by re-running chase. Nothing else can."""
    assert CLEARABLE == frozenset({"sla_clocks", "tickets"})


def test_the_reference_and_adjudication_records_are_protected():
    for name in (
        "findings", "assets", "owners",       # seeded, never regenerable in place
        "decisions", "human_queue",           # the adjudication record
        "idempotency",                        # what the resume control checks
        "exceptions", "assignments", "cycles", "reports",
    ):
        assert name in PROTECTED
        assert name not in CLEARABLE


def test_nothing_protected_can_be_named_as_a_target():
    for name in PROTECTED:
        assert refuse_reason(name) is not None


def test_an_unknown_collection_is_refused_rather_than_allowed():
    """Default deny. A collection added later is protected until listed."""
    assert refuse_reason("something_invented_next_week") is not None


def test_the_clearable_ones_are_permitted():
    for name in CLEARABLE:
        assert refuse_reason(name) is None


def test_the_source_never_mentions_the_agent_engine_or_its_session():
    """A reset script that can name the engine is one edit from deleting it."""
    for forbidden in ("reasoningEngines", "agent_engine", "delete_session",
                      "AGENT_ENGINE_ID", "ORCHESTRATOR_SESSION_ID"):
        assert forbidden not in SOURCE


def test_the_source_contains_no_collection_group_or_bulk_database_delete():
    """The only deletion path is per-document within an allowlisted collection."""
    for forbidden in ("collection_group", "databases delete", "recursive_delete"):
        assert forbidden not in SOURCE
