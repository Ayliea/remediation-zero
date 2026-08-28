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

from scripts.reset_derived import (
    CLEARABLE,
    PROTECTED,
    RESCAN_CREATED_MARKER,
    RESCAN_FIELDS,
    SEEDED_STATUS,
    refuse_reason,
    rescan_disposition,
)

SOURCE = (Path(__file__).resolve().parents[1] / "scripts" / "reset_derived.py").read_text()


def test_it_clears_exactly_the_three_derived_collections():
    """Derived state can be recomputed: chase rebuilds the clocks and tickets,
    re-running the rescan rebuilds the scan manifests. Nothing else can."""
    assert CLEARABLE == frozenset({"sla_clocks", "tickets", "scans"})


# --- undoing a rescan, and only a rescan -----------------------------------

def test_a_seeded_finding_is_not_touched():
    """The one that matters. A finding no rescan ever wrote to must be
    invisible to this script, or the reset stops being safe to run."""
    seeded = {"finding_id": "RZ-0001", "asset_id": "ast-01", "status": "open"}
    assert rescan_disposition(seeded) is None


def test_a_finding_a_rescan_created_is_removable():
    created = {"finding_id": "RZ-0401", "status": "open",
               RESCAN_CREATED_MARKER: "rescan-01"}
    assert rescan_disposition(created) == "created"


def test_a_seeded_finding_a_rescan_resolved_is_annotated_not_created():
    """It gets its fields stripped, never deleted. Deleting it would remove a
    finding the seed wrote, which no reset is allowed to do."""
    resolved = {"finding_id": "RZ-0005", "status": "resolved",
                "resolved_by_scan": "rescan-01", "resolved_cycle": 12}
    assert rescan_disposition(resolved) == "annotated"


def test_a_regressed_finding_is_annotated_too():
    regressed = {"finding_id": "RZ-0005", "status": "open",
                 "regressed_in_scan": "rescan-02"}
    assert rescan_disposition(regressed) == "annotated"


def test_every_field_the_rescan_path_writes_is_listed_for_removal():
    """A field added to the rescan writer and not here survives the reset,
    leaving a finding that says open while still carrying its resolution."""
    import tools.scan_store as store
    source = (Path(__file__).resolve().parents[1] / "tools" / "scan_store.py").read_text()

    for field in ("resolved_by_scan", "resolved_reason", "resolved_cycle",
                  "resolved_real_ts", "resolved_sim_ts", "regressed_in_scan",
                  "regressed_cycle", "regressed_real_ts", "regressed_sim_ts"):
        assert f'"{field}"' in source, f"{field} is not written by scan_store"
        assert field in RESCAN_FIELDS, f"{field} would survive a reset"


def test_the_created_marker_is_not_in_the_strip_list():
    """Findings carrying it are deleted outright, so stripping it would leave
    an orphan the seed never wrote and the reset can no longer recognise."""
    assert RESCAN_CREATED_MARKER not in RESCAN_FIELDS


def test_the_restored_status_is_what_the_seed_writes():
    import json
    corpus = json.loads(
        (Path(__file__).resolve().parents[1] / "data" / "findings.json").read_text())
    assert {record["status"] for record in corpus} == {SEEDED_STATUS}


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
