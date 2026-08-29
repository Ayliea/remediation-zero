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

"""The rescan driver's own logic, and the corpus it runs against.

The reconciler is tested elsewhere. What is tested here is everything around
it: whether a scan file that cannot support a closure is refused, and whether
the generated corpus satisfies the invariants the reconciler will enforce at
runtime rather than only at demo time.
"""

import json

import pytest

from scripts.gen_rescan import COVERAGE_RATE, NEW_FINDING_COUNT, SCAN_ID, build
from scripts.rescan import load_scan
from tools.rescan import Outcome, reconcile


# --- refusing a scan that cannot justify a closure --------------------------

@pytest.mark.parametrize("missing", ["scan_id", "covered_asset_ids", "findings"])
def test_a_scan_missing_a_required_key_is_refused(tmp_path, missing):
    """The dangerous shape is a missing manifest: reconcile would read the
    absent key as an empty set, resolve nothing, and report success. That is
    the safe direction, but it is a silent no-op dressed as a clean run, and
    the next person concludes the fleet found nothing to close."""
    scan = {"scan_id": "s", "covered_asset_ids": [], "findings": []}
    del scan[missing]
    path = tmp_path / "scan.json"
    path.write_text(json.dumps(scan))

    with pytest.raises(ValueError, match=missing):
        load_scan(path)


def test_a_complete_scan_loads(tmp_path):
    path = tmp_path / "scan.json"
    path.write_text(json.dumps(
        {"scan_id": "s", "covered_asset_ids": ["ast-01"], "findings": []}))

    assert load_scan(path)["scan_id"] == "s"


def test_an_empty_manifest_is_accepted_but_resolves_nothing(tmp_path):
    """An empty list is a real answer -- a scan that reached nothing -- and is
    different from the key being absent. It loads, and closes nothing."""
    path = tmp_path / "scan.json"
    path.write_text(json.dumps(
        {"scan_id": "s", "covered_asset_ids": [], "findings": []}))
    scan = load_scan(path)

    result = reconcile(previous=[{"finding_id": "RZ-1", "asset_id": "ast-01",
                                  "status": "open"}],
                       scan=scan["findings"],
                       covered_asset_ids=scan["covered_asset_ids"],
                       scan_id=scan["scan_id"])
    assert result.counts["resolved"] == 0


# --- the generated corpus ---------------------------------------------------

@pytest.fixture(scope="module")
def scan():
    return build()


def test_the_generator_is_deterministic():
    """The file is committed and the demo is rehearsed against it. A generator
    that drifts makes every measured number in the runbook a guess."""
    assert build() == build()


def test_the_committed_file_matches_the_generator(scan):
    """Regenerating must produce no diff, or the committed corpus and the code
    that claims to produce it have separated."""
    from pathlib import Path
    committed = json.loads(
        (Path(__file__).resolve().parents[1] / "data" / "rescan-01.json").read_text())
    assert committed == scan


def test_the_scan_satisfies_the_reconciler_it_will_be_fed_to(scan):
    """reconcile refuses a scan reporting a finding on an asset its manifest
    excludes. The generator is written to satisfy that check rather than the
    check being loosened to accept whatever it emits."""
    from pathlib import Path
    previous = json.loads(
        (Path(__file__).resolve().parents[1] / "data" / "findings.json").read_text())

    result = reconcile(previous=previous, scan=scan["findings"],
                       covered_asset_ids=scan["covered_asset_ids"],
                       scan_id=scan["scan_id"])
    assert sum(result.counts.values()) > 0


def test_every_reported_finding_is_on_a_covered_asset(scan):
    """The invariant the check above enforces, asserted directly so a failure
    names the cause rather than the symptom."""
    covered = set(scan["covered_asset_ids"])
    offenders = [f["finding_id"] for f in scan["findings"]
                 if f["asset_id"] not in covered]
    assert not offenders, f"reported on unscanned assets: {offenders[:5]}"


def test_coverage_is_partial_on_purpose(scan):
    """The assets it misses are what make unverifiable reachable. Full
    coverage would quietly delete the outcome the whole design exists to
    produce."""
    from pathlib import Path
    assets = json.loads(
        (Path(__file__).resolve().parents[1] / "data" / "assets.json").read_text())

    covered = len(scan["covered_asset_ids"])
    assert 0 < covered < len(assets)
    assert covered == int(len(assets) * COVERAGE_RATE)


def test_the_rescan_produces_all_the_outcomes_the_demo_shows(scan):
    """Resolved, persisting and unverifiable must all be non-empty, or a
    section of the runbook has nothing behind it."""
    from pathlib import Path
    previous = json.loads(
        (Path(__file__).resolve().parents[1] / "data" / "findings.json").read_text())
    counts = reconcile(previous=previous, scan=scan["findings"],
                       covered_asset_ids=scan["covered_asset_ids"],
                       scan_id=scan["scan_id"]).counts

    for outcome in ("resolved", "persisting", "unverifiable", "new"):
        assert counts[outcome] > 0, f"{outcome} is empty; the demo shows nothing"


def test_new_findings_do_not_collide_with_the_seeded_corpus(scan):
    """They are numbered past the original 400. A collision would overwrite a
    seeded finding on ingest rather than adding one."""
    from pathlib import Path
    previous = json.loads(
        (Path(__file__).resolve().parents[1] / "data" / "findings.json").read_text())
    seeded = {f["finding_id"] for f in previous}

    new = [f["finding_id"] for f in scan["findings"] if f["finding_id"] not in seeded]
    assert len(new) == NEW_FINDING_COUNT
    assert not (set(new) & seeded)


def test_no_new_finding_carries_the_planted_payload(scan):
    """The injection lives on exactly one finding in the original corpus. A
    second would make the two-layer defence check ambiguous about what it
    caught."""
    assert not any(f.get("injection_planted") for f in scan["findings"])


def test_every_reported_finding_carries_the_scan_that_reported_it(scan):
    assert all(f["scan_id"] == SCAN_ID for f in scan["findings"])
