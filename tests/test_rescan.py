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

"""What a rescan is allowed to conclude.

The dangerous direction is the quiet one. A rescan that fails to resolve a
fixed finding leaves a visible, annoying, correctable ticket. A rescan that
resolves an unfixed one removes a live vulnerability from the fleet's
attention and files a record saying it was handled. These tests are weighted
accordingly: most of them are about refusing to close things.
"""

import pytest

from tools.rescan import (
    STATUS_OPEN,
    STATUS_RESOLVED,
    Outcome,
    reconcile,
)


def finding(fid: str, asset: str, status: str = STATUS_OPEN) -> dict:
    return {"finding_id": fid, "asset_id": asset, "status": status}


def scanned(fid: str, asset: str) -> dict:
    return {"finding_id": fid, "asset_id": asset}


# ---------------------------------------------------------------------------
# The rule itself
# ---------------------------------------------------------------------------

def test_absent_and_covered_is_resolved():
    """The one case that closes a finding: we looked, and it was gone."""
    result = reconcile(
        previous=[finding("RZ-1", "ast-01")],
        scan=[],
        covered_asset_ids=["ast-01"],
        scan_id="scan-02",
    )
    only = result.outcomes[0]
    assert only.outcome is Outcome.RESOLVED
    assert "was covered" in only.reason


def test_absent_but_uncovered_is_unverifiable_not_resolved():
    """The case the coverage manifest exists for.

    Without it this finding is indistinguishable from the one above, and the
    fleet would close a ticket for a host nobody examined.
    """
    result = reconcile(
        previous=[finding("RZ-1", "ast-99")],
        scan=[],
        covered_asset_ids=["ast-01"],
        scan_id="scan-02",
    )
    only = result.outcomes[0]
    assert only.outcome is Outcome.UNVERIFIABLE
    assert only.outcome is not Outcome.RESOLVED
    assert "not covered" in only.reason


def test_still_reported_is_persisting():
    result = reconcile(
        previous=[finding("RZ-1", "ast-01")],
        scan=[scanned("RZ-1", "ast-01")],
        covered_asset_ids=["ast-01"],
        scan_id="scan-02",
    )
    assert result.outcomes[0].outcome is Outcome.PERSISTING


def test_newly_reported_is_new():
    result = reconcile(
        previous=[],
        scan=[scanned("RZ-9", "ast-01")],
        covered_asset_ids=["ast-01"],
        scan_id="scan-02",
    )
    assert result.outcomes[0].outcome is Outcome.NEW


# ---------------------------------------------------------------------------
# Refusing to close things
# ---------------------------------------------------------------------------

def test_a_scan_that_covered_nothing_resolves_nothing():
    """The safety property that matters most.

    A scanner that failed to reach anything reports no findings, which looks
    exactly like a fleet that fixed everything. An empty manifest is what
    tells the two apart, and it must resolve zero.
    """
    previous = [finding(f"RZ-{n}", f"ast-{n:02d}") for n in range(1, 21)]
    result = reconcile(
        previous=previous,
        scan=[],
        covered_asset_ids=[],
        scan_id="scan-02",
    )
    assert result.counts["resolved"] == 0
    assert result.counts["unverifiable"] == 20


def test_partial_coverage_resolves_only_the_covered_half():
    previous = [finding("RZ-1", "ast-01"), finding("RZ-2", "ast-02")]
    result = reconcile(
        previous=previous,
        scan=[],
        covered_asset_ids=["ast-01"],
        scan_id="scan-02",
    )
    resolved = {item.finding_id for item in result.of(Outcome.RESOLVED)}
    unverifiable = {item.finding_id for item in result.of(Outcome.UNVERIFIABLE)}
    assert resolved == {"RZ-1"}
    assert unverifiable == {"RZ-2"}


def test_an_already_resolved_finding_is_left_alone():
    """Re-running a rescan must not resolve anything twice, and must not
    resurrect a finding it closed on the previous run."""
    result = reconcile(
        previous=[finding("RZ-1", "ast-01", status=STATUS_RESOLVED)],
        scan=[],
        covered_asset_ids=["ast-01"],
        scan_id="scan-02",
    )
    assert result.outcomes == ()


def test_reconciling_the_same_scan_twice_is_stable():
    """The whole reconciliation, not just one finding, is idempotent."""
    previous = [finding("RZ-1", "ast-01"), finding("RZ-2", "ast-01")]
    scan = [scanned("RZ-2", "ast-01")]
    first = reconcile(previous=previous, scan=scan,
                      covered_asset_ids=["ast-01"], scan_id="scan-02")

    # Apply the first run's verdicts, the way the store would.
    applied = [
        finding(item.finding_id, item.asset_id,
                status=STATUS_RESOLVED if item.outcome is Outcome.RESOLVED
                else STATUS_OPEN)
        for item in first.outcomes
    ]
    second = reconcile(previous=applied, scan=scan,
                       covered_asset_ids=["ast-01"], scan_id="scan-02")

    assert first.counts["resolved"] == 1
    assert second.counts["resolved"] == 0
    assert second.counts["persisting"] == 1


# ---------------------------------------------------------------------------
# Self-contradictory input
# ---------------------------------------------------------------------------

def test_a_scan_reporting_an_uncovered_asset_is_refused():
    """The manifest and the findings disagree about what was examined.

    Preferring either half is a guess, and both guesses are wrong in a way
    that shows up as a confident closure rather than an error.
    """
    with pytest.raises(ValueError, match="not in its coverage manifest"):
        reconcile(
            previous=[],
            scan=[scanned("RZ-1", "ast-99")],
            covered_asset_ids=["ast-01"],
            scan_id="scan-02",
        )


def test_duplicate_finding_ids_are_refused():
    """Which duplicate survives decides whether a finding is resolved, and
    under a plain dict build that depends on iteration order."""
    with pytest.raises(ValueError, match="more than once"):
        reconcile(
            previous=[],
            scan=[scanned("RZ-1", "ast-01"), scanned("RZ-1", "ast-01")],
            covered_asset_ids=["ast-01"],
            scan_id="scan-02",
        )


def test_a_record_without_a_finding_id_is_refused():
    with pytest.raises(ValueError, match="no finding_id"):
        reconcile(
            previous=[{"asset_id": "ast-01", "status": STATUS_OPEN}],
            scan=[],
            covered_asset_ids=["ast-01"],
            scan_id="scan-02",
        )


def test_an_empty_scan_id_is_refused():
    """scan_id is recorded as the evidence for every closure it produces, so
    an empty one would file closures citing nothing."""
    with pytest.raises(ValueError, match="scan_id"):
        reconcile(previous=[], scan=[], covered_asset_ids=[], scan_id="  ")


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def test_counts_report_every_outcome_even_at_zero():
    """Missing and zero are different claims. A report that omits
    `unverifiable` because it was empty reads as though nobody asked."""
    result = reconcile(previous=[], scan=[], covered_asset_ids=[],
                       scan_id="scan-02")
    assert set(result.counts) == {o.value for o in Outcome}
    assert all(v == 0 for v in result.counts.values())


def test_every_outcome_carries_a_reason():
    """The reason is the audit trail a person reads when they want to know
    why something they remember stopped being chased."""
    result = reconcile(
        previous=[finding("RZ-1", "ast-01"), finding("RZ-2", "ast-99"),
                  finding("RZ-3", "ast-01")],
        scan=[scanned("RZ-3", "ast-01"), scanned("RZ-4", "ast-01")],
        covered_asset_ids=["ast-01"],
        scan_id="scan-02",
    )
    assert len(result.outcomes) == 4
    for item in result.outcomes:
        assert item.reason.strip()
        assert "scan-02" in item.reason
