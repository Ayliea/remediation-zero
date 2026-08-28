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

"""Reconcile a rescan against what the fleet is already chasing.

This is the input the chase state machine was written for and never had. Its
highest-priority rule is `resolved -> stop, the work is done`, and until now
nothing in the system could set that flag, so every finding ran the full arc to
escalation whether or not anyone had fixed it. The fleet could open and press.
It could not confirm.

Absence is the signal, and absence is treacherous
-------------------------------------------------
A rescan reports what it found. The interesting question is what it did *not*
find, because a vulnerability that has stopped being reported is the only
evidence of remediation a scanner ever gives you.

The trap is that two very different things produce an identical absence:

    the host was examined and is clean      the fix landed
    the host was never examined at all      nobody knows anything

A reconciler that cannot tell those apart closes tickets for machines nobody
looked at, and it does so silently, which makes it worse than not closing them
at all. An un-closed ticket is visible and annoying. A wrongly closed one
removes a real vulnerability from the fleet's attention and leaves a record
saying it was fixed.

So absence alone never resolves anything here. Every scan carries the set of
assets it actually covered, and a finding is resolved only when it is absent
*and* its asset is in that set. A finding whose asset was never reached is
`UNVERIFIABLE`: untouched, still chased, still counted against its SLA. The
fleet keeps pressing on exactly the things it has no evidence about, which is
the behaviour you want from something that presses on your behalf.

That is also what lets the question "how do you know it was fixed?" be answered
with "because we know what we looked at" rather than "because it stopped
appearing".

Nothing here reads a clock, touches a network, or writes anything. It maps
three inputs onto one verdict per finding so the rule can be tested exhaustively
in milliseconds and the callers stay boring.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Mapping

#: Statuses a finding can hold in the reference collection. A finding that is
#: already resolved is not a candidate for resolution again, which is what
#: makes re-running a rescan a no-op rather than a second closure.
STATUS_OPEN = "open"
STATUS_RESOLVED = "resolved"


class Outcome(Enum):
    """What one rescan says about one finding."""

    #: Absent from the rescan, and its asset was covered. The fix landed.
    RESOLVED = "resolved"
    #: Still reported. Nothing changes; the chase continues on its own clock.
    PERSISTING = "persisting"
    #: Absent, but its asset was never scanned. We looked at nothing and so we
    #: know nothing. Deliberately not resolved.
    UNVERIFIABLE = "unverifiable"
    #: Reported now and not before. Enters triage like any other finding.
    NEW = "new"
    #: Reported again after a previous scan resolved it. The fix came off, or
    #: never held. Reopened rather than filed fresh: it is the same finding,
    #: and a duplicate would lose the history of what was already tried.
    REGRESSED = "regressed"


@dataclass(frozen=True)
class FindingOutcome:
    """One verdict, carrying the reason it was reached.

    The reason is stored rather than recomputed at display time because it is
    the audit trail: it is what a person reads six weeks later when they want
    to know why a finding they remember stopped being chased.
    """

    finding_id: str
    asset_id: str
    outcome: Outcome
    reason: str


@dataclass(frozen=True)
class Reconciliation:
    """Every verdict from one rescan, plus what the scan actually covered."""

    scan_id: str
    outcomes: tuple[FindingOutcome, ...]
    covered_asset_ids: frozenset[str]

    def of(self, outcome: Outcome) -> tuple[FindingOutcome, ...]:
        """The verdicts of one kind, in input order."""
        return tuple(item for item in self.outcomes if item.outcome is outcome)

    @property
    def counts(self) -> dict[str, int]:
        """A count per outcome, with every outcome present even at zero.

        Missing keys and zero are different claims. A report that omits
        `unverifiable` because it happened to be empty reads as though the
        question was never asked.
        """
        tally = {outcome.value: 0 for outcome in Outcome}
        for item in self.outcomes:
            tally[item.outcome.value] += 1
        return tally


def _require_unique(records: Iterable[Mapping[str, Any]], *, what: str) -> dict:
    """Index records by finding_id, refusing duplicates.

    A duplicated finding_id in a scan silently discards one of the two under
    any dict-building scheme, and which one survives depends on iteration
    order. Since the survivor decides whether a finding is resolved, that is
    not a difference worth leaving to chance.
    """
    indexed: dict[str, Mapping[str, Any]] = {}
    for record in records:
        finding_id = record.get("finding_id")
        if not finding_id:
            raise ValueError(f"{what} contains a record with no finding_id")
        if finding_id in indexed:
            raise ValueError(f"{what} contains {finding_id} more than once")
        indexed[finding_id] = record
    return indexed


def reconcile(
    *,
    previous: Iterable[Mapping[str, Any]],
    scan: Iterable[Mapping[str, Any]],
    covered_asset_ids: Iterable[str],
    scan_id: str,
) -> Reconciliation:
    """Decide what one rescan says about every finding it bears on.

    Args:
        previous: the findings already in the system, each with `finding_id`,
            `asset_id` and `status`.
        scan: the findings this rescan reported.
        covered_asset_ids: the assets this rescan actually examined. Absence
            only means remediation for an asset in this set.
        scan_id: identifies the scan, and is recorded on everything it
            resolves so a closure can be traced back to its evidence.

    Returns:
        One `FindingOutcome` per finding in `previous`, plus one per finding
        in `scan` that `previous` had never seen.

    Raises:
        ValueError: on duplicate finding ids, a missing finding id, or a scan
            reporting a finding on an asset it claims not to have covered.
            Each of those means the inputs disagree with themselves, and a
            reconciler that proceeds on self-contradictory input produces
            confident wrong answers rather than obvious failures.
    """
    if not scan_id or not scan_id.strip():
        raise ValueError("scan_id must not be empty")

    covered = frozenset(covered_asset_ids)
    previous_by_id = _require_unique(previous, what="previous findings")
    scan_by_id = _require_unique(scan, what="scan findings")

    # A scan cannot report a finding on an asset it says it did not examine.
    # Trusting the findings would resolve things the manifest says were never
    # checked; trusting the manifest would discard a real observation. Neither
    # half is safe to prefer, so the disagreement is the error.
    for finding_id, record in scan_by_id.items():
        asset_id = record.get("asset_id")
        if asset_id not in covered:
            raise ValueError(
                f"scan {scan_id} reports {finding_id} on asset {asset_id}, "
                f"which is not in its coverage manifest. The manifest does not "
                f"describe this scan."
            )

    outcomes: list[FindingOutcome] = []

    for finding_id, record in previous_by_id.items():
        asset_id = record.get("asset_id")

        if record.get("status") == STATUS_RESOLVED:
            # Reported again after being closed. Silently skipping this is how
            # a rescan closes findings and then goes blind to their return:
            # the finding falls through this branch and is not new either, so
            # nothing in the system ever hears about it again.
            if finding_id in scan_by_id:
                outcomes.append(FindingOutcome(
                    finding_id=finding_id,
                    asset_id=asset_id,
                    outcome=Outcome.REGRESSED,
                    reason=(
                        f"reported again by {scan_id} after an earlier scan "
                        f"resolved it. The remediation did not hold."
                    ),
                ))
            # Otherwise still absent, still resolved. Re-running a rescan must
            # not resolve it twice, and must not resurrect it either.
            continue

        if finding_id in scan_by_id:
            outcomes.append(FindingOutcome(
                finding_id=finding_id,
                asset_id=asset_id,
                outcome=Outcome.PERSISTING,
                reason=f"still reported by {scan_id}",
            ))
        elif asset_id in covered:
            outcomes.append(FindingOutcome(
                finding_id=finding_id,
                asset_id=asset_id,
                outcome=Outcome.RESOLVED,
                reason=(
                    f"absent from {scan_id}, and asset {asset_id} was covered "
                    f"by that scan"
                ),
            ))
        else:
            outcomes.append(FindingOutcome(
                finding_id=finding_id,
                asset_id=asset_id,
                outcome=Outcome.UNVERIFIABLE,
                reason=(
                    f"absent from {scan_id}, but asset {asset_id} was not "
                    f"covered by it. Absence is not evidence here."
                ),
            ))

    for finding_id, record in scan_by_id.items():
        if finding_id not in previous_by_id:
            outcomes.append(FindingOutcome(
                finding_id=finding_id,
                asset_id=record.get("asset_id"),
                outcome=Outcome.NEW,
                reason=f"first reported by {scan_id}",
            ))

    return Reconciliation(
        scan_id=scan_id,
        outcomes=tuple(outcomes),
        covered_asset_ids=covered,
    )
