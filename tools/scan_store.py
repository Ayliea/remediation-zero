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

"""Persist what a rescan concluded.

`tools.rescan` decides; this writes. They are separate because the deciding is
the part worth testing exhaustively and the writing is the part that needs a
database, and fusing them would have made the first only testable through the
second.

Where each thing lands, and why
-------------------------------
`findings` is a reference collection: what the scanner observed. A resolution
is an observation -- a scanner stopped reporting something on a host it
checked -- so it is recorded there, by an ingestion script, exactly as the
original findings were.

`tickets` is chase's collection: what the fleet did about it. Nothing here
touches it. Chase reads the finding, sees it resolved, and closes its own
ticket on its own next cycle. That keeps the boundary the whole system is
built on intact: no writer reaches into another agent's collection, not even
to save a round trip.

`scans` is new, and it holds the coverage manifest. It exists because a
closure is only as good as the evidence for it, and the evidence is "this scan
examined this asset". Storing the manifest is what lets someone reconstruct,
months later, why a particular finding was closed -- and check whether that
was justified. A closure whose coverage record has been discarded is an
assertion, not a finding.
"""

import json
import logging
from typing import Any, Iterable, Optional

from google.cloud import firestore

from tools.clock import SimClock
from tools.idempotency import IdempotencyGuard
from tools.rescan import STATUS_RESOLVED, Outcome, Reconciliation

logger = logging.getLogger(__name__)

FINDINGS = "findings"
SCANS = "scans"


def _log(event: str, cycle: int, finding_id: str, **fields: Any) -> None:
    logger.info(json.dumps(
        {"event": event, "cycle_id": str(cycle), "finding_id": finding_id, **fields},
        sort_keys=True, default=str,
    ))


class ScanWriter:
    """Applies one reconciliation to the reference collections."""

    def __init__(
        self,
        store,
        client: Optional[firestore.Client] = None,
        clock: Optional[SimClock] = None,
    ) -> None:
        self._client = client or firestore.Client()
        self._clock = clock or SimClock.from_env()
        self._guard = IdempotencyGuard(store)

    # -- the manifest --------------------------------------------------------

    def record_scan(self, reconciliation: Reconciliation, cycle: int) -> str:
        """Store the scan and what it covered.

        Written before any resolution it justifies. If the run dies halfway,
        the surviving state is a manifest with fewer closures than it warrants,
        which is recoverable by re-running. The reverse -- closures whose
        coverage evidence was never stored -- is not recoverable, because
        nothing left records what the scan actually looked at.
        """
        stamp = self._clock.now()
        scan_id = reconciliation.scan_id

        @self._guard.protects(action="record_scan")
        def _perform(*, finding_id: str, cycle: int) -> str:
            self._client.collection(SCANS).document(scan_id).set({
                "scan_id": scan_id,
                "covered_asset_ids": sorted(reconciliation.covered_asset_ids),
                "counts": reconciliation.counts,
                "cycle": cycle,
                "real_ts": stamp.real_ts,
                "sim_ts": stamp.sim_ts,
            })
            _log("scan_recorded", cycle, "-", scan_id=scan_id,
                 covered=len(reconciliation.covered_asset_ids),
                 counts=reconciliation.counts)
            return f"scan:{scan_id}"

        # The scan is not a finding, so the idempotency key is derived from the
        # scan id in the finding slot. It is still one action, on one subject,
        # in one cycle, which is what the key is actually about.
        return _perform(finding_id=scan_id, cycle=cycle)

    # -- resolutions ---------------------------------------------------------

    def resolve(self, reconciliation: Reconciliation, cycle: int) -> int:
        """Mark every confirmed-remediated finding resolved.

        Returns the number of findings this call resolved, which is zero on a
        repeat run rather than the same number again.
        """
        stamp = self._clock.now()
        resolved = 0

        for item in reconciliation.of(Outcome.RESOLVED):
            # The guard returns a suppressed call's original result verbatim,
            # deliberately, so the caller cannot tell it was suppressed. That
            # makes the return value useless for counting: on a repeat run it
            # is the same truthy string as the first time. This flag is the
            # only honest way to report how many findings this call actually
            # changed, and reporting "106 resolved" on a re-run of a scan that
            # resolved nothing would misstate the one number a reviewer checks.
            ran = False

            @self._guard.protects(action="resolve_finding")
            def _perform(*, finding_id: str, cycle: int, item=item) -> str:
                nonlocal ran
                ran = True
                self._client.collection(FINDINGS).document(finding_id).update({
                    "status": STATUS_RESOLVED,
                    "resolved_by_scan": reconciliation.scan_id,
                    "resolved_reason": item.reason,
                    "resolved_cycle": cycle,
                    "resolved_real_ts": stamp.real_ts,
                    "resolved_sim_ts": stamp.sim_ts,
                })
                _log("finding_resolved", cycle, finding_id,
                     scan_id=reconciliation.scan_id, asset_id=item.asset_id,
                     reason=item.reason)
                return f"resolved:{finding_id}"

            _perform(finding_id=item.finding_id, cycle=cycle)
            if ran:
                resolved += 1

        return resolved

    # -- regressions ---------------------------------------------------------

    def reopen(self, reconciliation: Reconciliation, cycle: int) -> int:
        """Return regressed findings to open so the fleet chases them again.

        The resolution fields are cleared rather than left in place. A finding
        carrying both `status: open` and `resolved_by_scan` is a record that
        contradicts itself, and the next person to read it has to guess which
        half is current. The scan that saw it come back is recorded instead,
        so the history stays legible without staying ambiguous.

        Chase reopens the tracker issue on its own next cycle: the finding is
        no longer resolved and its ticket is no longer open, which is exactly
        the state that makes it file one, and open_issue already reopens an
        existing closed issue rather than filing a duplicate.
        """
        stamp = self._clock.now()
        reopened = 0

        for item in reconciliation.of(Outcome.REGRESSED):
            ran = False

            @self._guard.protects(action="reopen_finding")
            def _perform(*, finding_id: str, cycle: int, item=item) -> str:
                nonlocal ran
                ran = True
                self._client.collection(FINDINGS).document(finding_id).update({
                    "status": "open",
                    "resolved_by_scan": firestore.DELETE_FIELD,
                    "resolved_reason": firestore.DELETE_FIELD,
                    "resolved_cycle": firestore.DELETE_FIELD,
                    "resolved_real_ts": firestore.DELETE_FIELD,
                    "resolved_sim_ts": firestore.DELETE_FIELD,
                    "regressed_in_scan": reconciliation.scan_id,
                    "regressed_cycle": cycle,
                    "regressed_real_ts": stamp.real_ts,
                    "regressed_sim_ts": stamp.sim_ts,
                })
                _log("finding_regressed", cycle, finding_id,
                     scan_id=reconciliation.scan_id, asset_id=item.asset_id,
                     reason=item.reason)
                return f"reopened:{finding_id}"

            _perform(finding_id=item.finding_id, cycle=cycle)
            if ran:
                reopened += 1

        return reopened

    # -- new findings --------------------------------------------------------

    def ingest_new(
        self,
        reconciliation: Reconciliation,
        scan_findings: Iterable[dict],
        cycle: int,
    ) -> int:
        """Add findings this scan reported for the first time.

        They land in `findings` with status open and no triage decision, which
        is exactly the state the original corpus starts in, so the existing
        triage and assignment path picks them up on the next cycle with no
        special case for having arrived late.
        """
        from tools.ingest import to_document

        by_id = {record["finding_id"]: record for record in scan_findings}
        added = 0

        for item in reconciliation.of(Outcome.NEW):
            record = by_id.get(item.finding_id)
            if record is None:
                continue

            ran = False

            @self._guard.protects(action="ingest_finding")
            def _perform(*, finding_id: str, cycle: int, record=record) -> str:
                nonlocal ran
                ran = True
                document = to_document(record, self._clock, kind="findings")
                document["status"] = "open"
                document["first_seen_scan"] = reconciliation.scan_id
                self._client.collection(FINDINGS).document(finding_id).set(document)
                _log("finding_ingested", cycle, finding_id,
                     scan_id=reconciliation.scan_id)
                return f"ingested:{finding_id}"

            _perform(finding_id=item.finding_id, cycle=cycle)
            if ran:
                added += 1

        return added
