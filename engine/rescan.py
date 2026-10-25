# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""The rescan stage: apply a follow-up scan to what the fleet is already chasing.

This is the only path that can mark a finding resolved. It is called by
`scripts/rescan.py` in the cloud and by the local edition's command line,
never by an agent: chase reads a resolution, it does not make one.

Everything it concludes it concludes from two inputs: what the scan reported,
and which assets the scan actually examined. A dry run reconciles, logs the
same summary, and writes nothing to any collection or the journal.

Standard library only: nothing here imports a cloud SDK.
"""
import json
import logging
from pathlib import Path

from engine.ports import Ports
from tools.rescan import Outcome, reconcile
from tools.scan_store import ScanWriter

logger = logging.getLogger("remediation_zero.rescan")


def _log(event: str, cycle_id: str, finding_id: str, **fields) -> None:
    logger.info(json.dumps(
        {"event": event, "cycle_id": cycle_id, "finding_id": finding_id, **fields},
        sort_keys=True, default=str))


def load_scan(path: Path) -> dict:
    """Read a scan file, refusing one that cannot support a closure.

    A scan missing its coverage manifest is the dangerous shape: reconcile
    would read the absent key as an empty set, resolve nothing, and report
    success. That is the safe direction, but it is a silent no-op dressed as a
    clean run, and the next person concludes the fleet found nothing to close.
    """
    scan = json.loads(path.read_text(encoding="utf-8"))

    for key in ("scan_id", "covered_asset_ids", "findings"):
        if key not in scan:
            raise ValueError(f"{path.name} has no '{key}'. A scan without one "
                             f"cannot justify a closure.")
    return scan


def run_rescan(ports: Ports, cycle: int, scan: dict, dry_run: bool) -> dict:
    """Reconcile `scan` against `findings` and, unless `dry_run`, record it."""
    if not dry_run and ports.journal is None:
        # Refuse before any read or write: every apply write is keyed.
        raise ValueError("rescan apply needs a journal")
    if scan.get("source") == "greenbone" and "withheld_finding_ids" not in scan:
        # Without the list a low-quality re-sighting reads as absence and would
        # falsely close the finding. Refuse before any read or write.
        raise ValueError("greenbone scan is missing withheld_finding_ids; "
                         "refusing to reconcile")
    cycle_id = f"cycle-{cycle:03d}"

    previous = [doc.to_dict() for doc in ports.docs.collection("findings").stream()]
    _log("rescan_started", cycle_id, "-", scan_id=scan["scan_id"],
         previous_findings=len(previous), reported=len(scan["findings"]),
         covered_assets=len(scan["covered_asset_ids"]), dry_run=dry_run)

    reconciliation = reconcile(
        previous=previous,
        scan=scan["findings"],
        covered_asset_ids=scan["covered_asset_ids"],
        scan_id=scan["scan_id"],
        task_id=scan.get("task_id"),
        withheld_finding_ids=scan.get("withheld_finding_ids", ()),
    )

    counts = reconciliation.counts

    if dry_run:
        for item in reconciliation.of(Outcome.RESOLVED)[:5]:
            _log("would_resolve", cycle_id, item.finding_id,
                 asset_id=item.asset_id, reason=item.reason)
        for item in reconciliation.of(Outcome.UNVERIFIABLE)[:5]:
            _log("would_leave_open", cycle_id, item.finding_id,
                 asset_id=item.asset_id, reason=item.reason)
        _log("rescan_dry_run", cycle_id, "-", scan_id=scan["scan_id"],
             counts=counts)
        return {"cycle": cycle_id, "scan_id": scan["scan_id"],
                "counts": counts, "written": False}

    writer = ScanWriter(store=ports.journal, client=ports.docs, clock=ports.clock)

    # The manifest first. A run that dies after this leaves coverage evidence
    # with fewer closures than it warrants, which re-running repairs. The
    # reverse leaves closures whose evidence was never stored, and nothing
    # remaining records what the scan actually looked at.
    writer.record_scan(reconciliation, cycle=cycle, provenance={
        key: scan[key] for key in ("source", "task_id", "report_status")
        if scan.get(key) is not None})
    resolved = writer.resolve(reconciliation, cycle=cycle)
    reopened = writer.reopen(reconciliation, cycle=cycle)
    added = writer.ingest_new(reconciliation, scan["findings"], cycle=cycle)

    _log("rescan_finished", cycle_id, "-", scan_id=scan["scan_id"],
         counts=counts, newly_resolved=resolved, newly_reopened=reopened,
         newly_ingested=added)

    return {"cycle": cycle_id, "scan_id": scan["scan_id"], "counts": counts,
            "newly_resolved": resolved, "newly_reopened": reopened,
            "newly_ingested": added, "written": True}
