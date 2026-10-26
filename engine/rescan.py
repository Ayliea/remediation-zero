# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""The rescan stage: apply a follow-up scan to what the fleet is already chasing.

This is the only path that can mark a finding resolved. It is called by
`scripts/rescan.py` in the cloud, by the local edition's `rescan` command (demo
workspaces) and by the Greenbone import (`engine.scanner_import`), never by an
agent: chase reads a resolution, it does not make one. In a workspace holding
Greenbone findings a scan without a task id is refused before any write.

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


class GreenboneWorkspace(ValueError):
    """An untasked scan was offered to a workspace that imports from Greenbone."""


def holds_greenbone_findings(docs) -> bool:
    """True when any stored finding came from Greenbone (`source == "greenbone"`)."""
    return any((snap.to_dict() or {}).get("source") == "greenbone"
               for snap in docs.collection("findings").stream())


def run_rescan(ports: Ports, cycle: int, scan: dict, dry_run: bool) -> dict:
    """Reconcile `scan` against `findings` and, unless `dry_run`, record it."""
    if not dry_run and ports.journal is None:
        # Refuse before any read or write: every apply write is keyed.
        raise ValueError("rescan apply needs a journal")
    if not scan.get("task_id") and holds_greenbone_findings(ports.docs):
        # Before any write. A scan without a task id runs no task filter, so in
        # a Greenbone workspace it could close every task's findings, and a
        # synthetic scan would mix demo data into real data. Only the import
        # path (greenbone pull / upload / the timer) reconciles here.
        raise GreenboneWorkspace("this workspace imports from Greenbone; a scan without a "
                                 "task id is refused so it cannot resolve or add findings. "
                                 "Nothing was written.")
    if scan.get("source") == "greenbone":
        # Fail closed before any read or write. Without a task id no task
        # filter runs and the scan could close findings of every task; without
        # the withheld list a low-quality re-sighting reads as absence.
        if not scan.get("task_id"):
            raise ValueError("greenbone scan is missing task_id; "
                             "refusing to reconcile")
        if "withheld_finding_ids" not in scan:
            raise ValueError("greenbone scan is missing withheld_finding_ids; "
                             "refusing to reconcile")
        withheld = scan["withheld_finding_ids"]
        if not (isinstance(withheld, (list, tuple))
                and all(isinstance(item, str) for item in withheld)):
            raise ValueError("greenbone scan withheld_finding_ids must be a "
                             "list of strings; refusing to reconcile")
    unfinished = scan.get("unfinished_checks", [])
    if not (isinstance(unfinished, (list, tuple)) and all(
            isinstance(pair, (list, tuple)) and len(pair) == 2
            and all(isinstance(part, str) for part in pair) for pair in unfinished)):
        raise ValueError("scan unfinished_checks must be a list of [asset_id, nvt_oid]; "
                         "refusing to reconcile")
    cycle_id = f"cycle-{cycle:03d}"

    previous = [doc.to_dict() for doc in ports.docs.collection("findings").stream()]
    # A check that did not finish did not re-test its findings on that host: each is
    # withheld, so its absence leaves it open (unverifiable) rather than resolved.
    unchecked = {tuple(pair) for pair in unfinished}
    withheld_ids = list(scan.get("withheld_finding_ids", ())) + [
        record["finding_id"] for record in previous
        if (record.get("asset_id"), record.get("nvt_oid")) in unchecked and record.get("finding_id")]
    _log("rescan_started", cycle_id, "-", scan_id=scan["scan_id"],
         previous_findings=len(previous), reported=len(scan["findings"]),
         covered_assets=len(scan["covered_asset_ids"]), dry_run=dry_run)

    reconciliation = reconcile(
        previous=previous,
        scan=scan["findings"],
        covered_asset_ids=scan["covered_asset_ids"],
        scan_id=scan["scan_id"],
        task_id=scan.get("task_id"),
        withheld_finding_ids=list(dict.fromkeys(withheld_ids)),
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
