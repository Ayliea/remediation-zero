# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""The scanner_import stage: Greenbone reports in, task by task, through the rescan path.

This is where a client's real findings enter and where they get closed, so the
failures that matter are false closure, partial writes and silent drops.

- Only explicitly chosen tasks are imported, checked against the task id inside
  the report itself before anything is written. Only Done reports are imported.
- One report per task per cycle, decided before the report is downloaded:
  rescan writes are keyed on (finding, action, cycle), so a second report in one
  cycle would have its resolve suppressed. A task with no imported report yet
  takes only its newest Done report as a baseline; older ones are counted, not
  back-filled. After that, the oldest Done report whose gvmd timestamp is newer
  than the last imported report's scan end. Every import, pulled or uploaded,
  must be strictly newer by its own scan end than the task's last import.
- A report the parser refuses, or one with no scan time or not newer, is
  recorded in `scanner_state[task].refused` (report id and a closed reason, the
  last 20) and the pull moves on to the next newer one. It changes nothing.
- Everything one report writes (asset upserts, then `engine.rescan.run_rescan`
  exactly as it is, then the task's pull state), idempotency keys included,
  commits in one SQLite transaction or not at all. If anything fails after the
  first write, nothing from that report remains, and no stale key can suppress
  the retry.
- A pull that fails writes only the task's pull state: `last_result="failed"`
  and the error class, never the message. The previous import is kept, and the
  next task gets its own GMP session and its own result.
- Seeded demo data and Greenbone data never share a workspace.

Raw rejected entries and server text are never persisted or logged: counts and
fixed reason strings only. Every persisted stamp comes from `ports.clock`.

Standard library only: nothing here imports a cloud SDK.
"""
import dataclasses
import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Collection, Optional

from engine.ports import Ports
from engine.rescan import run_rescan
from engine.scanner_source import (
    DEFAULT_QOD_FLOOR, SOURCE, NormalisedScan, ScannerSource, normalise_greenbone,
    to_rescan_input,
)
from tools.docstore import AlreadyExists
from tools.gmp import GmpReportRefused
from tools.greenbone_report import REFUSAL_REASONS, ReportRefused, parse_report

logger = logging.getLogger("remediation_zero.scanner_import")

STATE = "scanner_state"
DONE = "Done"
#: Most non-Done reports listed per task in the pull state; the rest are counted.
MAX_SKIPPED_LISTED = 50
#: Refused reports remembered per task (`scanner_state[task].refused`).
MAX_REFUSED_KEPT = 20
#: Why a pulled report was refused. Closed, so it can be stored; never server text.
REFUSED_REASONS = frozenset(REFUSAL_REASONS) | {"no_scan_time", "not_newer",
                                                  "scan_time_in_future"}
#: Every closed reason an ImportRefused may carry. `already_imported_this_cycle`
#: is a lost race, not a fault in the report, so it is never stored as a refusal.
IMPORT_REFUSED_REASONS = REFUSED_REASONS | {"already_imported_this_cycle"}
#: Most report downloads per task per pull; the rest wait and are counted as `deferred`.
MAX_DOWNLOADS_PER_PULL = 5
#: How far a scan time may run ahead of the workspace clock (skew), and how far
#: gvmd's listing time and the report's own scan end may disagree. Seconds.
_DAY = 86400.0
#: Nothing scanned before this is plausible: 2000-01-01T00:00:00Z.
_EARLIEST_SCAN = 946684800.0
_UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_STATUS_RE = re.compile(r"[A-Za-z][A-Za-z ]{0,39}")
_NAME_UNSAFE = re.compile(r"[^A-Za-z0-9 ._()\-]")
#: The fixed reasons `tools.gmp` records for a report entry it refused.
_REFUSAL_REASONS = frozenset({"bad report id", "bad status", "bad timestamp"})
#: Fields an asset upsert refreshes on an existing asset. Nothing else is touched,
#: so owner, criticality, environment, internet_facing and anything a person set stay.
_ASSET_REFRESHED = ("ip", "os_cpe", "open_ports")


class ImportRefused(ValueError):
    """A report was refused before anything was written.

    `reason` is set (one of `REFUSED_REASONS`) when the refusal is about the
    report itself rather than the request, so a pull can record it and move on.
    """

    def __init__(self, message: str, *, reason: Optional[str] = None) -> None:
        super().__init__(message)
        if reason is not None and reason not in IMPORT_REFUSED_REASONS:
            raise ValueError(f"unknown refusal reason {reason!r}")
        self.reason = reason


def _cycle_id(cycle: int) -> str:
    return f"cycle-{cycle:03d}"


def _log(event: str, cycle: int, **fields: Any) -> None:
    logger.info(json.dumps({"event": event, "cycle_id": _cycle_id(cycle), "finding_id": "-",
                            **fields}, sort_keys=True, default=str))


# --- the Greenbone source ---------------------------------------------------------------


class GreenboneSource(ScannerSource):
    """A `ScannerSource` over GMP: one fresh client session per task.

    `client_factory()` returns an unopened `tools.gmp.GmpClient` (or a stand-in).
    Any GMP error poisons a client, so each `finished_reports(task_id)` closes the
    previous session and opens a new one, and `fetch` uses that task's session.
    A failure in one task therefore never makes a later task read as having no
    reports. `notes(task_id)` returns what that task's session refused, as a
    count and fixed reason strings only.
    """

    def __init__(self, client_factory: Callable[[], Any], *,
                 qod_floor: int = DEFAULT_QOD_FLOOR) -> None:
        self._factory = client_factory
        self._qod_floor = qod_floor
        self._client: Optional[Any] = None
        self._session = False  # finished_reports has run: fetch may (re)open a session
        self._notes: dict[str, dict] = {}

    def _open(self) -> Any:
        self.close()
        client = self._factory()
        client.__enter__()
        self._client = client
        return client

    def _record(self, task_id: str, client: Any) -> None:
        refused = list(getattr(client, "refused_reports", ()))
        self._notes[task_id] = {
            "refused_reports": len(refused),
            "refused_reasons": [reason if reason in _REFUSAL_REASONS else "other"
                                for _, reason in refused],
            "skipped_tasks": int(getattr(client, "skipped_tasks", 0) or 0),
        }

    def list_tasks(self) -> list[dict]:
        client = self._open()
        try:
            return client.list_tasks()
        finally:
            self.close()

    def finished_reports(self, task_id: str) -> list[dict]:
        self._notes.pop(task_id, None)
        self._session = True
        client = self._open()
        try:
            return client.finished_reports(task_id)
        finally:
            self._record(task_id, client)

    def fetch(self, report_id: str) -> NormalisedScan:
        """Download and normalise one report of the current task.

        Any GMP error poisons the session, so it is closed and the next fetch
        opens a fresh one. A response refused as a document (too large, unsafe,
        not well-formed) becomes `ReportRefused` with that reason and no server
        text, so the pull can record it and try the next report.
        """
        if not self._session:
            raise RuntimeError("fetch needs the task's session from finished_reports")
        client = self._client if self._client is not None else self._open()
        try:
            data = client.report_xml(report_id)
        except GmpReportRefused as exc:
            self.close()
            raise ReportRefused(f"gvmd's response for the report was refused ({exc.reason})",
                                reason=exc.reason) from None
        except BaseException:
            self.close()
            raise
        return normalise_greenbone(parse_report(data), qod_floor=self._qod_floor)

    def notes(self, task_id: str) -> dict:
        return dict(self._notes.get(task_id) or {
            "refused_reports": 0, "refused_reasons": [], "skipped_tasks": 0})

    def close(self) -> None:
        client, self._client = self._client, None
        if client is not None:
            client.__exit__(None, None, None)


# --- import one report ------------------------------------------------------------------


def _holds_seeded_findings(docs) -> bool:
    return any("source" not in snap.to_dict() for snap in docs.collection("findings").stream())


def _refuse_demo(docs) -> None:
    if _holds_seeded_findings(docs):
        raise ImportRefused("this workspace holds seeded demo findings; importing a Greenbone "
                            "report is refused so demo and real data never mix. "
                            "Nothing was written.")


def _upsert_assets(docs, scan: NormalisedScan, stamp) -> None:
    """Assets before findings. Keeps first_seen_*; never overwrites what a person set.

    Only evidence changes an asset: a hostname only when the report supplies
    one, and last_seen_* only for a host the report covered (finished and
    trusted). A host listed but not covered was not seen in any useful sense.
    """
    assets = docs.collection("assets")
    covered = set(scan.covered_asset_ids)
    for asset in scan.assets:
        ref = assets.document(asset["asset_id"])
        seen = asset["asset_id"] in covered
        last_seen = {"last_seen_scan": scan.scan_id, "last_seen_real_ts": stamp.real_ts,
                     "last_seen_sim_ts": stamp.sim_ts} if seen else {}
        if ref.get().exists:
            fields = {key: asset[key] for key in _ASSET_REFRESHED}
            if asset.get("hostname"):
                fields["hostname"] = asset["hostname"]
            ref.update({**fields, **last_seen})
        else:
            new = {key: value for key, value in asset.items() if key != "last_seen_scan"}
            ref.set({**new, **last_seen,
                     "first_seen_real_ts": stamp.real_ts, "first_seen_sim_ts": stamp.sim_ts,
                     "real_ts": stamp.real_ts, "sim_ts": stamp.sim_ts})


def _write_state(docs, task_id: str, fields: dict) -> None:
    """Replace `fields` at the top level of the task's pull state; keep every other field.

    Not `set(merge=True)`: that merges nested maps, so a key that vanished from
    the new `last_counts` would survive from an older import.
    """
    ref = docs.collection(STATE).document(task_id)
    if not ref.get().exists:
        try:
            ref.create({"task_id": task_id, **fields})
            return
        except AlreadyExists:
            pass  # written since we looked: fall through to a field update
    ref.update({"task_id": task_id, **fields})


def _uncovered_all(scan: NormalisedScan) -> bool:
    """Coverage emptied by fail-closed normalisation: the report could not be trusted."""
    return not scan.covered_asset_ids and scan.skipped.get("rejected", 0) > 0


def import_scan(ports: Ports, cycle: int, scan: NormalisedScan, *,
                chosen_task_ids: Collection[str], pull_notes: Optional[dict] = None,
                via: str = "pull") -> dict:
    """Import one normalised report, all of it or none of it.

    Refused (ImportRefused, nothing written) when the report's own task is not
    chosen, its status is not Done, its ids are malformed, it has no scan time,
    the workspace holds seeded findings, the task already imported a report
    this cycle, the report is not newer than the task's last imported one, or
    it was already imported. Returns the rescan summary plus `skipped` and
    `uncovered_all`.

    "Newer" is the report's own scan end (R19): reconciling an older report
    after a newer one would read it as a rescan, resolving findings the newer
    report still shows or reopening ones it saw fixed.
    """
    if ports.journal is None:
        raise ValueError("importing a report needs a journal")
    transaction = getattr(ports.docs, "transaction", None)
    journal_path = getattr(ports.journal, "path", None)
    if transaction is None or not journal_path:
        # Fail closed rather than split one report's writes across commits.
        raise ValueError("importing a report needs a store that can write it in one transaction")
    if scan.source != SOURCE:
        raise ImportRefused(f"report source {scan.source!r} is not {SOURCE!r}")
    if not _UUID_RE.fullmatch(scan.task_id or ""):
        raise ImportRefused("report names a task id that is not a UUID")
    if not _UUID_RE.fullmatch(scan.scan_id or ""):
        raise ImportRefused("report id is not a UUID")
    if scan.task_id not in set(chosen_task_ids):
        raise ImportRefused(f"report is from task {scan.task_id}, which is not chosen "
                            "for this install")
    if scan.report_status != DONE:
        status = scan.report_status if _STATUS_RE.fullmatch(scan.report_status or "") \
            else "unrecognised"
        raise ImportRefused(f"report status is {status}, not Done; only finished scans "
                            "are imported")
    scan_end = _instant(scan.scan_end)
    if scan_end is None:
        raise ImportRefused("report has no scan time; refusing to import",
                            reason="no_scan_time")
    # Plausibility only (R20): the workspace clock's wall time bounds a scan time
    # that would otherwise outrank every later report. Read, compared, never stored.
    if scan_end > ports.clock.now().real_ts + _DAY:
        raise ImportRefused("report scan time is in the future; refusing to import",
                            reason="scan_time_in_future")
    if scan_end < _EARLIEST_SCAN:
        raise ImportRefused("report scan time is before 2000; refusing to import",
                            reason="malformed")

    docs = ports.docs
    with transaction(journal=Path(journal_path), clock=ports.journal.clock) as journal:
        # Checked inside the transaction, which holds the write lock, so a
        # concurrent import cannot slip between the check and the writes.
        _refuse_demo(docs)
        state = docs.collection(STATE).document(scan.task_id).get()
        state = state.to_dict() if state.exists else {}
        if state.get("last_imported_cycle") == cycle:
            raise ImportRefused(f"task {scan.task_id} already imported a report in "
                                f"{_cycle_id(cycle)}; one report per task per cycle",
                                reason="already_imported_this_cycle")
        last_end = _instant(state.get("last_imported_scan_end"))
        if last_end is not None and scan_end <= last_end:
            raise ImportRefused("report is not newer than the last imported report for "
                                "this task", reason="not_newer")
        if docs.collection("scans").document(scan.scan_id).get().exists:
            raise ImportRefused(f"report {scan.scan_id} was already imported")

        stamp = ports.clock.now()
        _upsert_assets(docs, scan, stamp)
        summary = run_rescan(dataclasses.replace(ports, journal=journal), cycle,
                             to_rescan_input(scan), dry_run=False)
        uncovered_all = _uncovered_all(scan)
        notes = pull_notes or {}
        fields = {
            "last_pull_real_ts": stamp.real_ts, "last_pull_sim_ts": stamp.sim_ts,
            "last_result": "imported", "last_error_class": None,
            "last_imported_report_id": scan.scan_id,
            "last_imported_scan_end": scan.scan_end,
            "last_imported_cycle": cycle,
            "last_import_via": via,
            "last_counts": summary["counts"],
            "last_skipped": dict(scan.skipped),
            "last_uncovered_all": uncovered_all,
            "skipped": notes.get("skipped", []),
            "skipped_not_listed": notes.get("skipped_not_listed", 0),
            "baseline_not_imported": notes.get("baseline_not_imported", 0),
            "last_refused_reports": notes.get("refused_reports", 0),
            "last_refused_reasons": notes.get("refused_reasons", []),
            "last_skipped_tasks": notes.get("skipped_tasks", 0),
        }
        if "refused" in notes:
            fields["refused"] = notes["refused"]
        if "deferred" in notes:
            fields["deferred"] = notes["deferred"]
        _write_state(docs, scan.task_id, fields)
    _log("report_imported", cycle, task_id=scan.task_id, scan_id=scan.scan_id,
         counts=summary["counts"], skipped=dict(scan.skipped), uncovered_all=uncovered_all)
    return {**summary, "skipped": dict(scan.skipped), "uncovered_all": uncovered_all}


# --- pull -------------------------------------------------------------------------------


def _instant(stamp: Any) -> Optional[float]:
    """An ISO 8601 time as epoch seconds; None if it does not parse.

    Used only to order the scanner's own reports, never as a business time.
    """
    if not isinstance(stamp, str) or not stamp.strip():
        return None
    try:
        parsed = datetime.fromisoformat(stamp.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None  # a time without a zone is not assumed to be UTC
    try:
        return parsed.timestamp()
    except (OverflowError, ValueError):
        return None


def _choose(reports: list[dict], state: dict) -> dict:
    """The Done reports to try, in order, and what was met on the way.

    With a `last_imported_scan_end`: Done reports whose gvmd timestamp is
    strictly newer, oldest first. Without one: the baseline, newest Done
    first. If the newest is refused, an older Done report becomes the
    baseline instead (accepted in R21-2): the refused one stays recorded and
    is never downloaded again. At most one report is imported.
    """
    since = _instant(state.get("last_imported_scan_end"))
    listed = [r for r in reports if _UUID_RE.fullmatch(str(r.get("report_id") or ""))]
    if since is None:
        newer = listed
        candidates = [r for r in reversed(newer) if r.get("status") == DONE]
    else:
        timed = [(_instant(r.get("timestamp")), r) for r in listed]
        newer = [r for t, r in sorted((p for p in timed if p[0] is not None),
                                      key=lambda p: p[0]) if t > since]
        candidates = [r for r in newer if r.get("status") == DONE]
    skipped = [{"report_id": r.get("report_id"),
                "status": r.get("status") if _STATUS_RE.fullmatch(r.get("status") or "")
                else "unrecognised"}
               for r in newer if r.get("status") != DONE]
    return {"candidates": candidates, "baseline": since is None,
            "skipped": skipped[:MAX_SKIPPED_LISTED],
            "skipped_not_listed": max(len(skipped) - MAX_SKIPPED_LISTED, 0)}


def _source_notes(source: Any, task_id: str) -> dict:
    notes = getattr(source, "notes", None)
    found = notes(task_id) if callable(notes) else {}
    return {"refused_reports": int(found.get("refused_reports", 0) or 0),
            "refused_reasons": list(found.get("refused_reasons", [])),
            "skipped_tasks": int(found.get("skipped_tasks", 0) or 0)}


def _merge_refused(old: Any, new: list[dict]) -> list[dict]:
    """The task's refused reports, newest last, one entry per report, the last 20."""
    kept = [r for r in (old if isinstance(old, list) else [])
            if isinstance(r, dict) and r.get("reason") in REFUSED_REASONS
            and _UUID_RE.fullmatch(str(r.get("report_id") or ""))]
    fresh = {r["report_id"] for r in new}
    merged = [r for r in kept if r["report_id"] not in fresh] + new
    return merged[-MAX_REFUSED_KEPT:]


def _pull_task(ports: Ports, cycle: int, source: Any, task_id: str,
               chosen: list[str]) -> dict:
    docs = ports.docs
    found = docs.collection(STATE).document(task_id).get()
    state = found.to_dict() if found.exists else {}
    if state.get("last_imported_cycle") == cycle:
        # Decided before contacting the scanner: nothing is listed or downloaded.
        return {"task_id": task_id, "result": "already_imported_this_cycle"}
    refused_now: list[dict] = []
    try:
        reports = source.finished_reports(task_id)
        choice = _choose(reports, state)
        notes = {**_source_notes(source, task_id),
                 **{k: choice[k] for k in ("skipped", "skipped_not_listed")}}
        known = {r.get("report_id") for r in _merge_refused(state.get("refused"), [])}
        untried = [r for r in choice["candidates"] if r["report_id"] not in known]
        downloads, lost_race = 0, False

        def baseline_not_imported(imported: int) -> int:
            # Listed Done reports neither imported nor refused (only for a baseline).
            if not choice["baseline"]:
                return 0
            done = sum(1 for r in reports if r.get("status") == DONE)
            refused_ids = known | {r["report_id"] for r in refused_now}
            refused = sum(1 for r in reports if r.get("status") == DONE
                          and r.get("report_id") in refused_ids)
            return max(done - refused - imported, 0)

        for index, pick in enumerate(untried):
            if downloads >= MAX_DOWNLOADS_PER_PULL:
                break
            report_id = pick["report_id"]
            downloads += 1
            try:
                scan = source.fetch(report_id)
            except ReportRefused as exc:
                refused_now.append({"report_id": report_id, "reason": exc.reason})
                continue
            if scan.scan_id != report_id or scan.task_id != task_id:
                raise ImportRefused("the scanner returned a report other than the one listed")
            listed_at, ended_at = _instant(pick.get("timestamp")), _instant(scan.scan_end)
            if listed_at is not None and ended_at is not None \
                    and abs(ended_at - listed_at) > _DAY:
                # The report's own time disagrees with gvmd's: neither can be trusted.
                refused_now.append({"report_id": report_id, "reason": "malformed"})
                continue
            try:
                result = import_scan(ports, cycle, scan, chosen_task_ids=chosen, pull_notes={
                    **notes, "baseline_not_imported": baseline_not_imported(1),
                    "deferred": 0,
                    "refused": _merge_refused(state.get("refused"), refused_now)})
            except ImportRefused as exc:
                if exc.reason == "already_imported_this_cycle":
                    lost_race = True  # an upload for this task committed first
                    break
                if exc.reason is None:
                    raise
                refused_now.append({"report_id": report_id, "reason": exc.reason})
                continue
            return {"task_id": task_id, "result": "imported", "report_id": scan.scan_id,
                    "counts": result["counts"], "skipped": result["skipped"],
                    "uncovered_all": result["uncovered_all"], "refused": len(refused_now),
                    "deferred": 0}
        tried = {r["report_id"] for r in refused_now}
        deferred = 0 if lost_race else sum(1 for r in untried if r["report_id"] not in tried)
        outcome = "refused" if refused_now and not lost_race else "nothing_new"
        stamp = ports.clock.now()
        fields = {
            "last_pull_real_ts": stamp.real_ts, "last_pull_sim_ts": stamp.sim_ts,
            "last_result": outcome, "last_error_class": None,
            "refused": _merge_refused(state.get("refused"), refused_now),
            "deferred": deferred,
            "last_refused_reports": notes["refused_reports"],
            "last_refused_reasons": notes["refused_reasons"],
            "last_skipped_tasks": notes["skipped_tasks"],
        }
        if not lost_race:  # the upload that won wrote its own picture of the task
            fields.update(skipped=notes["skipped"],
                          skipped_not_listed=notes["skipped_not_listed"],
                          baseline_not_imported=baseline_not_imported(0))
        _write_state(docs, task_id, fields)
        return {"task_id": task_id, "result": outcome, "refused": len(refused_now),
                "deferred": deferred,
                "skipped_reports": len(notes["skipped"]) + notes["skipped_not_listed"]}
    except Exception as exc:  # noqa: BLE001 - recorded by class; the next task still runs
        error_class = type(exc).__name__
        notes = _source_notes(source, task_id)
        try:
            stamp = ports.clock.now()
            _write_state(docs, task_id, {
                "last_pull_real_ts": stamp.real_ts, "last_pull_sim_ts": stamp.sim_ts,
                "last_result": "failed", "last_error_class": error_class,
                "refused": _merge_refused(state.get("refused"), refused_now),
                "last_refused_reports": notes["refused_reports"],
                "last_refused_reasons": notes["refused_reasons"],
                "last_skipped_tasks": notes["skipped_tasks"],
            })
        except Exception as write_exc:  # noqa: BLE001 - the pull failure is still reported
            return {"task_id": task_id, "result": "failed", "error_class": error_class,
                    "state_write_failed": type(write_exc).__name__}
        return {"task_id": task_id, "result": "failed", "error_class": error_class}


def pull(ports: Ports, cycle: int, source: Any, *, chosen_task_ids: Collection[str]) -> dict:
    """Pull at most one new report per chosen task. Empty choice: nothing at all."""
    chosen = list(dict.fromkeys(chosen_task_ids))
    if not chosen:
        _log("scanner_pull_skipped", cycle, reason="no tasks chosen")
        return {"pulled": [], "reason": "no tasks chosen"}
    _refuse_demo(ports.docs)  # before contacting the scanner or writing anything
    pulled = []
    try:
        for task_id in chosen:
            outcome = _pull_task(ports, cycle, source, task_id, chosen)
            pulled.append(outcome)
            _log("scanner_pull", cycle, **{
                "task_id": task_id, "result": outcome["result"],
                "error_class": outcome.get("error_class"),
                "report_id": outcome.get("report_id"),
                "counts": outcome.get("counts"),
                "skipped": outcome.get("skipped"),
                "skipped_reports": outcome.get("skipped_reports"),
                "refused": outcome.get("refused"),
                "deferred": outcome.get("deferred")})
    finally:
        close = getattr(source, "close", None)
        if callable(close):
            close()
    return {"cycle": _cycle_id(cycle), "pulled": pulled}


# --- upload -----------------------------------------------------------------------------


def import_upload(ports: Ports, cycle: int, data: bytes, *, chosen_task_ids: Collection[str],
                  qod_floor: int = DEFAULT_QOD_FLOOR, add_task: bool = False) -> dict:
    """One uploaded report through the same checks as a pulled one.

    From an unchosen task it is refused unless `add_task`, the explicit
    confirmation; saving that choice to settings is the caller's job.
    """
    report = parse_report(data)
    scan = normalise_greenbone(report, qod_floor=qod_floor)
    chosen = set(chosen_task_ids)
    added = False
    if scan.task_id not in chosen:
        if not _UUID_RE.fullmatch(scan.task_id or ""):
            raise ImportRefused("report names a task id that is not a UUID")
        if not add_task:
            name = _NAME_UNSAFE.sub("", report.task_name or "")[:80].strip() or "(unnamed)"
            raise ImportRefused(f"report is from task {name} ({scan.task_id}), which is not "
                                "chosen for this install")
        chosen.add(scan.task_id)
        added = True
    result = import_scan(ports, cycle, scan, chosen_task_ids=chosen, via="upload")
    return {**result, "task_id": scan.task_id, "task_added": added}
