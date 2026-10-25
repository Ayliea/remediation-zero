# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Scanner-source normalisation: a parsed report in, assets, findings and coverage out.

A scanner source (today only Greenbone) is reduced to the shape the rescan
engine already consumes: a scan id, the assets the scan actually examined, and
the findings it reported. Coverage is the load-bearing part. A host counts as
covered only if the scanner finished it, because absence of a finding on a host
the scanner never completed proves nothing. A result on an unfinished host is
therefore dropped (counted as rejected), since reconcile refuses a finding on an
asset outside the covered set.

Log-level results (severity 0) and results below the QoD floor are skipped and
counted, never silently dropped. No timestamps are stamped here; the importer
stamps them through SimClock.

Standard library only. No clock is read here.
"""

from dataclasses import dataclass
from typing import Optional, Protocol

from tools.greenbone_report import GreenboneReport, Result

DEFAULT_QOD_FLOOR = 70
SOURCE = "greenbone"


@dataclass(frozen=True)
class NormalisedScan:
    scan_id: str
    source: str
    task_id: str
    report_status: str
    assets: tuple[dict, ...]
    findings: tuple[dict, ...]
    covered_asset_ids: tuple[str, ...]
    withheld_finding_ids: tuple[str, ...]
    skipped: dict[str, int]


class ScannerSource(Protocol):
    def list_tasks(self) -> list[dict]:
        """Each `{"task_id", "name"}`."""

    def finished_reports(self, task_id: str) -> list[dict]:
        """Each `{"report_id", "task_id", "status", "timestamp"}`, oldest first."""

    def fetch(self, report_id: str) -> NormalisedScan:
        """Fetch one report and normalise it."""


def asset_key(source: str, host_asset_id: Optional[str], ip: str) -> tuple[str, str]:
    """Return `(asset_id, origin)`. The scanner's own asset id wins; the IP is the fallback."""
    if host_asset_id:
        return "gb-" + host_asset_id, "greenbone_asset_id"
    return "gb-ip-" + ip, "source_ip"


def finding_key(asset_id: str, nvt_oid: str, port: str) -> str:
    return f"{asset_id}:{nvt_oid}:{port}"


def _port_spec(result: Result) -> str:
    return f"{result.port}/{result.protocol}" if result.protocol else result.port


def _finding(result: Result, asset_id: str, scan_id: str, task_id: str) -> dict:
    port = _port_spec(result)
    finding = {
        "finding_id": finding_key(asset_id, result.nvt_oid, port),
        "asset_id": asset_id,
        "source": SOURCE,
        "task_id": task_id,
        "nvt_oid": result.nvt_oid,
        "nvt_name": result.nvt_name,
        "cve_ids": list(result.cve_ids),
        "port": port,
        "protocol": result.protocol,
        "scanner_severity": result.severity,
        "scanner_cvss": result.severity,
        "qod": result.qod,
        "solution": result.solution,
        # Untrusted text: it must cross the guardrail boundary before any model sees it.
        "scanner_comment": f"{result.summary}\n\n{result.description}",
        "status": "open",
        "first_seen_scan": scan_id,
    }
    if len(result.cve_ids) == 1:
        finding["cve_id"] = result.cve_ids[0]
    return finding


def normalise_greenbone(report: GreenboneReport, *, qod_floor: int = DEFAULT_QOD_FLOOR) -> NormalisedScan:
    """Reduce a report to assets, findings and coverage, failing closed.

    A skipped (log, below-floor) result means the scanner saw something there,
    so its finding ID is withheld: absence of it must not be read as a fix. A
    parser-rejected result uncovers its host (or every host, when it cannot be
    attributed), because a result we could not read may be the one that proves
    the finding is still present.
    """
    scan_id = report.report_id
    assets, by_ip = [], {}
    for host in report.hosts:
        asset_id, origin = asset_key(SOURCE, host.asset_id, host.ip)
        by_ip[host.ip] = (asset_id, host.finished)
        assets.append({
            "asset_id": asset_id,
            "source": SOURCE,
            "asset_key_origin": origin,
            "ip": host.ip,
            "hostname": host.hostname,
            "os_cpe": host.os_cpe,
            "open_ports": list(host.open_ports),
            "first_seen_scan": scan_id,
            "last_seen_scan": scan_id,
        })

    unattributed = any(ip is None for _, _, ip in report.rejected)
    uncovered = {by_ip[ip][0] for _, _, ip in report.rejected if ip in by_ip}
    covered = [] if unattributed else [
        aid for aid, finished in by_ip.values() if finished and aid not in uncovered
    ]
    covered = list(dict.fromkeys(covered))
    covered_set = set(covered)

    skipped = {"log": 0, "below_qod": 0, "rejected": len(report.rejected), "not_finished": 0}
    findings: dict[str, dict] = {}
    withheld: dict[str, None] = {}
    for result in report.results:
        asset_id, finished = by_ip.get(result.ip, (None, False))
        is_log = result.severity <= 0
        if is_log or result.qod < qod_floor:
            skipped["log" if is_log else "below_qod"] += 1
            if asset_id in covered_set:
                withheld[finding_key(asset_id, result.nvt_oid, _port_spec(result))] = None
        elif asset_id not in covered_set:
            if asset_id is None or not finished:
                skipped["not_finished"] += 1  # host unfinished or unknown: cannot be reconciled
        else:
            finding = _finding(result, asset_id, scan_id, report.task_id)
            kept = findings.get(finding["finding_id"])
            if kept is None or finding["scanner_severity"] > kept["scanner_severity"]:
                findings[finding["finding_id"]] = finding
    return NormalisedScan(
        scan_id=scan_id,
        source=SOURCE,
        task_id=report.task_id,
        report_status=report.scan_status,
        assets=tuple(assets),
        findings=tuple(findings.values()),
        covered_asset_ids=tuple(covered),
        withheld_finding_ids=tuple(withheld),
        skipped=skipped,
    )


def to_rescan_input(scan: NormalisedScan) -> dict:
    return {
        "scan_id": scan.scan_id,
        "covered_asset_ids": list(scan.covered_asset_ids),
        "findings": list(scan.findings),
        "withheld_finding_ids": list(scan.withheld_finding_ids),
        "task_id": scan.task_id,
        "source": scan.source,
        "report_status": scan.report_status,
    }
