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
    scan_id = report.report_id
    assets, covered, by_ip = [], [], {}
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
        if host.finished and asset_id not in covered:
            covered.append(asset_id)

    skipped = {"log": 0, "below_qod": 0, "rejected": len(report.rejected)}
    findings: dict[str, dict] = {}
    for result in report.results:
        if result.severity <= 0:
            skipped["log"] += 1
        elif result.qod < qod_floor:
            skipped["below_qod"] += 1
        else:
            asset_id, finished = by_ip.get(result.ip, (None, False))
            if asset_id is None or not finished:  # host not finished: cannot be reconciled
                skipped["rejected"] += 1
                continue
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
        skipped=skipped,
    )


def to_rescan_input(scan: NormalisedScan) -> dict:
    return {
        "scan_id": scan.scan_id,
        "covered_asset_ids": list(scan.covered_asset_ids),
        "findings": list(scan.findings),
        "task_id": scan.task_id,
        "source": scan.source,
        "report_status": scan.report_status,
    }
