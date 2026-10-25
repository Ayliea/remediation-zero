# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Scanner-source normalisation: Greenbone reports to assets, findings, coverage."""

import dataclasses
import subprocess
from pathlib import Path

from engine.scanner_source import (
    asset_key, finding_key, normalise_greenbone, to_rescan_input,
)
from tools.greenbone_report import GreenboneReport, Result, ScannedHost, parse_report

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures" / "greenbone"


def FIX(name):
    return (FIXTURES / name).read_bytes()


def test_log_and_low_qod_results_are_skipped_and_counted():
    scan = normalise_greenbone(parse_report(FIX("report_basic.xml")))
    assert scan.skipped == {"log": 1, "below_qod": 1, "rejected": 1}
    assert len(scan.findings) == 3


def test_qod_floor_is_configurable():
    assert len(normalise_greenbone(parse_report(FIX("report_basic.xml")), qod_floor=20).findings) == 4


def test_only_finished_hosts_are_covered():
    scan = normalise_greenbone(parse_report(FIX("report_basic.xml")))
    ips = {a["ip"]: a["asset_id"] for a in scan.assets}
    assert ips["192.0.2.11"] in scan.covered_asset_ids      # finished, clean
    assert ips["192.0.2.12"] not in scan.covered_asset_ids  # unfinished


def test_host_without_asset_id_falls_back_to_ip_and_says_so():
    assert asset_key("greenbone", None, "192.0.2.20") == ("gb-ip-192.0.2.20", "source_ip")
    assert asset_key("greenbone", "abc", "192.0.2.20") == ("gb-abc", "greenbone_asset_id")


def test_finding_key_is_stable_across_reports():
    a = normalise_greenbone(parse_report(FIX("report_basic.xml")))
    b = normalise_greenbone(parse_report(FIX("report_export.xml")))
    assert {f["finding_id"] for f in a.findings} == {f["finding_id"] for f in b.findings}


def test_single_cve_sets_cve_id_and_multi_or_none_does_not():
    by = {len(f["cve_ids"]): f for f in normalise_greenbone(parse_report(FIX("report_basic.xml"))).findings}
    assert by[1]["cve_id"] == "CVE-2021-44228"
    assert "cve_id" not in by[0] and "cve_id" not in by[2]


def test_rescan_input_matches_engine_contract():
    data = to_rescan_input(normalise_greenbone(parse_report(FIX("report_basic.xml"))))
    assert {"scan_id", "covered_asset_ids", "findings"} <= set(data)
    assert all(f["asset_id"] in data["covered_asset_ids"] for f in data["findings"])


def _result(rid, port, protocol, ip="192.0.2.30"):
    return Result(result_id=rid, ip=ip, asset_id=None, port=port, protocol=protocol,
                  nvt_oid="1.3.6.1.4.1.25623.1.0.999", nvt_name="DNS example",
                  severity=5.0, qod=90, cve_ids=(), description="d", solution="s",
                  summary="sum")


def _host(finished=True):
    return ScannedHost(ip="192.0.2.30", asset_id=None, hostname=None, os_cpe=None,
                       open_ports=(), finished=finished)


def _report(results, hosts):
    return GreenboneReport(report_id="r1", task_id="t1", task_name="n", scan_status="Done",
                           hosts=tuple(hosts), results=tuple(results), rejected=())


def test_tcp_and_udp_on_one_port_are_distinct_findings():
    scan = normalise_greenbone(_report([_result("a", "53", "tcp"), _result("b", "53", "udp")], [_host()]))
    ids = {f["finding_id"] for f in scan.findings}
    assert len(ids) == 2
    assert {f["port"] for f in scan.findings} == {"53/tcp", "53/udp"}
    assert {f["protocol"] for f in scan.findings} == {"tcp", "udp"}
    assert finding_key("gb-ip-192.0.2.30", "1.3.6.1.4.1.25623.1.0.999", "53/tcp") in ids


def test_result_without_protocol_uses_bare_port():
    scan = normalise_greenbone(_report([_result("a", "general", None)], [_host()]))
    assert scan.findings[0]["port"] == "general"
    assert scan.findings[0]["finding_id"].endswith(":general")


def test_result_on_unfinished_host_is_rejected_but_host_is_listed():
    scan = normalise_greenbone(_report([_result("a", "80", "tcp")], [_host(finished=False)]))
    assert scan.findings == () and scan.skipped["rejected"] == 1
    assert len(scan.assets) == 1 and scan.covered_asset_ids == ()


def test_finding_and_asset_fields():
    scan = normalise_greenbone(parse_report(FIX("report_basic.xml")))
    f = next(f for f in scan.findings if f["nvt_oid"].endswith("117850"))
    assert f["source"] == "greenbone" and f["status"] == "open"
    assert f["task_id"] == "11111111-1111-4111-8111-111111111111"
    assert f["port"] == "8080/tcp" and f["protocol"] == "tcp"
    assert f["scanner_severity"] == f["scanner_cvss"] == 10.0
    assert f["scanner_comment"] == "Synthetic summary.\n\nSynthetic description."
    assert f["first_seen_scan"] == scan.scan_id
    a = next(a for a in scan.assets if a["ip"] == "192.0.2.10")
    assert a["asset_id"] == "gb-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    assert a["asset_key_origin"] == "greenbone_asset_id" and a["source"] == "greenbone"
    assert a["open_ports"] == ["22/tcp", "80/tcp", "443/tcp", "8080/tcp"]
    assert a["os_cpe"] == "cpe:/o:debian:debian_linux:12"


def test_normalised_scan_is_frozen():
    scan = normalise_greenbone(parse_report(FIX("report_basic.xml")))
    assert dataclasses.is_dataclass(scan)
    try:
        scan.scan_id = "x"
    except dataclasses.FrozenInstanceError:
        return
    raise AssertionError("NormalisedScan must be frozen")


def test_scanner_source_is_stdlib_only():
    done = subprocess.run(["python3", "-S", "-c", "import engine.scanner_source"],
                          cwd=ROOT, capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
