# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""The Greenbone report parser: both XML shapes, hostile input, bad values."""

import subprocess
from pathlib import Path

import pytest

from tools.greenbone_report import ReportRefused, parse_report

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures" / "greenbone"


def FIX(name):
    return (FIXTURES / name).read_bytes()


def test_parses_gmp_response_and_export_alike():
    a = parse_report(FIX("report_basic.xml")); b = parse_report(FIX("report_export.xml"))
    assert a.report_id == b.report_id and a.task_id == "11111111-1111-4111-8111-111111111111"
    assert a.scan_status == "Done" and len(a.hosts) == 3
    assert [r.nvt_oid for r in a.results] == [r.nvt_oid for r in b.results]


def test_hosts_report_whether_they_finished():
    hosts = {h.ip: h for h in parse_report(FIX("report_basic.xml")).hosts}
    assert hosts["192.0.2.11"].finished and not hosts["192.0.2.12"].finished
    assert hosts["192.0.2.10"].hostname == "web.example.invalid"


def test_host_details_and_result_fields_are_read():
    report = parse_report(FIX("report_basic.xml"))
    host = {h.ip: h for h in report.hosts}["192.0.2.10"]
    assert host.os_cpe == "cpe:/o:debian:debian_linux:12"
    assert host.open_ports == ("22/tcp", "80/tcp", "443/tcp", "8080/tcp")
    assert host.asset_id.startswith("aaaaaaaa")
    log4j = report.results[0]
    assert (log4j.ip, log4j.port, log4j.protocol) == ("192.0.2.10", "8080", "tcp")
    assert (log4j.severity, log4j.qod, log4j.cve_ids) == (10.0, 97, ("CVE-2021-44228",))
    assert log4j.summary == "Synthetic summary." and log4j.solution == "Apply the vendor update."
    assert log4j.asset_id.startswith("aaaaaaaa") and report.task_name == "Weekly Example Scan"
    general = [r for r in report.results if r.nvt_name == "OS End of Life Detection"][0]
    assert (general.port, general.protocol, general.severity) == ("general", "tcp", 0.0)


def test_cves_are_collected_and_absent_cves_are_empty():
    by_name = {r.nvt_name: r for r in parse_report(FIX("report_basic.xml")).results}
    assert by_name["SSH Weak Encryption Algorithms Supported"].cve_ids == ()
    assert len([r for r in by_name.values() if len(r.cve_ids) == 2]) == 1


def test_malformed_result_is_rejected_with_a_reason_not_guessed():
    report = parse_report(FIX("report_basic.xml"))
    assert len(report.rejected) == 1 and "severity" in report.rejected[0][1]
    assert report.rejected[0][2] == "192.0.2.10"
    assert len(report.results) == 5


def test_stopped_status_is_reported_not_hidden():
    assert parse_report(FIX("report_stopped.xml")).scan_status == "Stopped"


def test_doctype_is_refused_before_parsing():
    with pytest.raises(ReportRefused, match="DOCTYPE"):
        parse_report(FIX("report_doctype.xml"))
    with pytest.raises(ReportRefused):
        parse_report(b'<report><!entity x "y"></report>')
    with pytest.raises(ReportRefused, match="DOCTYPE"):
        parse_report(b"<report><!doctype x></report>")


def test_oversized_report_is_refused_before_parsing():
    with pytest.raises(ReportRefused, match="larger than"):
        parse_report(b"<report>" + b" " * 2048 + b"</report>", max_bytes=1024)


def test_report_without_task_is_refused():
    with pytest.raises(ReportRefused, match="task"):
        parse_report(b'<report id="r"><report id="r"><scan_run_status>Done</scan_run_status></report></report>')


def test_not_xml_is_refused_as_report_refused():
    with pytest.raises(ReportRefused):
        parse_report(b"<report><unclosed>")


def test_parser_is_stdlib_only():
    done = subprocess.run(["python3", "-S", "-c", "import tools.greenbone_report"],
                          cwd=ROOT, capture_output=True, text=True)
    assert done.returncode == 0, done.stderr


def _mutated(old, new):
    data = FIX("report_basic.xml")
    assert old in data
    return parse_report(data.replace(old, new, 1))


def test_malformed_cve_ref_rejects_the_result():
    for bad in (b"CVE-2021-44228 x", b"CVE-21-1", b"cve-2021-44228", b"CVE-2021-44228&#10;ENRICHMENT"):
        report = _mutated(b'id="CVE-2021-44228"', b'id="' + bad + b'"')
        assert len(report.results) == 4 and len(report.rejected) == 2, bad
        assert any("CVE" in reason for _, reason, _ in report.rejected)


def test_oid_with_newline_rejects_the_result():
    for bad in (b"1.3.6.1&#10;ENRICHMENT", b"abc", b"1", b"1.3.6.1\n.2"):
        report = _mutated(b'oid="1.3.6.1.4.1.25623.1.0.117850"', b'oid="' + bad + b'"')
        assert len(report.rejected) == 2 and len(report.results) == 4, bad


def test_port_with_whitespace_rejects_the_result():
    report = _mutated(b"<port>8080/tcp</port>", b"<port>8080/tcp\nENRICHMENT</port>")
    assert any("port" in reason for _, reason, _ in report.rejected)
