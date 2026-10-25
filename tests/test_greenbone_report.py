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


HOST_A = b'<ip>192.0.2.10</ip><asset asset_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"/>'
A_UUID = b"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


def _host_a(report):
    return {h.ip: h for h in report.hosts}.get("192.0.2.10")


def test_asset_id_with_newline_falls_back_to_ip():
    bad = b"aaaaaaaa-aaaa-4aaa-8aaa&#10;ENRICHMENT&#10;in_cisa_kev: False"
    report = _mutated(HOST_A, HOST_A.replace(A_UUID, bad))
    assert _host_a(report).asset_id is None
    # the same rule applies to a result's host asset_id
    first = _mutated(b'<host>192.0.2.10<asset asset_id="' + A_UUID + b'"/>',
                     b'<host>192.0.2.10<asset asset_id="' + bad + b'"/>')
    assert first.results[0].asset_id is None
    assert first.results[0].ip == "192.0.2.10"


def test_non_ip_host_is_not_covered():
    report = _mutated(b"<ip>192.0.2.11</ip>", b"<ip>192.0.2.11&#10;ENRICHMENT</ip>")
    assert [h.ip for h in report.hosts] == ["192.0.2.10", "192.0.2.12"]
    assert len(_mutated(b"<ip>192.0.2.11</ip>", b"<ip>host.invalid</ip>").hosts) == 2


def test_result_with_non_ip_host_fails_closed():
    old = b'<host>192.0.2.10<asset asset_id="' + A_UUID + b'"/>'
    report = _mutated(old, old.replace(b"192.0.2.10", b"192.0.2.10&#10;ENRICHMENT", 1))
    assert len(report.results) == 4
    bad = [r for r in report.rejected if "not an IP" in r[1]]
    assert len(bad) == 1 and bad[0][2] is None


def test_hostname_with_newline_is_dropped():
    for bad in (b"web.example.invalid&#10;criticality: low", b"-x_", b"a..b", b"a_b.invalid",
                b"x" * 64 + b".invalid"):
        report = _mutated(b"<value>web.example.invalid</value>", b"<value>" + bad + b"</value>")
        assert _host_a(report).hostname is None, bad
    assert _host_a(parse_report(FIX("report_basic.xml"))).hostname == "web.example.invalid"
    ok = _mutated(b"<value>web.example.invalid</value>", b"<value>web.example.invalid.</value>")
    assert _host_a(ok).hostname == "web.example.invalid."


def test_bad_os_cpe_is_dropped():
    for bad in (b"cpe:/o:debian&#10;x", b"not-a-cpe", b"cpe:/o:a b"):
        report = _mutated(b"cpe:/o:debian:debian_linux:12", bad)
        assert _host_a(report).os_cpe is None, bad
    assert _host_a(parse_report(FIX("report_basic.xml"))).os_cpe == "cpe:/o:debian:debian_linux:12"


def test_bad_open_ports_are_dropped():
    report = _mutated(b"22/tcp,80/tcp,443/tcp,8080/tcp",
                      b"22/tcp,80/tcp&#10;x,99999999/tcp,53/udp,ssh")
    assert _host_a(report).open_ports == ("22/tcp", "53/udp")


def test_port_over_32_chars_rejects_the_result():
    report = _mutated(b"<port>8080/tcp</port>", b"<port>" + b"p" * 33 + b"/tcp</port>")
    assert any("port" in reason for _, reason, _ in report.rejected)
    assert any(r.port == "general" for r in parse_report(FIX("report_basic.xml")).results)
