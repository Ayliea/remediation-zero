# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Regression tests for what the manual check against a real gvmd (26.42) showed.

1. gvmd 26 has a critical result level, `c`, which the report filter did not ask
   for; and nothing compared what gvmd sent with the report's own result total.
2. A check that did not finish (gvmd lists it under `<errors>`) was not read, so
   its absence could resolve a finding the check never re-tested.
3. A host's `ports` detail is bare numbers (`135,445`), with `tcp_ports` and
   `udp_ports` beside it; only `N/proto` entries were read, so every port was lost.

Synthetic fixtures only: the element shapes match the real responses, the values
are documentation IPs, `.invalid` names and synthetic UUIDs.
"""
import dataclasses
import xml.etree.ElementTree as ET

import pytest

from engine.rescan import run_rescan
from engine.scanner_import import import_scan
from engine.scanner_source import normalise_greenbone, to_rescan_input
from tests.test_gmp import (PASSWORD, USER, default_handler, report_entry, reports_response,  # noqa: F401
                            unix_target)
from tests.test_greenbone_review_fixes import card
from tests.test_scanner_import import (FIX, LOG4J, LOG4J_OID, TASK, WEB, docs, ports, report,  # noqa: F401
                                       rid, ws)
from tools.gmp import GmpClient
from tools.greenbone_report import ReportRefused, UnfinishedCheck, parse_report

A_UUID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
PORTS_DETAIL = b"<detail><name>ports</name><value>22/tcp,80/tcp,443/tcp,8080/tcp</value></detail>"


def _error(host=f'192.0.2.10<asset asset_id="{A_UUID}"/>', oid=LOG4J_OID):
    return (f'<error><host>{host}</host><port>general/tcp</port>'
            f'<description>NVT timed out after 320 seconds.</description>'
            f'<nvt oid="{oid}"><type>nvt</type><name>Synthetic check</name><cvss_base>10.0</cvss_base></nvt>'
            f'<scan_nvt_version>2026-01-01T00:00:00Z</scan_nvt_version><severity>-3</severity></error>')


def _with(data=None, *, before_results=b"", ports_detail=None):
    data = data or FIX("report_basic.xml")
    marker = b'<results start="1" max="1000">'
    assert marker in data
    data = data.replace(marker, before_results + marker, 1)
    if ports_detail is not None:
        assert PORTS_DETAIL in data
        data = data.replace(PORTS_DETAIL, ports_detail, 1)
    return parse_report(data)


def _count(full):
    return f"<result_count><full>{full}</full><filtered>{full}</filtered></result_count>".encode()


def _host(parsed, ip="192.0.2.10"):
    return {h.ip: h for h in parsed.hosts}[ip]


# --- 1. the critical level, and results gvmd did not send ----------------------------


def test_the_report_request_asks_for_every_level_including_critical(unix_target):
    resp = reports_response(report_entry(rid(1), TASK, "Done", "2026-01-01T10:00:00Z"))
    target, server = unix_target(default_handler({"get_reports": [resp]}))
    with GmpClient(target, USER, PASSWORD) as client:
        client.report_xml(rid(1))
    levels = dict(part.split("=", 1) for part in
                  ET.fromstring(server.requests[-1]).get("filter").split())["levels"]
    assert set(levels) == set("chmlgf")


def test_the_reports_own_result_total_is_read():
    total = len(_with().results) + len(_with().rejected)
    assert _with(before_results=_count(total)).results_expected == total
    assert _with().results_expected is None  # an export without it


@pytest.mark.parametrize("bad", [b"", b"many", b"-1", b"4.0", b"9" * 12])
def test_a_result_total_that_is_not_a_count_refuses_the_report(bad):
    with pytest.raises(ReportRefused):
        _with(before_results=b"<result_count><full>" + bad + b"</full></result_count>")


def test_results_gvmd_did_not_send_close_nothing():
    parsed = _with(before_results=_count(99))
    scan = normalise_greenbone(dataclasses.replace(parsed, rejected=()))
    assert scan.covered_asset_ids == ()
    assert scan.results_not_returned == 99 - len(parsed.results)
    complete = dataclasses.replace(parsed, rejected=(), results_expected=len(parsed.results))
    assert normalise_greenbone(complete).covered_asset_ids != ()
    assert normalise_greenbone(complete).results_not_returned == 0


def test_a_report_missing_results_resolves_nothing_and_says_how_many(ws, ports):
    import_scan(ports, 1, normalise_greenbone(report(1)), chosen_task_ids=[TASK])
    assert docs(ws, "findings")[LOG4J]["status"] == "open"
    # Every result gone, but the report says it had five: a critical one may be among them.
    missing = normalise_greenbone(report(2, results=(), results_expected=5))
    result = import_scan(ports, 2, missing, chosen_task_ids=[TASK])
    assert result["counts"]["resolved"] == 0 and result["uncovered_all"] is True
    assert all(f["status"] == "open" for f in docs(ws, "findings").values())
    state = docs(ws, "scanner_state")[TASK]
    assert state["last_results_not_returned"] == 5
    page = card(ws, [TASK])
    assert "5 results counted in the report are missing from it" in page
    assert "could not be trusted for coverage" in page


# --- 2. checks that did not finish ---------------------------------------------------


def test_errors_are_read_as_checks_that_did_not_finish():
    parsed = _with(before_results=b"<errors><count>3</count>" + _error().encode()
                   + _error(host="not-an-ip").encode() + _error(oid="1.3.6.1&#10;x").encode()
                   + b"</errors>")
    assert parsed.unfinished_checks == (
        UnfinishedCheck(ip="192.0.2.10", nvt_oid=LOG4J_OID),
        UnfinishedCheck(ip=None, nvt_oid=LOG4J_OID),
        UnfinishedCheck(ip="192.0.2.10", nvt_oid=None),
    )
    assert _with().unfinished_checks == ()


def _unfinished(*checks, **changes):
    return normalise_greenbone(report(2, with_log4j=False, unfinished_checks=tuple(checks), **changes))


def test_an_unfinished_check_names_its_host_and_check():
    scan = _unfinished(UnfinishedCheck(ip="192.0.2.10", nvt_oid=LOG4J_OID))
    assert scan.unfinished_checks == ((WEB, LOG4J_OID),)
    assert scan.unfinished_check_count == 1
    assert WEB in scan.covered_asset_ids  # one timed-out check does not uncover the host
    assert to_rescan_input(scan)["unfinished_checks"] == [[WEB, LOG4J_OID]]


def test_an_unfinished_check_on_an_unknown_host_applies_to_every_host():
    scan = _unfinished(UnfinishedCheck(ip=None, nvt_oid=LOG4J_OID))
    assets = {a["asset_id"] for a in scan.assets}
    assert set(scan.unfinished_checks) == {(asset, LOG4J_OID) for asset in assets}
    assert scan.unfinished_check_count == 1


def test_an_unfinished_check_with_no_readable_check_closes_nothing():
    scan = _unfinished(UnfinishedCheck(ip="192.0.2.10", nvt_oid=None))
    assert scan.covered_asset_ids == ()
    assert scan.skipped["rejected"] == 1


def test_a_check_that_did_not_finish_leaves_its_finding_open(ws, ports):
    import_scan(ports, 1, normalise_greenbone(report(1)), chosen_task_ids=[TASK])
    assert docs(ws, "findings")[LOG4J]["status"] == "open"
    # The Log4j check timed out on the web host this time: it was not re-tested.
    result = import_scan(ports, 2, _unfinished(UnfinishedCheck(ip="192.0.2.10", nvt_oid=LOG4J_OID)),
                         chosen_task_ids=[TASK])
    assert docs(ws, "findings")[LOG4J]["status"] == "open"
    assert result["counts"]["unverifiable"] >= 1 and result["unfinished_checks"] == 1
    assert docs(ws, "scanner_state")[TASK]["last_unfinished_checks"] == 1
    assert "1 checks did not finish" in card(ws, [TASK])


def test_without_the_error_the_same_report_resolves_it(ws, ports):
    import_scan(ports, 1, normalise_greenbone(report(1)), chosen_task_ids=[TASK])
    import_scan(ports, 2, _unfinished(), chosen_task_ids=[TASK])
    assert docs(ws, "findings")[LOG4J]["status"] == "resolved"


def test_the_pull_line_says_checks_did_not_finish():
    from scripts.local import pull_line
    line = pull_line({"task_id": TASK, "result": "imported", "counts": {"new": 3},
                      "skipped": {"log": 40}, "unfinished_checks": 2, "results_not_returned": 0})
    assert "2 checks did not finish; findings from them on those hosts stay open" in line


@pytest.mark.parametrize("bad", ["x", [["a"]], [["a", 1]], [("a", "b", "c")], [None]])
def test_a_malformed_unfinished_check_list_refuses_to_reconcile(ports, bad):
    scan = to_rescan_input(_unfinished())
    scan["unfinished_checks"] = bad
    with pytest.raises(ValueError):
        run_rescan(ports, 2, scan, dry_run=True)


# --- 3. open ports as real gvmd lists them -------------------------------------------


def test_bare_port_numbers_are_read_with_their_protocol():
    real = (b"<detail><name>ports</name><value>135,445,0,65536,8a</value></detail>"
            b"<detail><name>tcp_ports</name><value>135,445,0,65536,8a</value></detail>"
            b"<detail><name>udp_ports</name><value>53</value></detail>")
    assert _host(_with(ports_detail=real)).open_ports == ("135/tcp", "445/tcp", "53/udp")


def test_ports_with_their_protocol_are_still_read():
    assert _host(_with()).open_ports == ("22/tcp", "80/tcp", "443/tcp", "8080/tcp")


# --- the task card names its task; one asset is "1 asset" ----------------------------


def test_an_imported_report_stores_its_task_name_for_the_card(ws, ports):
    import_scan(ports, 1, normalise_greenbone(report(1, task_name="Weekly scan of 192.0.2.0/24")),
                chosen_task_ids=[TASK])
    assert docs(ws, "scanner_state")[TASK]["task_name"] == "Weekly scan of 192.0.2.0/24"
    assert "<h3>Weekly scan of 192.0.2.0/24</h3>" in card(ws, [TASK])


def test_a_task_name_is_cleaned_and_an_empty_one_keeps_the_last(ws, ports):
    import_scan(ports, 1, normalise_greenbone(report(1, task_name="Lab\n<b>scan</b>\x1b[31m" + "x" * 200)),
                chosen_task_ids=[TASK])
    name = docs(ws, "scanner_state")[TASK]["task_name"]
    assert name.startswith("Lab") and len(name) <= 80
    assert not set(name) & set("<>\n\x1b[")
    import_scan(ports, 2, normalise_greenbone(report(2, task_name="")), chosen_task_ids=[TASK])
    assert docs(ws, "scanner_state")[TASK]["task_name"] == name


@pytest.mark.parametrize("assets, heading", [(1, "1 asset recorded"), (2, "2 assets recorded"),
                                             (0, "0 assets recorded")])
def test_the_asset_heading_agrees_with_its_count(assets, heading):
    from ui import dashboard_view
    page = dashboard_view.render({"counts": {"assets": assets}, "scans": []}, "infrastructure")
    assert f"<h2>{heading}</h2>" in page


# --- a report that reached no host says so -------------------------------------------


def test_a_done_report_with_no_hosts_says_it_confirmed_nothing(ws, ports):
    from scripts.local import pull_line
    import_scan(ports, 1, normalise_greenbone(report(1)), chosen_task_ids=[TASK])
    # gvmd's alive test found nothing: a Done report with no hosts and no results.
    result = import_scan(ports, 2, normalise_greenbone(report(2, hosts=(), results=())),
                         chosen_task_ids=[TASK])
    assert result["counts"]["resolved"] == 0 and result["hosts_in_report"] == 0
    state = docs(ws, "scanner_state")[TASK]
    assert (state["last_hosts_in_report"], state["last_hosts_covered"]) == (0, 0)
    assert "This report scanned no hosts, so nothing could be confirmed" in card(ws, [TASK])
    line = pull_line({"task_id": TASK, "result": "imported", "counts": result["counts"],
                      "skipped": result["skipped"], "hosts_in_report": 0, "hosts_covered": 0})
    assert line.endswith("; the report scanned no hosts, so nothing could be confirmed")


def test_a_report_whose_hosts_all_did_not_finish_says_so(ws, ports):
    unfinished = tuple(dataclasses.replace(h, finished=False) for h in report(1).hosts)
    import_scan(ports, 1, normalise_greenbone(report(1, hosts=unfinished)), chosen_task_ids=[TASK])
    page = card(ws, [TASK])
    assert "No host in this report finished its scan, so nothing could be confirmed" in page
    assert "scanned no hosts" not in page


def test_a_report_that_covered_hosts_adds_no_such_line(ws, ports):
    import_scan(ports, 1, normalise_greenbone(report(1)), chosen_task_ids=[TASK])
    page = card(ws, [TASK])
    assert "nothing could be confirmed" not in page
