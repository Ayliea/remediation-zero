# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Regression tests for the final whole-branch review of the Greenbone connection (R29).

I1 a pull waits visibly while its cycle has not completed; I2 a zone-less
listing time is refused and counted; I3 results hidden by a rejected result on
the same host are counted; M1 UUIDs are one spelling; M2 reasonless upload
refusals have fixed words; M3 listing refusals are shown; M7 ticket wording for
findings without a single CVE; M8 the serve banner says "synthetic" only in demo.

Synthetic fixtures only: documentation IPs, `.invalid` hostnames, synthetic UUIDs.
"""
import dataclasses
import hashlib
import re

import pytest

from engine.scanner_import import REFUSED_KINDS, WAITING_FOR_CYCLE, import_scan, pull
from engine.scanner_source import normalise_greenbone
from engine.snapshot import snapshot
from tests.test_gmp import (PASSWORD, USER, default_handler, report_entry, reports_response,  # noqa: F401
                            unix_target)
from tests.test_greenbone_commands import (CLEAN_REPORT, REPORT, configure, credentials,  # noqa: F401
                                           fixed_clock, gvmd, gws, handler_for, page, post_report,
                                           run, tick)
from tests.test_scanner_import import (FIX, LOG4J, TASK, WEB, FakeSource, complete_cycle, docs,  # noqa: F401
                                       everything, ports, report, rid, ws)
from tools.gmp import GmpClient
from tools.greenbone_report import parse_report
from ui import dashboard_view

NEWER = "33333333-3333-4333-8333-333333333333"


def card(workspace, chosen):
    store = workspace.docs_for("dashboard")
    try:
        view = snapshot(store)
    finally:
        store.close()
    return dashboard_view.render(view, "infrastructure", chosen_tasks=chosen)


# --- I1: a pull waits, visibly, while its cycle has not completed -------------------


def test_a_pull_in_an_incomplete_cycle_records_that_it_waits(ws, ports):
    source = FakeSource()
    source.add(1)
    pull(ports, 1, source, chosen_task_ids=[TASK])
    first = docs(ws, "scanner_state")[TASK]
    source.add(2, with_log4j=False)
    source.listed.clear()
    out = pull(ports, 1, source, chosen_task_ids=[TASK])  # cycle 1 has no cycle record
    assert out["pulled"] == [{"task_id": TASK, "result": WAITING_FOR_CYCLE}]
    assert source.listed == [] and source.fetched == [rid(1)]  # the scanner was not contacted
    state = docs(ws, "scanner_state")[TASK]
    assert state["last_result"] == "waiting_for_cycle"
    assert state["last_pull_real_ts"] == first["last_pull_real_ts"]  # SimClock stamps (fixed clock)
    assert "last_pull_sim_ts" in state and state["last_imported_report_id"] == rid(1)
    assert set(docs(ws, "scans")) == {rid(1)}
    page = card(ws, [TASK])
    assert "Result: Waiting for the previous cycle to finish before importing more." in page
    assert "Result: Imported" not in page
    # Once the cycle completes, the next cycle's pull imports.
    complete_cycle(ws, 1)
    assert pull(ports, 2, source, chosen_task_ids=[TASK])["pulled"][0]["result"] == "imported"
    assert docs(ws, "findings")[LOG4J]["status"] == "resolved"


def test_a_completed_cycle_keeps_already_imported_this_cycle(ws, ports):
    source = FakeSource()
    source.add(1)
    pull(ports, 1, source, chosen_task_ids=[TASK])
    complete_cycle(ws, 1)
    before = everything(ws)
    assert pull(ports, 1, source, chosen_task_ids=[TASK])["pulled"][0]["result"] == \
        "already_imported_this_cycle"
    assert everything(ws) == before


def test_a_failed_cycle_then_a_tick_shows_waiting_on_state_cli_and_card(gws, gvmd, monkeypatch, capsys):
    current = {"report": REPORT, "stamp": "2026-10-20T01:00:00Z", "body": CLEAN_REPORT}
    path, _ = gvmd(handler_for(current=current))
    configure(gws, path)
    credentials(monkeypatch)

    def failing(workspace, number):
        raise RuntimeError("synthetic model failure")  # triage stops: no cycle record

    tick(gws, failing)
    assert docs(gws, "scanner_state")[TASK]["last_result"] == "imported"
    current.update(report=NEWER, stamp="2026-10-21T01:00:00Z", body=CLEAN_REPORT.replace(
        REPORT.encode(), NEWER.encode()).replace(b"2026-10-20", b"2026-10-21"))
    tick(gws, failing)
    state = docs(gws, "scanner_state")[TASK]
    assert state["last_result"] == "waiting_for_cycle"
    assert state["last_imported_report_id"] == REPORT and set(docs(gws, "scans")) == {REPORT}
    capsys.readouterr()
    assert run(monkeypatch, gws, "greenbone", "pull") == 0
    assert capsys.readouterr().out.splitlines() == [f"{TASK} waiting for the previous cycle to finish"]
    assert "Waiting for the previous cycle to finish before importing more." in card(gws, [TASK])

    def record_cycle(workspace, number):
        complete_cycle(workspace, number)

    tick(gws, record_cycle)  # cycle 1 completes now; its pull still waits
    tick(gws, record_cycle)  # cycle 2: the newer report imports
    state = docs(gws, "scanner_state")[TASK]
    assert state["last_result"] == "imported" and state["last_imported_report_id"] == NEWER
    assert state["last_imported_cycle"] == 2


# --- I2 + M3: a zone-less listing time is refused and counted -----------------------


def test_gmp_refuses_a_zoneless_listing_timestamp(unix_target):
    resp = reports_response(
        report_entry(rid(1), TASK, "Done", "2026-10-01T01:00:00Z"),
        report_entry(rid(2), TASK, "Done", "2026-10-02T01:00:00"),
        report_entry(rid(3), TASK, "Done", "2026-10-03"),
        report_entry(rid(4), TASK, "Done", "2026-10-04T01:00:00+02:00"))
    target, _ = unix_target(default_handler({"get_reports": [resp]}))
    with GmpClient(target, USER, PASSWORD) as client:
        reports = client.finished_reports(TASK)
        refused = client.refused_reports
    assert [r["report_id"] for r in reports] == [rid(1), rid(4)]
    assert refused == [(rid(2), "bad timestamp"), (rid(3), "bad timestamp")]


def test_a_zoneless_listing_is_counted_on_the_pull_line_state_and_card(gws, gvmd, monkeypatch, capsys):
    current = {"report": REPORT, "stamp": "2026-10-20T01:00:00", "body": CLEAN_REPORT}
    path, _ = gvmd(handler_for(current=current))
    configure(gws, path)
    credentials(monkeypatch)
    assert run(monkeypatch, gws, "greenbone", "pull", "--cycle", "1") == 0
    line = capsys.readouterr().out.strip()
    assert line.startswith(f"{TASK} nothing_new ")
    assert line.endswith("; 1 listed reports could not be read")
    state = docs(gws, "scanner_state")[TASK]
    assert state["last_refused_reports"] == 1 and state["last_refused_reasons"] == ["bad timestamp"]
    assert "1 reports in the Greenbone list could not be read and were not considered." in card(gws, [TASK])


# --- I3: results hidden by a rejected result on the same host are counted -----------


def _one_bad_among_five():
    base = report(1)
    on_web = [r for r in base.results if r.ip == "192.0.2.10" and r.severity > 0 and r.qod >= 70]
    extra = dataclasses.replace(on_web[-1], port="8443")
    results = tuple(on_web) + (extra,)  # four readable results on the web host...
    assert len(results) == 4
    # ...and a fifth that could not be read.
    return dataclasses.replace(base, results=results, rejected=(("r-bad", "malformed", "192.0.2.10"),))


def test_results_on_a_host_uncovered_by_a_rejection_are_counted():
    scan = normalise_greenbone(_one_bad_among_five())
    assert WEB not in scan.covered_asset_ids
    assert not [f for f in scan.findings if f["asset_id"] == WEB]
    assert scan.skipped["host_uncovered"] == 4 and scan.skipped["rejected"] == 1
    assert scan.host_uncovered_hosts == 1


def test_host_uncovered_reaches_state_pull_line_and_card(ws, ports):
    from scripts.local import pull_line
    result = import_scan(ports, 1, normalise_greenbone(_one_bad_among_five()), chosen_task_ids=[TASK])
    state = docs(ws, "scanner_state")[TASK]
    assert state["last_skipped"]["host_uncovered"] == 4 and state["last_host_uncovered_hosts"] == 1
    line = pull_line({"task_id": TASK, "result": "imported", "counts": result["counts"],
                      "skipped": result["skipped"], "host_uncovered_hosts": result["host_uncovered_hosts"]})
    assert line.endswith("; 4 results on 1 hosts were not imported because another result on that host "
                         "could not be read")
    assert ("4 results on 1 hosts were not imported because another result on that host could not be read."
            in card(ws, [TASK]))


# --- M1: one spelling per UUID -------------------------------------------------------


def _clean(xml):
    return re.sub(rb'<result id="00000000-0000-4000-8000-000000000006">.*?</result>', b"", xml, flags=re.S)


def test_upper_cased_uuids_map_to_the_same_asset_and_finding(ws, ports):
    first = _clean(FIX("report_basic.xml"))
    import_scan(ports, 1, normalise_greenbone(parse_report(first)), chosen_task_ids=[TASK])
    before = docs(ws, "findings")
    later = (first.replace(REPORT.encode(), NEWER.encode()).replace(b"2026-10-20", b"2026-10-21")
             .replace(b"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", b"AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA")
             .replace(TASK.encode(), TASK.upper().encode()))
    parsed = parse_report(later)
    assert parsed.task_id == TASK
    assert all(h.asset_id == h.asset_id.lower() for h in parsed.hosts if h.asset_id)
    result = import_scan(ports, 2, normalise_greenbone(parsed), chosen_task_ids=[TASK])
    assert result["counts"]["new"] == 0
    after = docs(ws, "findings")
    assert set(after) == set(before)
    assert after[LOG4J]["first_seen_scan"] == REPORT  # not overwritten by the later report


# --- M2: reasonless upload refusals have fixed words --------------------------------


def test_every_refusal_kind_has_a_fixed_upload_message():
    for kind in REFUSED_KINDS:
        assert dashboard_view.UPLOAD_MESSAGES[f"refused_{kind}"].endswith("Nothing was imported.")


def test_upload_into_a_demo_workspace_says_so(page):
    request, token, workspace = page
    seeder = workspace.docs_for("seed")
    seeder.collection("findings").document("RZ-0001").set({"finding_id": "RZ-0001", "status": "open"})
    seeder.close()
    _, _, sent, _ = post_report(request, token, add_task=True)
    assert sent["Location"] == "/?view=infrastructure&upload=refused_demo_workspace"
    assert "demo" in dashboard_view.UPLOAD_MESSAGES["refused_demo_workspace"]


def test_upload_of_a_report_not_done_says_so(page):
    request, token, _ = page
    _, _, sent, _ = post_report(request, token, FIX("report_stopped.xml"), add_task=True)
    assert sent["Location"] == "/?view=infrastructure&upload=refused_not_done"


def test_upload_with_a_report_id_that_is_not_a_uuid_says_so(page):
    request, token, _ = page
    bad = CLEAN_REPORT.replace(REPORT.encode(), b"not-a-uuid")
    _, _, sent, _ = post_report(request, token, bad, add_task=True)
    assert sent["Location"] == "/?view=infrastructure&upload=refused_bad_uuid"


def test_upload_of_a_report_already_imported_says_so(page, monkeypatch):
    from scripts import local
    request, token, _ = page
    assert post_report(request, token, add_task=True)[2]["Location"].endswith("upload=imported")
    monkeypatch.setattr(local, "next_cycle", lambda ws: 7)
    same_id_later = CLEAN_REPORT.replace(b"<scan_end>2026-10-20T01:30:00Z", b"<scan_end>2026-10-21T01:30:00Z")
    _, _, sent, _ = post_report(request, token, same_id_later)
    assert sent["Location"] == "/?view=infrastructure&upload=refused_already_imported"


def test_an_unknown_upload_code_shows_nothing():
    page = dashboard_view.render({"counts": {}, "scans": [], "scanner_state": []}, "infrastructure",
                                 upload_token="t", upload_code="refused_<script>")
    assert 'role="status"' not in page


# --- M7: ticket wording for findings without a single CVE ---------------------------


def test_ticket_wording_for_multi_cve_and_no_cve_findings():
    from tools.github_tickets import issue_body, issue_title
    owner = {"display_name": "Synthetic Owner", "email": "owner@example.invalid", "team": "it"}
    many = {"finding_id": "gb-x:1.2:80/tcp", "cve_ids": ["CVE-2021-44228", "CVE-2021-45046"],
            "asset_id": "gb-x", "scanner_severity": 10.0}
    none = {**many, "cve_ids": []}
    assert issue_title(many) == "[gb-x:1.2:80/tcp] no single CVE on gb-x — 10.0"
    assert issue_title(none) == "[gb-x:1.2:80/tcp] no CVE on gb-x — 10.0"
    assert "- CVE: no single CVE\n" in issue_body(many, owner, "2026-11-01", 7, "critical", "Patch.")
    assert "- CVE: no CVE\n" in issue_body(none, owner, "2026-11-01", 7, "critical", "Patch.")


def test_single_cve_ticket_text_is_byte_identical_to_before():
    """Digests of the text the pre-fix module (d600336) produced for the same inputs."""
    from tools.github_tickets import issue_body, issue_title
    owner = {"owner_id": "own-002", "display_name": "Ada Dunne", "email": "ada.dunne@example.invalid",
             "team": "platform"}
    finding = {"finding_id": "RZ-0101", "cve_id": "CVE-2015-2502", "cve_ids": ["CVE-2015-2502"],
               "asset_id": "ast-002", "scanner_severity": "high"}
    assert issue_title(finding) == "[RZ-0101] CVE-2015-2502 on ast-002 — high"
    body = issue_body(finding, owner, due="2026-09-10", sla_days=7, severity="high", remediation="Patch it.",
                      rationale="KEV listed.", evidence="Scanner saw it.", reviewer="Agreed.", attempts=1)
    assert hashlib.sha256(body.encode()).hexdigest() == \
        "6789c5b9a776fa583046edb50823b46e0b35170951055bf5ad8dba30313c95e5"
    cloud = {"finding_id": "RZ-0101", "cve_id": "CVE-2015-2502", "scanner_severity": "high"}
    body = issue_body(cloud, owner, due="2026-09-10", sla_days=7, severity="high", remediation="Patch it.")
    assert hashlib.sha256(body.encode()).hexdigest() == \
        "4714daf3d16d04b57029986b5cfb814571f9ee0aff6d7cb15232dc67bdd63073"
    assert issue_title({"finding_id": "X"}) == "[X] unknown CVE on an asset — unrated"


# --- M8: the serve banner -------------------------------------------------------------


@pytest.mark.parametrize("demo, prefix", [(True, "Local synthetic preview: "), (False, "Local dashboard: ")])
def test_serve_banner_says_synthetic_only_in_demo_and_the_launcher_accepts_both(demo, prefix):
    from scripts.local import serve_banner
    from scripts.local_launcher import is_ready_line
    line = serve_banner(demo, 8081)
    assert line == f"{prefix}http://127.0.0.1:8081"
    assert is_ready_line(line)
    assert not is_ready_line("Traceback (most recent call last):")


def test_launcher_starts_on_the_saved_records_banner(tmp_path, monkeypatch):
    import io
    from types import SimpleNamespace
    from scripts import local_launcher
    from tools import local_settings
    database = tmp_path / "w"
    local_settings.save(local_settings.settings_path(database), dict(local_settings.DEFAULTS,
                        mode="saved", open_browser=False, port=8083))
    monkeypatch.setattr("sys.argv", ["start", "--database", str(database)])
    started = []

    def start(command, **kwargs):
        started.append(command)
        return SimpleNamespace(stdout=io.StringIO("Local dashboard: http://127.0.0.1:8083\n"),
                               wait=lambda **kw: 0, poll=lambda: 0)
    monkeypatch.setattr(local_launcher.subprocess, "Popen", start)
    local_launcher.main()  # returns normally: the banner was recognised
    assert "--demo" not in started[-1]
