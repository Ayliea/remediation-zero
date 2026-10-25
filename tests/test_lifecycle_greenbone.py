# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""The Greenbone lifecycle end to end: pull, triage, chase, closure, regression.

A fake gvmd (`tests.test_gmp.FakeGvmd` with its `SeriesHandler`) answers over a
real Unix socket registered with the offline guard; nothing reaches a real
gvmd or the network. Each cycle runs what the cycle timer runs: the Greenbone
pull (`scanner_tick`), then the local cycle (`run_local_cycle`) with fake
models. Every pull goes through the real GMP client, parser, normaliser,
import path, rescan and chase.

1. Cycle 1 imports task A's baseline: a CVE-2021-44228 finding and one with
   no CVE, both triaged. The no-CVE one reaches the proposer as "not
   applicable (no CVE)", not as "unknown".
2. Cycle 2: task A's next report covers the web host without the Log4j
   finding. It is resolved, and chase closes its ticket.
3. Cycle 3: the finding is back. It is reopened as regressed, and chase
   reopens the ticket.
4. Cycle 4: task B's first report covers the same host and shows nothing,
   which would close everything if B had authority. It changes no finding.
   Task A's newer report is Stopped: never downloaded, recorded as skipped,
   and shown on the dashboard.

Finally no credential appears in any workspace file, in stdout or stderr, or
in any log record.

The wall clock is injected through `SimClock`'s `source` (one day per cycle),
so the synthetic scan times are in the past and each cycle's chase runs on a
day of its own. Synthetic data only: documentation IPs, `.invalid`
hostnames, synthetic UUIDs; CVE-2021-44228 is real and public.
"""
import logging
import xml.etree.ElementTree as ET

from engine.snapshot import snapshot
from scripts.local import next_cycle, run_local_cycle, scanner_tick
from tests.test_gmp import TASK_A, TASK_B, SeriesHandler, reports_response
from tests.test_greenbone_commands import gvmd  # noqa: F401 - the fake gvmd fixture
from tests.test_local_commands import cross_family
from tools import local_settings
from tools.clock import ClockMode, SimClock
from tools.local_layout import Workspace
from ui.dashboard_view import render

DAY = 86400.0
#: 2026-10-20T00:00:00Z. Cycle n runs at 06:00 on day n after it.
DAY0 = 1792454400.0
#: Distinctive, synthetic, and searched for in every file and every captured line.
USERNAME = "rz-lifecycle-reader-q7v"
PASSWORD = "Lc9-xK2-synthetic-Pw-m4r"
ENV = {"RZ_GREENBONE_USERNAME": USERNAME, "RZ_GREENBONE_PASSWORD": PASSWORD}

WEB_ASSET = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
WEB = f"gb-{WEB_ASSET}"
LOG4J_OID = "1.3.6.1.4.1.25623.1.0.117850"
SSH_OID = "1.3.6.1.4.1.25623.1.0.105611"
#: As Greenbone names them; `rows` keys every collection by the upper-cased form.
LOG4J_ID = f"{WEB}:{LOG4J_OID}:8080/tcp"
NO_CVE_ID = f"{WEB}:{SSH_OID}:22/tcp"
LOG4J, NO_CVE = LOG4J_ID.upper(), NO_CVE_ID.upper()

LOG4J_RESULT = (LOG4J_OID, "Apache Log4j RCE (Log4Shell)", "8080/tcp", "10.0", 97, ("CVE-2021-44228",))
SSH_RESULT = (SSH_OID, "SSH Weak Encryption Algorithms Supported", "22/tcp", "5.3", 95, ())


def report_id(task_letter, n):
    prefix = {"a": "33333333-3333-4333-8333", "b": "55555555-5555-4555-8555"}[task_letter]
    return f"{prefix}-{n:012d}"


def listed_at(day):
    """gvmd lists a report at its creation: 01:00 on that day."""
    return f"2026-10-{20 + day:02d}T01:00:00Z"


def scan_end(day):
    return f"2026-10-{20 + day:02d}T02:00:00Z"


def result_xml(n, oid, name, port, severity, qod, cves):
    refs = "".join(f'<ref type="cve" id="{cve}"/>' for cve in cves)
    return (f'<result id="00000000-0000-4000-8000-{n:012d}"><name>{name}</name>'
            f'<host>192.0.2.10<asset asset_id="{WEB_ASSET}"/><hostname>web.example.invalid</hostname></host>'
            f'<port>{port}</port><nvt oid="{oid}"><type>nvt</type><name>{name}</name>'
            f'<tags>summary=Synthetic summary.|solution_type=VendorFix</tags>'
            f'<solution type="VendorFix">Apply the vendor update.</solution><refs>{refs}</refs></nvt>'
            f'<threat>High</threat><severity>{severity}</severity>'
            f'<qod><value>{qod}</value><type>remote_banner</type></qod>'
            f'<description>Synthetic description.</description></result>')


def report_body(rid, task_id, task_name, day, results, status="Done"):
    """The get_reports response gvmd serves for one report: one web host, finished."""
    body = "".join(result_xml(i + 1, *r) for i, r in enumerate(results))
    return reports_response(
        f'<report id="{rid}" format_id="a994b278-1f62-11e1-96ac-406186ea4fc5" extension="xml">'
        f'<report id="{rid}"><scan_run_status>{status}</scan_run_status>'
        f'<timestamp>{listed_at(day)}</timestamp><scan_end>{scan_end(day)}</scan_end>'
        f'<task id="{task_id}"><name>{task_name}</name></task>'
        f'<results start="1" max="1000">{body}</results>'
        f'<host><ip>192.0.2.10</ip><asset asset_id="{WEB_ASSET}"/>'
        f'<start>{listed_at(day)}</start><end>{scan_end(day)}</end>'
        f'<detail><name>hostname</name><value>web.example.invalid</value></detail></host>'
        f'</report></report>')


def publish(series, letter, day, results, status="Done"):
    task_id, name = (TASK_A, "Weekly LAN") if letter == "a" else (TASK_B, "DMZ")
    rid = report_id(letter, day)
    series.publish(task_id, rid, status, listed_at(day),
                   report_body(rid, task_id, name, day, results, status))
    return rid


def rows(ws, collection):
    """Documents keyed by their own `finding_id` (or `task_id`) field, never the document id.

    The idempotency layer upper-cases a finding id wherever it keys a write: the finding's
    document id and the `finding_id` field of decisions, assignments, clocks and tickets.
    Only the finding's own `finding_id` field keeps Greenbone's case. Rows are keyed by the
    upper-cased id so one key names a finding in every collection."""
    store = ws.docs_for("dashboard")
    try:
        found = [s.to_dict() for s in store.collection(collection).stream()]
    finally:
        store.close()
    if collection == "scanner_state":
        return {row["task_id"]: row for row in found if row.get("task_id")}
    return {row["finding_id"].upper(): row for row in found if row.get("finding_id")}


def proposer_input(roles, finding_id):
    """The one text the proposer was given about `finding_id`."""
    inputs = [text for text in roles._fakes["proposer"].calls
              if f"finding_id: {finding_id}\n" in text]
    assert len(inputs) == 1, (finding_id, len(inputs))
    return inputs[0]


def record_owner(ws):
    """A person records who owns the web host. Greenbone assets arrive unowned (owners come
    in a later release); without an owner the assignment goes to the human queue and no
    ticket is opened, so there would be nothing for chase to close."""
    docs = ws.docs_for("seed")
    try:
        docs.collection("owners").document("own-01").set({
            "owner_id": "own-01", "email": "owner@example.invalid",
            "display_name": "Synthetic Owner", "team": "synthetic"})
        docs.collection("assets").document(WEB).update({"owner_id": "own-01"})
    finally:
        docs.close()


def test_greenbone_lifecycle_end_to_end(tmp_path, gvmd, capsys, caplog):  # noqa: F811
    caplog.set_level(logging.DEBUG)
    home = tmp_path / "install"
    ws = Workspace(home / "workspace")
    ws.init()
    series = SeriesHandler([(TASK_A, "Weekly LAN"), (TASK_B, "DMZ")])
    socket_path, server = gvmd(series)
    settings_file = local_settings.settings_path(ws.root)
    values = local_settings.load(settings_file)
    values["scanner"].update(transport="unix", socket_path=socket_path, task_ids=[TASK_A, TASK_B])
    local_settings.save(settings_file, values)
    roles = cross_family()
    wall = {"now": DAY0}
    clock = SimClock(ClockMode.REAL, source=lambda: wall["now"])

    def pull(n):
        wall["now"] = DAY0 + n * DAY + 6 * 3600
        assert next_cycle(ws) == n  # the number the cycle timer would take
        scanner_tick(ws, n, ENV, clock=clock)

    def cycle(n):
        return run_local_cycle(ws, n, roles=roles, clock=clock, environ={})

    # --- cycle 1: the baseline is pulled and triaged -----------------------------------
    a1 = publish(series, "a", 1, [LOG4J_RESULT, SSH_RESULT])
    pull(1)
    state = rows(ws, "scanner_state")
    assert state[TASK_A]["last_result"] == "imported"
    assert state[TASK_A]["last_imported_report_id"] == a1
    assert state[TASK_B]["last_result"] == "nothing_new"  # chosen, nothing listed yet
    findings = rows(ws, "findings")
    assert set(findings) == {LOG4J, NO_CVE}
    assert {f["finding_id"] for f in findings.values()} == {LOG4J_ID, NO_CVE_ID}
    assert findings[LOG4J]["cve_ids"] == ["CVE-2021-44228"]
    assert findings[NO_CVE]["cve_ids"] == []
    assert {f["task_id"] for f in findings.values()} == {TASK_A}
    record_owner(ws)
    first = cycle(1)
    assert first["outcomes"] == {"ratified": 2}
    assert first["chase"] == {"open_ticket": 2}

    # The no-CVE finding was decided on "not applicable", in the proposer's own input.
    no_cve_text = proposer_input(roles, NO_CVE_ID)
    assert "cve_ids: none (no CVE)" in no_cve_text
    assert "in_cisa_kev: not applicable (no CVE)" in no_cve_text
    assert "epss_score: not applicable (no CVE)" in no_cve_text
    assert "unknown (KEV list not available)" not in no_cve_text
    log4j_text = proposer_input(roles, LOG4J_ID)
    assert "cve_ids: CVE-2021-44228" in log4j_text
    assert "not applicable (no CVE)" not in log4j_text
    decisions = rows(ws, "decisions")
    assert {d["outcome"] for d in decisions.values()} == {"ratified"} and set(decisions) == {LOG4J, NO_CVE}
    tickets = rows(ws, "tickets")
    assert {f: t["status"] for f, t in tickets.items()} == {LOG4J: "open", NO_CVE: "open"}

    # --- cycle 2: absent on a covered host -> resolved, and chase closes the ticket -----
    a2 = publish(series, "a", 2, [SSH_RESULT])
    pull(2)
    findings = rows(ws, "findings")
    assert findings[LOG4J]["status"] == "resolved"
    assert findings[LOG4J]["resolved_by_scan"] == a2
    assert findings[NO_CVE]["status"] == "open"
    assert rows(ws, "tickets")[LOG4J]["status"] == "open"  # chase has not run yet
    second = cycle(2)
    assert second["outcomes"] == {}  # decided findings are not triaged again
    # The no-CVE ticket was opened a day ago: not yet due for a nudge.
    assert second["chase"] == {"close_ticket": 1, "wait": 1}
    ticket = rows(ws, "tickets")[LOG4J]
    assert ticket["status"] == "resolved" and ticket["resolved_by_scan"] == a2
    assert [e["action"] for e in ticket["history"]] == ["open_ticket", "close_ticket"]
    assert rows(ws, "tickets")[NO_CVE]["status"] == "open"

    # --- cycle 3: back again -> regressed, and chase reopens the ticket ----------------
    a3 = publish(series, "a", 3, [LOG4J_RESULT, SSH_RESULT])
    pull(3)
    findings = rows(ws, "findings")
    assert findings[LOG4J]["status"] == "open"
    assert findings[LOG4J]["regressed_in_scan"] == a3
    assert rows(ws, "scanner_state")[TASK_A]["last_counts"]["regressed"] == 1
    third = cycle(3)
    assert third["outcomes"] == {}
    # Two days after it opened, the no-CVE ticket is nudged (a 7-day SLA nudges every 1.75 days).
    assert third["chase"] == {"open_ticket": 1, "nudge": 1}
    ticket = rows(ws, "tickets")[LOG4J]
    assert ticket["status"] == "open"
    assert [e["action"] for e in ticket["history"]] == ["open_ticket", "close_ticket", "open_ticket"]
    assert len(roles._fakes["proposer"].calls) == 2  # each finding was paid for once

    # --- cycle 4: another task's report changes nothing; a Stopped report is skipped ----
    b4 = publish(series, "b", 4, [])  # covers the web host and shows nothing at all
    a4 = publish(series, "a", 4, [SSH_RESULT], status="Stopped")
    before = rows(ws, "findings")
    pull(4)
    assert rows(ws, "findings") == before
    state = rows(ws, "scanner_state")
    assert state[TASK_B]["last_result"] == "imported"
    assert state[TASK_B]["last_imported_report_id"] == b4
    assert state[TASK_B]["last_counts"]["resolved"] == 0
    assert state[TASK_A]["last_result"] == "nothing_new"
    assert state[TASK_A]["last_imported_report_id"] == a3
    assert state[TASK_A]["skipped"] == [{"report_id": a4, "status": "Stopped"}]
    assert a4 not in series.downloaded  # only Done reports are ever downloaded
    assert series.downloaded == [a1, a2, a3, b4]
    cycle(4)
    assert rows(ws, "findings") == before
    store = ws.docs_for("dashboard")
    try:
        page = render(snapshot(store), "infrastructure", chosen_tasks=[TASK_A, TASK_B])
    finally:
        store.close()
    assert f"<li>Stopped: {a4}</li>" in page

    # Read-only GMP: nothing but authenticate and get_reports was ever sent.
    assert {ET.fromstring(raw).tag for raw in server.requests} == {"authenticate", "get_reports"}

    # --- no credential anywhere ------------------------------------------------------
    files = [p for p in home.rglob("*") if p.is_file()]
    assert settings_file in files and any(p.suffix == ".sqlite3" for p in files)
    for path in files:
        data = path.read_bytes()
        for secret in (USERNAME, PASSWORD):
            assert secret.encode() not in data, path
    captured = capsys.readouterr()
    logged = "\n".join(record.getMessage() for record in caplog.records)
    for secret in (USERNAME, PASSWORD):
        assert secret not in captured.out and secret not in captured.err
        assert secret not in logged and secret not in caplog.text
