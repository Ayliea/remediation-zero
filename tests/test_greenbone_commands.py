# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""The `greenbone` commands and the cycle timer's pull.

Synthetic data only: documentation IPs, `.invalid` hosts, synthetic UUIDs. A
fake gvmd answers over a real unix socket; the offline guard's `fake_endpoints`
fixture is the only way in. The cycle uses fake models.
"""
import json
import logging
import re
import socket
import unicodedata
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from tests.test_gmp import (OK_AUTH, PASSWORD, TASK_A, TASK_B, USER, FakeGvmd, report_entry,
                            reports_response, tasks_response)
from tests.test_local_commands import (_fake_sources, _local, cross_family, docs, events,  # noqa: F401
                                       ws)
from tests.test_scanner_import import complete_cycle
from tools import local_settings
from tools.clock import ClockMode, SimClock
from tools.local_layout import Workspace

ROOT = Path(__file__).resolve().parents[1]
REPORT = "22222222-2222-4222-8222-222222222222"
REPORT_FILE = ROOT / "tests" / "fixtures" / "greenbone" / "report_basic.xml"
#: The fixture without its malformed result, so the report's coverage is trusted and its findings import.
CLEAN_REPORT = re.sub(r'<result id="00000000-0000-4000-8000-000000000006">.*?</result>', "",
                      REPORT_FILE.read_text(), flags=re.S).encode()
NOW = 1793145600.0  # 2026-10-28: after the fixture's scan time
USER_VAR, PASS_VAR = "RZ_GREENBONE_USERNAME", "RZ_GREENBONE_PASSWORD"
ANSI_NAME = "\x1b[31mRed\x1b[0m\x07 task " + "n" * 200


def handler_for(*, auth=None, current=None):
    """`current` (a dict with report/stamp/body) lets a test change the report gvmd serves."""
    current = current or {"report": REPORT, "stamp": "2026-10-20T01:00:00Z", "body": CLEAN_REPORT}

    def handler(tag, raw):
        if tag == "authenticate":
            return [auth] if auth else [OK_AUTH]
        if tag == "get_tasks":
            return [tasks_response((TASK_A, "Weekly LAN"), (TASK_B, "DMZ"))]
        if tag == "get_reports":
            if b"report_id=" in raw:
                return [current["body"]]
            return [reports_response(report_entry(current["report"], TASK_A, "Done", current["stamp"]))]
        return [f'<{tag}_response status="404" status_text="Not found"/>'.encode()]
    return handler


@pytest.fixture
def gvmd(tmp_path_factory, fake_endpoints):
    servers = []

    def start(handler=None):
        path = str(tmp_path_factory.mktemp("g") / "gvmd.sock")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(path)
        listener.listen(4)
        fake_endpoints.unix(path)
        servers.append(FakeGvmd(listener, handler or handler_for()))
        return path, servers[-1]
    yield start
    for server in servers:
        server.close()


@pytest.fixture
def gws(tmp_path):
    """An empty workspace: Greenbone data and seeded data never share one."""
    workspace = Workspace(tmp_path / "gw")
    workspace.init()
    return workspace


@pytest.fixture(autouse=True)
def fixed_clock(monkeypatch):
    from scripts import local
    monkeypatch.setattr(local.SimClock, "from_env",
                        classmethod(lambda cls, environ=None: SimClock(ClockMode.REAL, source=lambda: NOW)))


def configure(workspace, socket_path="/run/gvmd/gvmd.sock", task_ids=(TASK_A,), **scanner):
    path = local_settings.settings_path(workspace.root)
    values = local_settings.load(path)
    values["scanner"].update(transport="unix", socket_path=socket_path, task_ids=list(task_ids), **scanner)
    local_settings.save(path, values)


def credentials(monkeypatch, present=True):
    for name, value in ((USER_VAR, USER), (PASS_VAR, PASSWORD)):
        if present:
            monkeypatch.setenv(name, value)
        else:
            monkeypatch.delenv(name, raising=False)


def run(monkeypatch, workspace, *args):
    from scripts import local
    monkeypatch.setattr("sys.argv", ["local", "--database", str(workspace.root), *args])
    with pytest.raises(SystemExit) as stopped:
        local.main()
        raise SystemExit(0)
    return stopped.value.code or 0


def no_connection(monkeypatch):
    from scripts import local
    monkeypatch.setattr(local, "GmpClient", lambda *a, **k: pytest.fail("a connection was attempted"))


def fake_client(monkeypatch, *, tasks=None, enter_error=None):
    from scripts import local

    class Fake:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            if enter_error:
                raise enter_error
            return self

        def __exit__(self, *a):
            pass

        def list_tasks(self):
            return tasks or []
    monkeypatch.setattr(local, "GmpClient", Fake)


def task_ids(workspace):
    return local_settings.load(local_settings.settings_path(workspace.root))["scanner"]["task_ids"]


def everything_under(workspace):
    return {str(p): p.read_bytes() for p in workspace.root.parent.rglob("*") if p.is_file()}


def tick(workspace, run_cycle=None, **kwargs):
    from scripts.local_launcher import IntervalRunner
    IntervalRunner(workspace.root, 5, run=run_cycle or (lambda w, c: None), wait=lambda s: True,
                   **kwargs).tick()


# --- tasks, test -----------------------------------------------------------------------


def test_greenbone_tasks_lists_from_a_fake_server(gws, gvmd, monkeypatch, capsys):
    path, server = gvmd()
    configure(gws, path)
    credentials(monkeypatch)
    assert run(monkeypatch, gws, "greenbone", "tasks") == 0
    assert capsys.readouterr().out.splitlines() == [f"{TASK_A}  Weekly LAN", f"{TASK_B}  DMZ"]
    assert [ET.fromstring(r).tag for r in server.requests] == ["authenticate", "get_tasks"]


def test_greenbone_tasks_with_none_visible_says_why_on_stderr(gws, monkeypatch, capsys):
    # A new read-only account sees nothing until it is an observer on a task; an empty,
    # silent success read like a broken connection during the first real-gvmd check.
    configure(gws)
    credentials(monkeypatch)
    fake_client(monkeypatch, tasks=[])
    assert run(monkeypatch, gws, "greenbone", "tasks") == 0
    captured = capsys.readouterr()
    assert captured.out == ""  # stdout stays one task per line, for scripts
    assert "This account can see no tasks." in captured.err
    assert "add it as an observer" in captured.err


def test_task_names_are_cleaned_before_they_reach_the_terminal(gws, monkeypatch, capsys):
    configure(gws)
    credentials(monkeypatch)
    fake_client(monkeypatch, tasks=[{"task_id": TASK_A, "name": ANSI_NAME}])
    assert run(monkeypatch, gws, "greenbone", "tasks") == 0
    out = capsys.readouterr().out
    assert "\x1b" not in out and "\x07" not in out and "[31m" not in out
    line = out.splitlines()[0]
    assert line.startswith(f"{TASK_A}  Red task ")
    assert len(line.split("  ", 1)[1]) <= 80


def test_greenbone_test_prints_the_same_three_lines_as_the_page(gws, gvmd, monkeypatch, capsys):
    path, _ = gvmd()
    configure(gws, path)
    credentials(monkeypatch)
    assert run(monkeypatch, gws, "greenbone", "test") == 0
    assert capsys.readouterr().out.splitlines() == ["Connected: yes", "Signed in: yes", "Tasks listed: yes (2)"]


def test_greenbone_test_wrong_credentials_then_unreachable(gws, gvmd, monkeypatch, capsys):
    path, _ = gvmd(handler_for(auth=f'<authenticate_response status="400" status_text="no {PASSWORD}"/>'.encode()))
    configure(gws, path)
    credentials(monkeypatch)
    assert run(monkeypatch, gws, "greenbone", "test") == 1
    assert capsys.readouterr().out.splitlines() == ["Connected: yes", "Signed in: no", "Tasks listed: no"]
    fake_client(monkeypatch, enter_error=ConnectionRefusedError("nothing is listening"))
    assert run(monkeypatch, gws, "greenbone", "test") == 1
    assert capsys.readouterr().out.splitlines() == ["Connected: no", "Signed in: no", "Tasks listed: no"]


@pytest.mark.parametrize("command", [("tasks",), ("test",), ("pull",), ("pull", "--cycle", "3")])
def test_missing_credentials_exit_2_with_the_variable_names(gws, monkeypatch, capsys, command):
    configure(gws)
    credentials(monkeypatch, present=False)
    no_connection(monkeypatch)
    assert run(monkeypatch, gws, "greenbone", *command) == 2
    err = capsys.readouterr().err
    assert USER_VAR in err and PASS_VAR in err


# --- pull ------------------------------------------------------------------------------


def test_pull_prints_one_line_per_task_and_exits_by_result(gws, gvmd, monkeypatch, capsys):
    path, _ = gvmd()
    configure(gws, path, task_ids=(TASK_A, TASK_B))
    credentials(monkeypatch)
    assert run(monkeypatch, gws, "greenbone", "pull", "--cycle", "1") == 0
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 2
    assert lines[0].split()[:2] == [TASK_A, "imported"]
    assert re.search(r"findings=[1-9]\d* resolved=0 skipped=\d+ refused=0 deferred=0$", lines[0])
    assert lines[1].split()[:2] == [TASK_B, "nothing_new"]
    # the same, completed, cycle again: nothing is wrong, so a frequent cron pull exits 0
    complete_cycle(gws, 1)
    assert run(monkeypatch, gws, "greenbone", "pull", "--cycle", "1") == 0
    assert "already_imported_this_cycle" in capsys.readouterr().out


def test_pull_defaults_to_the_next_cycle_number(gws, gvmd, monkeypatch, capsys):
    path, _ = gvmd()
    configure(gws, path)
    credentials(monkeypatch)
    assert run(monkeypatch, gws, "greenbone", "pull") == 0
    assert docs(gws, "scanner_state")[TASK_A]["last_imported_cycle"] == 1


def test_pull_failure_prints_the_error_class_only_and_exits_1(gws, monkeypatch, capsys):
    configure(gws)
    credentials(monkeypatch)
    fake_client(monkeypatch, enter_error=OSError("secret detail zq"))
    assert run(monkeypatch, gws, "greenbone", "pull") == 1
    captured = capsys.readouterr()
    assert captured.out.split() == [TASK_A, "failed", "OSError"]
    assert "secret detail zq" not in captured.out + captured.err


def test_pull_with_no_chosen_tasks_makes_no_connection(gws, monkeypatch, capsys):
    configure(gws, task_ids=())
    credentials(monkeypatch)
    no_connection(monkeypatch)
    assert run(monkeypatch, gws, "greenbone", "pull") == 0
    assert "No tasks are chosen" in capsys.readouterr().out


# --- upload ----------------------------------------------------------------------------


def test_upload_from_an_unchosen_task_needs_add_task_and_writes_nothing(gws, monkeypatch, capsys):
    configure(gws, task_ids=())
    before = everything_under(gws)
    assert run(monkeypatch, gws, "greenbone", "upload", str(REPORT_FILE)) == 1
    assert (f"Task {TASK_A} is not chosen for this install. Re-run with --add-task to add it."
            in capsys.readouterr().err)
    assert everything_under(gws) == before


def test_upload_add_task_saves_the_task_only_after_parsing(gws, monkeypatch, capsys, tmp_path):
    configure(gws, task_ids=())
    junk = tmp_path / "junk.xml"
    junk.write_text("<not-a-report/>")
    assert run(monkeypatch, gws, "greenbone", "upload", str(junk), "--add-task") == 1
    assert task_ids(gws) == []
    capsys.readouterr()
    assert run(monkeypatch, gws, "greenbone", "upload", str(REPORT_FILE), "--add-task") == 0
    assert f"Adding task Weekly Example Scan ({TASK_A}) to this install." in capsys.readouterr().out
    assert task_ids(gws) == [TASK_A]
    assert REPORT in docs(gws, "scans")


def test_a_demo_workspace_refuses_the_import_and_the_settings_stay(gws, monkeypatch, capsys):
    configure(gws, task_ids=())
    seed = gws.docs_for("seed")
    seed.collection("findings").document("RZ-0001").set({"finding_id": "RZ-0001", "status": "open"})
    seed.close()
    assert run(monkeypatch, gws, "greenbone", "upload", str(REPORT_FILE), "--add-task") == 1
    captured = capsys.readouterr()
    assert task_ids(gws) == []
    assert "Adding task" not in captured.out
    assert "demo" in captured.err


def test_a_report_not_newer_is_refused_with_its_closed_reason_and_the_settings_stay(gws, monkeypatch, capsys):
    configure(gws, task_ids=())
    assert run(monkeypatch, gws, "greenbone", "upload", str(REPORT_FILE), "--add-task") == 0
    capsys.readouterr()
    configure(gws, task_ids=())  # forget the choice; the task's import state stays in the workspace
    older = REPORT_FILE.read_text().replace(REPORT, "44444444-4444-4444-8444-444444444444")
    path = gws.root.parent / "older.xml"
    path.write_text(older)
    assert run(monkeypatch, gws, "greenbone", "upload", str(path), "--add-task", "--cycle", "9") == 1
    captured = capsys.readouterr()
    assert task_ids(gws) == []
    assert "not_newer" in captured.err and "Adding task" not in captured.out


def test_upload_task_name_is_untrusted_and_cleaned(gws, monkeypatch, capsys, tmp_path):
    configure(gws, task_ids=())
    hostile = REPORT_FILE.read_text().replace("Weekly Example Scan", "Red&#8238;&#8203;&#9;\u009b[31m " + "n" * 200)
    path = tmp_path / "hostile.xml"
    path.write_text(hostile)
    assert run(monkeypatch, gws, "greenbone", "upload", str(path), "--add-task") == 0
    text = capsys.readouterr().out
    adding = next(line for line in text.splitlines() if line.startswith("Adding task"))
    name = adding[len("Adding task "):adding.rindex(f" ({TASK_A})")]
    assert name.startswith("Red") and len(name) <= 80
    assert not any(unicodedata.category(c)[0] == "C" for c in text.replace("\n", ""))


def test_upload_refuses_a_file_over_the_size_cap_without_reading_it(gws, monkeypatch, capsys, tmp_path):
    from scripts import local
    configure(gws, task_ids=())
    monkeypatch.setattr(local, "MAX_REPORT_BYTES", 100)
    big = tmp_path / "big.xml"
    big.write_bytes(b"x" * 101)
    monkeypatch.setattr(Path, "read_bytes", lambda self: pytest.fail("read the whole file"))
    assert run(monkeypatch, gws, "greenbone", "upload", str(big), "--add-task") == 1
    assert "larger than" in capsys.readouterr().err
    assert task_ids(gws) == []


def test_upload_needs_no_credentials_and_no_connection(gws, monkeypatch):
    configure(gws, task_ids=(TASK_A,))
    credentials(monkeypatch, present=False)
    no_connection(monkeypatch)
    assert run(monkeypatch, gws, "greenbone", "upload", str(REPORT_FILE)) == 0


# --- the timer -------------------------------------------------------------------------


def test_pull_then_cycle_triages_imported_findings(gws, gvmd, monkeypatch, caplog):
    from scripts.local import run_local_cycle
    caplog.set_level(logging.INFO)
    path, _ = gvmd()
    configure(gws, path)
    credentials(monkeypatch)
    before_cycle = []

    def cycle(workspace, number):
        before_cycle.append((number, len(docs(workspace, "findings"))))
        return run_local_cycle(workspace, number, roles=cross_family(),
                               clock=SimClock(ClockMode.REAL, source=lambda: NOW), environ={})

    tick(gws, cycle)
    assert before_cycle[0][0] == 1 and before_cycle[0][1] > 0, "imported before the cycle ran"
    findings, decisions = docs(gws, "findings"), docs(gws, "decisions")
    assert len(decisions) == len(findings)
    assert all(d["outcome"] == "ratified" for d in decisions.values())
    names = [json.loads(r.getMessage())["event"] for r in caplog.records if r.getMessage().startswith("{")]
    assert names.index("scanner_pull") < names.index("interval_cycle_finished")


def test_failed_pull_does_not_block_the_cycle(ws, monkeypatch, caplog):
    # A seeded workspace refuses any import outright: the pull raises, the cycle still runs.
    caplog.set_level(logging.INFO)
    configure(ws)
    credentials(monkeypatch)
    no_connection(monkeypatch)
    ran = []
    tick(ws, lambda w, c: ran.append(c))
    assert ran == [1]
    failed = events(caplog, "greenbone_pull_failed")
    assert len(failed) == 1 and failed[0]["error"] == "ImportRefused"
    assert not events(caplog, "cycle_failed")


def test_a_task_that_fails_to_pull_still_lets_the_cycle_run(gws, monkeypatch, caplog):
    caplog.set_level(logging.INFO)
    configure(gws)
    credentials(monkeypatch)
    fake_client(monkeypatch, enter_error=OSError("secret detail zq"))
    ran = []
    tick(gws, lambda w, c: ran.append(c))
    assert ran == [1]
    assert docs(gws, "scanner_state")[TASK_A]["last_result"] == "failed"
    assert "secret detail zq" not in caplog.text


def test_no_tasks_chosen_means_no_connection_and_no_failure_logged(gws, monkeypatch, caplog):
    caplog.set_level(logging.INFO)
    configure(gws, task_ids=())
    credentials(monkeypatch)
    no_connection(monkeypatch)
    ran = []
    tick(gws, lambda w, c: ran.append(c))
    assert ran == [1]
    assert not [r for r in caplog.records if "failed" in r.getMessage() or "credentials" in r.getMessage()]


def test_missing_credentials_are_logged_once_per_tick_and_the_cycle_runs(gws, monkeypatch, caplog):
    from scripts.local_launcher import IntervalRunner
    caplog.set_level(logging.INFO)
    configure(gws, task_ids=(TASK_A, TASK_B))
    credentials(monkeypatch, present=False)
    no_connection(monkeypatch)
    ran = []
    runner = IntervalRunner(gws.root, 5, run=lambda w, c: ran.append(c), wait=lambda s: True)
    runner.tick()
    assert ran == [1] and len(events(caplog, "greenbone_credentials_missing")) == 1
    runner.tick()
    assert len(events(caplog, "greenbone_credentials_missing")) == 2


def spy_enrichment(monkeypatch):
    from scripts import local
    calls = []
    monkeypatch.setattr(local, "urllib_get", _fake_sources(calls))
    # refresh() paces NVD calls with time.sleep, its keyword default: no waiting in tests
    from tools.enrichment_fetch import refresh
    monkeypatch.setitem(refresh.__kwdefaults__, "sleep", lambda seconds: None)
    return calls


def test_auto_enrichment_off_by_default_never_fetches(gws, gvmd, monkeypatch):
    path, _ = gvmd()
    configure(gws, path)  # auto_enrichment stays False
    credentials(monkeypatch)
    calls = spy_enrichment(monkeypatch)
    tick(gws)
    assert docs(gws, "findings")
    assert calls == []
    assert "enrichment" not in docs(gws, "scanner_state")


def test_auto_enrichment_on_fetches_only_the_new_cves_before_the_cycle(gws, gvmd, monkeypatch):
    from tools.enrichment import finding_cves
    path, _ = gvmd()
    configure(gws, path, auto_enrichment=True)
    credentials(monkeypatch)
    calls = spy_enrichment(monkeypatch)
    seen = []
    tick(gws, lambda w, c: seen.append(len(calls)))
    expected = sorted({c for f in docs(gws, "findings").values() for c in finding_cves(f)})
    assert expected
    assert sorted(u.split("=")[1] for u, _ in calls if "cveId" in u) == expected
    assert seen[0] > 0, "enrichment ran before the cycle"
    assert docs(gws, "scanner_state")["enrichment"]["kev"] == "ok"


def test_a_pull_with_nothing_new_fetches_no_enrichment(gws, gvmd, monkeypatch):
    path, _ = gvmd()
    configure(gws, path, auto_enrichment=True)
    credentials(monkeypatch)
    calls = spy_enrichment(monkeypatch)
    tick(gws)
    assert calls
    calls.clear()
    tick(gws)  # the report is already imported: nothing new
    assert calls == []


def test_enrichment_failure_is_logged_by_class_and_the_cycle_still_runs(gws, gvmd, monkeypatch, caplog):
    from scripts import local
    caplog.set_level(logging.INFO)
    path, _ = gvmd()
    configure(gws, path, auto_enrichment=True)
    credentials(monkeypatch)

    def boom(*a, **k):
        raise RuntimeError("secret detail zq")
    monkeypatch.setattr(local, "update_enrichment", boom)
    ran = []
    tick(gws, lambda w, c: ran.append(c))
    assert ran == [1]
    failed = events(caplog, "greenbone_enrichment_failed")
    assert len(failed) == 1 and failed[0]["error"] == "RuntimeError"
    assert "secret detail zq" not in caplog.text


# --- credentials never leak ------------------------------------------------------------


def test_no_credential_reaches_stdout_stderr_logs_settings_or_records(gws, gvmd, monkeypatch, capsys, caplog, tmp_path):
    caplog.set_level(logging.INFO)
    echo = f'<authenticate_response status="400" status_text="bad {USER} {PASSWORD}"/>'.encode()
    bad, _ = gvmd(handler_for(auth=echo))
    configure(gws, bad)
    credentials(monkeypatch)
    for command in (("tasks",), ("test",), ("pull",)):
        assert run(monkeypatch, gws, "greenbone", *command) == 1
    tick(gws)
    good, _ = gvmd()
    configure(gws, good)
    assert run(monkeypatch, gws, "greenbone", "pull", "--cycle", "7") == 0
    assert run(monkeypatch, gws, "greenbone", "upload", str(REPORT_FILE)) in (0, 1)
    captured = capsys.readouterr()
    haystack = captured.out + captured.err + caplog.text
    for secret in (PASSWORD, USER):
        assert secret not in haystack
        for path in tmp_path.rglob("*"):
            if path.is_file():
                assert secret.encode() not in path.read_bytes(), path


def test_help_lists_the_greenbone_commands():
    result = _local("greenbone", "--help")
    assert result.returncode == 0, result.stderr
    for name in ("tasks", "test", "pull", "upload"):
        assert name in result.stdout
    assert "greenbone" in _local("--help").stdout


# --- fix round 1 -----------------------------------------------------------------------


def test_a_failed_settings_save_after_the_import_says_so_and_exits_1(gws, monkeypatch, capsys):
    from scripts import local
    configure(gws, task_ids=())

    def broken(*args, **kwargs):
        raise OSError("disk full zq")
    monkeypatch.setattr(local.local_settings, "save", broken)
    assert run(monkeypatch, gws, "greenbone", "upload", str(REPORT_FILE), "--add-task") == 1
    captured = capsys.readouterr()
    assert f"Imported, but task {TASK_A} was not saved; add it in Settings." in captured.err
    assert "Adding task" not in captured.out and "Traceback" not in captured.err
    assert "disk full zq" not in captured.err
    assert REPORT in docs(gws, "scans")
    assert task_ids(gws) == []


def test_add_task_at_the_task_limit_is_refused_before_the_import(gws, monkeypatch, capsys):
    from scripts.local import MAX_CHOSEN_TASKS
    full = [f"{n:08x}-0000-4000-8000-000000000000" for n in range(MAX_CHOSEN_TASKS)]
    configure(gws, task_ids=full)
    assert run(monkeypatch, gws, "greenbone", "upload", str(REPORT_FILE), "--add-task") == 1
    err = capsys.readouterr().err
    assert f"At most {MAX_CHOSEN_TASKS} scan tasks can be chosen." in err
    assert docs(gws, "scans") == {} and docs(gws, "findings") == {}
    assert task_ids(gws) == full


def test_an_unrelated_value_error_is_not_reported_as_not_set_up(gws, gvmd, monkeypatch, capsys):
    from scripts import local
    path, _ = gvmd()
    configure(gws, path)
    credentials(monkeypatch)

    def broken(*args, **kwargs):
        raise ValueError("something else")
    monkeypatch.setattr(local, "pull", broken)
    with pytest.raises(ValueError):
        local.greenbone_pull_command(gws, local_settings.load(local_settings.settings_path(gws.root)),
                                     local.os.environ, 1)
    assert "not set up" not in capsys.readouterr().err


def test_a_cve_whose_first_fetch_failed_is_retried_on_the_next_imported_report(gws, gvmd, monkeypatch):
    from scripts import local
    current = {"report": REPORT, "stamp": "2026-10-20T01:00:00Z", "body": CLEAN_REPORT}
    path, _ = gvmd(handler_for(current=current))
    configure(gws, path, auto_enrichment=True)
    credentials(monkeypatch)
    calls = spy_enrichment(monkeypatch)
    base = local.urllib_get
    broken = {"on": True}

    def flaky(url, headers=None):
        if broken["on"] and url.endswith("cveId=CVE-2023-4863"):
            raise OSError("synthetic outage")
        return base(url, headers)
    monkeypatch.setattr(local, "urllib_get", flaky)

    def record_cycle(workspace, number):
        store = workspace.docs_for("triage_cycle")
        store.collection("cycles").document(f"cycle-{number:03d}").set({"cycle_id": f"cycle-{number:03d}", "cycle": number})
        store.close()
    tick(gws, record_cycle)
    nvd = json.loads((gws.root / "enrichment" / "nvd.json").read_text())
    assert "CVE-2023-4863" not in nvd and "CVE-2021-44228" in nvd
    # A newer report (no new findings) arrives; the failed CVE is asked for again, the cached ones are not.
    broken["on"] = False
    calls.clear()
    current.update(report="33333333-3333-4333-8333-333333333333", body=CLEAN_REPORT.replace(
        REPORT.encode(), b"33333333-3333-4333-8333-333333333333").replace(b"2026-10-20", b"2026-10-21"),
        stamp="2026-10-21T01:00:00Z")
    tick(gws, record_cycle)
    asked = sorted(u.split("=")[1] for u, _ in calls if "cveId" in u)
    assert asked == ["CVE-2023-4863"]
    assert "CVE-2023-4863" in json.loads((gws.root / "enrichment" / "nvd.json").read_text())


# --- upload from the dashboard ---------------------------------------------------------


BOUNDARY = "rzTestBoundary7MA4YWxk"


def multipart(fields, files=(), boundary=BOUNDARY):
    body = b""
    for name, value in fields:
        body += (f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n').encode()
    for name, filename, data in files:
        body += (f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'
                 'Content-Type: application/xml\r\n\r\n').encode() + data + b"\r\n"
    return body + f"--{boundary}--\r\n".encode()


@pytest.fixture
def page(gws, monkeypatch, signed_in):
    """(request, token, gws): the dashboard handler with the page's upload bound to the workspace."""
    import io
    from types import SimpleNamespace
    from scripts import local
    configure(gws, task_ids=())
    path = local_settings.settings_path(gws.root)
    shown = {"scanner_state": [], "counts": {}, "scans": []}
    cls = local.handler(SimpleNamespace(snapshot=lambda: shown), False, path, None,
                        local.page_upload(gws, path, {}), accounts=signed_in.accounts)

    def request(method="POST", route="/upload", body=b"", *, headers=None, host="127.0.0.1:8081"):
        obj = object.__new__(cls)
        obj.server = SimpleNamespace(server_port=8081)
        obj.client_address = ("127.0.0.1", 50000)
        obj.path = route
        base = {"Host": host, "Origin": f"http://{host}", "Content-Type": f"multipart/form-data; boundary={BOUNDARY}",
                "Content-Length": str(len(body)), "Cookie": signed_in.cookie()}
        base.update(headers or {})
        obj.headers = {k: v for k, v in base.items() if v is not None}
        obj.rfile, obj.wfile = io.BytesIO(body), io.BytesIO()
        status, sent = [], {}
        obj.send_response = status.append
        obj.send_header = lambda k, v: sent.update({k: v})
        obj.end_headers = lambda: None
        obj.send_error = lambda code, *a: status.append(code)
        getattr(obj, "do_" + method)()
        return status[0], obj.wfile.getvalue().decode(), sent, obj.rfile.tell()
    token = re.search('name="token" value="([^"]+)"', request("GET", "/?view=infrastructure")[1])[1]
    return request, token, gws


def post_report(request, token, data=CLEAN_REPORT, *, add_task=False, extra=()):
    fields = [("token", token)] + ([("add_task", "yes")] if add_task else []) + list(extra)
    return request(body=multipart(fields, [("report", "r.xml", data)]))


def test_upload_imports_through_the_same_path(page):
    request, token, gws = page
    status, _, sent, _ = post_report(request, token, add_task=True)
    assert status == 303 and sent["Location"] == "/?view=infrastructure&upload=imported"
    assert REPORT in docs(gws, "scans")
    assert task_ids(gws) == [TASK_A]
    assert docs(gws, "scanner_state")[TASK_A]["last_import_via"] == "upload"


def test_upload_from_unchosen_task_without_add_task_shows_the_refusal(page):
    request, token, gws = page
    before = everything_under(gws)
    status, _, sent, _ = post_report(request, token)
    assert status == 303 and sent["Location"] == "/?view=infrastructure&upload=not_chosen"
    assert everything_under(gws) == before and task_ids(gws) == []
    from ui import dashboard_view
    assert "not chosen for this install" in dashboard_view.UPLOAD_MESSAGES["not_chosen"]


def test_upload_that_parses_badly_changes_nothing(page):
    request, token, gws = page
    before = everything_under(gws)
    status, _, sent, _ = post_report(request, token, b"<not-a-report/>", add_task=True)
    assert sent["Location"].endswith("upload=parse_refused") and status == 303
    assert everything_under(gws) == before


def test_second_upload_in_the_same_cycle_is_refused_as_already_imported_this_cycle(page):
    request, token, gws = page
    assert post_report(request, token, add_task=True)[0] == 303
    older = CLEAN_REPORT.replace(REPORT.encode(), b"44444444-4444-4444-8444-444444444444")
    status, _, sent, _ = post_report(request, token, older)
    assert status == 303 and sent["Location"] == "/?view=infrastructure&upload=refused_already_imported_this_cycle"


def test_upload_rejects_cross_origin_and_oversized(page):
    request, token, gws = page
    before = everything_under(gws)
    good = multipart([("token", token), ("add_task", "yes")], [("report", "r.xml", CLEAN_REPORT)])
    assert request(body=good, headers={"Origin": "https://evil.invalid"})[0] == 403
    assert request(body=good, headers={"Origin": None})[0] == 403
    assert request(body=good, headers={"Sec-Fetch-Site": "cross-site"})[0] == 403
    assert request(body=good, host="evil.invalid:8081")[0] == 403
    from tools.greenbone_report import MAX_REPORT_BYTES
    status, _, _, consumed = request(body=b"", headers={"Content-Length": str(MAX_REPORT_BYTES + 64 * 1024 + 1)})
    assert status == 413 and consumed == 0
    assert request(body=good, headers={"Content-Type": "application/x-www-form-urlencoded"})[0] == 400
    assert request(body=multipart([("token", "wrong")], [("report", "r.xml", CLEAN_REPORT)]))[0] == 403
    assert everything_under(gws) == before


def test_upload_missing_content_length_refused_without_reading(page):
    request, token, gws = page
    good = multipart([("token", token), ("add_task", "yes")], [("report", "r.xml", CLEAN_REPORT)])
    for length in (None, "abc", "-5", "1e3", " 12", "٣"):
        status, _, _, consumed = request(body=good, headers={"Content-Length": length})
        assert status == 400 and consumed == 0, length
    assert docs(gws, "scans") == {}


def test_upload_with_extra_field_is_refused(page):
    request, token, gws = page
    before = everything_under(gws)
    assert post_report(request, token, add_task=True, extra=[("section", "scanner")])[0] == 400
    two = multipart([("token", token)], [("report", "a.xml", CLEAN_REPORT), ("report", "b.xml", CLEAN_REPORT)])
    assert request(body=two)[0] == 400
    assert request(body=multipart([("token", token)], [("other", "a.xml", CLEAN_REPORT)]))[0] == 400
    assert request(body=multipart([("token", token), ("add_task", "no")], [("report", "a.xml", CLEAN_REPORT)]))[0] == 400
    assert request(body=multipart([("token", token), ("token", token)], [("report", "a.xml", CLEAN_REPORT)]))[0] == 400
    assert request(body=multipart([("token", token)], []))[0] == 400
    assert everything_under(gws) == before


def test_upload_is_not_offered_without_the_page_wiring(gws, signed_in):
    import io
    from types import SimpleNamespace
    from scripts import local
    configure(gws, task_ids=())
    cls = local.handler(SimpleNamespace(snapshot=lambda: {}), False, local_settings.settings_path(gws.root),
                        accounts=signed_in.accounts)
    obj = object.__new__(cls)
    obj.server, obj.path = SimpleNamespace(server_port=8081), "/upload"
    obj.client_address = ("127.0.0.1", 50000)
    obj.headers = {"Host": "127.0.0.1:8081", "Origin": "http://127.0.0.1:8081", "Content-Length": "0",
                   "Cookie": signed_in.cookie()}
    codes = []
    obj.send_error = lambda code, *a: codes.append(code)
    obj.do_POST()
    assert codes == [403]


def test_many_parts_refused_before_parsing(page, monkeypatch):
    from scripts import local
    request, token, gws = page
    assert not hasattr(local, "BytesParser")  # the stdlib email parser is not in the upload path
    fields = [("token", token)] + [("x", "y")] * 5000
    assert request(body=multipart(fields, [("report", "r.xml", CLEAN_REPORT)]))[0] == 400
    assert docs(gws, "scans") == {}


def test_nested_multipart_refused(page):
    request, token, gws = page
    inner = multipart([("a", "b")], boundary="inner")
    body = (multipart([("token", token)]).replace(f"--{BOUNDARY}--\r\n".encode(), b"")
            + (f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="report"; filename="r.xml"\r\n'
               'Content-Type: multipart/mixed; boundary=inner\r\n\r\n').encode() + inner
            + f"\r\n--{BOUNDARY}--\r\n".encode())
    status, _, sent, _ = request(body=body)  # the report part is opaque bytes: not XML, so refused as such
    assert status == 303 and sent["Location"].endswith("upload=parse_refused")
    assert docs(gws, "scans") == {}


def test_reader_recursion_or_memory_error_is_a_400(page, monkeypatch):
    from scripts import local

    def boom(*a, **k):
        raise RecursionError()
    monkeypatch.setattr(local, "_read_upload_form", boom)
    request, token, gws = page
    assert post_report(request, token, add_task=True)[0] == 400
    monkeypatch.setattr(local, "_read_upload_form", lambda *a, **k: (_ for _ in ()).throw(MemoryError()))
    assert post_report(request, token, add_task=True)[0] == 400
    assert docs(gws, "scans") == {}


def test_page_upload_of_an_older_report_in_a_later_cycle_is_refused_as_not_newer(page, monkeypatch):
    from scripts import local
    request, token, gws = page
    assert post_report(request, token, add_task=True)[0] == 303 and docs(gws, "scans")
    monkeypatch.setattr(local, "next_cycle", lambda ws: 7)
    older = CLEAN_REPORT.replace(REPORT.encode(), b"44444444-4444-4444-8444-444444444444")
    status, _, sent, _ = post_report(request, token, older)
    assert status == 303 and sent["Location"] == "/?view=infrastructure&upload=refused_not_newer"


def _no_parse(monkeypatch):
    from scripts import local
    assert not hasattr(local, "BytesParser")


def _crafted(token, eol, count):
    part = f'--{BOUNDARY}{eol}Content-Disposition: form-data; name="x"{eol}{eol}y{eol}'
    head = f'--{BOUNDARY}{eol}Content-Disposition: form-data; name="token"{eol}{eol}{token}{eol}'
    return (head + part * count + f"--{BOUNDARY}--{eol}").encode()


def test_many_lf_only_parts_refused_before_parsing(page, monkeypatch):
    request, token, gws = page
    _no_parse(monkeypatch)
    assert request(body=_crafted(token, "\n", 20000))[0] == 400


def test_many_cr_only_parts_refused_before_parsing(page, monkeypatch):
    request, token, gws = page
    _no_parse(monkeypatch)
    assert request(body=_crafted(token, "\r", 20000))[0] == 400


def test_nested_part_behind_lf_delimiter_refused(page, monkeypatch):
    request, token, gws = page
    _no_parse(monkeypatch)
    body = (f'--{BOUNDARY}\nContent-Disposition: form-data; name="token"\n\n{token}\n'
            f'--{BOUNDARY}\nContent-Disposition: form-data; name="report"; filename="r.xml"\n'
            'Content-Type: multipart/mixed; boundary=inner\n\n--inner\n\nx\n--inner--\n'
            f'--{BOUNDARY}--\n').encode()
    assert request(body=body)[0] == 400
    assert docs(gws, "scans") == {}


def test_boundary_longer_than_70_refused(page, monkeypatch):
    request, token, gws = page
    _no_parse(monkeypatch)
    long = "b" * 71
    body = multipart([("token", token)], [("report", "r.xml", CLEAN_REPORT)], boundary=long)
    assert request(body=body, headers={"Content-Type": f"multipart/form-data; boundary={long}"})[0] == 400
    assert request(body=body, headers={"Content-Type": 'multipart/form-data; boundary=""'})[0] == 400
    assert docs(gws, "scans") == {}


def test_folded_nested_multipart_header_refused(page, monkeypatch):
    request, token, gws = page
    _no_parse(monkeypatch)
    body = (b"--B\r\nContent-Disposition: form-data; name=\"report\"; filename=\"r.xml\"\r\n"
            b"Content-Type:\r\n multipart/mixed; boundary=I\r\n\r\n"
            b"--I\r\n\r\nx\r\n--I\r\n\r\ny\r\n--I--\r\n--B--\r\n")
    assert request(body=body, headers={"Content-Type": "multipart/form-data; boundary=B"})[0] == 400
    assert docs(gws, "scans") == {}


# --- the strict multipart reader ---------------------------------------------------------------

CT = "multipart/form-data; boundary=----RzBoundary42"


def browser_body(report=b"<report/>", boundary="----RzBoundary42", add_task=True):
    """The shape a browser sends: token, report (with filename and Content-Type), add_task, close."""
    parts = [f'Content-Disposition: form-data; name="token"\r\n\r\ntok-1'.encode(),
             b'Content-Disposition: form-data; name="report"; filename="scan.xml"\r\n'
             b'Content-Type: text/xml\r\n\r\n' + report]
    if add_task:
        parts.append(b'Content-Disposition: form-data; name="add_task"\r\n\r\nyes')
    d = f"--{boundary}".encode()
    return d + b"\r\n" + (b"\r\n" + d + b"\r\n").join(parts) + b"\r\n" + d + b"--\r\n"


def read(body, ct=CT):
    from scripts.local import _read_upload_form
    return _read_upload_form(ct, body)


def refused(body, ct=CT):
    with pytest.raises(ValueError):
        read(body, ct)


def test_reader_accepts_a_browser_shaped_body():
    assert read(browser_body()) == {"token": b"tok-1", "report": b"<report/>", "add_task": True}
    assert read(browser_body(add_task=False))["add_task"] is False
    assert read(browser_body().removesuffix(b"\r\n"))["report"] == b"<report/>"  # no final CRLF
    assert read(browser_body(boundary="b b"), 'multipart/form-data; boundary="b b"')["token"] == b"tok-1"
    assert read(browser_body(), "Multipart/Form-Data;boundary=----RzBoundary42")["token"] == b"tok-1"


def test_reader_report_bytes_are_opaque():
    inner = b"--I\r\nContent-Type: multipart/mixed\r\n\r\nx\r\n--I--"
    assert read(browser_body(report=inner))["report"] == inner  # the XML parser, not this, refuses it


@pytest.mark.parametrize("ct", [
    "multipart/form-data; boundary*=UTF-8''abc", "multipart/form-data; boundary=abc; charset=x",
    "multipart/form-data; charset=x; boundary=abc", 'multipart/form-data; boundary="a\\"b"',
    "multipart/form-data; boundary=a\\b", "multipart/mixed; boundary=abc", "multipart/form-data",
    "multipart/form-data; boundary=", "multipart/form-data; boundary=" + "b" * 71,
    "multipart/form-data; boundary=ab ", 'multipart/form-data; boundary="ab "', "multipart/form-data; boundary=a;b",
    "multipart/form-data; boundary=a\r\nb", "multipart/form-data; boundary=é",
    "(x) multipart/form-data; boundary=abc"])
def test_reader_refuses_other_content_types(ct):
    refused(browser_body(boundary="abc"), ct)


def test_reader_treats_parentheses_as_plain_bytes():
    # Nothing interprets RFC 822 comments; a browser's "scan (1).xml" must upload.
    body = browser_body().replace(b'filename="scan.xml"', b'filename="scan (1).xml"')
    assert read(body)["report"] == b"<report/>"
    body = browser_body().replace(b"Content-Type: text/xml", b"Content-Type: (x) text/xml")
    assert read(body)["report"] == b"<report/>"


def test_reader_refuses_a_folded_header():
    refused(browser_body().replace(b"Content-Type: text/xml", b"Content-Type:\r\n text/xml"))
    refused(browser_body().replace(b'name="token"', b'name="token";\r\n x=y'))


def test_reader_refuses_lf_only_and_cr_only_bodies():
    refused(browser_body().replace(b"\r\n", b"\n"))
    refused(browser_body().replace(b"\r\n", b"\r"))


def test_reader_refuses_20000_parts_and_4_parts():
    d = b"------RzBoundary42"
    many = d + b"\r\n" + (b"\r\n" + d + b"\r\n").join(
        [b'Content-Disposition: form-data; name="x"\r\n\r\ny'] * 20000) + b"\r\n" + d + b"--\r\n"
    refused(many)
    four = browser_body().replace(b"\r\n------RzBoundary42--",
                                  b'\r\n------RzBoundary42\r\nContent-Disposition: form-data; name="x"\r\n\r\ny'
                                  b"\r\n------RzBoundary42--")
    refused(four)


def test_reader_refuses_a_missing_filename_or_a_filename_on_another_field():
    refused(browser_body().replace(b'; filename="scan.xml"', b""))
    refused(browser_body().replace(b'name="token"', b'name="token"; filename="x"'))


def test_reader_refuses_extra_headers_duplicates_and_missing_fields():
    refused(browser_body().replace(b"Content-Type: text/xml", b"X-Extra: 1"))
    refused(browser_body().replace(b"Content-Type: text/xml", b"Content-Type: a\r\nContent-Type: b"))
    refused(browser_body().replace(b'name="add_task"', b'name="token"'))
    refused(browser_body().replace(b'name="report"', b'name="other"'))
    refused(browser_body().replace(b'name="token"', b'name="add_task"'))
    refused(browser_body().replace(b"\r\n\r\nyes", b"\r\n\r\nno"))
    refused(browser_body().replace(b"tok-1", b"t" * 129))
    refused(browser_body().replace(b'name="token"', b'name="token"\x00'))
    refused(browser_body().replace(b"Content-Type: text/xml", b"Content-Type: " + b"a" * 1100))
    # a Content-Type header on a field other than report
    refused(browser_body().replace(b'name="add_task"\r\n', b'name="add_task"\r\nContent-Type: t\r\n'))


def test_reader_refuses_trailing_garbage_and_bad_framing():
    refused(browser_body() + b"x")
    refused(browser_body() + b"\r\n")
    refused(b"x" + browser_body())
    refused(browser_body().replace(b"------RzBoundary42--", b"------RzBoundary42"))
    refused(b"")


# --- R29 C1: the rescan command in a Greenbone workspace ----------------------------


@pytest.mark.parametrize("extra", [[], ["--dry-run"]])
def test_rescan_command_refuses_in_a_greenbone_workspace_and_writes_nothing(gws, monkeypatch, capsys,
                                                                           tmp_path, extra):
    configure(gws, task_ids=())
    clean = tmp_path / "clean.xml"
    clean.write_bytes(CLEAN_REPORT)
    assert run(monkeypatch, gws, "greenbone", "upload", str(clean), "--add-task") == 0
    assert docs(gws, "findings")
    capsys.readouterr()
    manual = tmp_path / "manual.json"
    manual.write_text(json.dumps({"scan_id": "manual-1", "covered_asset_ids": [], "findings": []}))
    for scan_file in (manual, ROOT / "data" / "rescan-01.json"):
        before = everything_under(gws)
        assert run(monkeypatch, gws, "rescan", "--cycle", "2", "--scan", str(scan_file), *extra) == 1
        assert ("This install imports from Greenbone; use greenbone pull or greenbone upload."
                in capsys.readouterr().err)
        assert everything_under(gws) == before


@pytest.mark.parametrize("claim", [{"source": "greenbone"}, {"task_id": "11111111-1111-4111-8111-111111111111"}])
def test_rescan_command_refuses_a_scan_claiming_a_scanner_task_even_in_an_empty_workspace(
        gws, monkeypatch, capsys, tmp_path, claim):
    configure(gws, task_ids=())
    forged = tmp_path / "forged.json"
    forged.write_text(json.dumps(dict({"scan_id": "manual-2", "covered_asset_ids": ["gb-x"],
                                       "findings": [{"finding_id": "gb-x:1.2.3:80/tcp"}]}, **claim)))
    before = everything_under(gws)
    assert run(monkeypatch, gws, "rescan", "--cycle", "1", "--scan", str(forged)) == 1
    assert "use greenbone pull or greenbone upload" in capsys.readouterr().err
    assert everything_under(gws) == before
