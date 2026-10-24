# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""The local edition's commands, the approval path and the full snapshot.

Synthetic data only: made-up findings, assets and owners on .invalid hosts.
The fake adapters answer from canned text, so the real parsing, journalling
and idempotency paths run unmodified.
"""
import json
import logging
import os
import socket
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

from tools.clock import ClockMode, SimClock
from tools.docstore import DELETE_FIELD
from tools.local_layout import Workspace
from tools.model_roles import ModelRoles, RoleConfig

ROOT = Path(__file__).resolve().parents[1]
FINDING_ID = "RZ-0001"
PROPOSAL_JSON = json.dumps({"severity": "high", "sla_days": 7,
                            "remediation": "Apply the vendor patch.",
                            "evidence": ["in CISA KEV"], "rationale": "Exploited."})
RATIFY = "INJECTION: none\nVERDICT: RATIFY\nREASON: evidence sufficient"
NO_PROPOSER = "no proposer configured: set one in Settings, then run the cycle again"
REFUSAL = ("{} is not a Remediation Zero workspace directory (a single-file database "
           "from an earlier version, or a non-empty folder). Choose a new or empty "
           "directory with --database DIR; nothing was changed.")


class FakeAdapter:
    def __init__(self, answer):
        self.answer, self.calls = answer, []

    def complete(self, system, user, *, json_output):
        self.calls.append(user)
        if isinstance(self.answer, BaseException):
            raise self.answer
        return self.answer


@dataclass(frozen=True)
class FakeRoles(ModelRoles):
    """Real role configuration; only adapter construction is replaced."""

    def adapter(self, role, *, vertex_client=None):
        return self._fakes[role]


def roles_with(proposer=None, reviewer=None, *, reviewer_family="claude"):
    endpoint = "http://127.0.0.1:9/v1"
    roles = FakeRoles(
        proposer=RoleConfig("proposer", "openai_chat", endpoint, "gpt-test", "gpt")
        if proposer is not None else None,
        reviewer=RoleConfig("reviewer", "openai_chat", endpoint, "reviewer-test",
                            reviewer_family)
        if reviewer is not None else None)
    object.__setattr__(roles, "_fakes", {"proposer": proposer, "reviewer": reviewer})
    return roles


def cross_family():
    return roles_with(FakeAdapter(PROPOSAL_JSON), FakeAdapter(RATIFY))


def same_family():
    return roles_with(FakeAdapter(PROPOSAL_JSON), FakeAdapter(RATIFY), reviewer_family="gpt")


@pytest.fixture
def ws(tmp_path):
    workspace = Workspace(tmp_path / "workspace")
    seed = workspace.docs_for("seed")
    seed.collection("findings").document(FINDING_ID).set({
        "finding_id": FINDING_ID, "asset_id": "ast-01", "cve_id": "CVE-2021-44228",
        "status": "open", "scanner_comment": "Synthetic scanner note."})
    seed.collection("assets").document("ast-01").set({
        "asset_id": "ast-01", "hostname": "app.corp.invalid", "owner_id": "own-01"})
    seed.collection("owners").document("own-01").set({
        "owner_id": "own-01", "email": "owner@example.invalid", "name": "Synthetic Owner"})
    seed.close()
    return workspace


def docs(ws, name):
    store = ws.docs_for("report")
    try:
        return {s.id: s.to_dict() for s in store.collection(name).stream()}
    finally:
        store.close()


def clock():
    return SimClock(ClockMode.REAL)


def approve_ports(ws):
    from scripts.local import approval_ports
    return approval_ports(ws, clock())


def events(caplog, name):
    found = []
    for record in caplog.records:
        try:
            line = json.loads(record.getMessage())
        except ValueError:
            continue
        if line.get("event") == name:
            found.append(line)
    return found


# --- the cycle command -------------------------------------------------------


def test_local_cycle_end_to_end_one_finding(ws, caplog):
    from scripts.local import run_local_cycle
    caplog.set_level(logging.INFO)
    result = run_local_cycle(ws, 1, roles=cross_family(), clock=clock(), environ={})
    assert result["cycle"] == "cycle-001"
    assert result["outcomes"] == {"ratified": 1}
    decision = docs(ws, "decisions")[f"{FINDING_ID}-c001"]
    assert decision["outcome"] == "ratified"
    assert decision["review_independence"] == "cross_family"
    assert f"{FINDING_ID}-c001" in docs(ws, "assignments")
    assert docs(ws, "sla_clocks")[FINDING_ID]["status"] == "open"
    ticket = docs(ws, "tickets")[FINDING_ID]
    assert "github_issue" not in ticket and "delivery" not in ticket
    assert len(docs(ws, "reports")) == 1
    assert "cycle-001" in docs(ws, "cycles")
    assert "cycle-001" in docs(ws, "memories")
    # Stage order: triage, chase, sweep, report.
    order = [e["event"] for e in (json.loads(r.getMessage()) for r in caplog.records
                                  if r.getMessage().startswith("{"))
             if e["event"] in ("cycle_finished", "chase_finished", "sweep_finished",
                               "report_written")]
    assert order == ["cycle_finished", "chase_finished", "sweep_finished", "report_written"]
    # No guard configured: the untrusted text was withheld, not sent.
    assert events(caplog, "untrusted_text_screened")[0]["screened"] is False
    # Every written lifecycle record carries both clocks.
    for name in ("decisions", "assignments", "reports", "memories"):
        for doc in docs(ws, name).values():
            assert "real_ts" in doc and "sim_ts" in doc, name


def test_local_cycle_without_a_proposer_refuses_before_any_write(tmp_path, capsys, monkeypatch):
    from scripts import local
    root = tmp_path / "fresh"
    monkeypatch.setattr("sys.argv", ["local", "--database", str(root), "cycle", "--cycle", "1"])
    with pytest.raises(SystemExit) as stop:
        local.main()
    assert stop.value.code == 1
    assert NO_PROPOSER in capsys.readouterr().err
    assert not root.exists()


def test_local_chase_dashboard_only_without_github_env(ws, monkeypatch):
    from engine.ports import NoDelivery
    from scripts import local

    def no_socket(*args, **kwargs):
        raise AssertionError("a socket was opened")

    monkeypatch.setattr(socket, "socket", no_socket)
    seen = []
    real = local.run_chase

    def spy(ports, cycle, **kwargs):
        seen.append(ports.delivery)
        return real(ports, cycle, **kwargs)

    monkeypatch.setattr(local, "run_chase", spy)
    local.run_local_cycle(ws, 1, roles=cross_family(), clock=clock(), environ={})
    assert len(seen) == 1 and isinstance(seen[0], NoDelivery)
    ticket = docs(ws, "tickets")[FINDING_ID]
    assert "github_issue" not in ticket and "delivery" not in ticket
    # Only both variables together turn tracker delivery on.
    store = ws.docs_for("chase")
    assert isinstance(local.chase_delivery(store, {"GITHUB_TICKET_REPO": "o/r"}), NoDelivery)
    assert isinstance(local.chase_delivery(store, {"GITHUB_TOKEN": "t"}), NoDelivery)
    from tools.delivery import GitHubDelivery
    both = {"GITHUB_TICKET_REPO": "synthetic/repo", "GITHUB_TOKEN": "synthetic-token"}
    assert isinstance(local.chase_delivery(store, both), GitHubDelivery)
    store.close()


# --- the approval path -------------------------------------------------------


def test_approve_lets_held_decision_proceed_next_cycle(ws, caplog):
    from engine.approve import approve
    from engine.snapshot import snapshot
    from scripts.local import run_local_cycle
    from ui.dashboard_view import render
    run_local_cycle(ws, 1, roles=same_family(), clock=clock(), environ={})
    decision_id = f"{FINDING_ID}-c001"
    before = docs(ws, "decisions")[decision_id]
    assert before["outcome"] == "held_for_approval"
    assert docs(ws, "assignments") == {}

    first = approve(approve_ports(ws), FINDING_ID, 1, "Synthetic Approver")
    second = approve(approve_ports(ws), FINDING_ID, 1, "Someone Else")
    assert first == second == decision_id
    approvals = docs(ws, "approvals")
    assert list(approvals) == [decision_id]
    record = approvals[decision_id]
    assert {k for k in record} == {"finding_id", "cycle", "decision_id", "approved_by",
                                   "real_ts", "sim_ts"}
    assert record["approved_by"] == "Synthetic Approver"
    assert docs(ws, "assignments") == {}  # approval alone assigns nothing

    caplog.set_level(logging.INFO)
    run_local_cycle(ws, 2, roles=same_family(), clock=clock(), environ={})
    assert decision_id in docs(ws, "assignments")
    assert docs(ws, "sla_clocks")[FINDING_ID]["status"] == "open"
    logged = events(caplog, "approved_by_person")
    assert len(logged) == 1
    assert logged[0]["finding_id"] == FINDING_ID and logged[0]["cycle_id"] == "cycle-001"
    # The decision record is exactly as recorded; the approval is separate.
    assert docs(ws, "decisions")[decision_id] == before

    # A third cycle does not apply the same approval again.
    caplog.clear()
    run_local_cycle(ws, 3, roles=same_family(), clock=clock(), environ={})
    assert events(caplog, "approved_by_person") == []

    store = ws.docs_for("report")
    page = render(snapshot(store), "activity")
    store.close()
    cards = [c for c in page.split("</article>") if "approved by Synthetic Approver" in c]
    assert len(cards) == 1
    assert "Reviewed by the same model family · approved by Synthetic Approver" in cards[0]
    for claim in ("Recommendation reviewed", "ratified", "independently reviewed"):
        assert claim not in cards[0]


def _counted(reviewer_family="claude"):
    proposer, reviewer = FakeAdapter(PROPOSAL_JSON), FakeAdapter(RATIFY)
    return roles_with(proposer, reviewer, reviewer_family=reviewer_family), proposer, reviewer


def test_second_local_cycle_triages_nothing_new(ws):
    from scripts.local import run_local_cycle
    roles, proposer, reviewer = _counted()
    run_local_cycle(ws, 1, roles=roles, clock=clock(), environ={})
    assert (len(proposer.calls), len(reviewer.calls)) == (1, 1)
    # An escalated clock must survive the next cycle untouched.
    shared = ws.docs_for("chase")
    shared.collection("sla_clocks").document(FINDING_ID).update({"status": "escalated"})
    shared.close()
    sla, tickets = docs(ws, "sla_clocks"), docs(ws, "tickets")
    assert sla[FINDING_ID]["status"] == "escalated"

    roles2, proposer2, reviewer2 = _counted()
    result = run_local_cycle(ws, 2, roles=roles2, clock=clock(), environ={})
    assert proposer2.calls == [] and reviewer2.calls == []
    assert docs(ws, "sla_clocks") == sla
    assert docs(ws, "tickets") == tickets
    assert list(docs(ws, "decisions")) == [f"{FINDING_ID}-c001"]
    # An empty pending list still closes the cycle: the record is written with
    # zero outcomes, so the next cycle number keeps advancing.
    assert result["outcomes"] == {}
    record = docs(ws, "cycles")["cycle-002"]
    assert record["outcomes"] == {} and record["finding_ids"] == []
    from scripts.local import next_cycle
    assert next_cycle(ws) == 3


def test_lapsed_exception_is_retriaged_next_cycle(ws):
    from engine.sweep import accept, run_sweep
    from scripts.local import _ports, run_local_cycle
    from tools.enrichment import Enrichment
    from worker.envelope import cycle_for_day
    sim = SimClock(ClockMode.SIM)
    roles, proposer, _ = _counted()
    run_local_cycle(ws, 1, roles=roles, clock=sim, environ={})
    first_sla = docs(ws, "sla_clocks")[FINDING_ID]

    not_kev = type("E", (), {"enrich": lambda self, cve: Enrichment(cve_id=cve, in_kev=False)})()
    store = ws.docs_for("exception_accept")
    accept(_ports(store, ws.journal(), sim), FINDING_ID, 7, "own-01", "Synthetic acceptance", 1,
           enrichment=not_kev)
    store.close()
    sim.advance(seconds=8 * 86400)
    store = ws.docs_for("sweep")
    assert run_sweep(_ports(store, ws.journal(), sim), cycle_for_day(sim.now().real_ts) + 1) == {"reopen": 1}
    store.close()
    assert docs(ws, "sla_clocks")[FINDING_ID]["status"] == "reopened_pending_triage"

    roles2, proposer2, _ = _counted()
    run_local_cycle(ws, 2, roles=roles2, clock=sim, environ={})
    assert len(proposer2.calls) == 1
    assert f"{FINDING_ID}-c002" in docs(ws, "decisions")
    assert f"{FINDING_ID}-c002" in docs(ws, "assignments")
    fresh = docs(ws, "sla_clocks")[FINDING_ID]
    # The re-triage starts a fresh SLA clock, as the cloud's assignment path does.
    assert fresh["status"] == "open" and fresh["cycle_started"] == 2
    assert fresh["started_sim_ts"] > first_sla["started_sim_ts"]

    roles3, proposer3, _ = _counted()
    run_local_cycle(ws, 3, roles=roles3, clock=sim, environ={})
    assert proposer3.calls == []


def test_approved_held_decision_assigned_without_new_held_decision(ws):
    from engine.approve import approve
    from scripts.local import run_local_cycle
    roles, _, _ = _counted(reviewer_family="gpt")
    run_local_cycle(ws, 1, roles=roles, clock=clock(), environ={})
    approve(approve_ports(ws), FINDING_ID, 1, "Synthetic Approver")
    queue = docs(ws, "human_queue")
    assert f"held-{FINDING_ID}-c001" in queue

    roles2, proposer2, reviewer2 = _counted(reviewer_family="gpt")
    run_local_cycle(ws, 2, roles=roles2, clock=clock(), environ={})
    assert proposer2.calls == [] and reviewer2.calls == []
    assert list(docs(ws, "assignments")) == [f"{FINDING_ID}-c001"]
    assert list(docs(ws, "decisions")) == [f"{FINDING_ID}-c001"]
    assert docs(ws, "human_queue") == queue


def test_seed_without_a_corpus_in_an_installed_tree(tmp_path):
    from scripts.build_local_installer import build
    installer = build(tmp_path / "install.py")
    app = tmp_path / "app"
    subprocess.run([sys.executable, "-S", str(installer), "--directory", str(app), "--yes",
                    "--no-start"], check=True, capture_output=True, timeout=30)
    assert not (app / "data").exists()
    result = _local("seed", cwd=app)
    assert result.returncode == 1
    assert "no corpus: pass --corpus DIR (findings.json, assets.json, owners.json)" in result.stderr
    assert not (app / "remediation-zero").exists()  # refused before any workspace exists
    partial = tmp_path / "partial"
    partial.mkdir()
    (partial / "findings.json").write_text("[]")
    result = _local("seed", "--corpus", str(partial), cwd=app)
    assert result.returncode == 1 and not (app / "remediation-zero").exists()


def test_lapsed_retriage_held_is_not_retriaged_again(ws):
    from engine.sweep import accept, run_sweep
    from scripts.local import _ports, run_local_cycle
    from tools.enrichment import Enrichment
    from worker.envelope import cycle_for_day
    sim = SimClock(ClockMode.SIM)
    run_local_cycle(ws, 1, roles=_counted()[0], clock=sim, environ={})
    not_kev = type("E", (), {"enrich": lambda self, cve: Enrichment(cve_id=cve, in_kev=False)})()
    store = ws.docs_for("exception_accept")
    accept(_ports(store, ws.journal(), sim), FINDING_ID, 7, "own-01", "Synthetic acceptance", 1,
           enrichment=not_kev)
    store.close()
    sim.advance(seconds=8 * 86400)
    store = ws.docs_for("sweep")
    run_sweep(_ports(store, ws.journal(), sim), cycle_for_day(sim.now().real_ts) + 1)
    store.close()

    held, proposer2, _ = _counted(reviewer_family="gpt")
    run_local_cycle(ws, 2, roles=held, clock=sim, environ={})
    assert len(proposer2.calls) == 1
    assert docs(ws, "decisions")[f"{FINDING_ID}-c002"]["outcome"] == "held_for_approval"
    assert docs(ws, "sla_clocks")[FINDING_ID]["status"] == "reopened_pending_triage"

    again, proposer3, reviewer3 = _counted(reviewer_family="gpt")
    run_local_cycle(ws, 3, roles=again, clock=sim, environ={})
    assert proposer3.calls == [] and reviewer3.calls == []


# --- the KEV source and enrichment presence (Ruling 32) -----------------------


def test_has_kev_true_and_false(tmp_path):
    from tools.enrichment import EnrichmentCache
    assert EnrichmentCache().has_kev is True  # the committed cache
    assert EnrichmentCache(cache_dir=tmp_path / "missing").has_kev is False
    corrupt = tmp_path / "corrupt"
    corrupt.mkdir()
    (corrupt / "cisa_kev.json").write_text("not json")
    assert EnrichmentCache(cache_dir=corrupt).has_kev is False
    empty = tmp_path / "empty"
    empty.mkdir()
    (empty / "cisa_kev.json").write_text("{}")
    cache = EnrichmentCache(cache_dir=empty)
    assert cache.has_kev is True and cache.has_epss is False and cache.has_nvd is False


def _accept_with(ws, cache_dir, approved):
    from engine.sweep import accept
    from scripts.local import _ports
    from tools.enrichment import EnrichmentCache
    store = ws.docs_for("exception_accept")
    try:
        return accept(_ports(store, ws.journal(), clock()), FINDING_ID, 7, "own-01",
                      "Synthetic acceptance", 1, approved_by_human=approved,
                      enrichment=EnrichmentCache(cache_dir=cache_dir))
    finally:
        store.close()


def test_accept_without_kev_source_requires_person(ws, tmp_path):
    with pytest.raises(ValueError, match="KEV list not available"):
        _accept_with(ws, tmp_path / "no-cache", approved=False)
    assert docs(ws, "exceptions") == {}
    queued = docs(ws, "human_queue")[f"acceptance-refused-{FINDING_ID}-c001"]
    assert queued["reason"] == "KEV list not available: a person must approve this acceptance"
    assert queued["kind"] == "acceptance_refused"
    with pytest.raises(ValueError):  # a repeat is absorbed by the refusal's key
        _accept_with(ws, tmp_path / "no-cache", approved=False)
    assert len(docs(ws, "human_queue")) == 1


def test_accept_without_kev_source_with_approval_proceeds(ws, tmp_path):
    assert _accept_with(ws, tmp_path / "no-cache", approved=True) == f"accepted:{FINDING_ID}"
    exception = docs(ws, "exceptions")[FINDING_ID]
    assert exception["approved_by_human"] is True and exception["in_kev"] is None
    assert docs(ws, "human_queue") == {}


def test_cycle_warns_when_enrichment_cache_absent(ws, tmp_path, monkeypatch, caplog, capsys):
    import tools.enrichment as enrichment
    from scripts.local import run_local_cycle
    missing = tmp_path / "no-cache"
    monkeypatch.setattr(enrichment, "DEFAULT_CACHE_DIR", missing)
    caplog.set_level(logging.INFO)
    run_local_cycle(ws, 1, roles=cross_family(), clock=clock(), environ={})
    absent = events(caplog, "enrichment_absent")
    assert absent == [{"event": "enrichment_absent", "sources": ["kev", "epss", "nvd"],
                       "cycle_id": "cycle-001", "finding_id": "-"}]
    assert (f"warning: enrichment cache not found at {missing}: kev, epss, nvd were not checked"
            in capsys.readouterr().err)


def test_cycle_does_not_warn_with_the_cache_present(ws, caplog):
    from scripts.local import run_local_cycle
    caplog.set_level(logging.INFO)
    run_local_cycle(ws, 1, roles=cross_family(), clock=clock(), environ={})
    assert events(caplog, "enrichment_absent") == []


def test_exception_accept_has_approved_by_person_flag():
    result = _local("exception", "accept", "--help")
    assert result.returncode == 0 and "--approved-by-person" in result.stdout


def test_approve_rejects_ratified_decision(ws):
    from engine.approve import approve
    from scripts.local import run_local_cycle
    run_local_cycle(ws, 1, roles=cross_family(), clock=clock(), environ={})
    with pytest.raises(ValueError):
        approve(approve_ports(ws), FINDING_ID, 1, "Synthetic Approver")
    with pytest.raises(ValueError):  # no decision at all for this cycle
        approve(approve_ports(ws), FINDING_ID, 9, "Synthetic Approver")
    assert docs(ws, "approvals") == {}


def test_approve_allows_unreviewed_and_dashboard_shows_command(ws):
    from engine.approve import approve
    from engine.snapshot import snapshot
    from scripts.local import run_local_cycle
    from ui.dashboard_view import render
    run_local_cycle(ws, 1, roles=roles_with(FakeAdapter(PROPOSAL_JSON)), clock=clock(),
                    environ={})
    assert docs(ws, "decisions")[f"{FINDING_ID}-c001"]["outcome"] == "unreviewed"
    store = ws.docs_for("report")
    page = render(snapshot(store), "actions", approve_command="python3 -S -m scripts.local --database '/w s'")
    store.close()
    assert "approve RZ-0001 --cycle 1" in page
    assert "--database &#x27;/w s&#x27;" in page
    assert approve(approve_ports(ws), FINDING_ID, 1, "Synthetic Approver") == f"{FINDING_ID}-c001"


# --- the snapshot and the dashboard -----------------------------------------


class _EmptyQuery:
    def __getattr__(self, name):
        return lambda *a, **k: self

    def stream(self):
        return iter(())

    def get(self):
        return [[type("A", (), {"value": 0})()]]


class _EmptyClient:
    def collection(self, name):
        return _EmptyQuery()


def test_snapshot_has_cloud_keys(ws, monkeypatch):
    import ui.app as cloud
    from engine.snapshot import snapshot
    monkeypatch.setattr(cloud, "db", lambda: _EmptyClient())
    monkeypatch.setattr(cloud, "reports_db", lambda: _EmptyClient())
    cloud_keys = set(cloud.snapshot())
    store = ws.docs_for("report")
    local = snapshot(store)
    store.close()
    assert set(local) == cloud_keys | {"failed_runs"}
    assert local["counts"]["findings"] == 1
    assert local["failed_runs"] == []


def test_failed_runs_shown_on_dashboard(ws):
    from engine.snapshot import snapshot
    from scripts.local import run_local_cycle
    from ui.dashboard_view import render
    # A malformed reference record (no CVE) stops the finding's run partway.
    seeder = ws.docs_for("seed")
    seeder.collection("findings").document(FINDING_ID).update({"cve_id": DELETE_FIELD})
    seeder.close()
    with pytest.raises(KeyError):
        run_local_cycle(ws, 1, roles=cross_family(), clock=clock(), environ={})
    store = ws.docs_for("report")
    data = snapshot(store)
    store.close()
    assert [(r["finding_id"], r["cycle"], r["error_class"]) for r in data["failed_runs"]] == [
        (FINDING_ID, 1, "KeyError")]
    page = render(data, "actions")
    section = page[page.index("Runs that did not finish"):]
    assert FINDING_ID in section and "Cycle 1" in section and "Error type: KeyError" in section
    assert "cve_id" not in section  # the class only, never the message
    # The cloud snapshot has no failed_runs key; nothing is rendered for it.
    assert "Runs that did not finish" not in render({}, "actions")


def test_dashboard_escapes_failed_run_and_approval_values():
    from ui.dashboard_view import render
    hostile = "<script>x</script>"
    data = {"failed_runs": [{"finding_id": hostile, "cycle": hostile, "error_class": hostile,
                             "real_ts": 0, "sim_ts": 0}],
            "decisions": [{"finding_id": hostile, "outcome": "held_for_approval", "cycle": 1,
                           "person_approval": {"approved_by": hostile}}]}
    for view in ("actions", "activity"):
        assert "<script>" not in render(data, view, approve_command=hostile)


# --- the interval runner -----------------------------------------------------


def test_interval_runner_skips_overlap(ws, caplog):
    from scripts.local_launcher import IntervalRunner
    caplog.set_level(logging.INFO)
    calls = []
    runner = IntervalRunner(ws.root, 5, run=lambda w, c: calls.append(c), wait=lambda s: True)
    assert runner.lock.acquire(blocking=False)  # a run is still active
    runner.tick()
    runner.lock.release()
    assert calls == []
    skipped = events(caplog, "cycle_skipped")
    assert skipped and skipped[0]["reason"] == "previous run still active"

    runner.tick()
    assert calls == [1]  # no cycles yet, so the first is 1
    writer = ws.docs_for("triage_cycle")
    writer.collection("cycles").document("cycle-004").set({"cycle_id": "cycle-004", "cycle": 4})
    writer.close()
    runner.tick()
    assert calls == [1, 5]


def test_interval_runner_survives_a_failing_run_and_logs_class_only(ws, caplog):
    from scripts.local_launcher import IntervalRunner
    caplog.set_level(logging.INFO)
    ticks = iter([False, False, True])  # wait() returns True when stopping

    def boom(w, c):
        raise RuntimeError("secret detail")

    runner = IntervalRunner(ws.root, 1, run=boom, wait=lambda seconds: next(ticks))
    runner.loop()
    failed = events(caplog, "cycle_failed")
    assert len(failed) == 2 and failed[0]["error"] == "RuntimeError"
    assert "secret detail" not in caplog.text


def test_interval_runner_off_at_zero(tmp_path):
    from scripts.local_launcher import start_interval_runner
    assert start_interval_runner(tmp_path / "w", 0) is None


# --- the command line --------------------------------------------------------


def _local(*args, cwd=ROOT, env=None):
    return subprocess.run([sys.executable, "-S", "-m", "scripts.local", *args], cwd=cwd,
                          capture_output=True, text=True, timeout=60, env=env)


def test_local_commands_stdlib_only(tmp_path):
    result = _local("--help")
    assert result.returncode == 0, result.stderr
    for command in ("init", "seed", "cycle", "rescan", "exception", "approve", "serve",
                    "check-models"):
        assert command in result.stdout
    assert "suggest-demo" not in result.stdout
    probe = subprocess.run([sys.executable, "-S", "-c",
        "import sys, scripts.local, scripts.local_launcher, engine.approve, engine.snapshot;"
        "bad = [m for m in sys.modules if m.split('.')[0] in "
        "('google', 'httpx', 'fastapi', 'requests', 'dotenv', 'ui.app')];"
        "print(bad)"], cwd=ROOT, capture_output=True, text=True, timeout=30)
    assert probe.returncode == 0, probe.stderr
    assert probe.stdout.strip() == "[]"


def test_cli_commands_work_without_models(tmp_path):
    root = tmp_path / "w"
    env = {k: v for k, v in os.environ.items() if not k.startswith(("RZ_", "GITHUB_"))}
    assert _local("--database", str(root), "init", env=env).returncode == 0
    seeded = _local("--database", str(root), "seed", env=env)
    assert seeded.returncode == 0, seeded.stderr
    assert json.loads(seeded.stdout)["findings"] > 0
    dry = _local("--database", str(root), "rescan", "--cycle", "1", "--scan",
                 str(ROOT / "data/rescan-01.json"), "--dry-run", env=env)
    assert dry.returncode == 0, dry.stderr
    listed = _local("--database", str(root), "exception", "list", env=env)
    assert listed.returncode == 0 and listed.stdout.strip() == ""
    missing = _local("--database", str(root), "exception", "accept", "RZ-9999", "--ttl", "7",
                     "--by", "own-01", "--reason", "synthetic", "--cycle", "1", env=env)
    assert missing.returncode == 1
    refused = _local("--database", str(root), "approve", "RZ-0001", "--cycle", "1", env=env)
    assert refused.returncode == 1
    assert "no decision" in refused.stderr
    cycle = _local("--database", str(root), "cycle", "--cycle", "1", env=env)
    assert cycle.returncode == 1
    assert NO_PROPOSER in cycle.stderr


@pytest.mark.parametrize("command", [["init"], ["seed"], ["cycle", "--cycle", "1"],
                                     ["exception", "list"], ["approve", "RZ-0001", "--cycle", "1"],
                                     ["serve", "--port", "0"], ["check-models"]])
def test_old_single_file_database_is_refused_unchanged(tmp_path, command):
    old = tmp_path / "remediation-zero.sqlite3"
    old.write_bytes(b"SQLite format 3\x00synthetic earlier-version bytes")
    os.chmod(old, 0o640)
    before = (old.read_bytes(), stat.S_IMODE(old.stat().st_mode))
    result = _local("--database", str(old), *command)
    assert result.returncode == 1
    assert REFUSAL.format(old) in result.stderr
    assert (old.read_bytes(), stat.S_IMODE(old.stat().st_mode)) == before


def test_non_empty_foreign_folder_is_refused_unchanged(tmp_path):
    folder = tmp_path / "photos"
    folder.mkdir()
    (folder / "holiday.txt").write_text("synthetic")
    result = _local("--database", str(folder), "init")
    assert result.returncode == 1
    assert REFUSAL.format(folder) in result.stderr
    assert sorted(p.name for p in folder.iterdir()) == ["holiday.txt"]


def test_default_workspace_keeps_existing_settings_file(tmp_path):
    from scripts import local, local_launcher
    from tools import local_settings
    assert local.DEFAULT_DATABASE == "remediation-zero"
    old = local_settings.settings_path(tmp_path / "remediation-zero.sqlite3")
    new = local_settings.settings_path(tmp_path / "remediation-zero")
    assert old == new == (tmp_path / "remediation-zero.settings.json").resolve()
    assert local_launcher.default_database(tmp_path) == tmp_path / "remediation-zero"
