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


def test_failed_triage_still_runs_chase_sweep_and_report(ws, monkeypatch, capsys):
    """A finding whose run raises must not stop the rest of the lifecycle."""
    from scripts import local
    seeder = ws.docs_for("seed")
    # A malformed reference record (no asset) stops the second finding's triage.
    seeder.collection("findings").document("RZ-0002").set({
        "finding_id": "RZ-0002", "cve_id": "CVE-2021-44228", "status": "open"})
    seeder.close()
    ran = []
    for name in ("run_chase", "run_sweep", "run_report"):
        real = getattr(local, name)
        monkeypatch.setattr(local, name, lambda *a, _real=real, _name=name, **k:
                            ran.append(_name) or _real(*a, **k))

    with pytest.raises(KeyError):
        local.run_local_cycle(ws, 1, roles=cross_family(), clock=clock(), environ={})

    assert ran == ["run_chase", "run_sweep", "run_report"]
    # RZ-0001 was ratified before RZ-0002 raised, and chase opened its ticket.
    assert docs(ws, "decisions")[f"{FINDING_ID}-c001"]["outcome"] == "ratified"
    assert FINDING_ID in docs(ws, "tickets")
    assert "report-c001" in docs(ws, "reports")
    assert [r["finding_id"] for r in docs(ws, "failed_runs").values()] == ["RZ-0002"]

    # A later stage failing too never hides the triage failure.
    monkeypatch.setattr(local, "run_sweep",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("sweep down")))
    with pytest.raises(KeyError):
        local.run_local_cycle(ws, 2, roles=cross_family(), clock=clock(), environ={})

    # The command line still exits 1 with the triage error's class only.
    monkeypatch.setattr(local, "run_local_cycle",
                        lambda *a, **k: (_ for _ in ()).throw(KeyError("cve_id")))
    monkeypatch.setattr(local.ModelRoles, "from_settings", lambda *_a: cross_family())
    monkeypatch.setattr("sys.argv", ["local", "--database", str(ws.root), "cycle", "--cycle", "2"])
    with pytest.raises(SystemExit) as stop:
        local.main()
    assert stop.value.code == 1
    assert "The cycle stopped (KeyError)" in capsys.readouterr().err


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


def test_unavailable_decision_is_retried_next_cycle(ws, monkeypatch):
    """Ruling 39: a reviewer outage is not a terminal answer locally."""
    from scripts.local import run_local_cycle
    from tools.adjudication import CapacityError
    monkeypatch.setattr("tools.inference_journal.sleep", lambda _s: None)
    down = FakeAdapter(CapacityError("Model endpoint temporarily unavailable"))
    run_local_cycle(ws, 1, roles=roles_with(FakeAdapter(PROPOSAL_JSON), down),
                    clock=clock(), environ={})
    assert docs(ws, "decisions")[f"{FINDING_ID}-c001"]["outcome"] == "unavailable"

    roles2, proposer2, reviewer2 = _counted()
    result = run_local_cycle(ws, 2, roles=roles2, clock=clock(), environ={})
    assert len(reviewer2.calls) == 1
    assert result["outcomes"] == {"ratified": 1}
    assert docs(ws, "decisions")[f"{FINDING_ID}-c002"]["outcome"] == "ratified"
    assert f"{FINDING_ID}-c002" in docs(ws, "assignments")

    # Once ratified it is no longer pending.
    roles3, proposer3, reviewer3 = _counted()
    run_local_cycle(ws, 3, roles=roles3, clock=clock(), environ={})
    assert proposer3.calls == [] and reviewer3.calls == []


def test_capacity_failed_triage_is_retried_next_cycle(ws, monkeypatch):
    from scripts.local import run_local_cycle
    from tools.adjudication import CapacityError
    monkeypatch.setattr("tools.inference_journal.sleep", lambda _s: None)
    down = FakeAdapter(CapacityError("Model endpoint temporarily unavailable"))
    run_local_cycle(ws, 1, roles=roles_with(down, FakeAdapter(RATIFY)),
                    clock=clock(), environ={})
    first = docs(ws, "decisions")[f"{FINDING_ID}-c001"]
    assert first["outcome"] == "human_queue"
    assert first["note"].startswith("triage failed: CapacityError")

    roles2, proposer2, reviewer2 = _counted()
    result = run_local_cycle(ws, 2, roles=roles2, clock=clock(), environ={})
    assert (len(proposer2.calls), len(reviewer2.calls)) == (1, 1)
    assert result["outcomes"] == {"ratified": 1}


def test_other_human_queue_decisions_stay_with_a_person(ws):
    """A rejection or a non-capacity triage failure is a person's to decide."""
    from scripts.local import run_local_cycle
    reject = FakeAdapter("INJECTION: none\nVERDICT: REJECT\nREASON: not supported")
    run_local_cycle(ws, 1, roles=roles_with(FakeAdapter(PROPOSAL_JSON), reject),
                    clock=clock(), environ={})
    assert docs(ws, "decisions")[f"{FINDING_ID}-c001"]["outcome"] == "human_queue"
    roles2, proposer2, reviewer2 = _counted()
    run_local_cycle(ws, 2, roles=roles2, clock=clock(), environ={})
    assert proposer2.calls == [] and reviewer2.calls == []


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
    # Ruling 36: an empty catalogue counts as loaded; `{}` is not a catalogue.
    empty = tmp_path / "empty"
    empty.mkdir()
    (empty / "cisa_kev.json").write_text('{"vulnerabilities": []}')
    cache = EnrichmentCache(cache_dir=empty)
    assert cache.has_kev is True and cache.has_epss is False and cache.has_nvd is False
    bare = tmp_path / "bare"
    bare.mkdir()
    (bare / "cisa_kev.json").write_text("{}")
    assert EnrichmentCache(cache_dir=bare).has_kev is False


def test_prompt_says_kev_unknown_without_the_list(tmp_path):
    from tools.enrichment import EnrichmentCache
    from tools.inference import render_finding
    finding = {"finding_id": FINDING_ID, "cve_id": "CVE-2021-44228", "scanner_comment": ""}
    absent = render_finding(finding, {}, EnrichmentCache(cache_dir=tmp_path / "none").enrich(
        "CVE-2021-44228"))
    assert "  in_cisa_kev: unknown (KEV list not available)\n" in absent
    assert "in_cisa_kev: False" not in absent


def test_prompt_unchanged_with_the_kev_list(tmp_path):
    from tools.enrichment import Enrichment, EnrichmentCache
    from tools.inference import render_finding
    finding = {"finding_id": FINDING_ID, "cve_id": "CVE-2021-44228", "scanner_comment": ""}
    present = EnrichmentCache().enrich("CVE-2021-44228")
    assert present.kev_checked is True
    rendered = render_finding(finding, {}, present)
    assert f"  in_cisa_kev: {present.in_kev}\n" in rendered
    # Byte-identical to an Enrichment built without the new field.
    import dataclasses
    legacy = Enrichment(**{f.name: getattr(present, f.name) for f in dataclasses.fields(present)
                           if f.name != "kev_checked"})
    assert render_finding(finding, {}, legacy) == rendered
    kev_empty = tmp_path / "k"
    kev_empty.mkdir()
    (kev_empty / "cisa_kev.json").write_text('{"vulnerabilities": []}')
    assert "  in_cisa_kev: False\n" in render_finding(
        finding, {}, EnrichmentCache(cache_dir=kev_empty).enrich("CVE-2021-44228"))


# --- the approval refuses a closed finding or a superseded decision ----------


def test_approve_refuses_a_finding_that_is_not_open(ws):
    from engine.approve import approve
    from scripts.local import run_local_cycle
    run_local_cycle(ws, 1, roles=_counted(reviewer_family="gpt")[0], clock=clock(), environ={})
    seeder = ws.docs_for("rescan")
    seeder.collection("findings").document(FINDING_ID).update({"status": "resolved"})
    seeder.close()
    with pytest.raises(ValueError, match="not open"):
        approve(approve_ports(ws), FINDING_ID, 1, "Synthetic Approver")
    assert docs(ws, "approvals") == {}


def test_approve_refuses_a_superseded_decision(ws):
    from engine.approve import approve
    from scripts.local import run_local_cycle
    run_local_cycle(ws, 1, roles=_counted(reviewer_family="gpt")[0], clock=clock(), environ={})
    # A later decision for the same finding (for example after a lapsed acceptance).
    store = ws.docs_for("triage_cycle")
    later = dict(docs(ws, "decisions")[f"{FINDING_ID}-c001"], cycle=2)
    later["sim_ts"] += 60
    store.collection("decisions").document(f"{FINDING_ID}-c002").set(later)
    store.close()
    with pytest.raises(ValueError, match="superseded"):
        approve(approve_ports(ws), FINDING_ID, 1, "Synthetic Approver")
    assert docs(ws, "approvals") == {}
    assert approve(approve_ports(ws), FINDING_ID, 2, "Synthetic Approver") == f"{FINDING_ID}-c002"


def test_approve_with_a_malformed_finding_id_says_so(tmp_path):
    result = _local("--database", str(tmp_path / "w"), "approve", "   ", "--cycle", "1")
    assert result.returncode == 1
    assert result.stderr == "invalid finding id:    \n"


# --- the GitHub issue body states the review honestly (Ruling 34) ------------


def _issue_body_for(ws, decision_update=None, approval=None):
    from tools.delivery import GitHubDelivery
    from tools.github_tickets import GitHubTickets
    store = ws.docs_for("triage_cycle")
    decision_id = f"{FINDING_ID}-c001"
    if decision_update:
        store.collection("decisions").document(decision_id).update(decision_update)
    store.close()
    if approval:
        approver = ws.docs_for("approve")
        approver.collection("approvals").document(decision_id).set(approval)
        approver.close()
    captured = {}

    class Tickets(GitHubTickets):
        def open_issue(self, finding_id, title, body, labels, cycle):
            captured["body"] = body
            return 7

    chase = ws.docs_for("chase")  # the store local delivery is given
    delivery = GitHubDelivery(Tickets(repo="synthetic/repo", token="synthetic", http=object()),
                              client=chase)
    delivery.deliver("open_ticket", FINDING_ID, {}, 1, 0.0, None)
    chase.close()
    return captured["body"]


def test_issue_body_same_family_never_claims_cross_family(ws):
    from scripts.local import run_local_cycle
    run_local_cycle(ws, 1, roles=cross_family(), clock=clock(), environ={})
    body = _issue_body_for(ws, {"review_independence": "same_family"})
    assert "different model family" not in body
    assert "Reviewed by the same model family:\n\n> evidence sufficient" in body


def test_issue_body_approved_held_says_approved_by_person(ws):
    from scripts.local import run_local_cycle
    run_local_cycle(ws, 1, roles=_counted(reviewer_family="gpt")[0], clock=clock(), environ={})
    decision_id = f"{FINDING_ID}-c001"
    body = _issue_body_for(ws, approval={"finding_id": FINDING_ID, "cycle": 1,
                                         "decision_id": decision_id,
                                         "approved_by": "Synthetic Approver",
                                         "real_ts": 0.0, "sim_ts": 0.0})
    assert "different model family" not in body and "Ratified" not in body
    assert "Reviewed by the same model family:" in body
    assert "Approved by Synthetic Approver." in body


def test_issue_body_unreviewed_says_so(ws):
    from scripts.local import run_local_cycle
    run_local_cycle(ws, 1, roles=roles_with(FakeAdapter(PROPOSAL_JSON)), clock=clock(), environ={})
    body = _issue_body_for(ws)
    assert "Not reviewed: a person's review is needed." in body
    assert "different model family" not in body


def test_issue_body_approved_unreviewed_says_approved_not_needed(ws):
    from scripts.local import run_local_cycle
    run_local_cycle(ws, 1, roles=roles_with(FakeAdapter(PROPOSAL_JSON)), clock=clock(), environ={})
    body = _issue_body_for(ws, approval={"finding_id": FINDING_ID, "cycle": 1,
                                         "decision_id": f"{FINDING_ID}-c001",
                                         "approved_by": "Synthetic Approver",
                                         "real_ts": 0.0, "sim_ts": 0.0})
    assert "Not reviewed by a model; approved by Synthetic Approver." in body
    assert "a person's review is needed" not in body
    assert "Approved by" not in body
    assert "different model family" not in body


def test_issue_body_cross_family_unchanged():
    from tools.github_tickets import issue_body
    finding = {"finding_id": "RZ-0101", "cve_id": "CVE-2015-2502", "asset_id": "ast-1",
               "scanner_severity": "high"}
    owner = {"display_name": "Synthetic Owner", "email": "owner@example.invalid", "team": "ops"}
    args = dict(due="2026-09-10", sla_days=7, severity="critical", remediation="Patch it.",
                rationale="Exploited.", evidence="['CISA KEV catalog']",
                reviewer="The severity is supported.", attempts=2)
    expected = "\n".join([
        "### Reviewer",
        "Ratified by an adversarial reviewer running on a different model family after 2 proposals:",
        "",
        "> The severity is supported.",
        "",
        "---",
    ])
    body = issue_body(finding, owner, **args)
    assert expected in body
    assert body == issue_body(finding, owner, **args, outcome="ratified", review="cross_family")
    # The pre-change renderer, kept in this test as the pinned reference.
    assert body == _reference_body(finding, owner, **args)


def _reference_body(finding, owner, due, sla_days, severity, remediation, rationale="",
                    evidence="", reviewer="", attempts=None):
    marker = "Remediation Zero"
    return "\n".join([
        f"**{severity.upper()}** · due **{due}** · SLA {sla_days} days", "",
        "### What to do", remediation or "_No remediation was proposed._", "",
        "### Finding", f"- Finding: `{finding['finding_id']}`",
        f"- CVE: `{finding.get('cve_id', 'unknown')}`",
        f"- Asset: `{finding.get('asset_id', 'unknown')}`",
        f"- Scanner severity: {finding.get('scanner_severity', 'unrated')}", "",
        "### Owner",
        f"- {owner.get('display_name', 'unassigned')} "
        f"({owner.get('email', 'no address')}) · team {owner.get('team', 'unknown')}", "",
        *(["### Why this severity", rationale, ""] if rationale else []),
        *([f"**Evidence cited:** {evidence}", ""] if evidence else []),
        *(["### Reviewer",
           "Ratified by an adversarial reviewer running on a different model "
           "family" + (f" after {attempts} proposals" if attempts and int(attempts) > 1 else "") + ":",
           "", f"> {reviewer}", ""] if reviewer else []),
        "---",
        f"Filed automatically by the **{marker}** chase agent. Nudges and "
        "escalations arrive as comments on this issue.", "",
        "> **This is synthetic.** The corpus, the asset and the owner are "
        "generated; only the CVE identifier is real. Nothing here describes an "
        "actual unpatched system.",
    ])


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


def test_cycle_warns_when_enrichment_cache_absent(ws, caplog, capsys):
    from scripts.local import run_local_cycle
    missing = ws.root / "enrichment"
    caplog.set_level(logging.INFO)
    run_local_cycle(ws, 1, roles=cross_family(), clock=clock(), environ={})
    absent = events(caplog, "enrichment_absent")
    assert absent == [{"event": "enrichment_absent", "sources": ["kev", "epss", "nvd"],
                       "cycle_id": "cycle-001", "finding_id": "-"}]
    assert (f"warning: enrichment cache not found at {missing}: kev, epss, nvd were not checked"
            in capsys.readouterr().err)


def test_cycle_does_not_warn_with_the_cache_present(ws, caplog):
    from scripts.local import run_local_cycle, update_enrichment
    update_enrichment(ws, {}, get=_fake_sources([]))
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
    assert set(local) == cloud_keys | {"failed_runs", "scanner_state"}
    assert local["counts"]["findings"] == 1
    assert local["failed_runs"] == []


def test_snapshot_returns_a_stored_cycle(ws):
    """Ruling 42: cycle records carry started_real_ts, never real_ts."""
    from engine.snapshot import snapshot
    from scripts.local import run_local_cycle
    run_local_cycle(ws, 1, roles=cross_family(), clock=SimClock(ClockMode.SIM), environ={})
    stored = docs(ws, "cycles")["cycle-001"]
    store = ws.docs_for("report")
    data = snapshot(store)
    store.close()
    assert [c["cycle_id"] for c in data["cycles"]] == ["cycle-001"]
    assert data["sim_now"] >= stored["finished_sim_ts"]


class _RecordingQuery(_EmptyQuery):
    def __init__(self, name, seen):
        self.name, self.seen = name, seen

    def order_by(self, field, **_kwargs):
        self.seen.append((self.name, field))
        return self


class _RecordingClient:
    def __init__(self):
        self.seen = []

    def collection(self, name):
        return _RecordingQuery(name, self.seen)


def test_cloud_snapshot_orders_cycles_by_their_real_fields(monkeypatch):
    import ui.app as cloud
    client = _RecordingClient()
    monkeypatch.setattr(cloud, "db", lambda: client)
    monkeypatch.setattr(cloud, "reports_db", lambda: _EmptyClient())
    cloud.snapshot()
    cycle_orders = [field for name, field in client.seen if name == "cycles"]
    assert cycle_orders == ["started_real_ts", "finished_sim_ts"]


def test_serve_reads_through_the_dashboard_stage(ws, monkeypatch):
    """Ruling 43: the served snapshot store cannot write any record."""
    from scripts import local
    stages, served = [], []
    real_docs_for = Workspace.docs_for

    def recording(self, stage):
        stages.append(stage)
        return real_docs_for(self, stage)

    class FakeServer:
        def __init__(self, address, handler_class):
            self.server_port = address[1]

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def serve_forever(self):
            served.append(True)

    captured = {}
    real_handler = local.handler

    def capture(store, *args, **kwargs):
        captured["store"] = store
        return real_handler(store, *args, **kwargs)

    monkeypatch.setattr(Workspace, "docs_for", recording)
    monkeypatch.setattr(local, "HTTPServer", FakeServer)
    monkeypatch.setattr(local, "handler", capture)
    monkeypatch.setattr("sys.argv", ["local", "--database", str(ws.root), "serve", "--port", "18081"])
    local.main()

    assert served == [True]
    assert stages == ["dashboard"]
    docs = captured["store"]._docs
    with pytest.raises(PermissionError):
        docs.collection("decisions").document("X-1").set({"a": 1})
    assert captured["store"].snapshot()["counts"]["findings"] == 1
    docs.close()


def test_failed_runs_shown_on_dashboard(ws):
    from engine.snapshot import snapshot
    from scripts.local import run_local_cycle
    from ui.dashboard_view import render
    # A malformed reference record (no asset) stops the finding's run partway.
    seeder = ws.docs_for("seed")
    seeder.collection("findings").document(FINDING_ID).update({"asset_id": DELETE_FIELD})
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
    assert "asset_id" not in section  # the class only, never the message
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


# --- the enrichment cache and update-enrichment (Task 5) ----------------------

CACHE_KEY = "synthetic-nvd-key-1b7c"


def _fake_sources(calls):
    import csv
    import gzip
    import io

    from tools.enrichment_fetch import EPSS_URL, KEV_URL

    def get(url, headers=None):
        calls.append((url, headers))
        if url == KEV_URL:
            return json.dumps({"vulnerabilities": [{"cveID": "CVE-2021-44228"}]}).encode()
        if url == EPSS_URL:
            out = io.StringIO()
            csv.writer(out).writerows([["cve", "epss", "percentile"],
                                       ["CVE-2021-44228", "0.9", "0.9"]])
            return gzip.compress(out.getvalue().encode())
        return json.dumps({"vulnerabilities": [{"cve": {"id": url.split("=")[1]}}]}).encode()
    return get


def test_cycle_reads_the_workspace_cache(ws, capsys):
    from scripts.local import run_local_cycle, update_enrichment
    update_enrichment(ws, {}, get=_fake_sources([]))
    capsys.readouterr()
    run_local_cycle(ws, 1, roles=cross_family(), clock=clock(), environ={})
    assert "enrichment cache not found" not in capsys.readouterr().err
    assert (ws.root / "enrichment" / "cisa_kev.json").is_file()


def test_cycle_warning_names_the_workspace_cache_path(ws, capsys):
    from scripts.local import run_local_cycle
    run_local_cycle(ws, 1, roles=cross_family(), clock=clock(), environ={})
    err = capsys.readouterr().err
    assert f"enrichment cache not found at {ws.root / 'enrichment'}" in err
    assert "kev, epss, nvd were not checked" in err


def test_update_enrichment_collects_every_workspace_cve_and_writes_status(ws):
    from scripts.local import update_enrichment
    seed = ws.docs_for("seed")
    seed.collection("findings").document("RZ-0002").set({
        "finding_id": "RZ-0002", "cve_ids": ["CVE-2020-0001", "CVE-2019-0708"], "status": "open"})
    seed.collection("findings").document("RZ-0003").set({"finding_id": "RZ-0003", "cve_ids": []})
    seed.close()
    calls = []
    result = update_enrichment(ws, {"NVD_API_KEY": CACHE_KEY}, get=_fake_sources(calls))
    asked = sorted(u.split("=")[1] for u, _ in calls if "cveId" in u)
    assert asked == ["CVE-2019-0708", "CVE-2020-0001", "CVE-2021-44228"]
    assert result["nvd_fetched"] == 3 and result["kev"] == "ok"
    status = docs(ws, "scanner_state")["enrichment"]
    assert (status["kev"], status["epss"], status["nvd_fetched"], status["failed"]) == ("ok", "ok", 3, [])
    assert "fetched" not in status
    assert {"last_run_real_ts", "last_run_sim_ts"} <= set(status)
    assert CACHE_KEY not in json.dumps(status)
    for path in ws.root.rglob("*"):
        if path.is_file():
            assert CACHE_KEY.encode() not in path.read_bytes()


def test_update_enrichment_with_a_subset_fetches_only_those(ws):
    from scripts.local import update_enrichment
    calls = []
    update_enrichment(ws, {}, cves=["CVE-2020-0001"], get=_fake_sources(calls))
    assert [u.split("=")[1] for u, _ in calls if "cveId" in u] == ["CVE-2020-0001"]


def test_update_enrichment_status_uses_the_clock_not_wall_time(ws):
    from scripts import local
    from tools.clock import Stamp

    class Fixed:
        def now(self):
            return Stamp(real_ts=111.5, sim_ts=222.5)
    local.update_enrichment(ws, {}, cves=[], get=_fake_sources([]), clock=Fixed())
    status = docs(ws, "scanner_state")["enrichment"]
    assert (status["last_run_real_ts"], status["last_run_sim_ts"]) == (111.5, 222.5)


def test_update_enrichment_says_it_reaches_the_internet(ws, capsys, monkeypatch):
    from scripts import local
    calls = []
    monkeypatch.setattr(local, "urllib_get", _fake_sources(calls))
    monkeypatch.setattr("sys.argv", ["local", "--database", str(ws.root), "update-enrichment"])
    local.main()
    out = capsys.readouterr().out
    assert out.startswith("This reaches the internet: CISA, FIRST EPSS and NVD.")
    assert "CVE-2021-44228" in " ".join(u for u, _ in calls)
    assert json.loads(out.splitlines()[-1])["kev"] == "ok"
