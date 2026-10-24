# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Reconstructed regressions for evidence preservation and durable retries."""
import pytest

from tools.adjudication import (AdjudicationFailure, AdjudicationOutcome, CapacityError,
                                Proposal, RetryStateError, Verdict, adjudicate)
from tools.clock import ClockMode, SimClock
from tools.decisions import DecisionWriter, to_decision_document
from tools.idempotency import CompletedCall, InMemoryIdempotencyStore, derive_record
from tools.inference_journal import InferenceJournal
from tools.recovery_audit import audit_recovery_snapshot
from tests.test_decisions import FakeClient, PROPOSAL


@pytest.fixture(autouse=True)
def no_backoff(monkeypatch):
    monkeypatch.setattr("tools.inference_journal.sleep", lambda _: None)


@pytest.mark.parametrize("limit", [True, False, 0, -1, 4, 1.5, "2", None])
def test_invalid_limits_before_models(limit):
    calls = []
    with pytest.raises(ValueError):
        adjudicate({}, lambda _: calls.append(1), lambda *_: calls.append(1), limit)
    assert not calls


@pytest.mark.parametrize("ratified,reason", [(1, "yes"), ("false", "no"), (None, "no"),
                                           (False, None), (True, 1), (False, " ")])
def test_verdict_types(ratified, reason):
    with pytest.raises(ValueError):
        Verdict(ratified, reason)


@pytest.mark.parametrize("error", [CapacityError("offline"), RuntimeError("invalid provider result")])
def test_rejection_then_failure_keeps_evidence(error):
    calls = []
    def review(*_):
        calls.append(1)
        if len(calls) == 1:
            return Verdict(False, "first objection")
        raise error
    try:
        result = adjudicate({"finding_id": "RZ-1"}, lambda _: PROPOSAL, review, 1)
    except AdjudicationFailure as exc:
        result = exc.adjudication
    assert result.verdicts == (Verdict(False, "first objection"),)
    assert result.attempts == 2
    assert result.outcome is (AdjudicationOutcome.UNAVAILABLE if isinstance(error, CapacityError)
                              else AdjudicationOutcome.HUMAN_QUEUE)


def setup_writer():
    client, store = FakeClient(), InMemoryIdempotencyStore()
    return client, store, DecisionWriter(store, client, SimClock(ClockMode.REAL))


def test_outage_records_and_escalates_once_and_replays_without_models():
    client, store, writer = setup_writer()
    calls = []
    def outage(*_):
        calls.append(1)
        raise CapacityError("offline")
    result = writer.adjudicate_once({"finding_id": "RZ-1"}, lambda _: PROPOSAL, outage, cycle=1)
    assert result.outcome is AdjudicationOutcome.UNAVAILABLE
    assert len(calls) == 4
    assert ("decisions", "RZ-1-c001") in client.docs
    assert ("human_queue", "reviewer-unavailable-RZ-1-c001") in client.docs
    def forbidden(*_):
        raise AssertionError("replay invoked a model")
    new_writer = DecisionWriter(store, client, SimClock(ClockMode.REAL))
    assert new_writer.adjudicate_once({"finding_id": "RZ-1"}, forbidden, forbidden, cycle=1) == result
    assert len(client.docs) == 2


def test_missing_escalation_repaired_without_overwriting_existing_queue():
    client, store, writer = setup_writer()
    from tools.adjudication import Adjudication
    result = Adjudication("RZ-1", AdjudicationOutcome.UNAVAILABLE, PROPOSAL, (), 1, "offline")
    client.docs[("decisions", "RZ-1-c001")] = to_decision_document(result, SimClock(ClockMode.REAL), 1)
    assert writer.restore("RZ-1", 1) == result
    queue = client.docs[("human_queue", "reviewer-unavailable-RZ-1-c001")]
    queue["human_note"] = "keep me"
    writer.restore("RZ-1", 1)
    assert queue["human_note"] == "keep me"


def test_orphan_queue_aborts_atomic_decision_write():
    client, _, writer = setup_writer()
    from tools.adjudication import Adjudication
    client.docs[("human_queue", "reviewer-unavailable-RZ-1-c001")] = {"original": True}
    with pytest.raises(RuntimeError, match="queue exists"):
        writer.record(Adjudication("RZ-1", AdjudicationOutcome.UNAVAILABLE, PROPOSAL), 1)
    assert ("decisions", "RZ-1-c001") not in client.docs


def test_completed_ledger_without_decision_refuses():
    _, store, writer = setup_writer()
    store.put(CompletedCall(derive_record("RZ-1", "decision", 1), "RZ-1-c001"))
    with pytest.raises(RuntimeError, match="reconciliation"):
        writer.restore("RZ-1", 1)


def test_four_crashes_consume_four_slots_across_restart():
    store = InMemoryIdempotencyStore()
    def crash():
        raise KeyboardInterrupt()
    for _ in range(4):
        with pytest.raises(KeyboardInterrupt):
            InferenceJournal(store, "RZ-1", 1).call("triage_1", Proposal, crash)
    with pytest.raises(CapacityError, match="budget"):
        InferenceJournal(store, "RZ-1", 1).call("triage_1", Proposal, lambda: pytest.fail("over budget"))


def test_saved_rejection_survives_second_round_crash():
    client, store, writer = setup_writer()
    calls = []
    def triage(_):
        calls.append(1)
        if len(calls) == 2:
            raise KeyboardInterrupt()
        return PROPOSAL
    with pytest.raises(KeyboardInterrupt):
        writer.adjudicate_once({"finding_id": "RZ-1"}, triage, lambda *_: Verdict(False, "first"), cycle=1)
    result = writer.adjudicate_once({"finding_id": "RZ-1"}, lambda _: PROPOSAL,
                                   lambda *_: Verdict(True, "fixed"), cycle=1)
    assert result.verdicts == (Verdict(False, "first"), Verdict(True, "fixed"))


def test_busy_stage_and_lost_reservation_ack_never_invoke_model(monkeypatch):
    store = InMemoryIdempotencyStore()
    key = derive_record("RZ-1", "inference_triage_1", 1)
    claim = store.acquire(key)
    journal = InferenceJournal(store, "RZ-1", 1)
    with pytest.raises(RetryStateError):
        journal.call("triage_1", Proposal, lambda: pytest.fail("busy model"))
    store.abandon(claim)
    real = store.reserve_once
    def lost(record):
        real(record)
        raise ConnectionError("ack lost")
    monkeypatch.setattr(store, "reserve_once", lost)
    with pytest.raises(RetryStateError):
        journal.call("triage_1", Proposal, lambda: pytest.fail("unconfirmed reservation"))
    assert store.get(derive_record("RZ-1", "inference_triage_1_attempt_1", 1).key)


def test_permanent_error_is_checkpointed_and_changed_context_refuses():
    store = InMemoryIdempotencyStore()
    def invalid():
        raise ValueError("bad response")
    journal = InferenceJournal(store, "RZ-1", 1, context="one")
    with pytest.raises(ValueError, match="bad response"):
        journal.call("triage_1", Proposal, invalid)
    with pytest.raises(ValueError, match="bad response"):
        journal.call("triage_1", Proposal, lambda: pytest.fail("repeated permanent error"))
    with pytest.raises(ValueError, match="changed"):
        InferenceJournal(store, "RZ-1", 1, context="two").call("review_1", Verdict, lambda: pytest.fail("mixed context"))


def test_persisted_stage_is_replayed_after_decision_commit_failure(monkeypatch):
    client, _, writer = setup_writer()
    real = client.batch
    monkeypatch.setattr(client, "batch", lambda: (_ for _ in ()).throw(ConnectionError("db down")))
    with pytest.raises(ConnectionError):
        writer.adjudicate_once({"finding_id": "RZ-1"}, lambda _: PROPOSAL,
                               lambda *_: Verdict(True, "yes"), cycle=1)
    monkeypatch.setattr(client, "batch", real)
    def forbidden(*_):
        pytest.fail("inference repeated after checkpoint")
    assert writer.adjudicate_once({"finding_id": "RZ-1"}, forbidden, forbidden, cycle=1).outcome is AdjudicationOutcome.RATIFIED


def test_audit_is_read_only_and_flags_duplicates_and_orphans():
    from tools.adjudication import Adjudication
    doc = to_decision_document(Adjudication("RZ-1", AdjudicationOutcome.UNAVAILABLE,
                              PROPOSAL, (Verdict(False, "first"),), 2), SimClock(ClockMode.REAL), 1)
    decisions = {"RZ-1-c001": doc}
    assert audit_recovery_snapshot(decisions, {})[0]["status"] == "repair_candidate"
    queue = {"x": {"decision_id": "RZ-1-c001"}, "y": {"decision_id": "RZ-1-c001"}}
    assert audit_recovery_snapshot(decisions, queue)[0]["status"] == "manual_review"
    assert audit_recovery_snapshot({}, queue)[0]["status"] == "manual_review"
    doc["verdicts"] = [{"ratified": "false", "reason": "bad"}]
    assert audit_recovery_snapshot(decisions, {})[0]["status"] == "manual_review"


@pytest.mark.parametrize("runner", ["procedural", "graph"])
@pytest.mark.parametrize("rejection_first", [False, True])
def test_both_runners_record_outage_preserve_rejection_and_suppress_replay(monkeypatch, runner, rejection_first):
    from types import SimpleNamespace
    from dataclasses import replace
    import subprocess
    import sys
    from tools import review_models as rm
    from tools.enrichment import Enrichment
    from tools.model_armor import ArmorVerdict
    client, store, writer = setup_writer()
    finding_id = "RZ-0001"
    client.docs[("findings", finding_id)] = {"finding_id": finding_id, "asset_id": "synthetic",
                                            "cve_id": "CVE-2021-44228", "scanner_comment": "synthetic"}
    armor = SimpleNamespace(screen=lambda *_: ArmorVerdict(blocked=False, screened=True))
    cache = SimpleNamespace(enrich=lambda cve: Enrichment(cve_id=cve))
    calls = []
    def propose(*args, **kwargs):
        assert kwargs["retry"] is False
        return replace(PROPOSAL, finding_id=kwargs["finding_id"])
    def review(*args, **kwargs):
        assert kwargs["retry"] is False
        calls.append(1)
        if rejection_first and len(calls) == 1:
            return Verdict(False, "first rejection")
        raise CapacityError("offline outage")
    monkeypatch.setattr(rm, "propose", propose)
    monkeypatch.setattr(rm, "review", review)
    if runner == "graph":
        from scripts.graph_cycle import build_handlers
        def run():
            handlers = build_handlers({"db": client, "clock": SimClock(ClockMode.REAL),
                "cache": cache, "genai": None, "armor": armor, "armor_token": "offline",
                "decisions": writer, "assignments": None, "cycle_id": "cycle-001", "scratch": {},
                "reasoning_model": "gemini", "reviewer_model": "gemma"})
            handlers["screen"](finding_id, 1)
            ctx = SimpleNamespace()
            assert handlers["review"](ctx, finding_id, 1) == "unavailable"
            assert ctx.route == "unavailable"
            handlers["unavailable"](finding_id, 1)
    else:
        from scripts import cycle
        monkeypatch.setattr(sys, "argv", ["cycle", "--cycle", "1", "--limit", "1"])
        monkeypatch.setattr(cycle.firestore, "Client", lambda: client)
        monkeypatch.setattr(cycle, "FirestoreIdempotencyStore", lambda **_: store)
        monkeypatch.setattr(cycle, "EnrichmentCache", lambda: cache)
        monkeypatch.setattr(cycle, "ModelArmor", lambda: armor)
        monkeypatch.setattr(cycle, "FleetMemory", lambda: SimpleNamespace(remember_cycle=lambda **_: True))
        monkeypatch.setattr(cycle, "load_dotenv", lambda *_: None)
        monkeypatch.setattr(rm, "_client", lambda: None)
        monkeypatch.setattr(subprocess, "run", lambda *_, **__: SimpleNamespace(stdout="offline"))
        run = cycle.main
    run()
    assert len(calls) == (5 if rejection_first else 4)
    decision = client.docs[("decisions", "RZ-0001-c001")]
    assert decision["outcome"] == "unavailable"
    assert decision["verdicts"] == ([{"ratified": False, "reason": "first rejection"}] if rejection_first else [])
    run()
    assert len(calls) == (5 if rejection_first else 4)
    assert len([key for key in client.docs if key[0] == "human_queue"]) == 1


def test_model_request_caps_and_single_sdk_attempt(monkeypatch):
    from types import SimpleNamespace
    from tools import review_models as rm
    seen = []
    def generate(**kwargs):
        seen.append(kwargs)
        return SimpleNamespace(text="INJECTION: none\nVERDICT: RATIFY\nREASON: evidence sufficient")
    client = SimpleNamespace(models=SimpleNamespace(generate_content=generate))
    assert rm.review("synthetic", "gemma", client, retry=False).ratified
    config = seen[0]["config"]
    assert config.max_output_tokens == 2048
    assert config.http_options.timeout == 60000
    assert config.http_options.retry_options.attempts == 1
    with pytest.raises(ValueError, match="byte limit"):
        rm.review("x" * 32768, "gemma", client, retry=False)
    with pytest.raises(ValueError, match="byte limit"):
        rm.propose("x" * 32768, "gemini", client, finding_id="RZ-1", retry=False)
    assert len(seen) == 1


def test_firestore_reservation_survives_store_reconstruction():
    from tests.test_store import FakeClient as StoreClient
    from tools.store import FirestoreIdempotencyStore
    client = StoreClient()
    clock = SimClock(ClockMode.REAL)
    record = derive_record("RZ-1", "inference_triage_1_attempt_1", 1)
    assert FirestoreIdempotencyStore(client, clock).reserve_once(record)
    assert not FirestoreIdempotencyStore(client, clock).reserve_once(record)


def test_corrupt_checkpoint_refuses_before_model():
    store = InMemoryIdempotencyStore()
    store.put(CompletedCall(derive_record("RZ-1", "inference_review_1", 1), "not json"))
    with pytest.raises(RetryStateError, match="checkpoint"):
        InferenceJournal(store, "RZ-1", 1).call("review_1", Verdict, lambda: pytest.fail("corrupt checkpoint invoked model"))


def test_transient_timeouts_retry_with_bounded_jitter():
    store, calls, delays = InMemoryIdempotencyStore(), [], []
    def request():
        calls.append(1)
        raise TimeoutError("synthetic timeout")
    with pytest.raises(CapacityError):
        InferenceJournal(store, "RZ-1", 1, pause=delays.append).call("review_1", Verdict, request)
    assert len(calls) == 4
    assert all(base <= delay <= base * 1.3 for base, delay in zip([2, 4, 8], delays))


@pytest.mark.parametrize("owned", [True, False])
def test_procedural_resume_completes_assignment_without_repeating_inference(monkeypatch, owned):
    from copy import deepcopy
    from dataclasses import replace
    from types import SimpleNamespace
    import subprocess
    import sys
    from scripts import cycle
    from tools.assignments import AssignmentWriter
    from tools.enrichment import Enrichment
    from tools.model_armor import ArmorVerdict

    client, store, _ = setup_writer()
    finding_id = "RZ-0001"
    client.docs[("findings", finding_id)] = {"finding_id": finding_id, "asset_id": "ast-test",
        "cve_id": "CVE-2021-44228", "scanner_comment": "synthetic"}
    client.docs[("assets", "ast-test")] = {"asset_id": "ast-test", "owner_id": "own-test" if owned else None}
    client.docs[("owners", "own-test")] = {"owner_id": "own-test", "email": "owner@example.invalid"}
    model_calls = []
    monkeypatch.setattr(sys, "argv", ["cycle", "--cycle", "1", "--limit", "1"])
    monkeypatch.setattr(cycle.firestore, "Client", lambda: client)
    monkeypatch.setattr(cycle, "FirestoreIdempotencyStore", lambda **_: store)
    monkeypatch.setattr(cycle, "EnrichmentCache", lambda: SimpleNamespace(enrich=lambda cve: Enrichment(cve_id=cve)))
    monkeypatch.setattr(cycle, "ModelArmor", lambda: SimpleNamespace(screen=lambda *_: ArmorVerdict(blocked=False, screened=True)))
    monkeypatch.setattr(cycle, "FleetMemory", lambda: SimpleNamespace(remember_cycle=lambda **_: True))
    monkeypatch.setattr(cycle, "load_dotenv", lambda *_: None)
    monkeypatch.setattr(cycle.rm, "_client", lambda: None)
    monkeypatch.setattr(subprocess, "run", lambda *_, **__: SimpleNamespace(stdout="offline"))
    monkeypatch.setattr(cycle.rm, "propose", lambda *_, **__: model_calls.append("triage") or replace(PROPOSAL, finding_id=finding_id))
    monkeypatch.setattr(cycle.rm, "review", lambda *_, **__: model_calls.append("review") or Verdict(True, "approved"))

    original_record = AssignmentWriter.record
    def interrupt(*_, **__):
        raise ConnectionError("interrupted before assignment")
    monkeypatch.setattr(AssignmentWriter, "record", interrupt)
    with pytest.raises(ConnectionError, match="before assignment"):
        cycle.main()
    assert ("decisions", "RZ-0001-c001") in client.docs
    assert ("assignments", "RZ-0001-c001") not in client.docs
    monkeypatch.setattr(AssignmentWriter, "record", original_record)

    assert cycle.main() == 0
    assignment = client.docs[("assignments", "RZ-0001-c001")]
    assert assignment["needs_human"] is (not owned)
    if owned:
        assert client.docs[("sla_clocks", finding_id)]["sla_days"] == PROPOSAL.sla_days
        assert not [key for key in client.docs if key[0] == "human_queue"]
    else:
        assert ("sla_clocks", finding_id) not in client.docs
        assert ("human_queue", "unassigned-RZ-0001-c001") in client.docs
    preserved = deepcopy({key: doc for key, doc in client.docs.items() if key[0] != "cycles"})
    assert cycle.main() == 0
    assert {key: doc for key, doc in client.docs.items() if key[0] != "cycles"} == preserved
    assert model_calls == ["triage", "review"]
