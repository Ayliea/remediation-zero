# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Explicit local-only integration checks. No cloud credentials or model calls."""
import os
import re
import uuid
import select
import subprocess
import sys
from time import sleep
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier


def emulator_endpoint(environ):
    endpoint = environ.get("FIRESTORE_EMULATOR_HOST", "")
    match = re.fullmatch(r"127\.0\.0\.1:([0-9]{1,5})", endpoint)
    if not match or not 1024 <= int(match[1]) <= 65535:
        raise ValueError("Set FIRESTORE_EMULATOR_HOST to 127.0.0.1:<port 1024..65535>; cloud fallback is forbidden")
    return endpoint


def make_client():
    endpoint = emulator_endpoint(os.environ)
    from google.auth.credentials import AnonymousCredentials
    from google.cloud import firestore
    client = firestore.Client(project="demo-rz-" + uuid.uuid4().hex[:16], credentials=AnonymousCredentials())
    if client._emulator_host != endpoint:
        raise RuntimeError("Firestore client did not select validated emulator")
    return client


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def run_checks(client):
    from google.api_core.exceptions import Aborted
    from tools.adjudication import Adjudication, AdjudicationOutcome, CapacityError, Proposal, Verdict
    from tools.clock import ClockMode, SimClock
    from tools.decisions import DecisionWriter
    from tools.idempotency import CompletedCall, IdempotencyInProgress, derive_record
    from tools.inference_journal import InferenceJournal
    from tools.store import FirestoreIdempotencyStore
    clock = SimClock(ClockMode.REAL)
    def store():
        return FirestoreIdempotencyStore(client=client, clock=clock)
    def writer():
        return DecisionWriter(store(), client=client, clock=clock)
    def race(fn):
        barrier = Barrier(8, timeout=15)
        def contender(_):
            barrier.wait()
            try:
                return fn()
            except Aborted:
                return "aborted"
        with ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(contender, range(8)))
        print("Contention deferrals:", outcomes.count("aborted"))
        return outcomes

    record = derive_record("RZ-EMU-RESERVE", "inference_triage_1_attempt_1", 1)
    check(sum(value is True for value in race(lambda: store().reserve_once(record))) == 1,
          "multiple or no reservation winners")
    check(not store().reserve_once(record), "fresh store reset reservation")
    print("PASS concurrent request reservations")

    record = derive_record("RZ-EMU-CLAIM", "decision", 1)
    claims = race(lambda: store().acquire(record))
    winners = [claim for claim in claims if claim != "aborted" and claim.acquired]
    check(len(winners) == 1, "multiple or no claim winners")
    old = winners[0]
    store().abandon(old)
    new = store().acquire(record)
    check(new.acquired, "released claim not recoverable")
    try:
        store().complete(old, CompletedCall(record, "stale"))
    except IdempotencyInProgress:
        pass
    else:
        raise AssertionError("stale worker completed replacement claim")
    store().abandon(old)
    store().complete(new, CompletedCall(record, "winner"))
    check(store().get(record.key).result == "winner", "stale worker altered winner")
    print("PASS concurrent claims and stale worker suppression")

    def unavailable(finding_id):
        proposal = Proposal(finding_id, "high", 7, "apply synthetic fix", ("synthetic evidence",), "offline case")
        return Adjudication(finding_id, AdjudicationOutcome.UNAVAILABLE, proposal,
                            (Verdict(False, "missing evidence"),), 2, "reviewer outage after rejection")
    finding_id = "RZ-EMU-ATOMIC"
    result = unavailable(finding_id)
    decision_id = finding_id + "-c001"
    queue = client.collection("human_queue").document("reviewer-unavailable-" + decision_id)
    queue.create({"sentinel": "existing synthetic orphan"})
    try:
        writer().record(result, 1)
    except RuntimeError as exc:
        check("queue exists without a decision" in str(exc), "unexpected failure")
    else:
        raise AssertionError("orphan queue did not refuse commit")
    check(not client.collection("decisions").document(decision_id).get().exists, "partial batch decision")
    check(queue.get().to_dict() == {"sentinel": "existing synthetic orphan"}, "orphan overwritten")
    print("PASS atomic batch rollback on queue conflict")

    finding_id = "RZ-EMU-OUTAGE"
    result = unavailable(finding_id)
    def record_terminal():
        try:
            writer().record(result, 1)
            return "recorded"
        except IdempotencyInProgress:
            return "deferred"
    outcomes = race(record_terminal)
    recovered = "recorded" in outcomes
    recoveries = 0
    for _ in range(4):
        if recovered:
            break
        recoveries += 1
        try:
            recovered = record_terminal() == "recorded"
        except Aborted:
            pass
    print("Post-contention recovery attempts:", recoveries)
    check(recovered, "no writer committed after bounded recovery")
    check(writer().restore(finding_id, 1) == result, "rejection evidence changed")
    writer().record(result, 1)
    entries = [doc for doc in client.collection("human_queue").stream()
               if doc.to_dict().get("finding_id") == finding_id]
    check(len(entries) == 1, "duplicate escalations")
    print("PASS rejection/outage persistence and concurrent duplicate suppression")

    finding_id = "RZ-EMU-REPLAY"
    def journal():
        return InferenceJournal(store(), finding_id, 1, pause=lambda _: None, context="synthetic-v1")
    rejection = Verdict(False, "missing evidence")
    check(journal().call("review_1", Verdict, lambda: rejection) == rejection, "checkpoint failed")
    def unexpected():
        raise AssertionError("checkpoint replay invoked inference")
    check(journal().call("review_1", Verdict, unexpected) == rejection, "rejection not replayed")
    calls = []
    def outage():
        calls.append(1)
        raise CapacityError("synthetic outage")
    for _ in range(2):
        try:
            journal().call("review_2", Verdict, outage)
        except CapacityError:
            pass
        else:
            raise AssertionError("outage accepted")
    check(len(calls) == 4, "retry budget reset or exceeded")
    check(journal().call("review_1", Verdict, unexpected) == rejection, "outage erased rejection")
    print("PASS checkpoint replay and durable outage retry limits")

    verify_process_kill(client)


def verify_process_kill(client):
    """SIGKILL after reservation, then real elapsed expiry of a test-only lease."""
    from tools.adjudication import Proposal, RetryStateError, Verdict
    from tools.clock import ClockMode, SimClock
    from tools.idempotency import CallClaim, CompletedCall, IdempotencyInProgress, derive_record
    from tools.inference_journal import InferenceJournal
    from tools.store import FirestoreIdempotencyStore

    clock = SimClock(ClockMode.REAL)
    store = FirestoreIdempotencyStore(client, clock)
    finding_id = "RZ-EMU-KILLED"
    rejection = Verdict(False, "preserve rejection before crash")
    journal = InferenceJournal(store, finding_id, 1, pause=lambda _: None, context="kill-v1")
    journal.call("review_1", Verdict, lambda: rejection)
    # Only this disposable worker uses a short lease. Real stamps come from
    # SimClock; no expired timestamp is fabricated or backdated.
    worker = r'''
import os, re, signal, sys
from google.auth.credentials import AnonymousCredentials
from google.cloud import firestore
from scripts.verify_recovery_emulator import emulator_endpoint
from tools.adjudication import Proposal
from tools.clock import ClockMode, SimClock
from tools.inference_journal import InferenceJournal
import tools.store as persistence
emulator_endpoint(os.environ)
if not re.fullmatch(r"demo-rz-[0-9a-f]{16}", sys.argv[1]):
    raise ValueError("synthetic project required")
persistence.CLAIM_LEASE_SECONDS = 10
client = firestore.Client(project=sys.argv[1], credentials=AnonymousCredentials())
store = persistence.FirestoreIdempotencyStore(client, SimClock(ClockMode.REAL))
def interrupted_inference():
    print("REQUEST_RESERVED", flush=True)
    signal.pause()
    raise AssertionError("worker unexpectedly resumed")
InferenceJournal(store, "RZ-EMU-KILLED", 1, context="kill-v1").call("triage_2", Proposal, interrupted_inference)
'''
    proc = subprocess.Popen([sys.executable, "-u", "-c", worker, client.project],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        ready, _, _ = select.select([proc.stdout], [], [], 20)
        check(bool(ready), "worker readiness timeout")
        check(proc.stdout.readline().strip() == "REQUEST_RESERVED", "worker failed before reservation")
        stage = derive_record(finding_id, "inference_triage_2", 1)
        before = client.collection("idempotency").document(stage.key).get().to_dict()
        stale = CallClaim(record=stage, acquired=True, token=before["claim_token"])
        proc.kill()
        check(proc.wait(timeout=5) < 0, "worker was not killed by a signal")
        check(before["claim_expires_real_ts"] > clock.now().real_ts, "test lease expired before busy check")
        calls = []
        def recovered_inference():
            calls.append(1)
            return Proposal(finding_id, "high", 7, "synthetic fix", ("synthetic evidence",), "recovered")
        try:
            journal.call("triage_2", Proposal, recovered_inference)
        except RetryStateError:
            pass
        else:
            raise AssertionError("live lease permitted duplicate inference")
        check(not calls, "model ran while killed worker lease was live")
        sleep(max(0, before["claim_expires_real_ts"] - clock.now().real_ts) + .1)
        recovered = InferenceJournal(store, finding_id, 1, pause=lambda _: None, context="kill-v1")
        recovered.call("triage_2", Proposal, recovered_inference)
        check(len(calls) == 1, "recovery did not invoke exactly one replacement request")
        for attempt in (1, 2):
            slot = derive_record(finding_id, f"inference_triage_2_attempt_{attempt}", 1)
            check(store.get(slot.key) is not None, "crashed or recovery request reservation lost")
        check(store.get(derive_record(finding_id, "inference_triage_2_attempt_3", 1).key) is None,
              "unexpected additional request")
        check(recovered.call("review_1", Verdict, lambda: None) == rejection, "saved rejection lost")
        try:
            store.complete(stale, CompletedCall(stage, "stale worker result"))
        except IdempotencyInProgress:
            pass
        else:
            raise AssertionError("stale claim replaced recovery checkpoint")
        print("PASS process kill, live-lease deferral and real lease expiry (10-second test lease)")
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.communicate(timeout=5)


def main():
    client = make_client()
    try:
        client.collection("readiness").document("probe").get(retry=None, timeout=3)
        print("Synthetic emulator project:", client.project)
        run_checks(client)
    finally:
        client.close()


if __name__ == "__main__":
    main()
