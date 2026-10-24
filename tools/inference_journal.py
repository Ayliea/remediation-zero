# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Durably bounded inference retries; request reservations never expire."""

import json
import random
from dataclasses import asdict
from time import sleep

try:
    import httpx
except ImportError:
    httpx = None
try:
    from google.api_core import exceptions
except ImportError:
    exceptions = None

from tools.adjudication import CapacityError, Proposal, RetryStateError, Verdict
from tools.idempotency import CompletedCall, derive_record

MAX_STAGE_ATTEMPTS = 4


def is_transient(exc):
    transient = (CapacityError, TimeoutError, ConnectionError)
    if httpx is not None:
        transient += (httpx.TransportError,)
    if exceptions is not None:
        transient += (exceptions.DeadlineExceeded, exceptions.ServiceUnavailable,
                      exceptions.ResourceExhausted)
    if isinstance(exc, transient):
        return True
    return getattr(exc, "code", None) in (408, 429, 500, 502, 503, 504)


class InferenceJournal:
    def __init__(self, store, finding_id, cycle, *, pause=None, context=""):
        self.store, self.finding_id, self.cycle = store, finding_id, cycle
        self.sleep, self.context = pause or sleep, context

    def _state(self, fn, *args):
        try:
            return fn(*args)
        except Exception as exc:
            raise RetryStateError("inference journal unavailable; budget must not reset") from exc

    def _ensure_context(self):
        key = derive_record(self.finding_id, "inference_context", self.cycle)
        claim = self._state(self.store.acquire, key)
        if claim.existing is not None:
            if claim.existing.result != self.context:
                raise ValueError("inference input/model/prompt changed within this cycle; human review required")
            return
        if not claim.acquired:
            raise RetryStateError("inference context is being checkpointed")
        try:
            self._state(self.store.complete, claim, CompletedCall(key, self.context))
        finally:
            self._state(self.store.abandon, claim)

    def call(self, stage, expected, fn):
        if stage not in {"triage_1", "review_1", "triage_2", "review_2"}:
            raise ValueError("unsupported inference stage")
        if expected is not (Proposal if stage.startswith("triage") else Verdict):
            raise ValueError("unexpected inference result type")
        key = derive_record(self.finding_id, "inference_" + stage, self.cycle)
        claim = self._state(self.store.acquire, key)
        if claim.existing is not None:
            try:
                payload = json.loads(claim.existing.result)
                failure = payload.get("_failure")
                if failure is not None:
                    if not isinstance(failure, str):
                        raise ValueError("invalid stored failure")
                else:
                    if expected is Proposal:
                        payload["evidence"] = tuple(payload["evidence"])
                    result = expected(**payload)
                    if expected is Proposal and result.finding_id != self.finding_id:
                        raise ValueError("stored proposal identity mismatch")
            except Exception as exc:
                raise RetryStateError("invalid inference checkpoint; reconciliation required") from exc
            if failure is not None:
                raise ValueError(failure)
            return result
        if not claim.acquired:
            raise RetryStateError("inference stage is in progress")
        try:
            self._ensure_context()
            for attempt in range(1, MAX_STAGE_ATTEMPTS + 1):
                slot = derive_record(self.finding_id, f"inference_{stage}_attempt_{attempt}", self.cycle)
                if not self._state(self.store.reserve_once, slot):
                    continue
                if attempt > 1:
                    delay = 2 ** (attempt - 1)
                    self.sleep(delay + random.uniform(0, delay * .3))
                try:
                    result = fn()
                    if not isinstance(result, expected):
                        raise ValueError(f"inference must return {expected.__name__}")
                    if expected is Proposal and result.finding_id != self.finding_id:
                        raise ValueError("proposal finding_id mismatch")
                except RetryStateError:
                    raise
                except Exception as exc:
                    if is_transient(exc):
                        continue
                    failure = f"{type(exc).__name__}: {exc}"
                    self._state(self.store.complete, claim, CompletedCall(key, json.dumps({"_failure": failure})))
                    raise
                self._state(self.store.complete, claim, CompletedCall(key, json.dumps(asdict(result))))
                return result
            raise CapacityError(f"{stage} unavailable: durable budget of {MAX_STAGE_ATTEMPTS} requests exhausted")
        finally:
            self._state(self.store.abandon, claim)
