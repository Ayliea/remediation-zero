# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""The guardrail port: what untrusted text crosses before any model sees it.

Cloud: Model Armor. Local: a user-configured guard model, or nothing, in which
case the text is withheld. Every failure path is blocked and unscreened, so a
guard that cannot answer never lets text through. Standard library only.
"""
import http.client
from typing import Callable, Protocol

from tools.adjudication import CapacityError
from tools.inference import FENCE_BEGIN, FENCE_END, _defang_fence, _load
from tools.model_armor import ArmorVerdict

_UNUSABLE = ArmorVerdict(blocked=True, screened=False, reasons=("guard response unusable",))
_PROMPT = "guard_v1.md"
#: An UNSAFE reason longer than this is cut, ending in "…".
MAX_REASON_CHARS = 200


class Guardrail(Protocol):
    def screen(self, text: str) -> ArmorVerdict: ...


class ModelArmorGuard:
    """Cloud edition: the existing Model Armor call, unchanged."""

    def __init__(self, armor, token: Callable[[], str]):
        self._armor = armor
        self._token = token

    def screen(self, text: str) -> ArmorVerdict:
        return self._armor.screen(text, self._token())


class NoGuard:
    """No guard configured: nothing is screened, so everything is withheld."""

    def screen(self, text: str) -> ArmorVerdict:
        return ArmorVerdict(blocked=True, screened=False, reasons=("no guard configured",))


def _parse(response: str) -> ArmorVerdict:
    if not isinstance(response, str):
        return _UNUSABLE
    lines = response.strip().splitlines()
    if len(lines) != 2:
        return _UNUSABLE
    verdict, reason_line = lines[0].rstrip(), lines[1]
    if verdict not in ("VERDICT: SAFE", "VERDICT: UNSAFE"):
        return _UNUSABLE
    # "REASON:" with nothing after it has no trailing space once stripped.
    if reason_line.rstrip() == "REASON:":
        reason = ""
    elif reason_line.startswith("REASON: "):
        reason = reason_line[len("REASON: "):].strip()
    else:
        return _UNUSABLE
    if verdict == "VERDICT: SAFE":
        return ArmorVerdict(blocked=False, screened=True)
    if not reason:
        return _UNUSABLE
    # The reason is model text that the screened input may have steered. It
    # is logged, so it is kept short enough that it cannot carry the payload.
    if len(reason) > MAX_REASON_CHARS:
        reason = reason[:MAX_REASON_CHARS - 1] + "…"
    return ArmorVerdict(blocked=True, screened=True, reasons=(reason,))


class GuardModelScreen:
    """Local edition: ask the guard model for a two-line verdict.

    One attempt, no retries. A screen that cannot answer withholds the text
    and the finding proceeds without it.
    """

    def __init__(self, adapter):
        self._adapter = adapter

    def screen(self, text: str) -> ArmorVerdict:
        user = "\n".join((FENCE_BEGIN, _defang_fence(text), FENCE_END))
        try:
            response = self._adapter.complete(_load(_PROMPT), user, json_output=False)
        except (CapacityError, ValueError, OSError, http.client.HTTPException):
            # A disconnect mid-response included: withhold, never pass through.
            return _UNUSABLE
        return _parse(response)


def guard_for(roles) -> Guardrail:
    """The local edition's guardrail: the guard model if configured, else none."""
    if roles.guard is None:
        return NoGuard()
    return GuardModelScreen(roles.adapter("guard"))
