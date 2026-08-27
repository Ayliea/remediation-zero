# Copyright 2026 Daviyon Daniels
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Deterministic idempotency keys for side-effecting tools.

Every tool that changes the world outside this process takes one of these. A
resumed agent recomputes the key from the same three facts and lands on the
same value, so the second attempt is recognised as the first one repeating
rather than as new work.

The key is opaque. Finding identifiers are not carried in document names,
because document names travel further than the records they name: into console
URLs, log lines, stack traces and error payloads that were never scoped to hold
vulnerability data. The cost of opacity is that a key alone does not say what
it refers to, so `derive_record` pairs every key with the components that
produced it. Writers persist the record, not the bare key, which keeps a single
finding's journey queryable end to end.

Normalisation policy
--------------------
The two failure directions are not symmetric, and the policy is tuned to that.

Normalising too little splits one thing into two keys: "CVE-2024-1234" and
"cve-2024-1234" open two tickets for one vulnerability. That is visible and
annoying.

Normalising too much merges two things into one key, so the second action is
recognised as a duplicate and silently never happens: a nudge that never sends,
an escalation that never fires. That is invisible, and it is the failure this
system exists to prevent.

So folding is applied only where the input space is known to make it safe, and
withheld everywhere else until real findings justify it:

  folded    case of finding_id, which is conventionally uppercase and where a
            lowercase variant means the same CVE
  folded    case of action, a vocabulary this system generates, where no action
            is case-significant and an inconsistent literal at one call site
            would otherwise mint a second key
  folded    surrounding whitespace, which is an artefact of transport
  kept      internal whitespace, unjustified to collapse without evidence
  kept      Unicode form. NFKC would fold fullwidth and other lookalikes into
            ASCII. finding_id originates in the trusted seed script rather than
            scanner free text, so there is no homoglyph pressure here, and
            folding without evidence risks merging distinct identifiers
  rejected  empty, whitespace-only, and non-string components, and negative
            cycles, which would each produce a valid-looking key from a bug
"""

import functools
import hashlib
from dataclasses import dataclass
from typing import Any, Callable, Optional, Protocol

#: Identifies the derivation scheme. Change this whenever the material fed to
#: the hash changes, including the normalisation policy, so that keys minted
#: under a new scheme are recognisably different rather than silently colliding
#: with old ones.
KEY_SCHEME = "rz-idem-v1"


@dataclass(frozen=True)
class IdempotencyRecord:
    """A key together with everything needed to explain it.

    Components are stored normalised, so they reproduce the key they are filed
    under. Frozen because a key that can be edited after the fact is not a key.
    """

    key: str
    finding_id: str
    action: str
    cycle: int
    scheme: str


def _normalize_text(value: str, *, field: str, case: str) -> str:
    """Strip surrounding whitespace and fold case. Reject what cannot be a key.

    Rejection is loud on purpose. An empty component still hashes to a
    perfectly valid-looking key, which would quietly deduplicate unrelated
    findings against one another.
    """
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string, got {type(value).__name__}")

    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field} must not be empty or whitespace only")

    return normalized.upper() if case == "upper" else normalized.lower()


def _normalize_cycle(cycle: int, *, field: str = "cycle") -> int:
    """Cycle numbers count upward from zero.

    bool is excluded explicitly because it is a subclass of int in Python, and
    True would otherwise pass as cycle 1.
    """
    if isinstance(cycle, bool) or not isinstance(cycle, int):
        raise ValueError(f"{field} must be an integer, got {type(cycle).__name__}")
    if cycle < 0:
        raise ValueError(f"{field} must not be negative, got {cycle}")
    return cycle


def _normalize(finding_id: str, action: str, cycle: int) -> tuple[str, str, int]:
    """Apply the normalisation policy to all three components.

    Idempotent: normalising an already-normalised triple is a no-op, which is
    what lets `derive_record` normalise once and still agree with `derive_key`.
    """
    return (
        _normalize_text(finding_id, field="finding_id", case="upper"),
        _normalize_text(action, field="action", case="lower"),
        _normalize_cycle(cycle),
    )


def _canonical(*parts: str) -> str:
    """Encode parts so that no value can impersonate a different split.

    Each part is prefixed with its length, which makes the encoding injective:
    two different tuples of parts cannot produce the same string. Plain
    concatenation and single-delimiter joins both fail this, and the failure is
    silent. Concatenating ("nudge", 12) and ("nudge1", 2) both yield "nudge12",
    which would let a cycle-12 nudge inherit an unrelated action's key and be
    suppressed as a duplicate.
    """
    return "|".join(f"{len(part)}:{part}" for part in parts)


def derive_key(finding_id: str, action: str, cycle: int) -> str:
    """Derive a stable key for one action on one finding in one cycle.

    Raises:
        ValueError: if any component cannot form a key. Never returns a
            plausible key for implausible input.
    """
    normalized_id, normalized_action, normalized_cycle = _normalize(
        finding_id, action, cycle
    )
    material = _canonical(
        KEY_SCHEME, normalized_id, normalized_action, str(normalized_cycle)
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def derive_record(finding_id: str, action: str, cycle: int) -> IdempotencyRecord:
    """Derive a key alongside the components that explain it.

    Prefer this over `derive_key` at every call site that persists something.
    """
    normalized_id, normalized_action, normalized_cycle = _normalize(
        finding_id, action, cycle
    )
    return IdempotencyRecord(
        key=derive_key(
            finding_id=normalized_id,
            action=normalized_action,
            cycle=normalized_cycle,
        ),
        finding_id=normalized_id,
        action=normalized_action,
        cycle=normalized_cycle,
        scheme=KEY_SCHEME,
    )


# ---------------------------------------------------------------------------
# Suppression
# ---------------------------------------------------------------------------


class IdempotencyStore(Protocol):
    """Where executed keys are remembered.

    Firestore backs this in the deployed system. The protocol exists so the
    suppression logic can be tested without standing up a database, not so
    that the deployed system can be tested against a fake: a tool that only
    works against the in-memory store does not work.
    """

    def get(self, key: str) -> Optional["CompletedCall"]:
        """Return the completed call for `key`, or None if it never ran."""

    def put(self, completed: "CompletedCall") -> None:
        """Record a completed call. Called only after the effect succeeded."""


@dataclass(frozen=True)
class CompletedCall:
    """The record of an effect that already happened, and what it returned."""

    record: IdempotencyRecord
    result: Any

    @property
    def key(self) -> str:
        return self.record.key

    @property
    def finding_id(self) -> str:
        return self.record.finding_id

    @property
    def action(self) -> str:
        return self.record.action

    @property
    def cycle(self) -> int:
        return self.record.cycle


class InMemoryIdempotencyStore:
    """A dict-backed store, for tests and local runs."""

    def __init__(self) -> None:
        self._calls: dict[str, CompletedCall] = {}

    def get(self, key: str) -> Optional[CompletedCall]:
        return self._calls.get(key)

    def put(self, completed: CompletedCall) -> None:
        self._calls[completed.key] = completed


class IdempotencyGuard:
    """Wraps side-effecting callables so a repeat call has no second effect.

    The decorated function must take `finding_id` and `cycle` as keyword
    arguments; the key is derived from those plus the action name. Keyword-only
    is deliberate, because positional arguments would make the key depend on
    call-site argument order.
    """

    def __init__(self, store: IdempotencyStore) -> None:
        self._store = store

    def protects(self, action: str) -> Callable:
        """Decorator factory naming the action this callable performs."""

        def decorate(fn: Callable) -> Callable:
            @functools.wraps(fn)
            def wrapper(*args: Any, finding_id: str, cycle: int, **kwargs: Any) -> Any:
                record = derive_record(
                    finding_id=finding_id, action=action, cycle=cycle
                )

                existing = self._store.get(record.key)
                if existing is not None:
                    # Already happened. Return what it returned the first time,
                    # so the caller cannot tell it was suppressed.
                    return existing.result

                result = fn(
                    *args,
                    finding_id=record.finding_id,
                    cycle=record.cycle,
                    **kwargs,
                )

                # Recorded only after the effect succeeded. Recording on entry
                # would let one transient failure permanently suppress an
                # action that never actually happened.
                self._store.put(CompletedCall(record=record, result=result))
                return result

            return wrapper

        return decorate
