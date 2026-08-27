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
"""

import hashlib
from dataclasses import dataclass

#: Identifies the derivation scheme. Change this whenever the material fed to
#: the hash changes, so that keys minted under a new scheme are recognisably
#: different rather than silently colliding with old ones.
KEY_SCHEME = "rz-idem-v1"


@dataclass(frozen=True)
class IdempotencyRecord:
    """A key together with everything needed to explain it.

    Frozen because a key that can be edited after the fact is not a key.
    """

    key: str
    finding_id: str
    action: str
    cycle: int
    scheme: str


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
    """Derive a stable key for one action on one finding in one cycle."""
    material = _canonical(KEY_SCHEME, finding_id, action, str(cycle))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def derive_record(finding_id: str, action: str, cycle: int) -> IdempotencyRecord:
    """Derive a key alongside the components that explain it.

    Prefer this over `derive_key` at every call site that persists something.
    """
    return IdempotencyRecord(
        key=derive_key(finding_id=finding_id, action=action, cycle=cycle),
        finding_id=finding_id,
        action=action,
        cycle=cycle,
        scheme=KEY_SCHEME,
    )
