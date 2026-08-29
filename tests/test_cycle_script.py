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

"""The tick driver's short-circuit, and the coupling it depends on.

cycle.py checks the idempotency ledger before calling any model, not just
before writing. The guard around the write is what makes the state correct,
but it only fires after triage and review have already run and been paid for,
so re-running a cycle would be correct and expensive.

That saving rests entirely on the key cycle.py looks up matching the key
DecisionWriter files under. If the two drift, nothing breaks and nothing
fails: the lookup simply never hits, every re-run pays for two model calls per
finding, and the only symptom is a bill. Drift with no failure mode is worth a
test precisely because nothing else will ever report it.
"""

import re
from pathlib import Path

from tools.idempotency import derive_key

ROOT = Path(__file__).resolve().parents[1]
CYCLE_SOURCE = (ROOT / "scripts" / "cycle.py").read_text()
DECISIONS_SOURCE = (ROOT / "tools" / "decisions.py").read_text()


def _action_in(source: str, pattern: str) -> str:
    match = re.search(pattern, source)
    assert match, f"could not find the action string via {pattern!r}"
    return match.group(1)


def test_the_short_circuit_looks_up_what_the_writer_files_under():
    """The coupling. Both sides name the action as a literal, in different
    files, and nothing connects them but this test."""
    checked = _action_in(CYCLE_SOURCE, r'derive_key\(\s*finding_id=finding_id,\s*action="([a-z_]+)"')
    written = _action_in(DECISIONS_SOURCE, r'protects\(action="([a-z_]+)"\)')

    assert checked == written, (
        f"cycle.py looks up '{checked}' but decisions.py files under "
        f"'{written}'. The short-circuit will never hit, every re-run pays "
        f"for the model calls again, and nothing will fail to tell you."
    )


def test_the_two_sides_derive_an_identical_key():
    """Not just the same action name -- the same key, through the real
    derivation, for the same finding and cycle."""
    checked = _action_in(CYCLE_SOURCE, r'derive_key\(\s*finding_id=finding_id,\s*action="([a-z_]+)"')
    written = _action_in(DECISIONS_SOURCE, r'protects\(action="([a-z_]+)"\)')

    assert derive_key("RZ-0001", checked, 7) == derive_key("RZ-0001", written, 7)


def test_the_short_circuit_happens_before_any_model_is_called():
    """Checking after the model call would still be correct and would cost
    exactly what it was meant to save."""
    skip_at = CYCLE_SOURCE.index("skipped_already_adjudicated")
    for model_call in ("propose(", "adjudicate("):
        called_at = CYCLE_SOURCE.find(model_call)
        if called_at != -1:
            assert skip_at < called_at, (
                f"{model_call} appears before the short-circuit, so a re-run "
                f"pays for it before deciding it was unnecessary")


def test_a_skipped_finding_is_counted_rather_than_passed_over_silently():
    """A cycle that reports nothing about what it skipped looks identical to
    a cycle that had nothing to do."""
    assert 'outcomes["skipped"]' in CYCLE_SOURCE


def test_a_missing_finding_is_logged_rather_than_crashing_the_cycle():
    """--start and --limit address findings by index, so asking for a range
    past the end of the corpus is an ordinary mistake, not a failure."""
    assert "finding_missing" in CYCLE_SOURCE
    assert "if not snapshot.exists:" in CYCLE_SOURCE


def test_blocked_or_unscreened_text_is_branched_on_explicitly():
    """Constraint 12 on this path: `screened` is distinct from `blocked` so
    the record can tell "we looked and it was bad" from "we could not look",
    and both have to stop the finding."""
    assert "verdict.blocked or not verdict.screened" in CYCLE_SOURCE
