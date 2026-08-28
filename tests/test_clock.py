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

"""SimClock is the single source of time for the entire system.

The demo's strongest claim is that a session really has been alive for days.
That claim is only worth something if real_ts is never falsifiable, so these
tests are as much about what the clock refuses to do as what it does.
"""

import ast
import time
from pathlib import Path

import pytest

from tools.clock import ClockMode, SimClock


def test_real_mode_reports_wall_clock_for_both_stamps():
    """In real mode there is nothing to simulate: sim_ts tracks wall clock."""
    clock = SimClock(mode=ClockMode.REAL)

    before = time.time()
    stamp = clock.now()
    after = time.time()

    assert before <= stamp.real_ts <= after
    assert before <= stamp.sim_ts <= after


def test_advance_is_refused_in_real_mode():
    """The guard that makes the elapsed-time claim defensible. In real mode
    there is no supported way to move time at all."""
    clock = SimClock(mode=ClockMode.REAL)

    with pytest.raises(RuntimeError, match="real"):
        clock.advance(seconds=3600)


def test_advance_moves_sim_ts_only():
    """A six-week lifecycle is demonstrable in three minutes, but the wall
    clock reading is untouched by it."""
    clock = SimClock(mode=ClockMode.SIM)

    start = clock.now()
    clock.advance(seconds=6 * 7 * 24 * 3600)
    end = clock.now()

    assert end.sim_ts - start.sim_ts == pytest.approx(6 * 7 * 24 * 3600, abs=1)
    assert end.real_ts - start.real_ts < 5


def test_real_ts_is_wall_clock_even_in_sim_mode():
    """real_ts is never simulated, never offset, never backdated, in any mode.
    This is the assertion the demo's credibility rests on."""
    clock = SimClock(mode=ClockMode.SIM)
    clock.advance(seconds=10 * 365 * 24 * 3600)

    before = time.time()
    stamp = clock.now()
    after = time.time()

    assert before <= stamp.real_ts <= after


def test_advance_refuses_to_move_backwards():
    """Time running backwards would let a stamped record predate the event it
    describes, which is indistinguishable from backdating."""
    clock = SimClock(mode=ClockMode.SIM)

    with pytest.raises(ValueError, match="negative"):
        clock.advance(seconds=-1)


def test_mode_is_read_from_the_environment():
    """SIM_CLOCK_MODE is the documented switch in .env.example."""
    assert SimClock.from_env({"SIM_CLOCK_MODE": "sim"}).mode is ClockMode.SIM
    assert SimClock.from_env({"SIM_CLOCK_MODE": "real"}).mode is ClockMode.REAL


def test_unset_mode_defaults_to_real():
    """The safe default is the one that cannot fabricate elapsed time."""
    assert SimClock.from_env({}).mode is ClockMode.REAL


def test_unrecognised_mode_is_rejected_rather_than_guessed():
    """A typo in .env must not silently select a mode. Guessing 'sim' would
    fabricate time; guessing 'real' would break a demo quietly."""
    with pytest.raises(ValueError, match="SIM_CLOCK_MODE"):
        SimClock.from_env({"SIM_CLOCK_MODE": "simulated"})


# ---------------------------------------------------------------------------
# The rule, enforced across the repository rather than asserted in prose
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[1]

SKIPPED_DIRS = frozenset({".venv", ".git", "__pycache__", ".pytest_cache", ".terraform"})

#: Every module allowed to read a wall clock directly, and why. The allowlist
#: is the test: anything absent from it fails, so a new clock read has to be
#: argued for in writing rather than merely committed. Recording the reason is
#: what stops the list growing by reflex each time the test goes red.
CLOCK_READERS = {
    "tools/clock.py":
        "the single source. Holds the one `time.time` reference in the "
        "system; everything that stamps a record delegates to now().",
    "tests/test_clock.py":
        "bounds-checks the clock against the wall clock, so it has to read "
        "the wall clock independently to have anything to compare against.",
    "scripts/verify_events.py":
        "poll deadlines while waiting for the dead-letter queue to drain. "
        "Measures elapsed time and writes no record.",
    "scripts/session-init.py":
        "prints the age of an existing session inside a refusal message. It "
        "writes no record; refusing is the whole point of the script.",
    "ui/app.py":
        "renders how long the long-running session has been alive, which is "
        "a wall-clock quantity no record carries. The console is read-only.",
}

#: Wall-clock reads, matched on the last two components of the dotted name so
#: that `from datetime import datetime` and `import datetime` are both caught.
#: The receiver is part of the match on purpose: `clock.now()` is the correct
#: call everywhere in this system, and matching the bare attribute `.now`
#: would reject every correct call site and accept nothing.
WALL_CLOCK_READS = frozenset({
    "time.time", "time.time_ns",
    "datetime.now", "datetime.utcnow",
    "date.today",
})

#: `from time import time` makes the read a bare name, out of reach of the
#: dotted match above, so the import itself is what gets caught.
WALL_CLOCK_IMPORTS = frozenset({("time", "time"), ("time", "time_ns")})


def _dotted_name(node: ast.AST) -> str | None:
    """Reconstruct an attribute chain such as `datetime.datetime.now`."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _clock_reads(path: Path) -> list[tuple[int, str]]:
    """Every direct clock read in one file, located by line.

    Parsed rather than grepped, because a substring search cannot tell a call
    from prose that mentions one. `tools/ingest.py` documents that it does not
    read a clock, naming the function it avoids; a grep reports that sentence
    as the violation it exists to deny.
    """
    hits: set[tuple[int, str]] = set()
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            # An Attribute node is reached for a call and for a bare reference
            # alike: `time.time()` and `source=time.time` surface the same
            # node. The second is how a clock read would otherwise be smuggled
            # past a check that only looked at calls.
            if node.attr == "SERVER_TIMESTAMP":
                hits.add((node.lineno, "SERVER_TIMESTAMP"))
                continue
            name = _dotted_name(node)
            if name and ".".join(name.split(".")[-2:]) in WALL_CLOCK_READS:
                hits.add((node.lineno, name))
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if (node.module, alias.name) in WALL_CLOCK_IMPORTS:
                    hits.add((node.lineno, f"from {node.module} import {alias.name}"))

    return sorted(hits)


def _source_files() -> list[Path]:
    """Every Python file in the repository, vendored code excluded."""
    return [
        path
        for path in sorted(REPO_ROOT.rglob("*.py"))
        if not SKIPPED_DIRS.intersection(path.parts)
    ]


def test_the_scan_covers_the_whole_repository():
    """A scan that silently matched nothing would pass every check below it."""
    scanned = _source_files()
    assert len(scanned) > 30, f"only {len(scanned)} files scanned; the walk is broken"
    assert REPO_ROOT / "tools" / "clock.py" in scanned


def test_no_module_outside_the_allowlist_reads_its_own_clock():
    """Constraint 6, across the repository rather than in one module.

    This rule used to be checked in exactly one file, which meant it held
    there and was unverified in the other forty.
    """
    offenders = {}
    for path in _source_files():
        relative = path.relative_to(REPO_ROOT).as_posix()
        if relative in CLOCK_READERS:
            continue
        if reads := _clock_reads(path):
            offenders[relative] = reads

    assert not offenders, (
        "These modules read a clock directly. Every stamp on a persisted "
        "record must come from SimClock.now(). If one of these genuinely "
        "writes no record, add it to CLOCK_READERS with the reason why:\n"
        + "\n".join(
            f"  {name}: " + ", ".join(f"line {line} {what}" for line, what in reads)
            for name, reads in sorted(offenders.items())
        )
    )


def test_the_allowlist_has_no_stale_entries():
    """An allowlist that outlives the reads it excuses stops describing the
    system and starts concealing it. An entry naming a file that no longer
    exists, or one that no longer reads a clock, is a failure in the same way
    an unexcused read is."""
    stale = []
    for relative in CLOCK_READERS:
        path = REPO_ROOT / relative
        if not path.exists():
            stale.append(f"{relative}: no such file")
        elif not _clock_reads(path):
            stale.append(f"{relative}: no longer reads a clock, so the entry is dead")

    assert not stale, "Stale CLOCK_READERS entries:\n" + "\n".join(
        f"  {entry}" for entry in stale
    )


def test_nothing_that_writes_a_record_is_on_the_allowlist():
    """The allowlist exists for scripts, tests and the read-only console.

    An agent, a worker or a tool is where records are stamped, so one
    appearing here would mean the rule had been relaxed in precisely the place
    it is meant to hold. tools/clock.py is the sole exception, because it is
    the source everything else delegates to.
    """
    writers = [
        name
        for name in CLOCK_READERS
        if name.startswith(("agents/", "worker/"))
        or (name.startswith("tools/") and name != "tools/clock.py")
    ]
    assert not writers, (
        "A record-writing module has been excused from the clock rule: "
        + ", ".join(writers)
    )
