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

import time

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
