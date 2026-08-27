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

"""SimClock: the single source of time for the entire system.

Nothing anywhere calls `datetime.now()`, `time.time()`, or a database server
timestamp directly. Every time read goes through here, and every persisted
record carries both stamps that `now()` returns.

The two stamps mean different things and only one of them is negotiable:

``real_ts``
    Wall clock. Never simulated, never offset, never backdated, in any mode,
    by any code path. The demo's central claim is that a session has genuinely
    been alive for days, and that claim is worth exactly nothing if this field
    can be moved. There is deliberately no API that writes it.

``sim_ts``
    Simulation time. In real mode it tracks wall clock. In sim mode it starts
    at wall clock and moves only when `advance()` is called, which is what
    lets a six-week remediation lifecycle be shown in three minutes without
    anyone claiming six weeks really passed.

Keeping both on every record is what makes the difference auditable after the
fact rather than a matter of trusting the narrator.
"""

import os
import time
from dataclasses import dataclass
from enum import Enum
from typing import Mapping, Optional

#: The environment variable documented in .env.example.
MODE_ENV_VAR = "SIM_CLOCK_MODE"


class ClockMode(Enum):
    """How `sim_ts` behaves. `real_ts` is wall clock in both."""

    REAL = "real"
    SIM = "sim"


@dataclass(frozen=True)
class Stamp:
    """A paired time reading. Both values are Unix epoch seconds.

    Frozen: a stamp that can be edited after the fact is not evidence.
    """

    real_ts: float
    sim_ts: float


class SimClock:
    """The system's only clock.

    Args:
        mode: `ClockMode.REAL` or `ClockMode.SIM`.
        source: Callable returning wall clock epoch seconds. Injectable for
            tests; production always uses `time.time`. Note that this injects
            the *wall clock source*, not `real_ts` semantics, and the tests
            that assert `real_ts` honesty deliberately do not use it.
    """

    def __init__(self, mode: ClockMode, source=time.time) -> None:
        self._mode = mode
        self._source = source
        self._sim_offset = 0.0

    @property
    def mode(self) -> ClockMode:
        return self._mode

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "SimClock":
        """Build from the environment.

        An unset variable defaults to real mode, which is the mode that cannot
        fabricate elapsed time. An unrecognised value is rejected rather than
        guessed: guessing `sim` would invent time, and guessing `real` would
        break a rehearsed demo quietly, so a typo has to be loud.
        """
        env = os.environ if env is None else env
        raw = env.get(MODE_ENV_VAR)
        if raw is None or raw == "":
            return cls(mode=ClockMode.REAL)

        try:
            return cls(mode=ClockMode(raw.strip().lower()))
        except ValueError:
            supported = ", ".join(repr(m.value) for m in ClockMode)
            raise ValueError(
                f"{MODE_ENV_VAR}={raw!r} is not a recognised mode. "
                f"Supported values are {supported}."
            ) from None

    def now(self) -> Stamp:
        """Read the current time as a pair of stamps.

        `real_ts` is read from wall clock on every call, unconditionally.
        """
        real_ts = self._source()
        sim_ts = real_ts + self._sim_offset
        return Stamp(real_ts=real_ts, sim_ts=sim_ts)

    def advance(self, seconds: float) -> Stamp:
        """Move `sim_ts` forward. Never moves `real_ts`.

        Raises:
            RuntimeError: if called in real mode. There is no supported way to
                move time in real mode, because the elapsed-time proof depends
                on there not being one.
            ValueError: if `seconds` is negative. Time running backwards would
                let a record predate the event it describes, which is not
                distinguishable from backdating.
        """
        if self._mode is not ClockMode.SIM:
            raise RuntimeError(
                "advance() is not available in real mode: real_ts is wall clock "
                "and elapsed time is never fabricated. Set SIM_CLOCK_MODE=sim "
                "for the accelerated demo."
            )
        if seconds < 0:
            raise ValueError(f"advance() requires a non-negative delta, got {seconds}")

        self._sim_offset += float(seconds)
        return self.now()
