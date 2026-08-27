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

"""The orchestrator shell's two observable behaviours."""

import json
import logging

import pytest

from agents.orchestrator.agent import PROMPT_PATH, heartbeat, load_instruction
from tools.clock import ClockMode, SimClock


def test_instruction_is_loaded_from_the_versioned_prompt_file():
    """Prompts are files, not string literals, so a behaviour change shows up
    in the diff as a behaviour change."""
    assert PROMPT_PATH.name == "orchestrator.md"
    assert "You own cycle control and delegation" in load_instruction()


def test_a_missing_prompt_is_an_error_not_a_silent_fallback(tmp_path):
    """A missing prompt must not quietly become a differently-behaved agent."""
    with pytest.raises(FileNotFoundError, match="orchestrator"):
        load_instruction(tmp_path / "orchestrator.md")


def test_heartbeat_carries_both_stamps_and_the_cycle_id(caplog):
    """Every log line is greppable to one finding and one cycle, and records
    both clocks so the gap between them is auditable."""
    clock = SimClock(mode=ClockMode.SIM)

    with caplog.at_level(logging.INFO, logger="remediation_zero.orchestrator"):
        event = heartbeat(clock, cycle_id="cycle-7", finding_id="CVE-2024-1234")

    emitted = json.loads(caplog.records[-1].message)
    assert emitted == event
    assert emitted["cycle_id"] == "cycle-7"
    assert emitted["finding_id"] == "CVE-2024-1234"
    assert emitted["real_ts"] > 0
    assert emitted["sim_ts"] > 0


def test_heartbeat_reports_simulated_time_without_moving_real_time():
    """The demo claim, at the log line where a judge would check it."""
    clock = SimClock(mode=ClockMode.SIM)
    before = heartbeat(clock, cycle_id="cycle-0")
    clock.advance(seconds=6 * 7 * 24 * 3600)
    after = heartbeat(clock, cycle_id="cycle-1")

    assert after["sim_ts"] - before["sim_ts"] > 3_600_000
    assert after["real_ts"] - before["real_ts"] < 5


def test_startup_refuses_when_the_model_is_unconfigured(unconfigured_env):
    """conftest supplies REASONING_MODEL so the module imports at all. This
    asserts the production behaviour it papers over: an unconfigured agent
    refuses to start rather than silently running a different model."""
    import importlib

    from agents.orchestrator import agent as agent_module

    with pytest.raises(ValueError, match="REASONING_MODEL"):
        importlib.reload(agent_module)

    # Leave the module importable for any test that runs after this one.
    unconfigured_env.setenv("REASONING_MODEL", "gemini-3.5-flash")
    importlib.reload(agent_module)
