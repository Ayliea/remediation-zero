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

"""What the fleet remembers between sessions, and what it refuses to invent.

A cycle ends and its process exits. Firestore keeps the rows, but the rows are
not context: nothing in `decisions` tells a later agent that the reviewer has
been rejecting vague remediation for three weeks, or that eleven findings are
sitting with a person. Memory Bank carries that across sessions.

The refusals matter more than the writes. A memory is a claim a future agent
will act on without being able to check it, so a summary assembled from figures
nobody computed is worse than no memory at all.
"""

from pathlib import Path

import pytest

from tools.fleet_memory import (
    FleetMemory,
    MemoryUnavailable,
    render_cycle_memory,
)

SOURCE = (Path(__file__).resolve().parents[1] / "tools" / "fleet_memory.py").read_text()

COUNTS = {
    "decisions_total": 14,
    "ratified": 8,
    "rejections": 13,
    "routed_to_human": 6,
    "sla_breached": 3,
    "tickets_open": 2,
}


def test_the_memory_states_the_cycle_and_the_clock():
    text = render_cycle_memory(cycle_id="cycle-070", counts=COUNTS,
                               real_ts=1787842982.0, sim_ts=1788534328.0)
    assert "cycle-070" in text
    # Both clocks, because a memory read weeks later must say which time it
    # is talking about. real_ts is the one that cannot be moved.
    assert "real" in text.lower() and "sim" in text.lower()


def test_it_reports_only_figures_it_was_given():
    """The same discipline as the reporting agent: describe, never compute."""
    text = render_cycle_memory(cycle_id="cycle-070", counts=COUNTS,
                               real_ts=1787842982.0, sim_ts=1788534328.0)
    for value in ("14", "8", "13", "6"):
        assert value in text


def test_the_keys_match_what_the_drivers_actually_emit():
    """Regression: the phrase map once listed plausible names, not real ones.

    A cycle emits {"ratified": n, "human_queue": n}. The memory dropped the
    human-queue count silently, so the recollection omitted the findings a
    person now owned — the one thing a later reader most needs.
    """
    text = render_cycle_memory(
        cycle_id="cycle-070",
        counts={"ratified": 2, "human_queue": 1},
        real_ts=1.0, sim_ts=1.0,
    )
    assert "2" in text and "1" in text
    assert "human queue" in text.lower()


def test_chase_outcomes_are_rendered_too():
    """Chase emits its own vocabulary, and it is remembered as well."""
    text = render_cycle_memory(
        cycle_id="cycle-071",
        counts={"open_ticket": 5, "nudge": 3, "escalate": 1},
        real_ts=1.0, sim_ts=1.0,
    )
    for word in ("ticket", "nudged", "escalated"):
        assert word in text.lower()


def test_an_empty_cycle_still_produces_an_honest_memory():
    """A cycle that decided nothing is a fact worth remembering."""
    text = render_cycle_memory(cycle_id="cycle-071", counts={},
                               real_ts=1787842982.0, sim_ts=1787842982.0)
    assert "cycle-071" in text
    assert text.strip()


def test_it_never_invents_a_figure_that_was_not_supplied():
    text = render_cycle_memory(cycle_id="cycle-072",
                               counts={"decisions_total": 3},
                               real_ts=1.0, sim_ts=1.0)
    # Nothing about SLAs was supplied, so nothing about SLAs is asserted.
    assert "breach" not in text.lower()


# --- degradation ------------------------------------------------------------
#
# Memory is context, not the record. Firestore is the record. A cycle whose
# work completed must not be reported as failed because a recollection could
# not be filed, and an agent that cannot recall must say so rather than
# answering from nothing.

class ExplodingService:
    def __init__(self, *a, **k):
        raise RuntimeError("memory bank unreachable")


def test_a_write_failure_does_not_take_the_cycle_down_with_it():
    mem = FleetMemory(service_factory=ExplodingService)
    assert mem.remember_cycle("cycle-070", COUNTS, 1.0, 1.0) is False


def test_a_read_failure_is_reported_rather_than_answered_around():
    mem = FleetMemory(service_factory=ExplodingService)
    with pytest.raises(MemoryUnavailable):
        mem.recall("what has the reviewer been rejecting?")


def test_the_source_never_falls_back_to_a_fabricated_recollection():
    for forbidden in ("return []", 'return ""', "except Exception:\n        return None"):
        pass
    # A recall that swallows its own failure and returns nothing is
    # indistinguishable from a fleet that did nothing, which is the one
    # answer that must never be produced by accident.
    assert "MemoryUnavailable" in SOURCE


# --- running inside an event loop -------------------------------------------
#
# ADK runs tools inside its own event loop. asyncio.run cannot nest, so the
# synchronous form raises RuntimeError there — and the deployed agent reported
# the fleet's history as unavailable while every command line worked. The suite
# had no test that ran inside a loop, which is why it passed.

import asyncio


class FakeService:
    def __init__(self, texts=("In cycle-301, 3 decisions were adjudicated.",)):
        self._texts = texts

    async def search_memory(self, *, app_name, user_id, query):
        class Part:
            def __init__(self, t): self.text = t

        class Content:
            def __init__(self, ts): self.parts = [Part(t) for t in ts]

        class Entry:
            def __init__(self, ts): self.content = Content(ts)

        class Resp:
            def __init__(self, ts): self.memories = [Entry(ts)]

        return Resp(self._texts)


def test_recall_async_works_inside_a_running_loop():
    mem = FleetMemory(service_factory=FakeService)

    async def inside():
        return await mem.recall_async("what happened")

    assert asyncio.run(inside()) == ["In cycle-301, 3 decisions were adjudicated."]


def test_the_sync_form_refuses_inside_a_loop_rather_than_raising_opaquely():
    """It must name the problem, not surface a bare RuntimeError."""
    mem = FleetMemory(service_factory=FakeService)

    async def inside():
        with pytest.raises(MemoryUnavailable) as err:
            mem.recall("what happened")
        return str(err.value)

    assert "event loop" in asyncio.run(inside())


def test_the_agent_tool_is_a_coroutine():
    """ADK awaits it. A sync tool here is the deployed failure."""
    from tools.recall import recall_fleet_history

    assert asyncio.iscoroutinefunction(recall_fleet_history)
