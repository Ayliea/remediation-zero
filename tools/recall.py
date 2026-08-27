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

"""The deployed agent's recollection of cycles it did not run.

This is the second read-only tool the orchestrator holds, and it is the one
that makes the deployment more than a reasoning surface. Cycles run on a daily
schedule in a Cloud Run worker, in a process that exits. Ask the deployed agent
what the fleet has been doing and it answers from Memory Bank — context formed
by other processes, in other sessions, over weeks.

Read-only, like every tool this agent has. Recalling is not writing.
"""

from tools.fleet_memory import FleetMemory, MemoryUnavailable


async def recall_fleet_history(query: str) -> str:
    """Recall what the fleet has done in past cycles.

    Args:
        query: what to recall, for example "what has the reviewer been
            rejecting" or "how many findings went to a human".

    Returns:
        The matching recollections, oldest first, or a plain statement that
        there are none. The two are different answers and are worded
        differently on purpose: a fleet with no history and a memory that
        could not be read must never look the same to the reader.
    """
    try:
        # Async, because ADK runs tools inside its own event loop and
        # asyncio.run cannot nest. The synchronous form raised RuntimeError in
        # the deployed engine while working from every command line, and the
        # agent reported the fleet's history as unavailable.
        memories = await FleetMemory().recall_async(query)
    except MemoryUnavailable as exc:
        # Surfaced, not swallowed. An agent that answers "nothing found" when
        # the truth is "could not look" has told the reader something false
        # about the fleet.
        return (
            f"Recollection is unavailable, which is not the same as the fleet "
            f"having no history. {exc}"
        )

    if not memories:
        return (
            "No recollection matches that. The fleet's memory is written one "
            "entry per completed cycle, so a question about something no cycle "
            "recorded returns nothing."
        )

    return "\n".join(f"- {m}" for m in memories)
