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

"""The deployed orchestrator: reasons over a finding, and writes nothing.

Delegates to two sub-agents through AgentTool — triage on Gemini, review on
Gemma — over a finding read by its one tool. Given a finding id it produces the
same adjudication the fleet produces, and persists none of it.

That boundary is deliberate and it is the reason the writing agents are absent
here. An Agent Engine runs as a single service account, so every sub-agent
attached to this one executes under one identity. Attaching ownership, chase,
exception and reporting would require that identity to hold every collection's
write access, and the claim this project makes loudest — that the reporting
agent is structurally incapable of writing a ticket — would stop being true of
the deployment carrying the project's name.

So the writes live where a per-agent identity is enforceable: the ADK Workflow
graph in scripts/graph_cycle.py, and the two Cloud Run workers, each running as
its own service account. This agent is the reasoning surface, read-only for the
same reason the console is read-only.

`root_agent` is the name ADK's loader looks for when resolving
`agents/orchestrator`.
"""

import json
import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from google.adk import Agent
from google.adk.tools import FunctionTool
from google.adk.tools.agent_tool import AgentTool

from tools.clock import SimClock
from tools.finding_lookup import lookup_finding

# The sub-agents are imported under two different layouts. In the repository
# they are agents/triage and agents/reviewer. Agent Engine stages each
# --extra_packages entry at /app/<basename>, so there they are top-level
# `triage` and `reviewer` while the orchestrator itself sits at
# /app/agents/orchestrator. Neither form resolves in the other environment.
try:  # repository layout
    from agents.reviewer.agent import build as build_reviewer
    from agents.triage.agent import build as build_triage
except ImportError:  # deployed layout
    from reviewer.agent import build as build_reviewer
    from triage.agent import build as build_triage

# Load .env before the module-level agent is constructed. ADK's loader imports
# this module to find root_agent, so configuration has to be present by then.
load_dotenv()

logger = logging.getLogger("remediation_zero.orchestrator")

AGENT_NAME = "orchestrator"

#: Prompts are versioned files, never string literals, so that a change to
#: agent behaviour shows up in the diff as a change to behaviour.
PROMPT_PATH = Path(__file__).resolve().parents[2] / "prompts" / "orchestrator.md"


def load_instruction(path: Path = PROMPT_PATH) -> str:
    """Load the agent instruction from its versioned file.

    Raises:
        FileNotFoundError: rather than falling back to an inline default. A
            missing prompt must not silently become a differently-behaved
            agent.
    """
    if not path.is_file():
        raise FileNotFoundError(
            f"Agent instruction not found at {path}. Prompts are versioned "
            f"files and are not inlined, so there is no fallback."
        )
    return path.read_text(encoding="utf-8")


def heartbeat(clock: SimClock, cycle_id: str, finding_id: str = "-") -> dict:
    """Emit one structured heartbeat and return what was emitted.

    Every line carries the cycle ID and the finding ID so that a single
    finding's journey is greppable end to end. Both stamps are recorded: the
    gap between them is the whole point of having two.
    """
    stamp = clock.now()
    event = {
        "event": "heartbeat",
        "agent": AGENT_NAME,
        "cycle_id": cycle_id,
        "finding_id": finding_id,
        "real_ts": stamp.real_ts,
        "sim_ts": stamp.sim_ts,
        "clock_mode": clock.mode.value,
    }
    logger.info(json.dumps(event, sort_keys=True))
    return event


def _model() -> str:
    """The reasoning model, from the environment.

    Raises rather than defaulting: a silently wrong model is a silently
    different agent, and the deployment must be the one that was tested.
    """
    model = os.environ.get("REASONING_MODEL", "").strip()
    if not model:
        raise ValueError(
            "REASONING_MODEL is not set. Copy .env.example to .env and set it."
        )
    return model


#: The orchestrator's whole capability surface: one reader and two sub-agents.
#:
#: lookup_finding is the only tool that touches a database, and it can only
#: read. The two AgentTools carry no tools of their own, so neither the
#: proposal nor the verdict can reach storage. Nothing on this path can write,
#: which is what makes it safe to run all three under one service account.
def _tools() -> list:
    return [
        FunctionTool(lookup_finding),
        AgentTool(build_triage()),
        AgentTool(build_reviewer()),
    ]


root_agent = Agent(
    name=AGENT_NAME,
    model=_model(),
    description="Owns cycle control and delegation for the remediation fleet.",
    instruction=load_instruction(),
    tools=_tools(),
)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, stream=sys.stdout, format="%(message)s")
    heartbeat(SimClock.from_env(), cycle_id="local-smoke")
