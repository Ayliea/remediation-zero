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

"""The triage agent, as the deployed orchestrator delegates to it.

Holds a model and a versioned prompt and nothing else. It has no tools, so it
cannot read or write anything: it reasons over the text it is handed and
answers. The orchestrator supplies that text from the one reader it has.
"""

import os
from pathlib import Path

from google.adk import Agent

AGENT_NAME = "triage"

#: Prompts are versioned files, never string literals, so a change to
#: behaviour shows up in the diff as a change to behaviour.
PROMPT_NAME = "triage.md"


def _find_prompt(start: Path = None) -> Path:
    """Locate the prompt by walking up from this module.

    The depth differs between environments and a fixed `parents[n]` is wrong in
    one of them. In the repository this file is agents/triage/agent.py, two
    levels below the prompts directory. Agent Engine stages each
    --extra_packages entry at /app/<basename>, so the same file is /app/triage/
    agent.py — one level below. A hard-coded index resolves to the filesystem
    root there and the agent fails to construct at import, which surfaces as an
    opaque error from stream_query rather than as a missing file.
    """
    here = (start or Path(__file__)).resolve()
    for parent in here.parents:
        candidate = parent / "prompts" / PROMPT_NAME
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(
        f"Agent instruction {PROMPT_NAME} not found in any prompts/ directory "
        f"above {here}. Prompts are versioned files and are not inlined, so "
        f"there is no fallback."
    )


def load_instruction(path: Path = None) -> str:
    """Load the agent instruction from its versioned file.

    Raises:
        FileNotFoundError: rather than falling back to an inline default. A
            missing prompt must not silently become a differently-behaved agent.
    """
    return (path or _find_prompt()).read_text(encoding="utf-8")


def _model() -> str:
    """The model, from the environment.

    Raises rather than defaulting. The cross-family split is an architectural
    decision: triage reasons on Gemini and review adjudicates on Gemma, because
    a model auditing its own reasoning shares its own blind spots. An agent that
    quietly fell back to a default model could erase that split without anyone
    noticing it had happened.
    """
    model = os.environ.get("REASONING_MODEL", "").strip()
    if not model:
        raise ValueError(
            "REASONING_MODEL is not set. Copy .env.example to .env and set it."
        )
    return model


def build() -> Agent:
    """Construct the agent. A function, so import does not require the env."""
    return Agent(
        name=AGENT_NAME,
        model=_model(),
        description="Proposes a severity, an SLA and a remediation path, citing evidence.",
        instruction=load_instruction(),
    )
