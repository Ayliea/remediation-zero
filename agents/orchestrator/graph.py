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

"""The fleet as an ADK Workflow graph.

Until now the cycle was a procedural loop that called each agent in turn. That
runs, but it is not a fleet: the delegation, the routing and the failure
handling all lived in one function, and none of it was inspectable from
outside. This module expresses the same lifecycle as a graph, which makes three
things true that were not before.

The routing is data. A finding goes to ownership because an edge says
`ratified` leads there, not because an `if` statement in a loop said so. The
graph can be printed, and what it says is what runs.

The contracts are checked before anything runs. ADK validates node schemas at
construction: an edge between two nodes whose types disagree fails to build,
rather than failing on the finding that happens to exercise it.

Resume is a property of the graph. Side-effecting nodes carry
`rerun_on_resume=False`, so a resumed workflow does not re-enter a node that
already completed. That sits on top of the idempotency keys rather than
replacing them: the keys make a repeated call harmless, and this makes the
repeated call not happen.

Nodes route but do not mutate shared state. Each one reads what it needs from
Firestore and writes only its own collection, which is the separation of
concerns the architecture claims, enforced by the shape of the graph rather
than by convention.
"""

import os
from typing import Any, Optional

from pydantic import BaseModel, Field

from google.adk.workflow import START, FunctionNode, RetryConfig, Workflow

#: Bounded, with backoff and jitter. Applied to the nodes that call a model,
#: because both models are capacity-constrained and a 429 is not a verdict.
MODEL_RETRY = RetryConfig(max_attempts=4, initial_delay=2.0, backoff_factor=2.0, jitter=True)


class CycleState(BaseModel):
    """What flows between nodes.

    Deliberately small. Identifiers and a route, not payloads: an agent that
    needs a finding reads the finding, which is what keeps each agent's inputs
    its own responsibility.
    """

    finding_id: str = Field(default="", description="the finding under adjudication")
    cycle: int = Field(default=0, description="the cycle number, part of every idempotency key")
    outcome: str = Field(default="", description="the last route emitted")


# --- routes -----------------------------------------------------------------
# String constants rather than literals at the call site, so a typo in an edge
# is a NameError at import rather than a silently unreachable branch.
RATIFIED = "ratified"
HUMAN_QUEUE = "human_queue"
UNAVAILABLE = "unavailable"
SCREENED = "screened"
PROPOSED = "proposed"
ASSIGNED = "assigned"
DONE = "done"


def build_graph(handlers: dict[str, Any]) -> Workflow:
    """Assemble the delegation graph.

    Args:
        handlers: the callable for each node, injected rather than imported.
            The graph describes the fleet; it does not decide how any single
            agent does its work, and keeping the two separate is what lets the
            graph be built and inspected without a cloud project.

    Returns:
        The workflow. Construction validates every edge, so a graph that
        builds is a graph whose node contracts agree.
    """
    def node(name: str, *, rerun_on_resume: bool, retry: Optional[RetryConfig] = None):
        return FunctionNode(
            func=handlers[name],
            name=name,
            parameter_binding="state",
            state_schema=CycleState,
            rerun_on_resume=rerun_on_resume,
            retry_config=retry,
        )

    # Screening is pure with respect to system state: it reads untrusted text
    # and decides whether a model may see it, so re-running it on resume is
    # safe and is the cheaper option than persisting its verdict.
    screen = node("screen", rerun_on_resume=True)

    # Triage writes nothing, so it may re-run. Review does not write either,
    # but both call models, so both carry the retry config.
    triage = node("triage", rerun_on_resume=True, retry=MODEL_RETRY)
    review = node("review", rerun_on_resume=True, retry=MODEL_RETRY)

    # Everything below here changes the world outside this process. None of it
    # re-runs on resume.
    record = node("record", rerun_on_resume=False)
    assign = node("assign", rerun_on_resume=False)
    queue = node("queue", rerun_on_resume=False)
    unavailable = node("unavailable", rerun_on_resume=False)

    return Workflow(
        name="remediation_cycle",
        description=(
            "One finding, from untrusted-text screening through adversarial "
            "review to either an accountable owner or a person."
        ),
        state_schema=CycleState,
        edges=[
            (START, screen),
            (screen, triage),
            (triage, review),
            # The adjudication decides where the finding goes. This is the
            # only branch in the fleet, and it is stated once, here.
            (review, {
                RATIFIED: record,
                HUMAN_QUEUE: queue,
                UNAVAILABLE: unavailable,
            }),
            # A ratified decision is recorded before anyone is made
            # accountable for it, so an assignment can never exist without the
            # decision that justifies it.
            (record, assign),
        ],
    )


def describe(workflow: Workflow) -> str:
    """Render the graph as text, so what runs can be read."""
    lines = [f"workflow: {workflow.name}", ""]
    for edge in workflow.edges:
        source, target = edge[0], edge[1]
        source_name = getattr(source, "name", str(source))
        if isinstance(target, dict):
            for route, destination in target.items():
                lines.append(
                    f"  {source_name:12} --[{route}]--> {getattr(destination, 'name', destination)}"
                )
        else:
            lines.append(f"  {source_name:12} ---------> {getattr(target, 'name', target)}")
    return "\n".join(lines)
