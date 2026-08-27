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

"""The delegation graph.

The graph is the architecture's claim about itself, so it is tested without a
cloud project: what these assert is the shape of the fleet, not whether any
agent works.
"""

import pytest

from agents.orchestrator.graph import (
    HUMAN_QUEUE,
    RATIFIED,
    UNAVAILABLE,
    CycleState,
    build_graph,
    describe,
)

NODE_NAMES = ("screen", "triage", "review", "record", "assign", "queue", "unavailable")


@pytest.fixture
def graph():
    # Signatures must name state fields: parameter_binding="state" resolves a
    # node's parameters against the state schema by name.
    def handler(finding_id: str, cycle: int) -> str:
        return "done"

    return build_graph({name: handler for name in NODE_NAMES})


def test_the_graph_builds(graph):
    """Construction validates every edge's node contracts, so a graph that
    builds is one whose nodes agree about what they pass each other."""
    assert graph.name == "remediation_cycle"
    assert graph.edges


def test_adjudication_is_the_only_branch(graph):
    """One decision point in the whole fleet. More than one branch means the
    routing logic has started living in two places."""
    branches = [e for e in graph.edges if isinstance(e[1], dict)]

    assert len(branches) == 1
    assert set(branches[0][1]) == {RATIFIED, HUMAN_QUEUE, UNAVAILABLE}


def test_an_unavailable_reviewer_has_its_own_destination(graph):
    """Capacity pressure must not share a path with rejection. Routing them
    together would put a decision no model made into the record."""
    branch = next(e for e in graph.edges if isinstance(e[1], dict))[1]

    assert branch[UNAVAILABLE].name != branch[HUMAN_QUEUE].name


def test_side_effecting_nodes_do_not_rerun_on_resume(graph):
    """The graph-level half of the resume guarantee. The idempotency keys make
    a repeated call harmless; this makes the repeated call not happen."""
    by_name = {}
    for edge in graph.edges:
        for candidate in (edge[0], edge[1]):
            targets = candidate.values() if isinstance(candidate, dict) else [candidate]
            for node in targets:
                if hasattr(node, "name"):
                    by_name[node.name] = node

    for name in ("record", "assign", "queue", "unavailable"):
        assert by_name[name].rerun_on_resume is False, name


def test_model_calling_nodes_carry_bounded_retry(graph):
    """Both models are capacity-constrained, and a retry that is not bounded
    is a cycle that can stall forever."""
    by_name = {}
    for edge in graph.edges:
        for candidate in (edge[0], edge[1]):
            targets = candidate.values() if isinstance(candidate, dict) else [candidate]
            for node in targets:
                if hasattr(node, "name"):
                    by_name[node.name] = node

    for name in ("triage", "review"):
        config = by_name[name].retry_config
        assert config is not None, name
        assert config.max_attempts == 4


def test_a_decision_is_recorded_before_anyone_is_assigned(graph):
    """An assignment without the decision that justifies it would start an SLA
    clock against a decision nobody made."""
    plain = [(e[0].name, e[1].name) for e in graph.edges
             if not isinstance(e[1], dict) and hasattr(e[0], "name")]

    assert ("record", "assign") in plain
    assert ("assign", "record") not in plain


def test_the_graph_renders_as_readable_text(graph):
    """The routing is data, so it can be printed. What it prints is what runs."""
    rendered = describe(graph)

    assert "remediation_cycle" in rendered
    assert f"--[{RATIFIED}]--> record" in rendered


def test_state_is_identifiers_not_payloads():
    """Each agent reads its own inputs. Passing findings through state would
    make the orchestrator responsible for what every agent needs."""
    assert set(CycleState.model_fields) == {"finding_id", "cycle", "outcome"}
