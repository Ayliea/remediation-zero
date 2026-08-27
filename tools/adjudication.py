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

"""The triage/review adjudication loop.

Triage proposes. The reviewer, running on a different model family, ratifies or
rejects with a stated reason. Nothing becomes state without passing that gate.

The rules the loop enforces:

    one retry, then the human queue      a disagreement is resolved once or it
                                         goes to a person. It never loops.
    every reason is kept                 disagreements are the evidence that
                                         the control is real, so the first
                                         objection survives the retry.
    capacity is not a verdict            Gemma MaaS returns 429 under load.
                                         Recording that as a rejection would
                                         put a decision no model made into the
                                         adjudication record.

The models are injected rather than imported so that the loop's behaviour can
be tested without model calls. That is a seam for testing the loop, not a
substitute for running the real thing.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Mapping, Optional


class AdjudicationOutcome(Enum):
    """How the adjudication ended."""

    #: The reviewer ratified the proposal. It may become state.
    RATIFIED = "ratified"
    #: Two rejections. A person decides; nothing becomes state.
    HUMAN_QUEUE = "human_queue"
    #: The reviewer could not be reached. Not a rejection, not a ratification.
    UNAVAILABLE = "unavailable"


class CapacityError(RuntimeError):
    """The reviewer was unreachable because of load, not because it disagreed.

    Raised for 429 and equivalent. Kept distinct from every other failure so
    that it can never be collapsed into a verdict.
    """


@dataclass(frozen=True)
class Proposal:
    """Triage's proposed decision, with the evidence it rests on."""

    finding_id: str
    severity: str
    sla_days: int
    remediation: str
    evidence: tuple[str, ...]
    rationale: str


@dataclass(frozen=True)
class Verdict:
    """The reviewer's adjudication. A rejection must say why."""

    ratified: bool
    reason: str

    def __post_init__(self) -> None:
        if not self.reason.strip():
            raise ValueError(
                "A verdict must state a reason. An unexplained rejection is "
                "not reviewable and cannot be acted on."
            )


@dataclass(frozen=True)
class Adjudication:
    """The full record: what was proposed, what was said about it, how it ended."""

    finding_id: str
    outcome: AdjudicationOutcome
    proposal: Optional[Proposal]
    verdicts: tuple[Verdict, ...] = field(default_factory=tuple)
    attempts: int = 0
    note: str = ""


#: One retry after a rejection, then a person. Not configurable by accident.
MAX_REVIEW_ATTEMPTS = 2


def adjudicate(
    finding: Mapping[str, Any],
    triage: Callable[[Mapping[str, Any]], Proposal],
    review: Callable[[Mapping[str, Any], Proposal], Verdict],
    max_capacity_retries: int = 3,
) -> Adjudication:
    """Run one finding through triage and review.

    Args:
        finding: the finding, as an agent sees it.
        triage: proposes a decision.
        review: ratifies or rejects. May raise `CapacityError`.
        max_capacity_retries: how many times a 429 is retried before the
            reviewer is declared unavailable. Capacity retries are counted
            separately from review attempts, because a queue-full response is
            not the reviewer disagreeing.

    Returns:
        The adjudication record, including every reason given.
    """
    verdicts: list[Verdict] = []
    proposal: Optional[Proposal] = None

    for attempt in range(1, MAX_REVIEW_ATTEMPTS + 1):
        proposal = triage(finding)

        verdict = None
        for capacity_attempt in range(1, max_capacity_retries + 1):
            try:
                verdict = review(finding, proposal)
                break
            except CapacityError as exc:
                if capacity_attempt >= max_capacity_retries:
                    # Unavailable, explicitly not rejected. Nothing is recorded
                    # as a verdict, because no model gave one.
                    return Adjudication(
                        finding_id=str(finding.get("finding_id", "")),
                        outcome=AdjudicationOutcome.UNAVAILABLE,
                        proposal=proposal,
                        verdicts=tuple(verdicts),
                        attempts=attempt,
                        note=f"reviewer unavailable after {capacity_attempt} attempts: {exc}",
                    )

        assert verdict is not None
        verdicts.append(verdict)

        if verdict.ratified:
            return Adjudication(
                finding_id=str(finding.get("finding_id", "")),
                outcome=AdjudicationOutcome.RATIFIED,
                proposal=proposal,
                verdicts=tuple(verdicts),
                attempts=attempt,
            )

    return Adjudication(
        finding_id=str(finding.get("finding_id", "")),
        outcome=AdjudicationOutcome.HUMAN_QUEUE,
        proposal=proposal,
        verdicts=tuple(verdicts),
        attempts=MAX_REVIEW_ATTEMPTS,
        note="rejected twice; a person decides",
    )
