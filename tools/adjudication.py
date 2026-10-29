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
    #: No reviewer is configured. A suggestion, not a decision; a person decides.
    UNREVIEWED = "unreviewed"
    #: Ratified by a reviewer of the same model family as the proposer, under
    #: the default policy. A person must approve before it may become state.
    HELD_FOR_APPROVAL = "held_for_approval"


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

    def __post_init__(self) -> None:
        if not self.finding_id.strip() or len(self.finding_id) > 128:
            raise ValueError("proposal finding_id must be non-empty and at most 128 characters")
        if self.severity not in {"critical", "high", "medium", "low"}:
            raise ValueError(f"unsupported proposal severity: {self.severity!r}")
        if isinstance(self.sla_days, bool) or not isinstance(self.sla_days, int):
            raise ValueError("proposal sla_days must be an integer")
        if not 1 <= self.sla_days <= 365:
            raise ValueError("proposal sla_days must be between 1 and 365")
        if not self.remediation.strip() or len(self.remediation) > 2_000:
            raise ValueError("proposal remediation must be non-empty and at most 2000 characters")
        if not self.evidence or len(self.evidence) > 20:
            raise ValueError("proposal evidence must contain between 1 and 20 entries")
        if any(not isinstance(item, str) or not item.strip() or len(item) > 500
               for item in self.evidence):
            raise ValueError("every proposal evidence entry must be non-empty and at most 500 characters")
        if not self.rationale.strip() or len(self.rationale) > 2_000:
            raise ValueError("proposal rationale must be non-empty and at most 2000 characters")


@dataclass(frozen=True)
class Verdict:
    """The reviewer's adjudication. A rejection must say why."""

    ratified: bool
    reason: str

    def __post_init__(self) -> None:
        if not isinstance(self.ratified, bool):
            raise ValueError("verdict ratified must be a bool")
        if not isinstance(self.reason, str) or not self.reason.strip():
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
    #: How independent the review was: cross_family, same_family or unreviewed.
    review_independence: str = "cross_family"
    #: Per role: format, model and family. Never endpoints or keys.
    models: Mapping[str, Any] = field(default_factory=dict)
    #: What was to happen to a same-family ratification: wait or proceed.
    same_family_policy: str = "wait"
    #: The business-context floor (tools.context_floor), when it was considered; None otherwise.
    floor: Optional[Mapping[str, Any]] = None


#: One retry after a rejection, then a person. Not configurable by accident.
MAX_REVIEW_ATTEMPTS = 2


class RetryStateError(RuntimeError):
    """Persistence is unavailable or busy; do not invent a terminal verdict."""


class AdjudicationFailure(ValueError):
    """Model/validation failure carrying all evidence obtained so far."""

    def __init__(self, adjudication: Adjudication):
        self.adjudication = adjudication
        super().__init__(adjudication.note)


def adjudicate(
    finding: Mapping[str, Any],
    triage: Callable[[Mapping[str, Any]], Proposal],
    review: Optional[Callable[[Mapping[str, Any], Proposal], Verdict]],
    max_capacity_retries: int = 3,
    *,
    independence: str,
    same_family_policy: str = "wait",
) -> Adjudication:
    """Run one finding through triage and review.

    Args:
        finding: the finding, as an agent sees it.
        triage: proposes a decision.
        review: ratifies or rejects. May raise `CapacityError`. `None` means
            no reviewer is configured: the result is `UNREVIEWED`.
        max_capacity_retries: how many times a 429 is retried before the
            reviewer is declared unavailable. Capacity retries are counted
            separately from review attempts, because a queue-full response is
            not the reviewer disagreeing.
        independence: how independent the review is (cross_family,
            same_family, unreviewed). Required, with no default: the record
            must never claim an independence the caller did not establish
            (hard constraint 3). A same-family ratification is held for a person
            unless `same_family_policy` is "proceed".
        same_family_policy: "wait" (default) or "proceed".

    Returns:
        The adjudication record, including every reason given.
    """
    if (isinstance(max_capacity_retries, bool)
            or not isinstance(max_capacity_retries, int)
            or not 1 <= max_capacity_retries <= 3):
        raise ValueError("max_capacity_retries must be an integer between 1 and 3")
    verdicts: list[Verdict] = []
    proposal: Optional[Proposal] = None
    provenance = {"review_independence": independence,
                  "same_family_policy": same_family_policy}

    for attempt in range(1, MAX_REVIEW_ATTEMPTS + 1):
        try:
            candidate = triage(finding)
            if not isinstance(candidate, Proposal):
                raise ValueError("triage must return Proposal")
            if candidate.finding_id != str(finding.get("finding_id", "")).strip():
                raise ValueError("proposal finding_id does not match the finding being adjudicated")
            proposal = candidate
        except (RetryStateError, AdjudicationFailure):
            raise
        except Exception as exc:
            raise AdjudicationFailure(Adjudication(
                str(finding.get("finding_id", "")), AdjudicationOutcome.HUMAN_QUEUE,
                proposal, tuple(verdicts), attempt,
                f"triage failed: {type(exc).__name__}: {exc}", **provenance)) from exc

        if review is None:
            return Adjudication(
                finding_id=str(finding.get("finding_id", "")),
                outcome=AdjudicationOutcome.UNREVIEWED,
                proposal=proposal,
                verdicts=(),
                attempts=attempt,
                note="needs a person's review: no reviewer configured",
                **provenance,
            )

        verdict = None
        for capacity_attempt in range(1, max_capacity_retries + 1):
            try:
                verdict = review(finding, proposal)
                if not isinstance(verdict, Verdict):
                    raise ValueError("review must return Verdict")
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
                        **provenance,
                    )
            except (RetryStateError, AdjudicationFailure):
                raise
            except Exception as exc:
                raise AdjudicationFailure(Adjudication(
                    str(finding.get("finding_id", "")), AdjudicationOutcome.HUMAN_QUEUE,
                    proposal, tuple(verdicts), attempt,
                    f"reviewer failed: {type(exc).__name__}: {exc}", **provenance)) from exc

        assert verdict is not None
        verdicts.append(verdict)

        if verdict.ratified:
            if independence == "same_family" and same_family_policy == "wait":
                return Adjudication(
                    finding_id=str(finding.get("finding_id", "")),
                    outcome=AdjudicationOutcome.HELD_FOR_APPROVAL,
                    proposal=proposal,
                    verdicts=tuple(verdicts),
                    attempts=attempt,
                    note="same-family review: needs a person's approval",
                    **provenance,
                )
            return Adjudication(
                finding_id=str(finding.get("finding_id", "")),
                outcome=AdjudicationOutcome.RATIFIED,
                proposal=proposal,
                verdicts=tuple(verdicts),
                attempts=attempt,
                **provenance,
            )

    return Adjudication(
        finding_id=str(finding.get("finding_id", "")),
        outcome=AdjudicationOutcome.HUMAN_QUEUE,
        proposal=proposal,
        verdicts=tuple(verdicts),
        attempts=MAX_REVIEW_ATTEMPTS,
        note="rejected twice; a person decides",
        **provenance,
    )
