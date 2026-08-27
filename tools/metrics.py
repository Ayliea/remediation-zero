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

"""Count what happened. Do not describe it.

Every number that reaches a report is produced here, by arithmetic over
records. The reporting agent's model is handed these numbers and is explicitly
forbidden from producing its own, because a language model asked for a rate
will return a plausible one, and a metrics report with a confident wrong
denominator is worse than no report at all.

The split is deliberate and it is the reason this module has no model client
and no prompt: the boundary between counting and describing is enforced by
there being nothing here that could describe.
"""

from collections import Counter
from typing import Any, Mapping, Sequence


def _rate(numerator: int, denominator: int) -> float:
    """A rate over an empty period is zero, not an error.

    A quiet week must still produce a report.
    """
    if denominator <= 0:
        return 0.0
    return numerator / denominator


def compute_metrics(
    decisions: Sequence[Mapping[str, Any]],
    tickets: Sequence[Mapping[str, Any]],
    sla_clocks: Sequence[Mapping[str, Any]],
    human_queue: Sequence[Mapping[str, Any]],
    exceptions: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Everything a report is allowed to state."""
    ratified = sum(1 for d in decisions if d.get("outcome") == "ratified")
    to_human = sum(1 for d in decisions if d.get("outcome") == "human_queue")
    unavailable = sum(1 for d in decisions if d.get("outcome") == "unavailable")

    verdicts = [v for d in decisions for v in d.get("verdicts", [])]
    rejections = [v for v in verdicts if not v.get("ratified")]

    severities = Counter(
        d.get("proposed_severity") for d in decisions if d.get("proposed_severity")
    )
    queue_kinds = Counter(item.get("kind", "adjudication") for item in human_queue)

    return {
        # Adjudication
        "decisions_total": len(decisions),
        "ratified": ratified,
        "routed_to_human": to_human,
        "reviewer_unavailable": unavailable,
        "ratification_rate": _rate(ratified, len(decisions)),
        "required_retry": sum(1 for d in decisions if int(d.get("attempts", 1)) > 1),
        # The control, measured. A disagreement rate of zero would mean the
        # reviewer was ratifying everything, which is indistinguishable from
        # having no reviewer.
        "verdicts_total": len(verdicts),
        "rejections": len(rejections),
        "disagreement_rate": _rate(len(rejections), len(verdicts)),
        "rejection_reasons": [v.get("reason", "") for v in rejections],
        # Chase
        "tickets_open": sum(1 for t in tickets if t.get("status") == "open"),
        "tickets_total": len(tickets),
        "nudges_sent": sum(int(t.get("nudges_sent", 0)) for t in tickets),
        "escalations": sum(1 for t in tickets if t.get("escalated")),
        # Deadlines
        "sla_tracked": len(sla_clocks),
        "sla_breached": sum(1 for s in sla_clocks if s.get("status") == "breached"),
        # Where the humans are
        "human_queue_total": len(human_queue),
        "human_queue_by_kind": dict(queue_kinds),
        # Deferred risk
        "exceptions_active": sum(1 for e in exceptions if e.get("status") == "active"),
        "exceptions_expired": sum(1 for e in exceptions if e.get("status") == "expired"),
        "severity_mix": dict(severities),
    }
