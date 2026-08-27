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

"""Writing the weekly report.

The report has two halves and they come from different places. The metrics are
counted by `tools.metrics` and stored verbatim. The prose is written by a model
that is handed those metrics and forbidden from producing its own.

Storing both means the narrative can always be checked against the figures it
claims to describe, by anyone, after the fact.
"""

import json
import os
from typing import Any, Optional

from google import genai
from google.genai import types
from google.cloud import firestore

from tools.clock import SimClock
from tools.idempotency import IdempotencyGuard
from tools.review_models import _load

COLLECTION = "reports"


def _presentable(metrics: dict[str, Any]) -> dict[str, Any]:
    """Round rates before the model sees them.

    Handing a model 0.6190476190476191 invites it to print
    0.6190476190476191. Presentation precision is a decision the code should
    make, not something to ask the model to remember not to do.
    """
    shown = dict(metrics)
    for key in ("ratification_rate", "disagreement_rate"):
        if key in shown:
            shown[key] = f"{shown[key] * 100:.0f}%"
    # Reasons matter more than their count, but twenty of them drowns the
    # prose. Distinct reasons, most recent first, capped.
    reasons = []
    for reason in reversed(shown.get("rejection_reasons", [])):
        trimmed = reason.strip()[:180]
        if trimmed and trimmed not in reasons:
            reasons.append(trimmed)
    shown["rejection_reasons"] = reasons[:6]
    return shown


def write_summary(metrics: dict[str, Any], model: str, client: genai.Client) -> str:
    """Ask the model to narrate metrics it did not compute."""
    payload = json.dumps(_presentable(metrics), indent=2, sort_keys=True, default=str)
    response = client.models.generate_content(
        model=model,
        contents=(
            "Here is the metrics block for this reporting period. Every figure "
            "you state must come from it.\n\n" + payload
        ),
        config=types.GenerateContentConfig(
            system_instruction=_load("reporting.md"),
            temperature=0.3,
        ),
    )
    return (response.text or "").strip()


class ReportWriter:
    """Records one report per period. Repeating the call has no second effect."""

    def __init__(
        self,
        store,
        client: Optional[firestore.Client] = None,
        clock: Optional[SimClock] = None,
    ) -> None:
        self._client = client or firestore.Client()
        self._clock = clock or SimClock.from_env()
        self._guard = IdempotencyGuard(store)

    def record(self, metrics: dict[str, Any], summary: str, cycle: int) -> str:
        @self._guard.protects(action="report")
        def _write(*, finding_id: str, cycle: int) -> str:
            stamp = self._clock.now()
            document_id = f"report-c{cycle:03d}"
            self._client.collection(COLLECTION).document(document_id).set(
                {
                    "report_id": document_id,
                    "cycle": cycle,
                    # Stored verbatim, next to the prose, so the narrative can
                    # always be checked against the figures it describes.
                    "metrics": metrics,
                    "summary": summary,
                    "real_ts": stamp.real_ts,
                    "sim_ts": stamp.sim_ts,
                }
            )
            return document_id

        # Reports are not per-finding, so the key uses a fixed sentinel in the
        # finding slot. The cycle number is what makes each report distinct.
        return _write(finding_id="__period__", cycle=cycle)
