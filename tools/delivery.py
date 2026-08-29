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

"""Turning a chase action into something a person actually receives.

The chase agent decides; this decides nothing. It translates an action the
agent already took into an artefact in a tracker, which keeps the decision
logic testable without a network and keeps this module replaceable when the
tracker changes.

The ticket record carries the issue number once one exists, so the common path
is a single comment. Creating is the exception, and looking before creating is
the recovery path for a ticket whose number was lost.
"""

import json
import logging
from typing import Any, Optional

from tools.chase import MAX_NUDGES
from tools.github_tickets import GitHubTickets, issue_body, issue_title
from tools.telemetry import cycle_id

logger = logging.getLogger("remediation_zero.delivery")

#: Applied to every issue this fleet files, so a human can filter them out.
LABELS = ["remediation-zero"]


class GitHubDelivery:
    """Deliver chase actions as GitHub issues and comments.

    Args:
        tickets: the GitHub client.
        client: Firestore, for reading the finding and the stored issue number.
    """

    def __init__(self, tickets: GitHubTickets, client: Any) -> None:
        self._gh = tickets
        self._db = client

    def deliver(
        self, event: str, finding_id: str, owner: Any, cycle: int,
        now_sim_ts: float, state: Any,
    ) -> Optional[int]:
        """Deliver one action. Returns an issue number when one was created."""
        ticket = (self._db.collection("tickets").document(finding_id)
                  .get().to_dict() or {})
        number = ticket.get("github_issue")

        if event == "open_ticket":
            if number:
                return None  # already filed; nothing to do
            finding = (self._db.collection("findings").document(finding_id)
                       .get().to_dict() or {"finding_id": finding_id})
            decision = self._latest_decision(finding_id)
            created = self._gh.open_issue(
                finding_id,
                issue_title(finding),
                issue_body(
                    finding, owner or {},
                    due=_day(getattr(state, "due_sim_ts", None)),
                    sla_days=decision.get("sla_days") or _sla_days(state),
                    severity=decision.get("severity", "unrated"),
                    remediation=decision.get("remediation", ""),
                    rationale=decision.get("rationale", ""),
                    evidence=decision.get("evidence", ""),
                    reviewer=decision.get("reviewer", ""),
                    attempts=decision.get("attempts"),
                ),
                labels=LABELS,
                cycle=cycle,
            )
            logger.info(json.dumps({
                "event": "issue_filed", "finding_id": finding_id,
                "cycle_id": cycle_id(cycle), "issue": created}, sort_keys=True))
            return created

        if not number:
            # A nudge with nowhere to land. Not an error: the issue may have
            # failed to file earlier and the next open_ticket reconciles it.
            return None

        self._gh.comment(number, _comment(event, cycle, now_sim_ts, state, owner))

        # Comment first, then close. The reverse posts into an issue that is
        # already out of every triage view, so the reason a person most wants
        # is the one they are least likely to see.
        if event == "close_ticket":
            self._gh.close_issue(number)
            logger.info(json.dumps({
                "event": "issue_closed", "finding_id": finding_id,
                "cycle_id": cycle_id(cycle), "issue": number}, sort_keys=True))
        return None

    def _latest_decision(self, finding_id: str) -> dict:
        """The ratified decision behind this ticket.

        Field names read off a real document rather than assumed. An earlier
        version looked for `severity` and `proposal.remediation`, which exist
        nowhere: the issues it filed said UNRATED with no remediation, which is
        a ticket that wastes the reader's time rather than saving it.
        """
        from google.cloud.firestore_v1.base_query import FieldFilter

        docs = [d.to_dict() for d in
                self._db.collection("decisions")
                .where(filter=FieldFilter("finding_id", "==", finding_id))
                .limit(10).stream()]
        ratified = [d for d in docs if d.get("outcome") == "ratified"]
        chosen = (ratified or docs or [{}])[-1]

        verdicts = chosen.get("verdicts") or []
        if isinstance(verdicts, str):
            try:
                import ast as _ast
                verdicts = _ast.literal_eval(verdicts)
            except Exception:  # noqa: BLE001
                verdicts = []
        ratifying = [v for v in verdicts if isinstance(v, dict) and v.get("ratified")]

        return {
            "severity": chosen.get("proposed_severity") or "unrated",
            "remediation": chosen.get("proposed_remediation") or "",
            "sla_days": chosen.get("proposed_sla_days"),
            "rationale": chosen.get("rationale") or "",
            "evidence": chosen.get("cited_evidence") or "",
            "reviewer": (ratifying[-1].get("reason") if ratifying else ""),
            "attempts": chosen.get("attempts"),
        }


def _day(sim_ts: Optional[float]) -> str:
    from datetime import datetime, timezone

    if not sim_ts:
        return "unscheduled"
    return datetime.fromtimestamp(sim_ts, tz=timezone.utc).strftime("%Y-%m-%d")


def _sla_days(state: Any) -> Any:
    started = getattr(state, "started_sim_ts", None)
    due = getattr(state, "due_sim_ts", None)
    if not started or not due:
        return "unknown"
    return round((due - started) / 86400)


def _comment(event: str, cycle: int, now_sim_ts: float, state: Any, owner: Any) -> str:
    """What the owner reads when the fleet follows up.

    Each says what happened, why now, and what happens next, because a nudge
    that does not say what follows it is only noise.
    """
    who = (owner or {}).get("display_name", "the owner")
    overdue = getattr(state, "days_overdue", lambda _: 0)(now_sim_ts)
    sent = getattr(state, "nudges_sent", 0)

    if event == "nudge":
        # Days remaining, computed from the deadline rather than from
        # days_overdue, which is zero until the deadline passes and so said
        # "0 days remain" on every nudge sent while there was still time.
        due = getattr(state, "due_sim_ts", None)
        remaining = (due - now_sim_ts) / 86400 if due else None
        if remaining is None or remaining < 0:
            when = "the SLA has already passed"
        else:
            days = round(remaining)
            when = (f"{days} simulated day{'s' if days != 1 else ''} "
                    f"{'remain' if days != 1 else 'remains'} before the SLA expires")

        left = MAX_NUDGES - (sent + 1)
        follows = (
            f"{left} more nudge{'s' if left != 1 else ''} follow"
            f"{'' if left != 1 else 's'}, then it escalates automatically."
            if left > 0 else
            "That was the last nudge. The next cycle escalates."
        )
        return (
            f"**Nudge {sent + 1} of {MAX_NUDGES}** · cycle {cycle}\n\n"
            f"{who}, this is still open and {when}. {follows}"
        )
    if event == "escalate":
        return (
            f"**Escalated** · cycle {cycle}\n\n"
            f"The SLA passed {overdue:.0f} simulated days ago after "
            f"{sent} nudges. Escalation happens once — the fleet will not "
            f"re-escalate on every subsequent cycle."
        )
    if event == "human_queue":
        return (
            f"**Handed to a person** · cycle {cycle}\n\n"
            f"Escalated and still unresolved {overdue:.0f} simulated days past "
            f"the SLA. The fleet has no further action that does not involve a "
            f"human, so it has stopped rather than continuing to nudge. This is "
            f"a successful outcome, not a failure."
        )
    if event == "close_ticket":
        scan = getattr(state, "resolved_by_scan", None) or "a later scan"
        return (
            f"**Resolved** · cycle {cycle}\n\n"
            f"{scan} did not report this finding, and the asset it was found "
            f"on was covered by that scan. Absence on a scanned asset is what "
            f"the fleet treats as evidence of remediation — absence on an "
            f"asset that was never examined is not, and would have left this "
            f"open.\n\n"
            f"Closing. Nothing further is required from {who}."
        )
    return f"Chase action `{event}` · cycle {cycle}."
