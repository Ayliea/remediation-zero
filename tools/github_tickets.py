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

"""Filing the ticket somewhere a person will actually see it.

This is the first thing the fleet does that leaves the system. Every other
action the chase agent takes is a Firestore write it could take back; an issue
in a tracker cannot be un-filed quietly, and a duplicate is visible to somebody
who did not ask for it.

So there are two independent defences against filing twice. The ticket record
carries the issue number once one exists, which is the fast path and the one
that holds across cycles. Before creating anything, this module also searches
the tracker for the finding id, which is the slow path and the one that holds
when Firestore has lost the number or a cycle was interrupted between the API
call and the write that recorded it. Either alone would be a guess.

And a rule that decides the failure behaviour: **Firestore is the record and
GitHub is a delivery of it.** A cycle whose deadline, nudge count and
escalation were written correctly has done its work; if the tracker could not
be reached, that is a delivery failure to retry, not a cycle to fail. The
inverse would be worse — refusing to record a nudge because a webhook was down
loses the fact that the nudge was due.

The corpus is synthetic, and every issue says so in its own body. An engineer
who stumbles on one of these must not spend ten minutes wondering whether they
have a real unpatched host.
"""

import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

logger = logging.getLogger("remediation_zero.github")

API = "https://api.github.com"

#: How far back to scan when recovering a lost issue number. Ten pages is a
#: thousand issues, and the scan only runs when the ticket record has no number.
MAX_LIST_PAGES = 10

#: Stamped into every title so an issue can be found again by finding id, and
#: so a human scanning a list can see which system filed it.
MARKER = "Remediation Zero"


class GitHubUnavailable(RuntimeError):
    """The tracker could not be reached, or was not configured.

    Named rather than generic so the caller can tell a delivery failure from a
    programming error and degrade on exactly one of them.
    """


def issue_title(finding: Any) -> str:
    """A title carrying the finding id, so the issue is findable by search."""
    return (
        f"[{finding['finding_id']}] {finding.get('cve_id', 'unknown CVE')} "
        f"on {finding.get('asset_id', 'an asset')} "
        f"— {finding.get('scanner_severity', 'unrated')}"
    )


def issue_body(
    finding: Any,
    owner: Any,
    due: str,
    sla_days: Any,
    severity: str,
    remediation: str,
    rationale: str = "",
    evidence: str = "",
    reviewer: str = "",
    attempts: Any = None,
) -> str:
    """The issue as the accountable person reads it.

    Leads with what to do and by when, because that is what the reader needs;
    the provenance sits underneath. The synthetic notice is not a disclaimer in
    small print — an engineer who finds one of these and cannot immediately tell
    whether it describes a real unpatched host has been actively harmed by it.
    """
    return "\n".join([
        f"**{severity.upper()}** · due **{due}** · SLA {sla_days} days",
        "",
        f"### What to do",
        remediation or "_No remediation was proposed._",
        "",
        "### Finding",
        f"- Finding: `{finding['finding_id']}`",
        f"- CVE: `{finding.get('cve_id', 'unknown')}`",
        f"- Asset: `{finding.get('asset_id', 'unknown')}`",
        f"- Scanner severity: {finding.get('scanner_severity', 'unrated')}",
        "",
        "### Owner",
        f"- {owner.get('display_name', 'unassigned')} "
        f"({owner.get('email', 'no address')}) · team {owner.get('team', 'unknown')}",
        "",
        *( ["### Why this severity", rationale, ""] if rationale else []),
        *( [f"**Evidence cited:** {evidence}", ""] if evidence else []),
        *( ["### Reviewer",
            f"Ratified by an adversarial reviewer running on a different model "
            f"family" + (f" after {attempts} proposals" if attempts and int(attempts) > 1 else "") + ":",
            "",
            f"> {reviewer}", ""] if reviewer else []),
        "---",
        f"Filed automatically by the **{MARKER}** chase agent. Nudges and "
        "escalations arrive as comments on this issue.",
        "",
        "> **This is synthetic.** The corpus, the asset and the owner are "
        "generated; only the CVE identifier is real. Nothing here describes an "
        "actual unpatched system.",
    ])


class GitHubTickets:
    """Create and comment on issues in one repository.

    Args:
        repo: "owner/name".
        token: a token with `repo` scope. Never logged, never placed in a URL.
        http: injected for tests.
    """

    def __init__(self, repo: str, token: str, http: Optional[Any] = None) -> None:
        if not repo:
            raise GitHubUnavailable(
                "No repository configured. Set GITHUB_TICKET_REPO to "
                "'owner/name'; the fleet will not guess where to file."
            )
        if not token:
            raise GitHubUnavailable(
                "No GitHub token available. Set GITHUB_TOKEN. Failing here is "
                "deliberate: a 401 discovered inside a retry loop is harder to "
                "read than a refusal at the call site."
            )
        self._repo = repo
        self._token = token
        self._http = http or _make_http(self)

    def find_issue(self, finding_id: str) -> Optional[int]:
        """The issue already filed for this finding, if there is one.

        Listed and matched locally, not searched. GitHub's search index is
        eventually consistent: an issue created seconds ago is not found by
        `search/issues`, which was demonstrated here by filing issue 1 and
        having the search return nothing immediately afterwards. A duplicate
        defence with a blind window is worse than none, because it reports
        safety it does not have — and the window is exactly when a re-run
        happens.

        The list endpoint is consistent immediately. It is also the recovery
        path rather than the hot path: the ticket record carries the issue
        number once one exists, so this scan runs only when that number is
        missing.

        Returns None rather than a plausible number when nothing matches. A
        guess here comments on somebody else's issue.
        """
        row = self._find_issue_row(finding_id)
        return int(row["number"]) if row else None

    def _find_issue_row(self, finding_id: str) -> Optional[dict]:
        """The matching issue as GitHub returned it, state included.

        `find_issue` deliberately narrows this to a number, because a number is
        all a caller needs to comment. `open_issue` needs more: an issue that
        has been closed is still the issue for this finding, but commenting on
        it delivers a nudge nobody will read. Splitting the row out keeps both
        callers honest without a second round trip for the state.
        """
        marker = f"[{finding_id}]"
        page = 1
        while page <= MAX_LIST_PAGES:
            batch = self._call(
                "GET",
                f"{API}/repos/{self._repo}/issues"
                f"?state=all&per_page=100&page={page}",
            ) or []
            if not batch:
                return None
            for issue in batch:
                if marker in (issue.get("title") or ""):
                    return issue
            if len(batch) < 100:
                return None
            page += 1
        # Exhausted the cap rather than the repository. Say so instead of
        # returning None, which the caller would read as "nothing filed yet"
        # and act on by filing again.
        raise GitHubUnavailable(
            f"Scanned {MAX_LIST_PAGES} pages without finding {finding_id} and "
            f"without reaching the end. Refusing to report it absent."
        )

    def reopen(self, issue_number: int) -> None:
        """Reopen a closed issue so what follows it is visible.

        A finding that comes back is the same finding, so it keeps its issue
        rather than gaining a duplicate. But a closed issue is out of every
        triage view and most notification settings, so a nudge or an escalation
        posted to one is delivered in the sense that the API accepted it and in
        no other sense. Reopening is what makes the delivery true.
        """
        self._call("PATCH", f"{API}/repos/{self._repo}/issues/{issue_number}",
                   {"state": "open"})

    def open_issue(self, finding_id: str, title: str, body: str,
                   labels: Optional[list] = None) -> int:
        """File the issue, or return the number of the one already filed."""
        row = self._find_issue_row(finding_id)
        if row is not None:
            existing = int(row["number"])
            was_closed = (row.get("state") or "").lower() == "closed"
            if was_closed:
                self.reopen(existing)
            logger.info(json.dumps({
                "event": "github_issue_exists", "finding_id": finding_id,
                "cycle_id": "-", "issue": existing,
                "reopened": was_closed}, sort_keys=True))
            return existing

        created = self._call("POST", f"{API}/repos/{self._repo}/issues", {
            "title": title, "body": body, "labels": labels or [],
        })
        number = (created or {}).get("number")
        if not number:
            raise GitHubUnavailable(
                f"GitHub accepted the request but returned no issue number: "
                f"{str(created)[:200]}"
            )
        return int(number)

    def comment(self, issue_number: int, body: str) -> None:
        """Add a comment. Nudges and escalations arrive this way."""
        self._call(
            "POST", f"{API}/repos/{self._repo}/issues/{issue_number}/comments",
            {"body": body})

    # -- transport -----------------------------------------------------------

    def _call(self, method: str, url: str, body: Optional[Any] = None) -> Any:
        try:
            return self._http.request(method, url, body)
        except GitHubUnavailable:
            raise
        except Exception as exc:  # noqa: BLE001 - deliberately broad
            # The token is never interpolated into this message. It would
            # otherwise reach logs, tracebacks and any error surfaced to a user.
            raise GitHubUnavailable(
                f"GitHub could not be reached: {type(exc).__name__}: "
                f"{str(exc)[:200]}"
            ) from exc

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "remediation-zero",
        }


def _make_http(tickets: "GitHubTickets"):
    """The default transport: urllib, because four calls do not need a
    dependency. The token travels in a header and never in the URL."""

    def request(method: str, url: str, body: Optional[Any] = None) -> Any:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        for key, value in tickets._headers().items():
            req.add_header(key, value)
        if data:
            req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=20) as response:
            raw = response.read().decode()
        return json.loads(raw) if raw else {}

    return type("Http", (), {"request": staticmethod(request)})()
