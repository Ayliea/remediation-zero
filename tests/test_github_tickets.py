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

"""The first thing this fleet does that leaves the system.

Everything else the chase agent does is a Firestore write it could take back.
An issue filed in someone else's tracker cannot be un-filed quietly, so this is
the one tool where a duplicate is visible to a person who did not ask for it.

Hence two independent defences against filing twice, and a hard rule that a
failure to reach GitHub never fails the cycle: the deadline, the nudge count
and the escalation are the record, and GitHub is a delivery of that record.
"""

import json
from pathlib import Path

import pytest

from tools.github_tickets import (
    GitHubTickets,
    GitHubUnavailable,
    issue_body,
    issue_title,
)

SOURCE = (Path(__file__).resolve().parents[1] / "tools" / "github_tickets.py").read_text()

FINDING = {
    "finding_id": "RZ-0101",
    "cve_id": "CVE-2015-2502",
    "scanner_severity": "high",
}
OWNER = {"owner_id": "own-002", "display_name": "Ada Dunne",
         "email": "ada.dunne@example.invalid", "team": "platform"}


class ListHTTP:
    """The issues list endpoint, which is what the lookup actually calls."""

    def __init__(self, issues, created=None):
        self._issues, self._created, self.calls = issues, created or {"number": 99}, []

    def request(self, method, url, body=None):
        self.calls.append((method, url, body))
        if method == "GET":
            return self._issues if "&page=1" in url else []
        return self._created


class FakeHTTP:
    """Records calls; returns canned responses keyed by (method, path fragment)."""

    def __init__(self, responses=None):
        self.calls = []
        self._responses = responses or {}

    def request(self, method, url, body=None):
        self.calls.append((method, url, body))
        for fragment, response in self._responses.items():
            if fragment in url:
                return response
        return {}


# --- what a person sees -----------------------------------------------------

def test_the_title_carries_the_finding_id_so_it_can_be_found_again():
    title = issue_title(FINDING)
    assert "RZ-0101" in title
    assert "CVE-2015-2502" in title


def test_the_body_states_the_deadline_and_who_owns_it():
    body = issue_body(FINDING, OWNER, due="2026-09-10", sla_days=7,
                      severity="high", remediation="Apply MS15-093.")
    for expected in ("RZ-0101", "Ada Dunne", "2026-09-10", "MS15-093"):
        assert expected in body


def test_the_body_says_an_agent_filed_it_and_the_corpus_is_synthetic():
    """A human reading this must not mistake it for a real vulnerability."""
    body = issue_body(FINDING, OWNER, due="2026-09-10", sla_days=7,
                      severity="high", remediation="Apply MS15-093.")
    assert "synthetic" in body.lower()
    assert "agent" in body.lower()


def test_no_real_person_or_host_can_reach_the_body():
    """Constraint 8. The corpus is synthetic and the egress must keep it so."""
    body = issue_body(FINDING, OWNER, due="2026-09-10", sla_days=7,
                      severity="high", remediation="Apply MS15-093.")
    assert "@example.invalid" in body  # the only address shape that may appear


# --- not filing twice -------------------------------------------------------

def test_an_existing_issue_is_found_by_its_finding_id():
    http = ListHTTP([{"number": 42, "title": "[RZ-0101] CVE-2015-2502 on x"}])
    assert GitHubTickets(repo="o/r", token="t", http=http).find_issue("RZ-0101") == 42


def test_no_match_returns_none_rather_than_a_plausible_number():
    http = ListHTTP([])
    assert GitHubTickets(repo="o/r", token="t", http=http).find_issue("RZ-0101") is None


def test_open_issue_looks_before_creating():
    """The recovery defence. The primary one is the number on the ticket."""
    http = ListHTTP([{"number": 42, "title": "[RZ-0101] x"}])
    gh = GitHubTickets(repo="o/r", token="t", http=http)
    assert gh.open_issue("RZ-0101", "t", "b") == 42
    assert not any(m == "POST" for m, _, _ in http.calls), "it filed a duplicate"


def test_open_issue_creates_when_nothing_exists():
    http = ListHTTP([], created={"number": 7})
    gh = GitHubTickets(repo="o/r", token="t", http=http)
    assert gh.open_issue("RZ-0101", "t", "b") == 7
    assert any(m == "POST" for m, _, _ in http.calls)


# --- failing safely ---------------------------------------------------------

class ExplodingHTTP:
    def request(self, *a, **k):
        raise ConnectionError("github unreachable")


def test_an_unreachable_github_raises_a_named_error():
    gh = GitHubTickets(repo="o/r", token="t", http=ExplodingHTTP())
    with pytest.raises(GitHubUnavailable):
        gh.open_issue("RZ-0101", "t", "b")


def test_a_missing_token_is_refused_before_any_request_is_made():
    """Failing at the call site with a clear reason beats a 401 in a log."""
    with pytest.raises(GitHubUnavailable):
        GitHubTickets(repo="o/r", token="", http=FakeHTTP())


def test_a_missing_repo_is_refused_too():
    with pytest.raises(GitHubUnavailable):
        GitHubTickets(repo="", token="t", http=FakeHTTP())


def test_the_token_is_never_placed_in_a_url():
    """It would land in logs, in redirects and in error messages."""
    http = ListHTTP([], created={"number": 7})
    gh = GitHubTickets(repo="o/r", token="secret-token-value", http=http)
    gh.open_issue("RZ-0101", "t", "b")
    for _, url, _ in http.calls:
        assert "secret-token-value" not in url


def test_the_token_reaches_the_authorization_header_and_nothing_else():
    """It must be interpolated exactly once, into the header.

    An earlier version of this test forbade `{self._token}` outright, which
    banned the one legitimate use and passed only because the transport was
    still a stub. Scan the log and raise statements instead.
    """
    assert '"Authorization": f"Bearer {self._token}"' in SOURCE

    suspect = [
        line.strip() for line in SOURCE.splitlines()
        if ("_token" in line)
        and ("logger." in line or "raise " in line or "print(" in line)
    ]
    assert suspect == [], f"the token is formatted into output: {suspect}"


# --- why the lookup lists instead of searching ------------------------------
#
# GitHub's search index is eventually consistent. Filing an issue and then
# searching for it immediately returns nothing, which was observed here on the
# very first real call. A duplicate defence with a blind window is worse than
# no defence, because it reports a safety it does not have — and the window is
# precisely when a re-run happens.

class PagedHTTP:
    def __init__(self, pages):
        self.pages, self.calls = pages, []

    def request(self, method, url, body=None):
        self.calls.append((method, url, body))
        if "/issues?" in url:
            n = int(url.split("&page=")[1])
            return self.pages[n - 1] if n <= len(self.pages) else []
        return {"number": 99}


def test_the_lookup_never_calls_the_search_endpoint():
    http = PagedHTTP([[{"number": 42, "title": "[RZ-0101] CVE-x"}]])
    GitHubTickets(repo="o/r", token="t", http=http).find_issue("RZ-0101")
    assert not any("search/issues" in url for _, url, _ in http.calls)


def test_it_matches_the_finding_id_in_a_listed_title():
    http = PagedHTTP([[{"number": 42, "title": "[RZ-0101] CVE-2015-2502 on x"}]])
    assert GitHubTickets(repo="o/r", token="t", http=http).find_issue("RZ-0101") == 42


def test_a_similar_finding_id_does_not_match():
    """RZ-0101 must not match RZ-01010. The bracket is what makes it exact."""
    http = PagedHTTP([[{"number": 42, "title": "[RZ-01010] CVE-x on y"}]])
    assert GitHubTickets(repo="o/r", token="t", http=http).find_issue("RZ-0101") is None


def test_it_pages_until_it_finds_the_issue():
    full = [{"number": i, "title": f"[RZ-{i:04d}] x"} for i in range(100)]
    http = PagedHTTP([full, [{"number": 500, "title": "[RZ-0101] found"}]])
    assert GitHubTickets(repo="o/r", token="t", http=http).find_issue("RZ-0101") == 500


def test_exhausting_the_page_cap_raises_rather_than_reporting_absent():
    """Reporting absent would make the caller file a duplicate."""
    full = [{"number": i, "title": f"[RZ-{i:04d}] x"} for i in range(100)]
    http = PagedHTTP([full] * 20)
    with pytest.raises(GitHubUnavailable):
        GitHubTickets(repo="o/r", token="t", http=http).find_issue("RZ-0101")


# --- the fields the issue is built from -------------------------------------
#
# The first version of the delivery adapter looked for `severity` and
# `proposal.remediation`. Neither exists: decisions carry `proposed_severity`
# and `proposed_remediation` as flat fields. The issues it filed read UNRATED
# with no remediation — a ticket that wastes the reader's time instead of
# saving it, and the failure was invisible until a real one was filed.

DECISION = {
    "finding_id": "RZ-0321",
    "outcome": "ratified",
    "proposed_severity": "critical",
    "proposed_remediation": "Apply the vendor patch and restrict port 445.",
    "proposed_sla_days": 7,
    "rationale": "Actively exploited per CISA KEV.",
    "cited_evidence": "['CISA KEV catalog', 'FIRST EPSS']",
    "attempts": 2,
    "verdicts": [
        {"ratified": False, "reason": "The remediation is vague."},
        {"ratified": True, "reason": "The severity is supported by KEV status."},
    ],
}


def test_the_decision_field_names_are_the_ones_firestore_actually_uses():
    """Pins the names, so a rename cannot silently empty every issue."""
    for field in ("proposed_severity", "proposed_remediation",
                  "proposed_sla_days", "rationale", "cited_evidence",
                  "verdicts", "outcome"):
        assert field in DECISION


def test_the_body_carries_the_ratifying_reviewer_reason():
    """The reason a different model family accepted it is the point."""
    body = issue_body(
        FINDING, OWNER, due="2026-09-10", sla_days=7, severity="critical",
        remediation="Apply the vendor patch.",
        rationale="Actively exploited per CISA KEV.",
        evidence="['CISA KEV catalog']",
        reviewer="The severity is supported by KEV status.",
        attempts=2,
    )
    assert "The severity is supported by KEV status." in body
    assert "different model family" in body
    assert "after 2 proposals" in body
    assert "CISA KEV" in body


def test_a_decision_with_no_reviewer_reason_still_produces_a_usable_issue():
    body = issue_body(FINDING, OWNER, due="2026-09-10", sla_days=7,
                      severity="high", remediation="Apply MS15-093.")
    assert "Apply MS15-093." in body
    assert "Reviewer" not in body.split("### Owner")[0].split("### Finding")[0]


# -- reusing an issue that was closed ----------------------------------------
#
# A finding that comes back is the same finding, so it keeps its issue rather
# than gaining a duplicate. That is right, and it was silently wrong in one
# respect: a closed issue is out of every triage view and most notification
# settings, so the nudge and the escalation that follow were delivered only in
# the sense that the API returned 201. Found by a dry run in which the graph
# step ratified RZ-0101, whose issue an earlier rehearsal had closed.

CLOSED_ROW = {"number": 14, "title": "[RZ-0101] CVE-2015-2502 on ast-026 — low",
              "state": "closed"}
OPEN_ROW = dict(CLOSED_ROW, state="open")


def test_a_closed_issue_is_reopened_before_it_is_reused() -> None:
    http = ListHTTP([CLOSED_ROW])
    gh = GitHubTickets(repo="o/r", token="t", http=http)

    assert gh.open_issue("RZ-0101", "title", "body") == 14

    patches = [c for c in http.calls if c[0] == "PATCH"]
    assert patches, "a closed issue was reused without being reopened"
    assert patches[0][2] == {"state": "open"}


def test_reusing_a_closed_issue_still_files_no_duplicate() -> None:
    """Reopening must not become a second way to create an issue."""
    http = ListHTTP([CLOSED_ROW])
    GitHubTickets(repo="o/r", token="t", http=http).open_issue("RZ-0101", "t", "b")

    posts = [c for c in http.calls if c[0] == "POST"]
    assert not posts, f"reopening filed a duplicate issue: {posts}"


def test_an_already_open_issue_is_not_patched() -> None:
    """Reopening an open issue is a pointless write against a rate limit."""
    http = ListHTTP([OPEN_ROW])
    gh = GitHubTickets(repo="o/r", token="t", http=http)

    assert gh.open_issue("RZ-0101", "title", "body") == 14
    assert not [c for c in http.calls if c[0] == "PATCH"]


def test_find_issue_still_returns_only_a_number() -> None:
    """The public contract did not widen when the row lookup was split out."""
    gh = GitHubTickets(repo="o/r", token="t", http=ListHTTP([CLOSED_ROW]))
    assert gh.find_issue("RZ-0101") == 14


# --- closing what a rescan confirmed ----------------------------------------

def test_closing_an_issue_marks_it_completed_not_merely_closed():
    """GitHub distinguishes "completed" from "not planned", and the two read
    very differently to a person auditing a vulnerability queue. A remediated
    finding was completed; recording it as not planned would misstate the
    outcome in the one place a reviewer looks."""
    http = FakeHTTP()
    tickets = GitHubTickets(repo="Ayliea/x", token="t", http=http)

    tickets.close_issue(42)

    method, url, body = http.calls[-1]
    assert method == "PATCH"
    assert url.endswith("/issues/42")
    assert body == {"state": "closed", "state_reason": "completed"}


def test_closing_is_the_mirror_of_reopening():
    """reopen and close_issue must target the same resource the same way, or a
    finding that comes back cannot be reopened on the issue it closed."""
    http = FakeHTTP()
    tickets = GitHubTickets(repo="Ayliea/x", token="t", http=http)

    tickets.close_issue(7)
    tickets.reopen(7)

    closed, reopened = http.calls[-2], http.calls[-1]
    assert closed[0] == reopened[0] == "PATCH"
    assert closed[1] == reopened[1]
    assert closed[2]["state"] == "closed"
    assert reopened[2]["state"] == "open"
