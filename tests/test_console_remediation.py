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

"""What the console says about remediation.

A count of what was fixed, rendered on its own, invites exactly the reading the
coverage gate exists to prevent: close what you looked at, and let a reader
assume you looked everywhere. So the two numbers are rendered as a pair, the
same way the two clocks are, and the tests here are mostly about the pairing
rather than about either number.
"""

import re
from pathlib import Path

from ui.app import render

SOURCE = (Path(__file__).resolve().parents[1] / "ui" / "app.py").read_text()


def base(**over):
    """The smallest data dict render() accepts."""
    data = {
        "resolved_total": 106,
        "scans": [],
        "latest_scan": {
            "scan_id": "rescan-01",
            "covered_asset_ids": [f"ast-{n:02d}" for n in range(1, 46)],
            "counts": {"resolved": 106, "persisting": 192, "unverifiable": 102,
                       "new": 12, "regressed": 0},
        },
        "human_queue": [], "sla": [], "decisions": [], "tickets": [],
        "exceptions": [], "cycles": [], "reports": [],
        "counts": {"findings": 412, "assets": 60, "owners": 12, "decisions": 79,
                   "tickets": 0, "human_queue": 60, "idempotency": 450},
        "sim_now": 0.0,
    }
    data.update(over)
    return data


def text_of(html):
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html))


# --- the pairing ------------------------------------------------------------

def test_both_numbers_are_rendered():
    page = text_of(render(base()))
    assert "106" in page
    assert "102" in page


def test_what_cannot_be_vouched_for_is_never_rendered_without_what_was_fixed():
    """And vice versa. They share the .clocks grid, which is the idiom this
    page already uses for two values that must be read together."""
    html = render(base())
    assert "clock--fixed" in html
    assert "clock--unknown" in html
    # Same container, so one cannot be dropped without the other.
    fixed, unknown = html.index("clock--fixed"), html.index("clock--unknown")
    between = html[fixed:unknown]
    assert between.count("<div class=\"clocks\">") == 0, "they were split apart"


def test_coverage_is_stated_with_the_numbers():
    """45 of 60 is what makes 106 mean anything."""
    page = text_of(render(base()))
    assert "45" in page and "60" in page
    assert "rescan-01" in page


def test_the_unverifiable_wording_says_they_are_still_being_chased():
    """A reader who thinks unverifiable means dropped has understood the
    opposite of what happens."""
    page = text_of(render(base()))
    assert "still chased" in page
    assert "SLA clock" in page


# --- honesty about what has and has not happened ----------------------------

def test_it_does_not_claim_chase_has_already_closed_the_tickets():
    """A rescan resolves findings; chase closes their tickets on its next
    cycle. Between the two there is a real window in which the tickets are
    still open, and the console is read during it."""
    page = text_of(render(base()))
    assert "Chase closed each ticket" not in page
    assert "next cycle closes the ticket" in page


def test_before_any_rescan_it_says_so_rather_than_rendering_zeroes():
    """Zero resolved and zero unverifiable is indistinguishable from a scan
    that ran and found nothing. Saying no scan has run is the honest render."""
    page = text_of(render(base(latest_scan={}, resolved_total=0)))
    assert "No rescan has run yet" in page
    assert "cannot confirm" in page


# --- the console still only reads -------------------------------------------

def test_the_new_query_is_a_read():
    """Constraint: the console never writes. A filtered count is still a read,
    but the assertion is worth keeping next to the code that added a query."""
    assert ".count()" in SOURCE
    for forbidden in (".set(", ".update(", ".delete("):
        assert forbidden not in SOURCE


def test_the_filtered_count_is_not_mixed_into_the_collection_sizes():
    """`counts` is a strip of raw collection sizes. A filtered count rendered
    beside `findings 412` reads as though the two are the same kind of
    number, and the underscore in the key leaks into the page."""
    html = render(base())
    assert "findings_resolved" not in html
