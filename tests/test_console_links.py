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

"""The console links a ticket to the issue a person can actually open.

A ticket that exists only in a database is a claim about work. One a reader can
click is the work. This is the only outbound link the console renders, so the
two ways it can be wrong both matter: a missing link hides the strongest thing
the fleet does, and a link built without a configured tracker is a dead href
dressed as a live one.
"""

import re
from pathlib import Path

SOURCE = (Path(__file__).resolve().parents[1] / "ui" / "app.py").read_text()


def test_the_tracker_url_comes_from_the_environment():
    """Never a hard-coded repository. A fork files into its own."""
    assert "os.environ" in SOURCE.split("TRACKER_URL")[1][:200]
    assert "github.com/Ayliea" not in SOURCE


def test_a_link_is_rendered_only_when_both_are_present():
    """A stored issue number with no tracker configured must not become '/12'."""
    assert "if issue and TRACKER_URL else" in SOURCE


def test_the_link_opens_safely():
    """target=_blank without noopener hands the opener to the linked page."""
    anchor = SOURCE[SOURCE.index('f\'<a class="k" href='):]
    anchor = anchor[:anchor.index("if issue")]
    assert 'rel="noopener noreferrer"' in anchor
    assert 'target="_blank"' in anchor


def test_the_issue_number_is_coerced_to_an_integer():
    """It reaches an href. A string from Firestore would be injected as-is."""
    assert "int(issue)" in SOURCE


def test_the_console_still_holds_no_write_path():
    """The link is outbound. It must not have brought a client with it."""
    for forbidden in (".set(", ".update(", ".delete(", "add_memory"):
        assert forbidden not in SOURCE
