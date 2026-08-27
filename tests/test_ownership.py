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

"""Ownership resolution.

Mapping an asset to an accountable human is a lookup, not a judgement, so these
tests are about what happens when the lookup fails rather than about reasoning.
The interesting cases are all the ones where nobody is accountable.
"""

import pytest

from tools.ownership import Assignment, resolve_owner

ASSETS = {
    "ast-001": {"asset_id": "ast-001", "owner_id": "own-001", "hostname": "h1.corp.invalid"},
    "ast-002": {"asset_id": "ast-002", "owner_id": "own-missing", "hostname": "h2.corp.invalid"},
    "ast-003": {"asset_id": "ast-003", "hostname": "h3.corp.invalid"},
}
OWNERS = {
    "own-001": {"owner_id": "own-001", "display_name": "Ada Dunne",
                "email": "ada.dunne@example.invalid", "team": "platform"},
}


def test_a_finding_resolves_to_the_accountable_human():
    assignment = resolve_owner(
        {"finding_id": "RZ-0001", "asset_id": "ast-001"}, ASSETS, OWNERS
    )

    assert isinstance(assignment, Assignment)
    assert assignment.owner_id == "own-001"
    assert assignment.owner_email == "ada.dunne@example.invalid"
    assert assignment.needs_human is False


def test_an_asset_with_no_owner_field_goes_to_a_person():
    """Unowned infrastructure is the normal case in a real estate, and the
    fleet must not invent an owner for it."""
    assignment = resolve_owner(
        {"finding_id": "RZ-0002", "asset_id": "ast-003"}, ASSETS, OWNERS
    )

    assert assignment.needs_human is True
    assert "no owner" in assignment.reason.lower()


def test_an_owner_id_that_does_not_exist_goes_to_a_person():
    """A dangling reference is worse than a missing one: it looks resolved.
    Assigning to an owner record that is not there would produce a ticket
    nobody receives and an SLA clock nobody is watching."""
    assignment = resolve_owner(
        {"finding_id": "RZ-0003", "asset_id": "ast-002"}, ASSETS, OWNERS
    )

    assert assignment.needs_human is True
    assert assignment.owner_id is None
    assert "own-missing" in assignment.reason


def test_a_finding_for_an_unknown_asset_goes_to_a_person():
    assignment = resolve_owner(
        {"finding_id": "RZ-0004", "asset_id": "ast-999"}, ASSETS, OWNERS
    )

    assert assignment.needs_human is True
    assert "ast-999" in assignment.reason


def test_resolution_never_raises_on_bad_data():
    """A malformed finding must not take the cycle down. Findings are never
    silently dropped, so this has to end in the human queue rather than an
    exception."""
    assignment = resolve_owner({"finding_id": "RZ-0005"}, ASSETS, OWNERS)

    assert assignment.needs_human is True
