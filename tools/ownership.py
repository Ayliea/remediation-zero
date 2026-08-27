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

"""Map an affected asset to the human accountable for it.

This is deliberately not a model call. In this estate the mapping is a lookup
through the asset registry, and putting a language model in a deterministic
path would add latency, cost and a failure mode in exchange for nothing. The
boring, verifiable choice is the right one here, and the agent's real work is
in the cases where the lookup does not resolve.

Those cases are the point. Unowned infrastructure is normal in a real estate,
and the fleet must never invent an owner: a ticket assigned to nobody is worse
than no ticket, because it comes with an SLA clock that nobody is watching. A
dangling owner reference is worse still, because it looks resolved.

Everything that does not resolve goes to a person. Findings are never dropped.
"""

from dataclasses import dataclass
from typing import Any, Mapping, Optional


@dataclass(frozen=True)
class Assignment:
    """Who is accountable for a finding, or why nobody is."""

    finding_id: str
    asset_id: Optional[str]
    owner_id: Optional[str] = None
    owner_email: Optional[str] = None
    owner_name: Optional[str] = None
    team: Optional[str] = None
    needs_human: bool = False
    reason: str = ""


def resolve_owner(
    finding: Mapping[str, Any],
    assets: Mapping[str, Mapping[str, Any]],
    owners: Mapping[str, Mapping[str, Any]],
) -> Assignment:
    """Resolve one finding to an accountable human.

    Never raises. A malformed finding ends in the human queue rather than
    taking the cycle down, because findings are never silently dropped.
    """
    finding_id = str(finding.get("finding_id", "unknown"))
    asset_id = finding.get("asset_id")

    if not asset_id:
        return Assignment(
            finding_id=finding_id,
            asset_id=None,
            needs_human=True,
            reason="Finding carries no asset_id, so there is nothing to map to an owner.",
        )

    asset = assets.get(asset_id)
    if asset is None:
        return Assignment(
            finding_id=finding_id,
            asset_id=asset_id,
            needs_human=True,
            reason=f"Asset {asset_id} is not in the asset registry.",
        )

    owner_id = asset.get("owner_id")
    if not owner_id:
        return Assignment(
            finding_id=finding_id,
            asset_id=asset_id,
            needs_human=True,
            reason=f"Asset {asset_id} has no owner recorded. Unowned infrastructure "
            f"is assigned to a person rather than guessed at.",
        )

    owner = owners.get(owner_id)
    if owner is None:
        # A dangling reference looks resolved, which is what makes it
        # dangerous: the ticket would be raised and the clock would start.
        return Assignment(
            finding_id=finding_id,
            asset_id=asset_id,
            needs_human=True,
            reason=f"Asset {asset_id} names owner {owner_id}, which is not in the "
            f"owner registry. Dangling reference, not an assignment.",
        )

    return Assignment(
        finding_id=finding_id,
        asset_id=asset_id,
        owner_id=owner_id,
        owner_email=owner.get("email"),
        owner_name=owner.get("display_name"),
        team=owner.get("team"),
        needs_human=False,
        reason="Resolved through the asset registry.",
    )
