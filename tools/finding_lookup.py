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

"""Read one finding and render it the way the agents see it.

This is the only tool the deployed orchestrator is given, and the reason it is
the only one is worth stating plainly.

An Agent Engine runs as a single service account. Every sub-agent attached to
the deployed orchestrator therefore executes under one identity, so attaching
the agents that write — ownership, chase, exception, reporting — would require
that identity to hold every collection's write access. The claim this project
makes loudest is that the reporting agent is structurally incapable of writing a
ticket, and it would stop being true of the deployment that carries the
project's name.

So the deployed agent reasons and does not persist. It reads a finding, hands it
to triage, hands the proposal to the reviewer, and returns the adjudication. The
decision it reaches is not written anywhere: writing is done by the graph and
the scheduled workers, which run under identities that hold exactly the access
their own agent needs.

That is the same argument the console already makes. The interface a stranger
can reach holds no credential that can change the record it displays.
"""

import os
from dataclasses import replace
from typing import Any, Optional

from tools.enrichment import EnrichmentCache
from tools.model_armor import ModelArmor, apply_verdict
from tools.review_models import render_finding

#: Seeded reference data, written by the seed script and never by an agent.
FINDINGS = "findings"
ASSETS = "assets"

_cache: Optional[EnrichmentCache] = None
_armor: Optional[ModelArmor] = None


#: Returned when screening could not even be attempted. Distinct wording from
#: Model Armor's own notice so the record can tell the two apart.
WITHHELD_ON_ERROR = (
    "[untrusted scanner text withheld: the screener could not be reached, so "
    "this text was never checked and is not shown]"
)


class FindingNotFound(LookupError):
    """No such finding.

    Raised rather than returning an empty record. An agent handed a blank
    finding reasons confidently about the blank, and a triage proposal derived
    from nothing is harder to spot than an error.
    """


def _enrichment_cache() -> EnrichmentCache:
    global _cache
    if _cache is None:
        _cache = EnrichmentCache()
    return _cache


def _armor_token() -> str:
    """An access token from the ambient service account.

    Not a subprocess call to gcloud, which is how the command-line drivers get
    theirs. There is no gcloud binary inside Agent Engine, and a screener that
    cannot authenticate returns unreachable — which fails closed and withholds
    every scanner comment, turning a missing binary into a silent loss of the
    only untrusted field the agents reason over.
    """
    import google.auth
    import google.auth.transport.requests

    credentials, _ = google.auth.default(
        scopes=["https://www.googleapis.com/auth/cloud-platform"])
    credentials.refresh(google.auth.transport.requests.Request())
    return credentials.token


def _screen_comment(text: str) -> str:
    """Screen the one untrusted field, and return what a model may see.

    Constraint 12: untrusted text passes Model Armor before reaching any
    reasoning context. The command-line paths did this and the deployed path
    did not, which meant the boundary was missing on exactly the surface a
    visitor exercises. The reviewer still caught the planted injection, but the
    reviewer is the second layer; this is the first.

    Fails closed by construction: `screen` returns blocked on an unreachable
    service and `parse_sanitize_response` returns blocked on a response it
    cannot read, so `apply_verdict` withholds in both cases without this
    function needing to decide anything.
    """
    global _armor
    if not text or not text.strip():
        return text
    if _armor is None:
        _armor = ModelArmor()
    try:
        verdict = _armor.screen(text, _armor_token())
    except Exception:  # noqa: BLE001 - deliberately broad
        # Could not even attempt it. Withhold rather than pass through: an
        # unscreened prompt on a bad minute is the failure this exists to stop.
        return WITHHELD_ON_ERROR
    return apply_verdict(text, verdict)


def _client() -> Any:
    """A Firestore reader, addressed by project id rather than project number.

    Inside Agent Engine the metadata server supplies the project as its number,
    and Firestore does not resolve a database by number: the request comes back
    as `The database (default) does not exist for project 978104855285`, which
    reads like the database is missing rather than like the project was
    addressed the wrong way. Passing the id explicitly avoids the whole class
    of confusion, and GOOGLE_CLOUD_PROJECT is set in
    .agent_engine_config.json for exactly this reason.
    """
    from google.cloud import firestore

    # RZ_FIRESTORE_PROJECT first: Agent Engine reserves GOOGLE_CLOUD_PROJECT
    # and refuses to deploy when it appears in the environment config, so the
    # deployed engine cannot be told the project under that name. Locally the
    # standard variable is set in .env and is the right thing to read.
    project = (os.environ.get("RZ_FIRESTORE_PROJECT")
               or os.environ.get("GOOGLE_CLOUD_PROJECT")
               or "").strip()
    return firestore.Client(project=project) if project else firestore.Client()


def lookup_finding(finding_id: str, client: Any = None) -> str:
    """Return one finding, its asset and its enrichment, as agent-ready text.

    Args:
        finding_id: for example "RZ-0101".
        client: injected in tests. Defaults to a Firestore client.

    Returns:
        The same rendering the graph passes to triage and to the reviewer, so
        what a judge sees in the playground is what the fleet actually reasons
        over rather than a demonstration variant of it.

    Raises:
        FindingNotFound: if there is no such finding.
    """
    db = client if client is not None else _client()

    snapshot = db.collection(FINDINGS).document(str(finding_id).strip()).get()
    if not snapshot.exists:
        raise FindingNotFound(
            f"No finding {finding_id!r}. The corpus is RZ-0001 to RZ-0400."
        )
    finding = snapshot.to_dict() or {}

    asset_snapshot = db.collection(ASSETS).document(
        str(finding.get("asset_id", ""))
    ).get()
    asset = (asset_snapshot.to_dict() or {}) if asset_snapshot.exists else {}

    # Scanner prose and cached NVD prose both came from outside this system.
    # Both are screened before the rendering that a model will read.
    finding = dict(finding)
    finding["scanner_comment"] = _screen_comment(
        finding.get("scanner_comment") or "")

    enrichment = _enrichment_cache().enrich(finding.get("cve_id", ""))
    enrichment = replace(
        enrichment,
        description=_screen_comment(enrichment.description or ""),
    )
    return render_finding(finding, asset, enrichment)
