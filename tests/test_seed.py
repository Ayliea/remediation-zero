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

"""The synthetic corpus.

Most of these are safety tests rather than correctness tests. The corpus is
committed to a public repository, so "contains nothing real" is a property that
has to hold on every regeneration, not a thing that was true once when someone
checked by eye.
"""

import ipaddress
import json
import re

import pytest

from scripts.seed import (
    ASSET_COUNT,
    FINDING_COUNT,
    OWNER_COUNT,
    SEED,
    build_corpus,
)


@pytest.fixture(scope="module")
def corpus():
    return build_corpus()


def test_the_same_seed_produces_byte_identical_output():
    """The corpus is committed, so regenerating it must not produce a diff.
    A noisy diff would hide a real change to the data among churn."""
    first = json.dumps(build_corpus(), sort_keys=True)
    second = json.dumps(build_corpus(), sort_keys=True)

    assert first == second


def test_a_different_seed_produces_different_output():
    """Guards the determinism test above from passing trivially, which it
    would if the generator ignored the seed entirely."""
    assert build_corpus(seed=SEED) != build_corpus(seed=SEED + 1)


def test_corpus_has_the_planned_shape(corpus):
    assert len(corpus["findings"]) == FINDING_COUNT
    assert len(corpus["assets"]) == ASSET_COUNT
    assert len(corpus["owners"]) == OWNER_COUNT


def test_every_cve_is_real(corpus):
    """Drawn from the cached CISA KEV catalogue rather than invented, so
    enrichment against KEV, NVD and EPSS returns genuine data."""
    kev = {
        v["cveID"]
        for v in json.load(open("data/cache/cisa_kev.json"))["vulnerabilities"]
    }
    for finding in corpus["findings"]:
        assert finding["cve_id"] in kev, finding["cve_id"]


def test_no_routable_ip_addresses_anywhere(corpus):
    """Constraint 8. Every address must be in a reserved documentation range,
    which cannot belong to anyone."""
    blob = json.dumps(corpus)
    for match in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", blob):
        addr = ipaddress.ip_address(match)
        assert not addr.is_global, f"{match} is a globally routable address"


def test_no_resolvable_hostnames_or_email_domains(corpus):
    """Reserved TLDs only. .invalid and .example can never be registered, so
    no hostname or address here can ever reach anything."""
    allowed = (".invalid", ".example", ".local")

    # Email domains, checked on the domain half only. The local part of an
    # address is not a hostname and matching it as one is a false positive.
    emails = {o["email"] for o in corpus["owners"]}
    assert emails, "expected owners to have addresses"
    for email in emails:
        domain = email.rsplit("@", 1)[1].lower()
        assert domain.endswith(allowed), f"{email} has a registrable domain"

    # Hostnames, checked wherever they appear.
    hostnames = {a["hostname"].lower() for a in corpus["assets"]}
    assert hostnames, "expected assets to have hostnames"
    for hostname in hostnames:
        assert hostname.endswith(allowed), f"{hostname} is registrable"


def test_referential_integrity(corpus):
    """A finding pointing at a missing asset would fail during the demo, not
    during generation."""
    asset_ids = {a["asset_id"] for a in corpus["assets"]}
    owner_ids = {o["owner_id"] for o in corpus["owners"]}

    for asset in corpus["assets"]:
        assert asset["owner_id"] in owner_ids
    for finding in corpus["findings"]:
        assert finding["asset_id"] in asset_ids


def test_exactly_one_finding_carries_the_injection_payload(corpus):
    """Used to exercise the Model Armor boundary and the reviewer agent.
    Exactly one, so the control test has an unambiguous expected result."""
    planted = [f for f in corpus["findings"] if f.get("injection_planted")]

    assert len(planted) == 1
    assert "ignore" in planted[0]["scanner_comment"].lower()


def test_findings_carry_no_ingest_timestamps(corpus):
    """Reference data is stamped by SimClock at ingest, not at generation.
    Baking a wall clock read into a committed file would make the corpus
    non-deterministic and would put a fabricated real_ts in the repository."""
    for finding in corpus["findings"]:
        assert "real_ts" not in finding
        assert "sim_ts" not in finding
