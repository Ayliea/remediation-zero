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

"""Runtime enrichment reads the cache and never reaches the network.

Constraint 11 exists because a live demonstration must not be breakable by a
third-party API being slow, rate-limited, or down at that moment. That is a
property of the code, so it is asserted here rather than assumed.
"""

import json
import urllib.request

import pytest

from tools.enrichment import EnrichmentCache

KNOWN_KEV_CVE = "CVE-2021-44228"  # Log4Shell, certain to be in KEV


@pytest.fixture(scope="module")
def cache():
    return EnrichmentCache()


def test_enrichment_never_performs_network_io(cache, monkeypatch):
    """The load-bearing test. If enrichment can reach the network at all, then
    the demo depends on someone else's uptime."""

    def explode(*args, **kwargs):
        raise AssertionError("enrichment attempted network I/O")

    monkeypatch.setattr(urllib.request, "urlopen", explode)
    monkeypatch.setattr(urllib.request, "Request", explode)

    result = cache.enrich(KNOWN_KEV_CVE)
    assert result.cve_id == KNOWN_KEV_CVE


def test_kev_membership_is_reported_with_its_due_date(cache):
    result = cache.enrich(KNOWN_KEV_CVE)

    assert result.in_kev is True
    assert result.kev_due_date


def test_epss_score_is_reported_as_a_probability(cache):
    result = cache.enrich(KNOWN_KEV_CVE)

    assert result.epss_score is not None
    assert 0.0 <= result.epss_score <= 1.0
    assert 0.0 <= result.epss_percentile <= 1.0


def test_every_corpus_finding_can_be_enriched(cache):
    """Enrichment that fails on part of the corpus fails during the demo."""
    findings = json.load(open("data/findings.json"))
    for finding in findings:
        result = cache.enrich(finding["cve_id"])
        assert result.in_kev is True, finding["cve_id"]
        assert result.epss_score is not None, finding["cve_id"]


def test_an_unknown_cve_degrades_rather_than_raising(cache):
    """A CVE outside the cache is a gap in evidence, not a crash. Triage must
    be able to say 'no data' and carry on."""
    result = cache.enrich("CVE-1999-99999")

    assert result.in_kev is False
    assert result.epss_score is None
    assert result.cvss_base is None


def test_enrichment_carries_citations(cache):
    """Triage proposes severity with cited evidence, so the evidence has to
    arrive already attributed rather than being attributed afterwards."""
    result = cache.enrich(KNOWN_KEV_CVE)

    assert result.sources
    joined = " ".join(result.sources).lower()
    assert "kev" in joined
    assert "epss" in joined


def test_missing_nvd_cache_degrades_rather_than_raising(tmp_path):
    """NVD is the slowest source to populate. A partially populated cache must
    still yield usable enrichment from the sources that are present."""
    (tmp_path / "cisa_kev.json").write_text(
        json.dumps({"vulnerabilities": [{"cveID": KNOWN_KEV_CVE, "dueDate": "2021-12-24",
                                         "knownRansomwareCampaignUse": "Known"}]})
    )
    (tmp_path / "epss.json").write_text(json.dumps({KNOWN_KEV_CVE: {"epss": 0.9, "percentile": 0.99}}))

    partial = EnrichmentCache(cache_dir=tmp_path)
    result = partial.enrich(KNOWN_KEV_CVE)

    assert result.in_kev is True
    assert result.epss_score == 0.9
    assert result.cvss_base is None
