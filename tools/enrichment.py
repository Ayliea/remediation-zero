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

"""Vulnerability enrichment, read from disk.

Three authoritative public sources, each cached by `scripts/fetch-enrichment.py`
and read from disk here:

    CISA KEV  is this vulnerability known to be exploited in the wild, and by
              when does CISA require federal agencies to remediate it
    EPSS      the probability it will be exploited in the next thirty days
    NVD       CVSS base score, vector and description

This module performs no network I/O. That is deliberate and load-bearing: a
live demonstration must not be breakable by a third-party API being slow,
rate-limited, or unreachable at that moment, and there is a test asserting the
property rather than trusting the intent.

A missing source degrades rather than raises. Enrichment that crashes on a
partially populated cache would take the whole cycle down over an absent CVSS
score, when "no data from this source" is a perfectly reportable answer that
triage can reason about and cite.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CACHE_DIR = REPO_ROOT / "data" / "cache"


@dataclass(frozen=True)
class Enrichment:
    """Everything known about one CVE, with its evidence already attributed.

    Citations travel with the data rather than being attached later, because
    triage must cite its evidence and evidence attributed after the fact is not
    really cited.
    """

    cve_id: str
    in_kev: bool = False
    kev_due_date: Optional[str] = None
    kev_ransomware: bool = False
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    cvss_base: Optional[float] = None
    cvss_severity: Optional[str] = None
    cvss_vector: Optional[str] = None
    description: Optional[str] = None
    sources: tuple[str, ...] = field(default_factory=tuple)

    @property
    def has_evidence(self) -> bool:
        """False when no source knew anything, so triage can say so plainly."""
        return bool(self.sources)


class EnrichmentCache:
    """Reads the cached sources once and answers from memory.

    Args:
        cache_dir: where the cache files live. Overridable for tests; a missing
            directory or a missing file is treated as an absent source rather
            than an error.
    """

    def __init__(self, cache_dir: Optional[Path] = None) -> None:
        self._dir = Path(cache_dir) if cache_dir else DEFAULT_CACHE_DIR
        self._kev = self._load_kev()
        self._epss = self._load_json("epss.json")
        self._nvd = self._load_json("nvd.json")

    def _load_json(self, name: str) -> dict[str, Any]:
        path = self._dir / name
        if not path.is_file():
            return {}
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            # A corrupt cache file is an absent source, not a crash. The
            # fetch script is how it gets repaired.
            return {}

    def _load_kev(self) -> dict[str, dict[str, Any]]:
        catalogue = self._load_json("cisa_kev.json")
        return {v["cveID"]: v for v in catalogue.get("vulnerabilities", [])}

    def enrich(self, cve_id: str) -> Enrichment:
        """Everything the cache knows about `cve_id`."""
        sources: list[str] = []

        kev_entry = self._kev.get(cve_id)
        if kev_entry:
            sources.append("CISA KEV catalog")

        epss_entry = self._epss.get(cve_id)
        if epss_entry:
            sources.append("FIRST EPSS")

        cvss_base, cvss_severity, cvss_vector, description = self._from_nvd(cve_id)
        if cvss_base is not None or description:
            sources.append("NVD")

        return Enrichment(
            cve_id=cve_id,
            in_kev=kev_entry is not None,
            kev_due_date=(kev_entry or {}).get("dueDate"),
            kev_ransomware=(kev_entry or {}).get("knownRansomwareCampaignUse")
            == "Known",
            epss_score=(epss_entry or {}).get("epss"),
            epss_percentile=(epss_entry or {}).get("percentile"),
            cvss_base=cvss_base,
            cvss_severity=cvss_severity,
            cvss_vector=cvss_vector,
            description=description,
            sources=tuple(sources),
        )

    def _from_nvd(self, cve_id: str):
        """Pull CVSS and description out of an NVD record.

        NVD nests metrics under a version key that varies by record, so the
        preferred versions are tried in order rather than assumed.
        """
        entry = self._nvd.get(cve_id)
        if not entry or entry.get("_not_found") or entry.get("_error"):
            return None, None, None, None

        description = None
        for item in entry.get("descriptions", []):
            if item.get("lang") == "en":
                description = item.get("value")
                break

        metrics = entry.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key) or []
            if not entries:
                continue
            data = entries[0].get("cvssData", {})
            return (
                data.get("baseScore"),
                data.get("baseSeverity") or entries[0].get("baseSeverity"),
                data.get("vectorString"),
                description,
            )

        return None, None, None, description
