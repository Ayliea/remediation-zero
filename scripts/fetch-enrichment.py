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

"""Populate the enrichment cache. Run rarely, never at demo time.

Constraint 11: CISA KEV, NVD and EPSS are queried once and cached to disk. The
runtime enrichment path in `tools/enrichment.py` reads the cache and never
performs network I/O, so a live demonstration cannot be broken by a third-party
API being slow, rate-limiting, or down.

This script is the only thing that talks to those APIs. It is resumable: NVD is
fetched one CVE at a time under an unauthenticated rate limit of roughly five
requests per thirty seconds, so a full run takes around forty minutes and is
written incrementally. Re-running skips whatever is already cached.
"""

import csv
import gzip
import io
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CACHE_DIR = REPO_ROOT / "data" / "cache"
FINDINGS = REPO_ROOT / "data" / "findings.json"

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"

USER_AGENT = "remediation-zero/0.1 (hackathon build; contact via GitHub)"

#: Unauthenticated NVD allows ~5 requests per rolling 30s. Stay under it: being
#: throttled mid-run is slower than going slowly on purpose.
NVD_DELAY_SECONDS = 6.5


def _get(url: str, timeout: int = 60) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def _wanted_cves() -> set[str]:
    """Every CVE this project can be asked about."""
    corpus = {f["cve_id"] for f in json.loads(FINDINGS.read_text(encoding="utf-8"))}
    kev_path = CACHE_DIR / "cisa_kev.json"
    kev = set()
    if kev_path.is_file():
        kev = {
            v["cveID"]
            for v in json.loads(kev_path.read_text(encoding="utf-8"))["vulnerabilities"]
        }
    return corpus | kev


def fetch_kev() -> Path:
    path = CACHE_DIR / "cisa_kev.json"
    payload = json.loads(_get(KEV_URL))
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"  KEV : {len(payload['vulnerabilities'])} entries -> {path.name}")
    return path


def fetch_epss() -> Path:
    """The full EPSS dataset in one request, rather than per-CVE lookups."""
    path = CACHE_DIR / "epss.json"
    raw = gzip.decompress(_get(EPSS_URL, timeout=180)).decode("utf-8")

    # The file opens with a '#model_version,score_date' comment line.
    lines = [ln for ln in raw.splitlines() if not ln.startswith("#")]
    reader = csv.DictReader(io.StringIO("\n".join(lines)))

    # The full dataset is ~365k scores and 26MB, which is not a reasonable
    # thing to commit. Keep only what this project can ask about: the corpus
    # CVEs plus every KEV entry, since the corpus is drawn from KEV.
    wanted = _wanted_cves()
    scores = {
        row["cve"]: {
            "epss": float(row["epss"]),
            "percentile": float(row["percentile"]),
        }
        for row in reader
        if row.get("cve") in wanted
    }
    path.write_text(json.dumps(scores, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"  EPSS: {len(scores)} scores -> {path.name}")
    return path


def fetch_nvd(cves: list[str]) -> Path:
    """Fetch one CVE at a time, writing incrementally so the run is resumable.

    A failure on one CVE is recorded and skipped rather than aborting the run:
    forty minutes of progress should not be lost to one bad response.
    """
    path = CACHE_DIR / "nvd.json"
    cached = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}

    todo = [c for c in cves if c not in cached]
    print(f"  NVD : {len(cached)} already cached, {len(todo)} to fetch")
    if not todo:
        return path

    for index, cve in enumerate(todo, start=1):
        try:
            payload = json.loads(_get(NVD_URL.format(cve=cve)))
            vulns = payload.get("vulnerabilities") or []
            cached[cve] = vulns[0]["cve"] if vulns else {"_not_found": True}
        except (urllib.error.URLError, TimeoutError, ValueError, KeyError) as exc:
            cached[cve] = {"_error": f"{type(exc).__name__}: {exc}"}

        if index % 10 == 0 or index == len(todo):
            path.write_text(
                json.dumps(cached, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            done = len(cached)
            print(f"    {done}/{len(cves)} cached", flush=True)

        if index < len(todo):
            time.sleep(NVD_DELAY_SECONDS)

    path.write_text(json.dumps(cached, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def main() -> int:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cves = sorted({f["cve_id"] for f in json.loads(FINDINGS.read_text(encoding="utf-8"))})
    print(f"Populating enrichment cache for {len(cves)} distinct CVEs.")

    which = sys.argv[1:] or ["kev", "epss", "nvd"]
    if "kev" in which:
        fetch_kev()
    if "epss" in which:
        fetch_epss()
    if "nvd" in which:
        fetch_nvd(cves)

    print("\nCache populated. The runtime path reads these files and never")
    print("performs network I/O, so the demo does not depend on these APIs.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
