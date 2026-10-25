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

Hard constraint 7: CISA KEV, NVD and EPSS are queried once and cached to disk. The
runtime enrichment path in `tools/enrichment.py` reads the cache and never
performs network I/O, so a live demonstration cannot be broken by a third-party
API being slow, rate-limiting, or down.

The fetching lives in `tools/enrichment_fetch.py`, shared with the local
edition's `update-enrichment`; this script points it at the repository's
`data/cache` and the synthetic corpus. It is resumable: NVD is fetched one CVE
at a time under a rate limit (set NVD_API_KEY for the faster keyed limit), and
re-running skips whatever is already cached. Pass kev, epss and/or nvd to
refresh only those.
"""

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.enrichment import finding_cves  # noqa: E402
from tools.enrichment_fetch import refresh, urllib_get  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
CACHE_DIR = REPO_ROOT / "data" / "cache"
FINDINGS = REPO_ROOT / "data" / "findings.json"


def main() -> int:
    findings = json.loads(FINDINGS.read_text(encoding="utf-8"))
    cves = sorted({cve for f in findings for cve in finding_cves(f)})
    print(f"Populating enrichment cache for {len(cves)} distinct CVEs.")

    which = sys.argv[1:] or ["kev", "epss", "nvd"]

    def progress(kind, first, second):
        if kind == "start":
            print(f"  NVD : {first} already cached, {second} to fetch")
        else:
            print(f"    {first}/{second} cached", flush=True)

    result = refresh(cves, CACHE_DIR, get=urllib_get, nvd_api_key=os.environ.get("NVD_API_KEY") or None,
                     sources=which, progress=progress)
    if result["kev"] == "ok":
        print(f"  KEV : {result['kev_entries']} entries -> cisa_kev.json")
    elif result["kev"] == "failed":
        print("  KEV : failed; the previous file was kept")
    if result["epss"] == "ok":
        print(f"  EPSS: {result['epss_scores']} scores -> epss.json")
    elif result["epss"] == "failed":
        print("  EPSS: failed; the previous file was kept")
    if result["nvd_failed"]:
        print(f"  NVD : {len(result['nvd_failed'])} failed; the next run retries them")

    print("\nCache populated. The runtime path reads these files and never")
    print("performs network I/O, so the demo does not depend on these APIs.")
    # A failed KEV or EPSS source is a failed run; individual NVD failures are
    # retried next run and, as before, do not fail it.
    return 1 if "failed" in (result["kev"], result["epss"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
