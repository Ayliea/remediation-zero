#!/usr/bin/env python3
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

"""Generate the follow-up scan, deterministically.

    .venv/bin/python scripts/gen_rescan.py

The original corpus spreads its 400 findings across `scan-01` through
`scan-07`. Those are one discovery sweep partitioned arbitrarily, not a
sequence in time, so the follow-up takes its own identifier rather than
extending a numbering that never meant what it looks like it means.

What this produces is deliberately not a clean second look:

    covered assets        45 of 60. A real sweep misses hosts -- they are off,
                          they moved, credentials expired, the scanner never
                          had a route. The 15 it misses are what make
                          UNVERIFIABLE reachable, and UNVERIFIABLE is the
                          outcome the whole design exists to produce.
    remediated            about a third of the findings on covered assets stop
                          being reported. These are the closures.
    still reported        the rest. The chase continues on its own clock.
    new                   findings that did not exist before, on covered assets
                          only. They enter triage like any other finding.

Every new finding sits on an asset inside the coverage manifest, because
`tools.rescan` refuses a scan whose findings name an asset it claims not to
have examined. That refusal is a real control, so the generator is written to
satisfy it rather than the check being loosened to accept whatever this emits.

Fixed seed. Regenerating produces no diff, which is what lets the file be
committed and the demo be rehearsed against the same numbers every time.
"""

import json
import random
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

DATA_DIR = REPO_ROOT / "data"
OUT_PATH = DATA_DIR / "rescan-01.json"

#: Distinct from scripts/seed.py's seed so the two do not draw the same
#: sequence and accidentally correlate which findings vanish with which were
#: generated first.
SEED = 20260828

SCAN_ID = "rescan-01"

#: Fraction of assets the follow-up sweep actually reached.
COVERAGE_RATE = 0.75

#: Fraction of findings on covered assets that stopped being reported.
REMEDIATION_RATE = 0.34

#: Findings that did not exist at the first sweep.
NEW_FINDING_COUNT = 12

BENIGN_COMMENTS = [
    "Detected during authenticated sweep.",
    "Service responded on the expected port.",
    "Version banner matched a vulnerable range.",
    "Confirmed by credentialed check.",
    "Newly exposed after a configuration change.",
]


def build(seed: int = SEED) -> dict:
    """Build the follow-up scan from the committed corpus."""
    rng = random.Random(seed)

    assets = json.loads((DATA_DIR / "assets.json").read_text(encoding="utf-8"))
    findings = json.loads((DATA_DIR / "findings.json").read_text(encoding="utf-8"))

    asset_ids = sorted(asset["asset_id"] for asset in assets)
    covered = sorted(rng.sample(asset_ids, k=int(len(asset_ids) * COVERAGE_RATE)))
    covered_set = set(covered)

    reported = []
    for finding in findings:
        if finding["asset_id"] not in covered_set:
            # Not examined. It is not reported, and the reconciler will call
            # that unverifiable rather than fixed.
            continue
        if rng.random() < REMEDIATION_RATE:
            # Remediated: absent from this scan on an asset that was checked.
            continue
        reported.append({
            "finding_id": finding["finding_id"],
            "asset_id": finding["asset_id"],
            "cve_id": finding["cve_id"],
            "scanner_severity": finding["scanner_severity"],
            "scanner_cvss": finding["scanner_cvss"],
            "port": finding["port"],
            "proof": finding["proof"],
            "scanner_comment": finding["scanner_comment"],
            "scan_id": SCAN_ID,
        })

    # New findings. Numbered past the original corpus so nothing collides, and
    # placed only on covered assets so the manifest stays truthful.
    highest = max(int(f["finding_id"].split("-")[1]) for f in findings)
    cve_pool = sorted({f["cve_id"] for f in findings})

    for offset in range(NEW_FINDING_COUNT):
        asset_id = covered[rng.randrange(len(covered))]
        reported.append({
            "finding_id": f"RZ-{highest + offset + 1:04d}",
            "asset_id": asset_id,
            "cve_id": cve_pool[rng.randrange(len(cve_pool))],
            "scanner_severity": rng.choices(
                ["low", "medium", "high", "critical"], weights=[3, 5, 4, 2], k=1
            )[0],
            "scanner_cvss": round(rng.uniform(3.0, 10.0), 1),
            "port": rng.choice([22, 80, 135, 443, 445, 3389, 5432, 8080]),
            "proof": "Version banner matched vulnerable range on port.",
            # No planted payload here. The injection lives on exactly one
            # finding in the original corpus, and a second one would make the
            # two-layer defence check ambiguous about what it caught.
            "scanner_comment": rng.choice(BENIGN_COMMENTS),
            "scan_id": SCAN_ID,
        })

    reported.sort(key=lambda record: record["finding_id"])

    return {
        "scan_id": SCAN_ID,
        "covered_asset_ids": covered,
        "findings": reported,
    }


def main() -> int:
    scan = build()

    OUT_PATH.write_text(
        json.dumps(scan, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    findings = json.loads((DATA_DIR / "findings.json").read_text(encoding="utf-8"))
    reported_ids = {record["finding_id"] for record in scan["findings"]}
    original_ids = {record["finding_id"] for record in findings}
    covered = set(scan["covered_asset_ids"])

    remediated = sum(
        1 for record in findings
        if record["asset_id"] in covered and record["finding_id"] not in reported_ids
    )
    unverifiable = sum(
        1 for record in findings if record["asset_id"] not in covered
    )

    print(f"wrote {OUT_PATH.relative_to(REPO_ROOT)}")
    print(f"seed: {SEED} (fixed; regenerating produces no diff)")
    print(f"  scan_id            : {scan['scan_id']}")
    print(f"  assets covered     : {len(covered)} of "
          f"{len(json.loads((DATA_DIR / 'assets.json').read_text()))}")
    print(f"  findings reported  : {len(scan['findings'])}")
    print(f"  -> remediated      : {remediated}  (absent, asset covered)")
    print(f"  -> unverifiable    : {unverifiable}  (absent, asset NOT covered)")
    print(f"  -> new             : {len(reported_ids - original_ids)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
