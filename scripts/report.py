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

"""Produce the reporting period's summary.

    ./scripts/report.sh --cycle 30

Reads every collection the reporting agent is permitted to read, counts the
metrics in code, and asks a model to narrate figures it did not compute.
"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dotenv import load_dotenv
from google.cloud import firestore

from scripts import quiet_sdk_logging
from tools import review_models as rm
from tools.clock import SimClock
from tools.metrics import compute_metrics
from tools.reports import REPORTS_DATABASE, ReportWriter, write_summary
from tools.store import FirestoreIdempotencyStore

REPO_ROOT = Path(__file__).resolve().parents[1]
logger = logging.getLogger("remediation_zero.reporting")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cycle", type=int, required=True)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, stream=sys.stdout, format="%(message)s")
    quiet_sdk_logging()
    load_dotenv(REPO_ROOT / ".env")

    clock = SimClock.from_env()
    # Two clients on purpose: reads come from the operational database, the
    # report is written to the one the reporting identity can write.
    client = firestore.Client()
    reports_client = firestore.Client(database=REPORTS_DATABASE)

    def rows(name):
        return [d.to_dict() for d in client.collection(name).stream()]

    # Reporting reads. It does not write to any of these, and once the
    # per-agent identities are in place it will not be able to.
    metrics = compute_metrics(
        decisions=rows("decisions"),
        tickets=rows("tickets"),
        sla_clocks=rows("sla_clocks"),
        human_queue=rows("human_queue"),
        exceptions=rows("exceptions"),
        # Reference collections. Reporting reads them and, under its own
        # identity, cannot write them -- which the probe control proves.
        findings=rows("findings"),
        scans=rows("scans"),
        assets=rows("assets"),
    )

    summary = write_summary(metrics, os.environ["REASONING_MODEL"], rm._client())

    store = FirestoreIdempotencyStore(client=reports_client, clock=clock)
    document_id = ReportWriter(
        store=store, client=reports_client, clock=clock
    ).record(
        metrics=metrics, summary=summary, cycle=args.cycle
    )

    logger.info(json.dumps({
        "event": "report_written", "cycle_id": f"cycle-{args.cycle:03d}",
        "finding_id": "-", "report_id": document_id,
        "decisions": metrics["decisions_total"],
        "disagreement_rate": round(metrics["disagreement_rate"], 3),
    }, sort_keys=True))

    print("\n" + "=" * 68)
    print(summary)
    print("=" * 68)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
