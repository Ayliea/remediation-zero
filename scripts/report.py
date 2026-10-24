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
import logging
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dotenv import load_dotenv
from google.cloud import firestore

from engine.ports import NoDelivery, NoTelemetry, Ports
from engine.report import run_report
from scripts import quiet_sdk_logging
from tools import review_models as rm
from tools.clock import SimClock
from tools.docstore import FirestoreDocStore
from tools.guardrail import NoGuard
from tools.model_roles import ModelRoles
from tools.reports import REPORTS_DATABASE, ReportWriter
from tools.store import FirestoreIdempotencyStore

REPO_ROOT = Path(__file__).resolve().parents[1]


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

    roles = ModelRoles.from_env(os.environ)
    store = FirestoreIdempotencyStore(client=reports_client, clock=clock)
    # The cloud parts: reads from the operational database, the report and
    # its idempotency record to the reports database.
    ports = Ports(docs=FirestoreDocStore(client), journal=store, clock=clock,
                  roles=roles, guard=NoGuard(), delivery=NoDelivery(), memory=None,
                  telemetry=NoTelemetry())
    summary = run_report(
        ports, args.cycle,
        writer=ReportWriter(store=store, client=reports_client, clock=clock),
        vertex_client=rm._client,
    )

    print("\n" + "=" * 68)
    print(summary)
    print("=" * 68)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
