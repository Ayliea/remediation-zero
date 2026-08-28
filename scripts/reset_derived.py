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

"""Clear the two derived collections so the chase lifecycle can be replayed.

This is the only script in the repository that deletes anything, which is why
its blast radius is a closed allowlist rather than an argument.

`sla_clocks`, `tickets` and `scans` are derived state: chase rebuilds the
first two from the decisions that produced them and re-running the rescan
rebuilds the third, so clearing them costs nothing that cannot be recomputed.
Everything else is refused.

One exception, kept deliberately narrow. A rescan writes derived state into
`findings`, which is seeded reference data and is never cleared wholesale. So
this script undoes exactly what a rescan wrote there and nothing else: it
removes the findings a rescan created, and strips the resolution and
regression fields from the seeded ones it annotated, putting their status
back. Without that, one rescan makes the demo unrehearsable -- the clocks and
tickets reset, but the findings stay resolved, so the next run closes their
tickets on sight and the arc never plays again. `decisions` and `human_queue` are the
adjudication record, `idempotency` is what the resume control checks itself
against, and `findings`, `assets` and `owners` are seeded reference data.

Why this exists at all: rehearsing the demo advances simulated time, and every
advance ages the clocks. After enough rehearsals almost every clock reads
`breached`, so chase escalates nearly everything and stops showing the
lifecycle it exists to demonstrate. Resetting the clocks is the honest fix.
Winding simulated time backwards would not be, and `real_ts` is untouched by
either: it is wall clock and this script never writes one.

The Agent Engine and its long-running session are not reachable from here.
There is no code path to them and the tests assert the source does not name
them, because a script that can name the engine is one edit away from deleting
the one resource in this project that cannot be regenerated.

    ./scripts/reset-derived.sh              # show what would go
    ./scripts/reset-derived.sh --confirm    # actually delete
"""

import argparse
import sys
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(REPO_ROOT / ".env")

from google.cloud import firestore  # noqa: E402

#: Derived state. Chase recomputes the first two from the decisions that
#: produced them, and re-running the rescan recomputes the third.
CLEARABLE = frozenset({"sla_clocks", "tickets", "scans"})

#: A rescan writes derived state into `findings`, which is a reference
#: collection and stays protected from wholesale clearing. That leaves one
#: narrow thing this script has to be able to undo, expressed as a single rule:
#: it removes what a rescan wrote, and nothing a seed wrote.
#:
#: Without it, rehearsing the demo is a one-way door. The reset clears the
#: clocks and the tickets, but 106 findings stay marked resolved, so the next
#: run closes their tickets on sight and the nudge-and-escalate arc the demo
#: exists to show never happens again.
RESCAN_FIELDS = (
    "resolved_by_scan", "resolved_reason", "resolved_cycle",
    "resolved_real_ts", "resolved_sim_ts",
    "regressed_in_scan", "regressed_cycle",
    "regressed_real_ts", "regressed_sim_ts",
)

#: Present only on findings a rescan created, never on a seeded one. It is the
#: whole basis for deleting a finding, so it is deliberately a field only the
#: rescan ingest path writes.
RESCAN_CREATED_MARKER = "first_seen_scan"

#: What a seeded finding's status is, and therefore what a reset restores.
SEEDED_STATUS = "open"


def rescan_disposition(document: dict) -> Optional[str]:
    """What a rescan did to this finding, or None if it never touched it.

    "created" means the finding did not exist before a rescan reported it, so
    removing it returns the corpus to its seeded 400. "annotated" means a
    seeded finding was marked resolved or regressed, so the fields come off
    and the status goes back. A seeded finding is never deleted under either.
    """
    if document.get(RESCAN_CREATED_MARKER):
        return "created"
    if any(field in document for field in RESCAN_FIELDS):
        return "annotated"
    return None

#: Named so the refusal can say what the collection is, rather than only that
#: it is not on the list. Anything absent from both sets is refused too.
PROTECTED = {
    "findings": "seeded reference data",
    "assets": "seeded reference data",
    "owners": "seeded reference data",
    "decisions": "the adjudication record",
    "human_queue": "the adjudication record",
    "idempotency": "what the resume control checks itself against",
    "exceptions": "risk acceptances, which carry their own TTL",
    "assignments": "the ownership record",
    "cycles": "the cycle record",
    "reports": "written by the reporting agent to its own database",
}


def refuse_reason(collection: str) -> Optional[str]:
    """Say why this collection may not be cleared, or None if it may.

    Default deny: a collection that is on neither list is refused. A
    collection added to the schema later is protected before anyone
    remembers to protect it, which is the only ordering that is safe.
    """
    if collection in CLEARABLE:
        return None
    if collection in PROTECTED:
        return f"{collection} is {PROTECTED[collection]}"
    return f"{collection} is not a known derived collection"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--confirm", action="store_true",
        help="actually delete. Without it this only reports what would go.",
    )
    args = parser.parse_args()

    client = firestore.Client()

    planned = []
    for name in sorted(CLEARABLE):
        reason = refuse_reason(name)
        if reason:  # unreachable by construction, checked anyway
            print(f"refusing {name}: {reason}", file=sys.stderr)
            return 1
        planned.append((name, [d.id for d in client.collection(name).stream()]))

    # What a rescan wrote into the reference collection. Read here so the dry
    # run reports it before --confirm acts on it, exactly like the deletions.
    created, annotated = [], []
    for snapshot in client.collection("findings").stream():
        disposition = rescan_disposition(snapshot.to_dict() or {})
        if disposition == "created":
            created.append(snapshot.id)
        elif disposition == "annotated":
            annotated.append(snapshot.id)

    total = sum(len(ids) for _, ids in planned)
    print("\nDerived state reset")
    print("Rebuildable by re-running chase. Nothing else is touched.\n")
    for name, ids in planned:
        print(f"  {name:12} {len(ids):4} documents")
    print(f"\n  {'total':12} {total:4} documents")

    print("\nWritten by a rescan, and undone with it:")
    print(f"  {'findings':12} {len(created):4} created by a rescan, removed")
    print(f"  {'findings':12} {len(annotated):4} seeded, resolution fields stripped "
          f"and status back to {SEEDED_STATUS}")
    print(f"  {'':12} {'':4} seeded findings are never deleted")

    print("\nNot touched:")
    for name, why in sorted(PROTECTED.items()):
        if name == "findings":
            # Listing it as untouched would be false: the pass above strips
            # what a rescan wrote here. It is still protected in the sense
            # that matters -- no seeded finding is ever deleted -- and saying
            # only "not touched" would misdescribe the script to the person
            # deciding whether to run it.
            print(f"  {name:12} {why}; never deleted, rescan fields undone above")
            continue
        print(f"  {name:12} {why}")

    if not args.confirm:
        print("\nDry run. Re-run with --confirm to delete.")
        return 0

    deleted = 0
    for name, ids in planned:
        collection = client.collection(name)
        for doc_id in ids:
            collection.document(doc_id).delete()
            deleted += 1

    findings = client.collection("findings")

    # Findings a rescan created. Only these, and only ever these: the marker
    # is written by the rescan ingest path and by nothing else, so a seeded
    # finding cannot carry it and cannot be reached from here.
    for doc_id in created:
        findings.document(doc_id).delete()
        deleted += 1

    # Seeded findings a rescan annotated. The document stays; the fields it
    # added come off and the status goes back to what the seed wrote.
    stripped = 0
    for doc_id in annotated:
        findings.document(doc_id).update(
            {field: firestore.DELETE_FIELD for field in RESCAN_FIELDS}
            | {"status": SEEDED_STATUS}
        )
        stripped += 1

    print(f"\nDeleted {deleted} documents.")
    print(f"Stripped rescan fields from {stripped} seeded findings.")
    print("Run chase again to rebuild the clocks:")
    print("  SIM_CLOCK_MODE=sim ./scripts/chase.sh --cycle N --advance-days 8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
