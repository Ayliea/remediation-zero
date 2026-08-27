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

"""Run one remediation cycle.

Reads findings from Firestore, enriches them from the local cache, puts each
through triage and adversarial review, and records the adjudication.

Safe to re-run. Every decision write is keyed on the finding, the action and
the cycle number, so running the same cycle twice produces the same decisions
rather than a second copy of each.
"""

import argparse
import json
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dotenv import load_dotenv
from google.cloud import firestore

from tools import review_models as rm
from tools.adjudication import adjudicate
from tools.clock import SimClock
from tools.cycles import merge_cycle_record
from tools.assignments import AssignmentWriter
from tools.decisions import DecisionWriter
from tools.enrichment import EnrichmentCache
from tools.idempotency import derive_key
from tools.model_armor import ModelArmor, apply_verdict
from tools.ownership import resolve_owner
from tools.store import FirestoreIdempotencyStore

REPO_ROOT = Path(__file__).resolve().parents[1]

logger = logging.getLogger("remediation_zero.cycle")


def _log(event: str, cycle_id: str, finding_id: str, **fields) -> None:
    """Structured only. Every line carries the finding and the cycle, so one
    finding's journey is greppable end to end."""
    logger.info(
        json.dumps(
            {"event": event, "cycle_id": cycle_id, "finding_id": finding_id, **fields},
            sort_keys=True,
            default=str,
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cycle", type=int, required=True, help="cycle number")
    parser.add_argument("--limit", type=int, default=5, help="findings this cycle")
    parser.add_argument("--start", type=int, default=1, help="first finding index")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, stream=sys.stdout, format="%(message)s")
    # The SDKs log every request at INFO, which buries the structured cycle
    # log that is the actual observability surface.
    for noisy in ("httpx", "google_genai", "google.auth", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    load_dotenv(REPO_ROOT / ".env")

    import os

    clock = SimClock.from_env()
    client = firestore.Client()
    cache = EnrichmentCache()
    genai_client = rm._client()
    reasoning_model = os.environ["REASONING_MODEL"]
    reviewer_model = os.environ["REVIEWER_MODEL"]

    armor = ModelArmor()
    import subprocess
    armor_token = subprocess.run(
        ["gcloud", "auth", "application-default", "print-access-token"],
        capture_output=True, text=True, check=False).stdout.strip()

    store = FirestoreIdempotencyStore(client=client, clock=clock)
    writer = DecisionWriter(store=store, client=client, clock=clock)
    assigner = AssignmentWriter(store=store, client=client, clock=clock)

    cycle_id = f"cycle-{args.cycle:03d}"
    started = clock.now()
    _log("cycle_started", cycle_id, "-", clock_mode=clock.mode.value,
         limit=args.limit, real_ts=started.real_ts, sim_ts=started.sim_ts)

    finding_ids = [f"RZ-{i:04d}" for i in range(args.start, args.start + args.limit)]
    assets = {a["asset_id"]: a for a in
              (d.to_dict() for d in client.collection("assets").stream())}
    owners = {o["owner_id"]: o for o in
              (d.to_dict() for d in client.collection("owners").stream())}

    outcomes: dict[str, int] = {}

    for finding_id in finding_ids:
        snapshot = client.collection("findings").document(finding_id).get()
        if not snapshot.exists:
            _log("finding_missing", cycle_id, finding_id)
            continue

        # Short-circuit before any model call, not just before the write.
        # The guard around the write is what makes the state correct, but it
        # only fires after triage and review have already run and been paid
        # for. Re-running a cycle should cost nothing, so the completed-call
        # record is checked here too.
        already = store.get(
            derive_key(finding_id=finding_id, action="decision", cycle=args.cycle)
        )
        if already is not None:
            _log("skipped_already_adjudicated", cycle_id, finding_id,
                 decision_id=already.result)
            outcomes["skipped"] = outcomes.get("skipped", 0) + 1
            continue

        finding = snapshot.to_dict()
        asset = assets.get(finding["asset_id"], {})
        enrichment = cache.enrich(finding["cve_id"])

        # The untrusted-content boundary. The scanner comment is the only field
        # here that originated outside this system, and it is screened before
        # either model sees it. Everything else is trusted metadata written by
        # the seed script.
        raw_comment = finding.get("scanner_comment") or ""
        verdict = armor.screen(raw_comment, armor_token)
        finding = dict(finding)
        finding["scanner_comment"] = apply_verdict(raw_comment, verdict)
        if verdict.blocked or not verdict.screened:
            _log("untrusted_text_screened", cycle_id, finding_id,
                 blocked=verdict.blocked, screened=verdict.screened,
                 confidence=verdict.confidence, reasons=list(verdict.reasons))

        rendered = rm.render_finding(finding, asset, enrichment)

        _log("triage_started", cycle_id, finding_id, cve_id=finding["cve_id"],
             in_kev=enrichment.in_kev, epss=enrichment.epss_score)

        try:
            adjudication = adjudicate(
                finding,
                triage=lambda _f: rm.propose(rendered, reasoning_model, genai_client),
                review=lambda _f, p: rm.review(
                    rendered + "\n\nPROPOSAL\n" + json.dumps(
                        {"severity": p.severity, "sla_days": p.sla_days,
                         "remediation": p.remediation, "evidence": list(p.evidence),
                         "rationale": p.rationale}, indent=2),
                    reviewer_model, genai_client),
            )
        except Exception as exc:
            # One finding failing must not take the cycle down, and it must not
            # vanish either. It goes to a person with what is known about why.
            _log("finding_failed", cycle_id, finding_id,
                 error=f"{type(exc).__name__}: {exc}"[:300])
            client.collection("human_queue").document(
                f"failed-{finding_id}-c{args.cycle:03d}").set({
                    "finding_id": finding_id, "cycle": args.cycle,
                    "kind": "cycle_failure",
                    "reason": f"Adjudication did not complete: "
                              f"{type(exc).__name__}: {exc}"[:400],
                    "real_ts": clock.now().real_ts, "sim_ts": clock.now().sim_ts})
            outcomes["failed"] = outcomes.get("failed", 0) + 1
            continue

        document_id = writer.record(adjudication, cycle=args.cycle)
        outcomes[adjudication.outcome.value] = outcomes.get(
            adjudication.outcome.value, 0) + 1

        # Only a ratified decision proceeds to ownership. A finding in the
        # human queue is waiting on a person, and assigning it would start an
        # SLA clock against a decision nobody has made yet.
        if adjudication.outcome.value == "ratified":
            assignment = resolve_owner(finding, assets, owners)
            assignment_id = assigner.record(
                assignment, cycle=args.cycle,
                sla_days=adjudication.proposal.sla_days if adjudication.proposal else None)
            _log("assigned", cycle_id, finding_id,
                 owner_id=assignment.owner_id, team=assignment.team,
                 needs_human=assignment.needs_human,
                 assignment_id=assignment_id, reason=assignment.reason[:120])

        _log("adjudicated", cycle_id, finding_id,
             outcome=adjudication.outcome.value,
             attempts=adjudication.attempts,
             severity=adjudication.proposal.severity if adjudication.proposal else None,
             decision_id=document_id,
             rejections=[v.reason[:120] for v in adjudication.verdicts if not v.ratified])

    finished = clock.now()

    # The cycle record is the one write that is not keyed on a finding, so it
    # needs its own protection. A re-run adjudicates nothing and would
    # otherwise overwrite the original outcomes with {"skipped": n}, destroying
    # the record of what the cycle actually did. First run wins; later runs
    # append their timestamps and leave the outcomes alone.
    cycle_ref = client.collection("cycles").document(cycle_id)
    existing = cycle_ref.get()
    prior = existing.to_dict() if existing.exists else None
    fresh = {
        "cycle_id": cycle_id,
        "cycle": args.cycle,
        "finding_ids": finding_ids,
        "outcomes": outcomes,
        "clock_mode": clock.mode.value,
        "started_real_ts": started.real_ts,
        "started_sim_ts": started.sim_ts,
        "finished_real_ts": finished.real_ts,
        "finished_sim_ts": finished.sim_ts,
    }
    cycle_ref.set(merge_cycle_record(prior, fresh))
    if prior:
        _log("cycle_rerun", cycle_id, "-", outcomes=outcomes,
             preserved_outcomes=prior.get("outcomes"))

    _log("cycle_finished", cycle_id, "-", outcomes=outcomes,
         elapsed_real_s=round(finished.real_ts - started.real_ts, 1))
    print(json.dumps({"cycle": cycle_id, "outcomes": outcomes}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
