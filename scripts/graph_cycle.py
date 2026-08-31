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

"""Run one finding through the delegation graph.

    ./scripts/graph.sh --cycle 60 --finding RZ-0330

Same lifecycle as scripts/cycle.py, expressed as an ADK Workflow rather than a
procedural loop. The routing lives in the graph, the retry and resume policy
live on the nodes, and each handler does one agent's work.
"""

import argparse
import asyncio
import json
import logging
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dotenv import load_dotenv
from google.adk import Runner
from google.adk.sessions import InMemorySessionService
from google.cloud import firestore
from google.genai import types

from agents.orchestrator.graph import (
    HUMAN_QUEUE, RATIFIED, UNAVAILABLE, CycleState, build_graph, describe,
)
from scripts import quiet_sdk_logging
from tools import review_models as rm
from tools.adjudication import (
    AdjudicationOutcome, CapacityError, Proposal, Verdict, adjudicate,
)
from tools.assignments import AssignmentWriter
from tools.clock import SimClock
from tools.decisions import DecisionWriter
from tools.enrichment import EnrichmentCache
from tools.model_armor import ModelArmor, apply_verdict
from tools.ownership import resolve_owner
from tools.store import FirestoreIdempotencyStore
from tools.telemetry import (cycle_id, configure_tracing, finding_span,
                            flush, set_outcome)

REPO_ROOT = Path(__file__).resolve().parents[1]
logger = logging.getLogger("remediation_zero.graph")


def _log(event: str, cycle_id: str, finding_id: str, **fields) -> None:
    logger.info(json.dumps(
        {"event": event, "cycle_id": cycle_id, "finding_id": finding_id, **fields},
        sort_keys=True, default=str))


def build_handlers(clients: dict) -> dict:
    """One callable per node. Each is one agent's responsibility, and nothing
    else's: none of them decides where the finding goes next."""
    db = clients["db"]
    clock = clients["clock"]
    cache = clients["cache"]
    genai_client = clients["genai"]
    armor = clients["armor"]
    armor_token = clients["armor_token"]
    writer = clients["decisions"]
    assigner = clients["assignments"]
    cycle_id = clients["cycle_id"]
    scratch = clients["scratch"]

    def screen(finding_id: str, cycle: int) -> str:
        finding = db.collection("findings").document(finding_id).get().to_dict() or {}
        asset = db.collection("assets").document(
            finding.get("asset_id", "")).get().to_dict() or {}
        enrichment = cache.enrich(finding.get("cve_id", ""))

        raw = finding.get("scanner_comment") or ""
        raw_description = enrichment.description or ""
        verdict = armor.screen(
            f"SCANNER COMMENT\n{raw}\n\nNVD DESCRIPTION\n{raw_description}",
            armor_token,
        )
        finding = dict(finding)
        finding["scanner_comment"] = apply_verdict(raw, verdict)
        enrichment = replace(
            enrichment, description=apply_verdict(raw_description, verdict)
        )

        scratch["rendered"] = rm.render_finding(finding, asset, enrichment)
        scratch["finding"] = finding
        _log("screened", cycle_id, finding_id,
             blocked=verdict.blocked, screened=verdict.screened,
             confidence=verdict.confidence)
        return "screened"

    def triage(finding_id: str, cycle: int) -> str:
        _log("triage_started", cycle_id, finding_id)
        return "proposed"

    def review(ctx, finding_id: str, cycle: int) -> str:
        """Triage and adversarial review, with the retry rule between them.

        Both halves live in this node because the retry is a property of the
        pair, not of either one: a rejected proposal is re-proposed, and that
        loop must not be expressible as a cycle in the graph.

        This is the only node that emits a route. A FunctionNode's return
        value is its output, not its branch: the branch is set on the context,
        and a node with conditional edges that never sets one ends its branch
        silently. That failure is quiet, so the route is set on every path
        through this function rather than only on the interesting ones.
        """
        rendered = scratch["rendered"]
        result = adjudicate(
            scratch["finding"],
            triage=lambda _f: rm.propose(
                rendered, clients["reasoning_model"], genai_client,
                finding_id=finding_id,
            ),
            review=lambda _f, p: rm.review(
                rendered + "\n\nPROPOSAL\n" + json.dumps(
                    {"severity": p.severity, "sla_days": p.sla_days,
                     "remediation": p.remediation, "evidence": list(p.evidence),
                     "rationale": p.rationale}, indent=2),
                clients["reviewer_model"], genai_client),
        )
        scratch["adjudication"] = result
        _log("adjudicated", cycle_id, finding_id,
             outcome=result.outcome.value, attempts=result.attempts,
             rejections=[v.reason[:120] for v in result.verdicts if not v.ratified])
        ctx.route = result.outcome.value
        return result.outcome.value

    def record(finding_id: str, cycle: int) -> str:
        document_id = writer.record(scratch["adjudication"], cycle=cycle)
        _log("decision_recorded", cycle_id, finding_id, decision_id=document_id)
        return "recorded"

    def assign(finding_id: str, cycle: int) -> str:
        owners = {o["owner_id"]: o for o in
                  (d.to_dict() for d in db.collection("owners").stream())}
        assets = {a["asset_id"]: a for a in
                  (d.to_dict() for d in db.collection("assets").stream())}
        assignment = resolve_owner(scratch["finding"], assets, owners)
        proposal = scratch["adjudication"].proposal
        assignment_id = assigner.record(
            assignment, cycle=cycle,
            sla_days=proposal.sla_days if proposal else None)
        _log("assigned", cycle_id, finding_id, owner_id=assignment.owner_id,
             needs_human=assignment.needs_human, assignment_id=assignment_id)
        return "assigned"

    def queue(finding_id: str, cycle: int) -> str:
        # The decision writer already appends to the human queue for this
        # outcome, so this node records the decision and nothing more.
        document_id = writer.record(scratch["adjudication"], cycle=cycle)
        _log("routed_to_human", cycle_id, finding_id, decision_id=document_id)
        return "queued"

    def unavailable(finding_id: str, cycle: int) -> str:
        """The reviewer could not be reached. Not a rejection, not a
        ratification, and deliberately its own destination."""
        stamp = clock.now()
        db.collection("human_queue").document(
            f"reviewer-unavailable-{finding_id}-c{cycle:03d}").set({
                "finding_id": finding_id, "cycle": cycle,
                "kind": "reviewer_unavailable",
                "reason": scratch["adjudication"].note or "reviewer unreachable",
                "real_ts": stamp.real_ts, "sim_ts": stamp.sim_ts})
        _log("reviewer_unavailable", cycle_id, finding_id)
        return "queued"

    return {"screen": screen, "triage": triage, "review": review,
            "record": record, "assign": assign, "queue": queue,
            "unavailable": unavailable}


async def run(finding_id: str, cycle: int) -> int:
    load_dotenv(REPO_ROOT / ".env")
    clock = SimClock.from_env()
    db = firestore.Client()
    store = FirestoreIdempotencyStore(client=db, clock=clock)

    clients = {
        "db": db, "clock": clock, "cache": EnrichmentCache(),
        "genai": rm._client(), "armor": ModelArmor(),
        "armor_token": subprocess.run(
            ["gcloud", "auth", "application-default", "print-access-token"],
            capture_output=True, text=True, check=False).stdout.strip(),
        "decisions": DecisionWriter(store=store, client=db, clock=clock),
        "assignments": AssignmentWriter(store=store, client=db, clock=clock),
        "reasoning_model": os.environ["REASONING_MODEL"],
        "reviewer_model": os.environ["REVIEWER_MODEL"],
        "cycle_id": cycle_id(cycle),
        "scratch": {},
    }

    traced = configure_tracing(os.environ.get("GOOGLE_CLOUD_PROJECT"))
    _log("tracing", clients["cycle_id"], finding_id, enabled=traced)

    workflow = build_graph(build_handlers(clients))
    print(describe(workflow))
    print()

    runner = Runner(
        node=workflow,
        app_name="remediation-zero",
        session_service=InMemorySessionService(),
        auto_create_session=True,
    )

    # One span for the whole finding. Every span ADK creates for a node, a
    # model call or a tool call nests inside it, which is what makes a single
    # finding's journey one readable trace rather than scattered fragments.
    with finding_span(finding_id, clients["cycle_id"]) as span:
        async for event in runner.run_async(
            user_id="orchestrator",
            session_id=f"graph-{cycle}-{finding_id}",
            state_delta={"finding_id": finding_id, "cycle": cycle, "outcome": ""},
            new_message=types.Content(role="user", parts=[types.Part(text=finding_id)]),
        ):
            if getattr(event, "error_message", None):
                _log("node_error", clients["cycle_id"], finding_id,
                     error=str(event.error_message)[:200])

        adjudication = clients["scratch"].get("adjudication")
        if adjudication is not None:
            set_outcome(span, adjudication.outcome.value)

    # Spans are batched, so a short-lived script would otherwise exit with its
    # trace still in memory. A cycle that ran but produced no trace looks
    # exactly like a cycle that never ran.
    flush()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cycle", type=int, required=True)
    parser.add_argument("--finding", required=True)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, stream=sys.stdout, format="%(message)s")
    quiet_sdk_logging("google.adk")

    return asyncio.run(run(args.finding, args.cycle))


if __name__ == "__main__":
    raise SystemExit(main())
