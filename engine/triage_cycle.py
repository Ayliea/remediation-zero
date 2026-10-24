# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""The triage-cycle stage: screen, triage, review, assign, close the cycle.

One body for both cloud paths and the local edition. `scripts/cycle.py` calls
`run_triage_cycle`; the handlers in `scripts/graph_cycle.py` call the step
functions one node at a time. Each edition supplies its parts through `Ports`.

Safe to re-run. Every decision write is keyed on the finding, the action and
the cycle number, so running the same cycle twice produces the same decisions
rather than a second copy of each. The stage never delivers anything; tracker
delivery belongs to chase.

Standard library only: nothing here imports a cloud SDK.
"""
import json
import logging
from dataclasses import replace
from typing import Any, Optional

from engine.ports import Ports
from tools import inference
from tools.adjudication import Adjudication
from tools.assignments import AssignmentWriter
from tools.cycles import merge_cycle_record
from tools.decisions import DecisionWriter
from tools.docstore import AlreadyExists
from tools.enrichment import Enrichment
from tools.idempotency import derive_key
from tools.model_armor import ArmorVerdict, apply_verdict
from tools.ownership import Assignment, resolve_owner

logger = logging.getLogger("remediation_zero.cycle")

NO_PROPOSER = "no proposer configured: set one in Settings, then run the cycle again"
FAILED_RUNS = "failed_runs"


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


def run_triage_cycle(ports: Ports, cycle: int, *, finding_ids: Optional[list] = None,
                     enrichment: Any, vertex_client: Any = None) -> dict:
    """Run one cycle over `finding_ids` (every finding when None).

    Returns this run's cycle record. A finding that raises stops the cycle:
    the failure is recorded when the edition asks for it, and re-raised.
    """
    # Refuse before any read-modify-write or model call (Ruling 21). A
    # misconfigured adapter also fails here, before the first log line.
    adapters = build_adapters(ports, vertex_client=vertex_client)
    writer = DecisionWriter(store=ports.journal, client=ports.docs, clock=ports.clock)
    assigner = AssignmentWriter(store=ports.journal, client=ports.docs, clock=ports.clock)
    if finding_ids is None:
        finding_ids = sorted(s.id for s in ports.docs.collection("findings").stream())

    cycle_id = f"cycle-{cycle:03d}"
    started = ports.clock.now()
    _log("cycle_started", cycle_id, "-", clock_mode=ports.clock.mode.value,
         limit=len(finding_ids), real_ts=started.real_ts, sim_ts=started.sim_ts)

    assets = {a["asset_id"]: a for a in
              (d.to_dict() for d in ports.docs.collection("assets").stream())}
    owners = {o["owner_id"]: o for o in
              (d.to_dict() for d in ports.docs.collection("owners").stream())}

    outcomes: dict[str, int] = {}

    for finding_id in finding_ids:
        try:
            _one_finding(ports, cycle, cycle_id, finding_id, enrichment, adapters,
                         writer, assigner, assets, owners, outcomes)
        except Exception as exc:
            _record_failure(ports, finding_id, cycle, cycle_id, exc)
            raise

    return close_cycle(ports, cycle, outcomes, finding_ids=finding_ids, started=started)


def _one_finding(ports, cycle, cycle_id, finding_id, enrichment, adapters,
                 writer, assigner, assets, owners, outcomes) -> None:
    snapshot = ports.docs.collection("findings").document(finding_id).get()
    if not snapshot.exists:
        _log("finding_missing", cycle_id, finding_id)
        return

    # Short-circuit before any model call, not just before the write.
    # The guard around the write is what makes the state correct, but it
    # only fires after triage and review have already run and been paid
    # for. Re-running a cycle should cost nothing, so the completed-call
    # record is checked here too.
    restored = writer.restore(finding_id, cycle)
    already = ports.journal.get(
        derive_key(finding_id=finding_id, action="decision", cycle=cycle)
    )
    if restored is not None:
        # A durable decision is not proof that downstream assignment ran.
        # Resume that idempotent effect without repeating paid inference.
        reconciled = assign_if_ratified(ports, restored, cycle, finding=snapshot.to_dict(),
                                        assets=assets, owners=owners, assigner=assigner)
        if reconciled is not None:
            assignment_id, assignment = reconciled
            _log("assignment_reconciled", cycle_id, finding_id,
                 assignment_id=assignment_id, needs_human=assignment.needs_human)
        _log("skipped_already_adjudicated", cycle_id, finding_id,
             decision_id=f"{finding_id}-c{cycle:03d}")
        outcomes["skipped"] = outcomes.get("skipped", 0) + 1
        return

    finding = snapshot.to_dict()
    asset = assets.get(finding["asset_id"], {})
    finding, enriched, verdict = screen_finding(
        ports, finding, cycle, enrichment.enrich(finding["cve_id"]))
    if verdict.blocked or not verdict.screened:
        _log("untrusted_text_screened", cycle_id, finding_id,
             blocked=verdict.blocked, screened=verdict.screened,
             confidence=verdict.confidence, reasons=list(verdict.reasons))

    _log("triage_started", cycle_id, finding_id, cve_id=finding["cve_id"],
         in_kev=enriched.in_kev, epss=enriched.epss_score)

    try:
        adjudication = triage_and_review(ports, finding, asset, enriched, cycle,
                                         writer=writer, adapters=adapters)
    except Exception as exc:
        # Model failures have durable evidence. Persistence failure must
        # stop execution for replay, never manufacture another escalation.
        _log("finding_failed", cycle_id, finding_id,
             error=f"{type(exc).__name__}: {exc}"[:300])
        raise

    document_id = writer.record(adjudication, cycle=cycle)
    adjudication = writer.restore(finding_id, cycle)
    outcomes[adjudication.outcome.value] = outcomes.get(
        adjudication.outcome.value, 0) + 1

    assigned = assign_if_ratified(ports, adjudication, cycle, finding=finding,
                                  assets=assets, owners=owners, assigner=assigner)
    if assigned is not None:
        assignment_id, assignment = assigned
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


def _record_failure(ports: Ports, finding_id: str, cycle: int, cycle_id: str,
                    exc: BaseException) -> None:
    """Ruling 3: the class name only, first failure kept, never masking `exc`."""
    if not ports.record_failed_runs:
        return
    try:
        stamp = ports.clock.now()
        ports.docs.collection(FAILED_RUNS).document(f"{finding_id}-c{cycle:03d}").create({
            "finding_id": finding_id, "cycle": cycle, "error_class": type(exc).__name__,
            "real_ts": stamp.real_ts, "sim_ts": stamp.sim_ts})
    except AlreadyExists:
        pass
    except Exception as write_error:  # noqa: BLE001 - must never mask `exc`
        _log("failed_run_not_recorded", cycle_id, finding_id,
             error=type(write_error).__name__)


def screen_finding(ports: Ports, finding: dict, cycle: int,
                   enrichment: Enrichment) -> tuple[dict, Enrichment, ArmorVerdict]:
    """The untrusted-content boundary, crossed before any model sees the text.

    Both scanner prose and cached vendor advisory prose originated outside
    this system. Screen them together before either model sees either one;
    structured scores and booleans remain typed data rather than instructions.
    """
    raw_comment = finding.get("scanner_comment") or ""
    raw_description = enrichment.description or ""
    boundary_text = (
        f"SCANNER COMMENT\n{raw_comment}\n\n"
        f"NVD DESCRIPTION\n{raw_description}"
    )
    verdict = ports.guard.screen(boundary_text)
    finding = dict(finding)
    finding["scanner_comment"] = apply_verdict(raw_comment, verdict)
    enrichment = replace(
        enrichment, description=apply_verdict(raw_description, verdict)
    )
    return finding, enrichment, verdict


def _require_proposer(ports: Ports) -> None:
    if ports.roles is None or ports.roles.proposer is None:
        raise ValueError(NO_PROPOSER)


def build_adapters(ports: Ports, *, vertex_client: Any = None) -> tuple:
    """(proposer, reviewer). No reviewer role: no adapter is built, and
    adjudication ends unreviewed."""
    _require_proposer(ports)
    roles = ports.roles
    proposer = roles.adapter("proposer", vertex_client=vertex_client)
    reviewer = (None if roles.independence() == "unreviewed"
                else roles.adapter("reviewer", vertex_client=vertex_client))
    return proposer, reviewer


def triage_and_review(ports: Ports, finding: dict, asset: dict, enrichment: Enrichment,
                      cycle: int, *, writer: Optional[DecisionWriter] = None,
                      adapters: Optional[tuple] = None,
                      vertex_client: Any = None) -> Adjudication:
    """Triage and adversarial review, journalled so a resume never pays twice.

    `finding` and `enrichment` must already have crossed `screen_finding`.
    """
    _require_proposer(ports)
    proposer, reviewer = (adapters if adapters is not None
                          else build_adapters(ports, vertex_client=vertex_client))
    if writer is None:
        writer = DecisionWriter(store=ports.journal, client=ports.docs, clock=ports.clock)
    finding_id = finding["finding_id"]
    rendered = inference.render_finding(finding, asset, enrichment)
    return writer.adjudicate_once(
        finding,
        triage=lambda _f: inference.propose(
            rendered, proposer,
            finding_id=finding_id, retry=False,
        ),
        review=None if reviewer is None else lambda _f, p: inference.review(
            rendered + "\n\nPROPOSAL\n" + json.dumps(
                {"severity": p.severity, "sla_days": p.sla_days,
                 "remediation": p.remediation, "evidence": list(p.evidence),
                 "rationale": p.rationale}, indent=2),
            reviewer, retry=False),
        cycle=cycle,
        context=inference.inference_fingerprint(rendered, ports.roles),
        roles=ports.roles,
    )


def assign_if_ratified(ports: Ports, adjudication: Adjudication, cycle: int, *,
                       finding: Optional[dict] = None, assets: Optional[dict] = None,
                       owners: Optional[dict] = None,
                       assigner: Optional[AssignmentWriter] = None,
                       ) -> Optional[tuple[str, Assignment]]:
    """(assignment_id, assignment) for a ratified decision, else None.

    Only a ratified decision proceeds to ownership. A finding in the human
    queue is waiting on a person, and assigning it would start an SLA clock
    against a decision nobody has made yet.
    """
    if adjudication.outcome.value == "ratified":
        if owners is None:
            owners = {o["owner_id"]: o for o in
                      (d.to_dict() for d in ports.docs.collection("owners").stream())}
        if assets is None:
            assets = {a["asset_id"]: a for a in
                      (d.to_dict() for d in ports.docs.collection("assets").stream())}
        if finding is None:
            finding = ports.docs.collection("findings").document(
                adjudication.finding_id).get().to_dict()
        if assigner is None:
            assigner = AssignmentWriter(store=ports.journal, client=ports.docs,
                                        clock=ports.clock)
        assignment = resolve_owner(finding, assets, owners)
        assignment_id = assigner.record(
            assignment, cycle=cycle,
            sla_days=adjudication.proposal.sla_days if adjudication.proposal else None)
        return assignment_id, assignment
    return None


def close_cycle(ports: Ports, cycle: int, outcomes: dict, *, finding_ids: list,
                started: Any) -> dict:
    """Write the cycle record, file it into memory once, and report it finished.

    Returns this run's record. Called only when every finding completed.
    """
    cycle_id = f"cycle-{cycle:03d}"
    finished = ports.clock.now()

    # The cycle record is the one write that is not keyed on a finding, so it
    # needs its own protection. A re-run adjudicates nothing and would
    # otherwise overwrite the original outcomes with {"skipped": n}, destroying
    # the record of what the cycle actually did. First run wins; later runs
    # append their timestamps and leave the outcomes alone.
    cycle_ref = ports.docs.collection("cycles").document(cycle_id)
    existing = cycle_ref.get()
    prior = existing.to_dict() if existing.exists else None
    fresh = {
        "cycle_id": cycle_id,
        "cycle": cycle,
        "finding_ids": finding_ids,
        "outcomes": outcomes,
        "clock_mode": ports.clock.mode.value,
        "started_real_ts": started.real_ts,
        "started_sim_ts": started.sim_ts,
        "finished_real_ts": finished.real_ts,
        "finished_sim_ts": finished.sim_ts,
    }
    cycle_ref.set(merge_cycle_record(prior, fresh))
    if prior:
        _log("cycle_rerun", cycle_id, "-", outcomes=outcomes,
             preserved_outcomes=prior.get("outcomes"))

    # File the cycle into memory before reporting it finished: the process
    # that ran this cycle exits, and the store keeps the rows, but the rows
    # are not context. A failure here is logged and does not fail the cycle.
    # Not on a re-run. A second recollection of a cycle that adjudicated
    # nothing would sit alongside the first and describe the same cycle as
    # having done nothing, which is the kind of memory that is worse than none.
    if not prior:
        filed = ports.memory.remember_cycle(
            cycle_id=cycle_id, counts=dict(outcomes),
            real_ts=finished.real_ts, sim_ts=finished.sim_ts,
        )
        _log("cycle_remembered", cycle_id, "-", filed=filed)

    _log("cycle_finished", cycle_id, "-", outcomes=outcomes,
         elapsed_real_s=round(finished.real_ts - started.real_ts, 1))
    return fresh
