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
from dataclasses import dataclass, fields, replace
from typing import Any, Optional

from engine.ports import Ports
from tools import inference
from tools.adjudication import Adjudication
from tools.assignments import AssignmentWriter
from tools.cycles import merge_cycle_record
from tools.decisions import DecisionWriter
from tools.docstore import AlreadyExists, FieldFilter
from tools.enrichment import Enrichment, enrich_finding, finding_cves
from tools.idempotency import derive_key
from tools.guardrail import NoGuard
from tools.model_armor import ArmorVerdict, apply_verdict
from tools.ownership import Assignment, resolve_owner

logger = logging.getLogger("remediation_zero.cycle")

NO_PROPOSER = "no proposer configured: set one in Settings, then run the cycle again"
FAILED_RUNS = "failed_runs"
#: The prefix tools.adjudication.adjudicate writes when triage raised a
#: CapacityError: f"triage failed: {type(exc).__name__}: {exc}".
CAPACITY_TRIAGE_NOTE = "triage failed: CapacityError"


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


def pending_findings(docs) -> list:
    """Finding ids awaiting triage, sorted: the local edition's cycle scope.

    Pending means status "open" and either no decision in any cycle, or an
    SLA clock the exception sweep set to "reopened_pending_triage" when a
    risk acceptance lapsed, until a decision newer (by `sim_ts`) than the
    exception's `reopened_sim_ts` exists. So a lapsed finding is re-triaged
    once, even when that re-triage ends held or unreviewed. A finding regressed by a rescan already has a
    decision; chase reopens its ticket, as in the cloud. The cloud passes
    its own explicit window and never calls this.

    An outage is not an answer (Ruling 39): a finding whose newest decision
    is `unavailable`, or `human_queue` because triage hit a CapacityError,
    is pending again in every later cycle until a model answers.
    """
    latest: dict = {}  # finding_id -> newest decision sim_ts
    newest: dict = {}  # finding_id -> (sim_ts, cycle, row) of the newest decision
    for d in docs.collection("decisions").stream():
        row = d.to_dict() or {}
        finding_id, sim_ts = row.get("finding_id"), row.get("sim_ts") or 0
        latest[finding_id] = max(latest.get(finding_id, sim_ts), sim_ts)
        rank = (sim_ts, row.get("cycle") or 0)
        if finding_id not in newest or rank >= newest[finding_id][:2]:
            newest[finding_id] = (*rank, row)

    def outage(finding_id) -> bool:
        row = newest[finding_id][2]
        return (row.get("outcome") == "unavailable"
                or (row.get("outcome") == "human_queue"
                    and str(row.get("note") or "").startswith(CAPACITY_TRIAGE_NOTE)))
    reopened = {(s.to_dict() or {}).get("finding_id") for s in
                docs.collection("sla_clocks").where(
                    filter=FieldFilter("status", "==", "reopened_pending_triage")).stream()}

    def awaits_retriage(finding_id) -> bool:
        exception = docs.collection("exceptions").document(finding_id).get().to_dict() or {}
        reopened_at = exception.get("reopened_sim_ts")
        return reopened_at is None or latest[finding_id] <= reopened_at

    open_ids = {s.id for s in docs.collection("findings").where(
        filter=FieldFilter("status", "==", "open")).stream()}
    return sorted(f for f in open_ids
                  if f not in latest or outage(f)
                  or (f in reopened and awaits_retriage(f)))


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
    # Kept so the cloud read pattern is identical; its action= literal is the
    # anchor tests/test_cycle_script.py checks against the writer's key.
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
        ports, finding, cycle, enrich_finding(enrichment, finding))
    if verdict.blocked or not verdict.screened:
        _log("untrusted_text_screened", cycle_id, finding_id,
             blocked=verdict.blocked, screened=verdict.screened,
             confidence=verdict.confidence, reasons=list(verdict.reasons))

    _log("triage_started", cycle_id, finding_id, cve_id=finding.get("cve_id"),
         cve_ids=finding_cves(finding), in_kev=enriched.in_kev, epss=enriched.epss_score)

    try:
        adjudication = triage_and_review(ports, finding, asset, enriched, cycle,
                                         writer=writer, adapters=adapters,
                                         screening=verdict)
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
    # Named, never hidden inside "ratified" (Ruling 41). The cloud is always
    # cross family, so its outcomes never carry this key.
    if (adjudication.outcome.value == "ratified"
            and adjudication.review_independence == "same_family"):
        outcomes["ratified_same_family"] = outcomes.get("ratified_same_family", 0) + 1

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


@dataclass(frozen=True)
class StrictNameVerdict(ArmorVerdict):
    """A no-guard verdict whose test name was shown because it is plain text (D1).

    Local only: the decision record gains `nvt_name_unscreened_strict`, so the
    record says the name was shown unscreened under the strict rule.
    """

    nvt_name_unscreened_strict: bool = True


def screen_finding(ports: Ports, finding: dict, cycle: int,
                   enrichment: Enrichment) -> tuple[dict, Enrichment, ArmorVerdict]:
    """The untrusted-content boundary, crossed before any model sees the text.

    Both scanner prose and cached vendor advisory prose originated outside
    this system. Screen them together before either model sees either one;
    structured scores and booleans remain typed data rather than instructions.
    """
    raw_comment = finding.get("scanner_comment") or ""
    raw_description = enrichment.description or ""
    raw_name = finding.get("nvt_name") or ""
    boundary_text = (
        f"SCANNER COMMENT\n{raw_comment}\n\n"
        f"NVD DESCRIPTION\n{raw_description}"
    )
    if raw_name:  # only Greenbone findings carry it; others screen as before
        boundary_text += f"\n\nNVT NAME\n{raw_name}"
    verdict = ports.guard.screen(boundary_text)
    finding = dict(finding)
    finding.pop(inference.PLAIN_NAME_KEY, None)  # only this function may set it
    finding["scanner_comment"] = apply_verdict(raw_comment, verdict)
    if raw_name:
        finding["nvt_name"] = apply_verdict(raw_name, verdict)
        # D1: with no guard configured at all (not a guard that failed), a
        # no-CVE finding's test name that is plain text under the strict rule
        # is shown in the header. A finding with a CVE already has evidence.
        plain = inference.plain_test_name(raw_name)
        if (isinstance(ports.guard, NoGuard) and plain is not None
                and not finding_cves(finding)
                and not inference.is_legacy_finding(finding)):
            finding[inference.PLAIN_NAME_KEY] = plain
            verdict = StrictNameVerdict(**{f.name: getattr(verdict, f.name)
                                           for f in fields(ArmorVerdict)})
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
                      cycle: int, *, screening: ArmorVerdict,
                      writer: Optional[DecisionWriter] = None,
                      adapters: Optional[tuple] = None,
                      vertex_client: Any = None) -> Adjudication:
    """Triage and adversarial review, journalled so a resume never pays twice.

    `finding` and `enrichment` must already have crossed `screen_finding`, and
    `screening` is that crossing's verdict. It is required so no path can
    record a decision without saying whether its untrusted text was screened.
    """
    _require_proposer(ports)
    proposer, reviewer = (adapters if adapters is not None
                          else build_adapters(ports, vertex_client=vertex_client))
    if writer is None:
        writer = DecisionWriter(store=ports.journal, client=ports.docs, clock=ports.clock)
    finding_id = finding["finding_id"]
    rendered = inference.render_finding(finding, asset, enrichment)
    legacy = inference.is_legacy_finding(finding)  # one decision: prompt and fingerprint
    return writer.adjudicate_once(
        finding,
        triage=lambda _f: inference.propose(
            rendered, proposer,
            finding_id=finding_id, retry=False, legacy=legacy,
        ),
        review=None if reviewer is None else lambda _f, p: inference.review(
            rendered + "\n\nPROPOSAL\n" + json.dumps(
                {"severity": p.severity, "sla_days": p.sla_days,
                 "remediation": p.remediation, "evidence": list(p.evidence),
                 "rationale": p.rationale}, indent=2),
            reviewer, retry=False),
        cycle=cycle,
        context=inference.inference_fingerprint(
            rendered, ports.roles, legacy=legacy),
        roles=ports.roles,
        screening=screening,
    )


def assign_if_ratified(ports: Ports, adjudication: Adjudication, cycle: int, *,
                       finding: Optional[dict] = None, assets: Optional[dict] = None,
                       owners: Optional[dict] = None,
                       assigner: Optional[AssignmentWriter] = None,
                       approval: Optional[dict] = None,
                       ) -> Optional[tuple[str, Assignment]]:
    """(assignment_id, assignment) for a ratified decision, else None.

    Only a ratified decision proceeds to ownership. A finding in the human
    queue is waiting on a person, and assigning it would start an SLA clock
    against a decision nobody has made yet.

    The one other way through is a person's approval (`approval`, the local
    edition's `approvals/<decision_id>` record) of an unreviewed or held
    decision. The decision itself is not changed: its outcome, models and
    review independence stay exactly as recorded, and the approval is a
    separate record. The cloud path never passes one.
    """
    decision_id = f"{adjudication.finding_id}-c{cycle:03d}"
    if approval is not None and approval.get("decision_id") != decision_id:
        approval = None
    if adjudication.outcome.value == "ratified":
        return _assign(ports, adjudication, cycle, finding, assets, owners, assigner)
    elif approval is not None and adjudication.outcome.value in ("unreviewed", "held_for_approval"):
        _log("approved_by_person", f"cycle-{cycle:03d}", adjudication.finding_id,
             decision_id=decision_id, outcome=adjudication.outcome.value,
             review_independence=adjudication.review_independence)
        return _assign(ports, adjudication, cycle, finding, assets, owners, assigner)
    return None


def _assign(ports, adjudication, cycle, finding, assets, owners, assigner):
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
    # No memory port (an edition that keeps none): nothing to file.
    if not prior and ports.memory is not None:
        filed = ports.memory.remember_cycle(
            cycle_id=cycle_id, counts=dict(outcomes),
            real_ts=finished.real_ts, sim_ts=finished.sim_ts,
        )
        _log("cycle_remembered", cycle_id, "-", filed=filed)

    _log("cycle_finished", cycle_id, "-", outcomes=outcomes,
         elapsed_real_s=round(finished.real_ts - started.real_ts, 1))
    return fresh
