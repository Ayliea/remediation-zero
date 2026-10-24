# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""A person's approval of a decision the fleet could not ratify on its own.

`approve` records the approval and changes nothing else: the decision keeps
its outcome, models and review independence exactly as recorded. Only an
`unreviewed` or `held_for_approval` decision can be approved; a ratified,
rejected or unavailable one is refused before any write.

`assign_approved` is what the next cycle run does with it: each approved
decision that has no assignment yet goes through `assign_if_ratified` with
its approval, which logs `approved_by_person` and assigns it. Both are keyed
on the finding, the action and the decision's own cycle, so repeating either
has no second effect.

Standard library only.
"""
import json
import logging

from engine.ports import Ports
from engine.triage_cycle import assign_if_ratified
from tools.assignments import AssignmentWriter
from tools.decisions import DecisionWriter
from tools.docstore import AlreadyExists, FieldFilter
from tools.idempotency import IdempotencyGuard, derive_record

logger = logging.getLogger("remediation_zero.approve")

COLLECTION = "approvals"
APPROVABLE = ("unreviewed", "held_for_approval")
MAX_NAME = 200


class ApprovalRefused(ValueError):
    """The approval was refused; nothing was written."""


class InvalidFindingId(ApprovalRefused):
    """The finding id is malformed; its message is printed as is."""


def approve(ports: Ports, finding_id: str, cycle: int, by: str) -> str:
    """Record `by`'s approval of the decision for `finding_id` in `cycle`.

    Returns the approval id, which is the decision id. A repeat returns the
    same id and writes nothing; the first approval is the one kept.
    """
    if (not isinstance(by, str) or not by.strip() or len(by) > MAX_NAME
            or any(ch in by for ch in "\r\n")):
        raise ApprovalRefused("give the approver's name with --by (one line, at most 200 characters)")
    try:
        key = derive_record(finding_id, "approval", cycle)  # validates both
    except ValueError:
        raise InvalidFindingId(f"invalid finding id: {finding_id}") from None
    decision_id = f"{key.finding_id}-c{key.cycle:03d}"
    snapshot = ports.docs.collection("decisions").document(decision_id).get()
    if not snapshot.exists:
        raise ApprovalRefused(f"no decision {decision_id}: run that cycle first")
    decision = snapshot.to_dict() or {}
    outcome = decision.get("outcome")
    if outcome not in APPROVABLE:
        raise ApprovalRefused(f"decision {decision_id} is {outcome}; only an unreviewed "
                              "or held decision can be approved")
    finding = ports.docs.collection("findings").document(key.finding_id).get().to_dict() or {}
    if finding.get("status") != "open":
        raise ApprovalRefused(f"finding {key.finding_id} is not open; there is nothing to approve")
    newer = [d.id for d in ports.docs.collection("decisions").where(
                 filter=FieldFilter("finding_id", "==", key.finding_id)).stream()
             if ((d.to_dict() or {}).get("sim_ts") or 0) > (decision.get("sim_ts") or 0)]
    if newer:
        raise ApprovalRefused(f"decision {decision_id} has been superseded by {sorted(newer)[-1]}; "
                              "approve the newer decision instead")

    @IdempotencyGuard(ports.journal).protects(action="approval")
    def _write(*, finding_id: str, cycle: int) -> str:
        stamp = ports.clock.now()
        try:
            ports.docs.collection(COLLECTION).document(decision_id).create({
                "finding_id": finding_id, "cycle": cycle, "decision_id": decision_id,
                "approved_by": by.strip(), "real_ts": stamp.real_ts, "sim_ts": stamp.sim_ts})
        except AlreadyExists:
            pass  # a resumed call after the write: the first approval stands
        return decision_id

    result = _write(finding_id=key.finding_id, cycle=key.cycle)
    logger.info(json.dumps({"event": "approval_recorded", "finding_id": key.finding_id,
                            "cycle_id": f"cycle-{key.cycle:03d}", "decision_id": result},
                           sort_keys=True))
    return result


def assign_approved(ports: Ports) -> list:
    """Assign every approved decision not yet assigned; return their ids.

    Runs with the triage stage's ports, which may write `assignments`.
    """
    writer = DecisionWriter(store=ports.journal, client=ports.docs, clock=ports.clock)
    assigner = AssignmentWriter(store=ports.journal, client=ports.docs, clock=ports.clock)
    assigned = []
    for snapshot in sorted(ports.docs.collection(COLLECTION).stream(), key=lambda s: s.id):
        approval = snapshot.to_dict() or {}
        decision_id = approval.get("decision_id")
        if not decision_id or ports.docs.collection("assignments").document(decision_id).get().exists:
            continue
        decision = writer.restore(approval["finding_id"], approval["cycle"])
        if decision is None:
            continue
        result = assign_if_ratified(ports, decision, approval["cycle"],
                                    assigner=assigner, approval=approval)
        if result is not None:
            assigned.append(result[0])
    return assigned
