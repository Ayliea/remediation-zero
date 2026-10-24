# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Read-only audit of complete, consistent exported snapshots. No cloud clients."""
import math

from tools.adjudication import AdjudicationOutcome, Proposal, Verdict


def _validate(document_id, doc):
    finding_id, cycle = doc["finding_id"], doc["cycle"]
    if not isinstance(finding_id, str) or not finding_id.strip():
        raise ValueError("invalid finding identity")
    if isinstance(cycle, bool) or not isinstance(cycle, int) or cycle < 0:
        raise ValueError("invalid cycle")
    if document_id != f"{finding_id.strip().upper()}-c{cycle:03d}":
        raise ValueError("decision ID mismatch")
    outcome = AdjudicationOutcome(doc["outcome"])
    attempts = doc["attempts"]
    if isinstance(attempts, bool) or not isinstance(attempts, int) or not 0 <= attempts <= 2:
        raise ValueError("invalid attempts")
    for field in ("real_ts", "sim_ts"):
        value = doc[field]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise ValueError("invalid timestamp")
    verdicts = [Verdict(**v) for v in doc["verdicts"]]
    if len(verdicts) > attempts:
        raise ValueError("too many verdicts")
    if doc["proposed_severity"] is not None:
        Proposal(finding_id, doc["proposed_severity"], doc["proposed_sla_days"],
                 doc["proposed_remediation"], tuple(doc["cited_evidence"]), doc["rationale"])
    elif outcome is AdjudicationOutcome.RATIFIED:
        raise ValueError("ratified decision has no proposal")
    if outcome is AdjudicationOutcome.RATIFIED and (not verdicts or not verdicts[-1].ratified):
        raise ValueError("ratified outcome has no ratification")
    if outcome is not AdjudicationOutcome.RATIFIED and any(v.ratified for v in verdicts):
        raise ValueError("terminal failure contradicts ratification")
    return outcome


def audit_recovery_snapshot(decisions, human_queue):
    """Return per-record classifications; never repair or infer missing evidence."""
    results, linked = [], set()
    for document_id, doc in decisions.items():
        try:
            outcome = _validate(document_id, doc)
            expected = (f"reviewer-unavailable-{document_id}"
                        if outcome is AdjudicationOutcome.UNAVAILABLE else document_id)
            matches = []
            for queue_id, entry in human_queue.items():
                if (queue_id in {document_id, f"reviewer-unavailable-{document_id}"}
                    or entry.get("decision_id") == document_id
                    or (entry.get("kind") in {"reviewer_unavailable", "cycle_failure"}
                        and entry.get("finding_id") == doc["finding_id"]
                        and entry.get("cycle") == doc["cycle"])):
                    matches.append((queue_id, entry))
                    linked.add(queue_id)
            if not matches:
                status = "no_action" if outcome is AdjudicationOutcome.RATIFIED else "repair_candidate"
                reason = "no escalation required" if status == "no_action" else "terminal decision missing escalation"
            elif len(matches) != 1 or outcome is AdjudicationOutcome.RATIFIED:
                status, reason = "manual_review", "duplicate or contradictory escalation"
            else:
                queue_id, entry = matches[0]
                consistent = (queue_id == expected and entry.get("decision_id") == document_id
                              and entry.get("finding_id") == doc["finding_id"]
                              and entry.get("cycle") == doc["cycle"]
                              and entry.get("verdicts") == doc["verdicts"])
                status = "no_action" if consistent else "manual_review"
                reason = "matching evidence" if consistent else "escalation identity/evidence mismatch"
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            status, reason = "manual_review", f"invalid decision evidence: {exc}"
        results.append({"decision_id": document_id, "status": status, "reason": reason})
    for queue_id, entry in human_queue.items():
        if queue_id not in linked and (entry.get("decision_id") or entry.get("kind") in {"reviewer_unavailable", "cycle_failure"}):
            results.append({"queue_id": queue_id, "status": "manual_review", "reason": "unlinked escalation; cannot reconstruct decision"})
    return results
