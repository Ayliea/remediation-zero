# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""The exception stage: record risk acceptances, and sweep for lapsed ones.

The sweep is what makes a TTL mean anything. Without it an acceptance expires
in a field nobody reads. `scripts/exception.py` and the scheduled worker call
this in the cloud; the local edition calls it with its own `Ports`.

An acceptance of a KEV entry needs a person's explicit approval, and a
refused one goes to the human queue rather than vanishing.

Standard library only: nothing here imports a cloud SDK.
"""
import json
import logging
from typing import Any, Optional

from engine.ports import Ports
from tools.enrichment import EnrichmentCache, enrich_finding, finding_cves
from tools.docstore import FieldFilter
from tools.exception_store import ExceptionWriter
from tools.idempotency import fold_finding_id
from tools.exceptions import Exception_, ExceptionAction, next_action

logger = logging.getLogger("remediation_zero.exceptions")


class NoSuchFinding(LookupError):
    """An acceptance named a finding that is not in `findings`."""


def _log(event: str, cycle_id: str, finding_id: str, **fields) -> None:
    logger.info(json.dumps(
        {"event": event, "cycle_id": cycle_id, "finding_id": finding_id, **fields},
        sort_keys=True, default=str))


def _writer(ports: Ports) -> ExceptionWriter:
    return ExceptionWriter(store=ports.journal, client=ports.docs, clock=ports.clock)


def run_sweep(ports: Ports, cycle: int) -> dict[str, int]:
    """Reopen every risk acceptance whose TTL has lapsed, and report what it did.

    The clock in `ports` is the authoritative one: a caller that advanced it
    passes it here rather than this stage building a second clock.
    """
    clock = ports.clock
    writer = _writer(ports)

    cycle_id = f"cycle-{cycle:03d}"
    stamp = clock.now()

    _log("sweep_started", cycle_id, "-", sim_ts=stamp.sim_ts,
         sim_ahead_days=round((stamp.sim_ts - stamp.real_ts) / 86400, 2))
    actions: dict[str, int] = {}
    for snapshot in ports.docs.collection("exceptions").stream():
        data = snapshot.to_dict()
        exception = Exception_(
            finding_id=data["finding_id"],
            accepted_by=data.get("accepted_by", "unknown"),
            reason=data.get("reason", ""),
            accepted_sim_ts=data["accepted_sim_ts"],
            ttl_days=int(data["ttl_days"]),
            reopened=bool(data.get("reopened", False)),
        )
        action = next_action(exception, stamp.sim_ts)
        actions[action.value] = actions.get(action.value, 0) + 1
        if action is ExceptionAction.REOPEN:
            result = writer.reopen(exception, cycle=cycle, now_sim_ts=stamp.sim_ts)
            _log("acceptance_expired", cycle_id, exception.finding_id,
                 ttl_days=exception.ttl_days,
                 accepted_by=exception.accepted_by, result=result)
    _log("sweep_finished", cycle_id, "-", actions=actions)
    return actions


_SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})
_PERSON_APPROVABLE = frozenset({"unreviewed", "held_for_approval"})


def _decided_severity(ports: Ports, finding_id: str) -> str:
    """The severity of the finding's NEWEST decision, if that one was reviewed.

    Newest by (cycle, sim_ts, document id: ties are broken deterministically), of any outcome: a later unreviewed, rejected or
    unavailable proposal supersedes an older ratified one, and an older
    decision is never consulted. Reviewed means ratified, or unreviewed / held
    with a person's approval. Not reviewed, no proposed severity, or a value
    outside the known severities is "critical", so the gate fails closed.
    """
    rows = [(snap.id, snap.to_dict() or {}) for snap in ports.docs.collection(
        "decisions").where(filter=FieldFilter("finding_id", "==", finding_id)).stream()]
    if not rows:
        return "critical"
    doc_id, newest = max(rows, key=lambda r: (r[1].get("cycle") or 0, r[1].get("sim_ts") or 0, r[0]))
    outcome = newest.get("outcome")
    reviewed = outcome == "ratified" or (
        outcome in _PERSON_APPROVABLE
        and ports.docs.collection("approvals").document(doc_id).get().exists)
    value = newest.get("proposed_severity")
    value = value.strip().lower() if isinstance(value, str) else ""
    return value if reviewed and value in _SEVERITIES else "critical"


def accept(ports: Ports, finding_id: str, ttl_days: int, by: str, reason: str,
           cycle: int, *, approved_by_human: bool = False,
           enrichment: Optional[Any] = None) -> str:
    """Record one risk acceptance and return the writer's result.

    Raises `NoSuchFinding` before anything is written when the finding is
    unknown. Raises `ValueError` when the acceptance is refused; the refusal
    has already been routed to the human queue under its own key.
    `enrichment` defaults to the on-disk cache; KEV membership comes from it.
    """
    cycle_id = f"cycle-{cycle:03d}"
    # Typed by a person, so in whatever case: findings are filed under the folded id.
    # A blank id is no finding; ValueError is reserved for a routed refusal.
    if not isinstance(finding_id, str) or not finding_id.strip():
        raise NoSuchFinding("no such finding: (blank)")
    finding_id = fold_finding_id(finding_id)
    finding = ports.docs.collection("findings").document(finding_id).get().to_dict()
    if not finding:
        raise NoSuchFinding(f"no such finding: {finding_id}")
    cache = enrichment if enrichment is not None else EnrichmentCache()
    # No KEV source: membership is unknown (None), which the acceptance rules
    # refuse without a person. The getattr(..., True) fallback exists only for
    # test fakes; production always passes an EnrichmentCache, which has has_kev.
    # A finding with no CVE cannot be checked against KEV at all: in_kev is
    # False, and the acceptance rule is the decided severity instead. With
    # several CVEs, in_kev is True if any one of them is.
    no_cve_severity = None
    if not finding_cves(finding):
        in_kev = False
        no_cve_severity = _decided_severity(ports, finding_id)
    else:
        in_kev = (enrich_finding(cache, finding).in_kev
                  if getattr(cache, "has_kev", True) else None)
    try:
        result = _writer(ports).accept(
            finding_id=finding_id, cycle=cycle, accepted_by=by,
            reason=reason, ttl_days=ttl_days, in_kev=in_kev,
            approved_by_human=approved_by_human,
            no_cve_severity=no_cve_severity,
        )
        _log("risk_accepted", cycle_id, finding_id, ttl_days=ttl_days,
             in_kev=in_kev, approved_by_human=approved_by_human,
             result=result)
    except ValueError as exc:
        _log("acceptance_refused", cycle_id, finding_id, in_kev=in_kev,
             reason=str(exc), routed_to="human_queue")
        raise
    return result
