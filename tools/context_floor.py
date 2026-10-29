# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""The fixed floor: Crown jewels under active exploitation is never ranked below High.

The owner's decision (business-context design, 2026-10-29). The model and the reviewer
decide everything above the floor; this check runs after adjudication, is deterministic and
needs no model, so it can be tested and checked by someone who did not write it.

When the host's criticality is high (Crown jewels) and any of the finding's CVEs is in CISA
KEV, the effective severity is at least `high` and the SLA at most FLOOR_SLA_DAYS, or the
days left until the KEV due date when that date is still in the future and sooner. KEV's
older due dates are years past and would set a one-day SLA on almost everything, so a past
date does not tighten anything. A finding whose KEV status is unknown (no list available)
is not floored, and the record says why.

The proposal is never edited: the reviewer ratified what the model proposed, and the record
keeps both. The floor is a separate field (tools.decisions.effective_severity reads it).
Standard library only. `now_sim_ts` comes from SimClock.
"""
import dataclasses
from datetime import datetime, timezone
from math import ceil
from typing import Any, Mapping, Optional

from tools.adjudication import Adjudication

FLOOR_SLA_DAYS = 14
_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _days_until(due: Optional[str], now_sim_ts: float) -> Optional[int]:
    try:
        when = datetime.strptime(due or "", "%Y-%m-%d").replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None
    days = ceil((when - now_sim_ts) / 86400)
    return days if days >= 1 else None


def apply_floor(adjudication: Adjudication, facts: Mapping[str, Any], enrichment: Any,
                now_sim_ts: float) -> Adjudication:
    """The adjudication with `floor` set when the floor was considered, else unchanged."""
    proposal = adjudication.proposal
    if (proposal is None or facts.get("criticality") != "high"
            or not getattr(enrichment, "applicable", True)):
        return adjudication
    if not getattr(enrichment, "kev_checked", True):
        return dataclasses.replace(adjudication, floor={"applied": False, "reason": "KEV list not available"})
    if not enrichment.in_kev:
        return adjudication
    cap = min(FLOOR_SLA_DAYS, _days_until(enrichment.kev_due_date, now_sim_ts) or FLOOR_SLA_DAYS)
    severity = proposal.severity if _RANK[proposal.severity] >= _RANK["high"] else "high"
    sla_days = min(proposal.sla_days, cap)
    moved = (severity, sla_days) != (proposal.severity, proposal.sla_days)
    reason = ("raised to High: Crown jewels and actively exploited" if severity != proposal.severity
              else "deadline shortened: Crown jewels and actively exploited" if moved
              else "within the floor for Crown jewels and actively exploited")
    return dataclasses.replace(adjudication, floor={"applied": True, "severity": severity,
                                                    "sla_days": sla_days, "reason": reason})
