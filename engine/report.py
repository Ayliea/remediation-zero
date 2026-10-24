# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""The reporting stage: count the period's metrics, narrate them, store both.

Reads every collection the reporting agent is permitted to read, counts the
metrics in code, and asks the summarizer role to narrate figures it did not
compute. With no summarizer configured the report says so in place of prose.

Reporting writes `reports` and nothing else. In the cloud that is a separate
database its identity can write; locally `docs_for("report")` refuses every
other collection. Standard library only: nothing here imports a cloud SDK.
"""
import json
import logging
from typing import Any, Callable, Optional

from engine.ports import Ports
from tools.metrics import compute_metrics
from tools.reports import ReportWriter, write_summary
from tools.telemetry import cycle_id

logger = logging.getLogger("remediation_zero.reporting")


def run_report(ports: Ports, cycle: int, *, writer: Optional[ReportWriter] = None,
               vertex_client: Optional[Callable[[], Any]] = None) -> str:
    """Write this period's report and return its summary text.

    `writer` defaults to a `ReportWriter` over `ports.docs`; the cloud passes
    one over the reports database. `vertex_client` is a factory, called only
    when the summarizer is a Vertex role.
    """
    db = ports.docs

    def rows(name):
        return [d.to_dict() for d in db.collection(name).stream()]

    # Reporting reads. It does not write to any of these, and once the
    # per-agent identities are in place it will not be able to.
    metrics = compute_metrics(
        decisions=rows("decisions"),
        tickets=rows("tickets"),
        sla_clocks=rows("sla_clocks"),
        human_queue=rows("human_queue"),
        exceptions=rows("exceptions"),
        # Reference collections. Reporting reads them and, under its own
        # identity, cannot write them -- which the probe control proves.
        findings=rows("findings"),
        scans=rows("scans"),
        assets=rows("assets"),
    )

    roles = ports.roles
    # No summarizer role: no adapter is built and the report carries metrics alone.
    if roles is None or roles.summarizer is None:
        summarizer = None
        # Local only: the cloud script refuses before this without its model.
        logger.info(json.dumps({
            "event": "summary_skipped", "reason": "no summarizer configured",
            "cycle_id": cycle_id(cycle), "finding_id": "-",
        }, sort_keys=True))
    else:
        # The Vertex client is built only when the role is a Vertex one.
        is_vertex = roles.summarizer.format == "vertex"
        summarizer = roles.adapter(
            "summarizer",
            vertex_client=vertex_client() if is_vertex and vertex_client else None,
        )
    summary = write_summary(metrics, summarizer)

    if writer is None:
        writer = ReportWriter(store=ports.journal, client=db, clock=ports.clock)
    document_id = writer.record(metrics=metrics, summary=summary, cycle=cycle)

    logger.info(json.dumps({
        "event": "report_written", "cycle_id": cycle_id(cycle),
        "finding_id": "-", "report_id": document_id,
        "decisions": metrics["decisions_total"],
        "disagreement_rate": round(metrics["disagreement_rate"], 3),
    }, sort_keys=True))
    return summary
