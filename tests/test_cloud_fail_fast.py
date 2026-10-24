# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Ruling 40: the cloud wiring fails fast without its models, as on base 1b88fc3.

On the base, scripts/cycle.py and scripts/graph_cycle.py read
os.environ["REASONING_MODEL"] and os.environ["REVIEWER_MODEL"], and
scripts/report.py read os.environ["REASONING_MODEL"], so a missing model was a
KeyError before any write or log line. The cloud never produces an unreviewed
decision or an unsummarised report. Nothing here reaches a cloud service: every
client is a fake that fails if it is used.
"""
import asyncio
import json
import logging
from types import SimpleNamespace

import pytest

MODELS = {"REASONING_MODEL": "gemini-3.5-flash",
          "REVIEWER_MODEL": "gemma-4-26b-a4b-it-maas"}


class Unused:
    """A client that may be built but never read from or written to."""

    def __init__(self, *args, **kwargs):
        pass

    def __getattr__(self, name):
        pytest.fail(f"a client was used before the fail-fast check: {name}")


def _env(monkeypatch, missing):
    for name, value in MODELS.items():
        if name == missing:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)


def _no_lines(caplog):
    lines = [r for r in caplog.records if r.name.startswith("remediation_zero")]
    assert lines == []


@pytest.mark.parametrize("missing", ["REASONING_MODEL", "REVIEWER_MODEL"])
def test_cloud_cycle_without_a_model_raises_key_error_first(monkeypatch, caplog, missing):
    from scripts import cycle
    _env(monkeypatch, missing)
    caplog.set_level(logging.INFO)
    monkeypatch.setattr("sys.argv", ["cycle", "--cycle", "1"])
    monkeypatch.setattr(cycle, "load_dotenv", lambda *_a, **_k: None)
    monkeypatch.setattr(cycle.firestore, "Client", Unused)
    monkeypatch.setattr(cycle, "EnrichmentCache", Unused)
    monkeypatch.setattr(cycle.rm, "_client", Unused)
    monkeypatch.setattr(cycle, "ModelArmor", lambda: pytest.fail("reached Model Armor"))
    monkeypatch.setattr(cycle, "run_triage_cycle", lambda *a, **k: pytest.fail("ran the cycle"))

    with pytest.raises(KeyError, match=missing):
        cycle.main()
    _no_lines(caplog)


def test_cloud_report_without_reasoning_model_raises_key_error_first(monkeypatch, caplog):
    from scripts import report
    _env(monkeypatch, "REASONING_MODEL")
    caplog.set_level(logging.INFO)
    monkeypatch.setattr("sys.argv", ["report", "--cycle", "1"])
    monkeypatch.setattr(report, "load_dotenv", lambda *_a, **_k: None)
    monkeypatch.setattr(report.firestore, "Client", Unused)
    monkeypatch.setattr(report, "run_report", lambda *a, **k: pytest.fail("ran the report"))

    with pytest.raises(KeyError, match="REASONING_MODEL"):
        report.main()
    _no_lines(caplog)


@pytest.mark.parametrize("missing", ["REASONING_MODEL", "REVIEWER_MODEL"])
def test_graph_cycle_without_a_model_raises_key_error_first(monkeypatch, caplog, missing):
    """Confirmation only: graph_cycle never lost its fail-fast."""
    from scripts import graph_cycle
    _env(monkeypatch, missing)
    caplog.set_level(logging.INFO)
    monkeypatch.setattr(graph_cycle, "load_dotenv", lambda *_a, **_k: None)
    monkeypatch.setattr(graph_cycle.firestore, "Client", Unused)
    monkeypatch.setattr(graph_cycle, "FirestoreIdempotencyStore", Unused)
    monkeypatch.setattr(graph_cycle, "EnrichmentCache", Unused)
    monkeypatch.setattr(graph_cycle.rm, "_client", Unused)
    monkeypatch.setattr(graph_cycle, "ModelArmor", Unused)
    monkeypatch.setattr(graph_cycle, "DecisionWriter", Unused)
    monkeypatch.setattr(graph_cycle, "AssignmentWriter", Unused)
    monkeypatch.setattr(graph_cycle.subprocess, "run",
                        lambda *a, **k: SimpleNamespace(stdout=""))
    monkeypatch.setattr(graph_cycle, "configure_tracing",
                        lambda *_a: pytest.fail("reached tracing"))

    with pytest.raises(KeyError, match=missing):
        asyncio.run(graph_cycle.run("RZ-0001", 1))
    _no_lines(caplog)


def test_local_report_without_summarizer_logs_summary_skipped(tmp_path, caplog):
    from engine.ports import NoDelivery, NoTelemetry, Ports
    from engine.report import run_report
    from tools.clock import ClockMode, SimClock
    from tools.guardrail import NoGuard
    from tools.local_layout import Workspace
    from tools.model_roles import ModelRoles
    from tools.reports import NO_SUMMARIZER

    ws = Workspace(tmp_path / "workspace")
    clock = SimClock(ClockMode.SIM)
    ports = Ports(docs=ws.docs_for("report"), journal=ws.journal(), clock=clock,
                  roles=ModelRoles(), guard=NoGuard(), delivery=NoDelivery(),
                  memory=None, telemetry=NoTelemetry())
    caplog.set_level(logging.INFO, logger="remediation_zero.reporting")

    assert run_report(ports, 7) == NO_SUMMARIZER

    lines = [json.loads(r.getMessage()) for r in caplog.records
             if r.name == "remediation_zero.reporting"]
    skipped = [line for line in lines if line["event"] == "summary_skipped"]
    assert skipped == [{"event": "summary_skipped", "reason": "no summarizer configured",
                        "cycle_id": "cycle-007", "finding_id": "-"}]
    assert [line["event"] for line in lines] == ["summary_skipped", "report_written"]
