# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
import dataclasses
import json
import logging
import subprocess
import sys

import pytest

import tools.telemetry
from engine.ports import NoDelivery, NoTelemetry, Ports, Telemetry


def test_engine_ports_stdlib_only():
    r = subprocess.run([sys.executable, "-S", "-c",
                        "import engine.ports, tools.local_memory"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_no_delivery_logs_and_returns_none(caplog):
    with caplog.at_level(logging.INFO):
        assert NoDelivery().deliver("open_ticket", "F-1", None, 3, 1.0, None) is None
    rec = [json.loads(r.getMessage()) for r in caplog.records
           if "delivery_skipped" in r.getMessage()]
    assert rec == [{"event": "delivery_skipped", "reason": "dashboard-only",
                    "finding_id": "F-1", "cycle_id": "cycle-003"}]


def test_no_telemetry_noops():
    t = NoTelemetry()
    with t.finding_span("F-1", "cycle-001") as span:
        t.set_outcome(span, "ok")
    assert t.flush() is None


def test_cloud_telemetry_module_satisfies_protocol():
    assert isinstance(tools.telemetry, Telemetry)
    assert isinstance(NoTelemetry(), Telemetry)


def test_ports_shape():
    fields = [f.name for f in dataclasses.fields(Ports)]
    assert fields == ["docs", "journal", "clock", "roles", "guard", "delivery",
                      "memory", "telemetry", "record_failed_runs"]
    p = Ports(None, None, None, None, None, NoDelivery(), None, NoTelemetry())
    assert p.record_failed_runs is False
    with pytest.raises(dataclasses.FrozenInstanceError):
        p.docs = 1
