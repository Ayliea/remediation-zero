# Copyright 2026 Daviyon Daniels
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.

"""The public evidence console is cheap to read and difficult to embed."""

import json
import threading
import time

from fastapi.testclient import TestClient

import ui.app as console


def test_snapshot_cache_reuses_a_projection_inside_the_ttl(monkeypatch):
    calls = []
    monkeypatch.setattr(console, "_snapshot_cache", None)
    monkeypatch.setattr(console, "snapshot", lambda: calls.append(1) or {"ok": True})

    first = console.cached_snapshot(now_real_ts=100)
    second = console.cached_snapshot(now_real_ts=109)

    assert first is second
    assert calls == [1]


def test_snapshot_cache_refreshes_after_the_ttl(monkeypatch):
    calls = []
    monkeypatch.setattr(console, "_snapshot_cache", None)
    monkeypatch.setattr(console, "snapshot", lambda: {"version": len(calls.append(1) or calls)})

    assert console.cached_snapshot(now_real_ts=100)["version"] == 1
    assert console.cached_snapshot(now_real_ts=111)["version"] == 2


def test_console_has_cache_validators_and_defensive_headers(monkeypatch):
    monkeypatch.setattr(console, "cached_snapshot", lambda: {})
    monkeypatch.setattr(console, "render", lambda _data: "<html>evidence</html>")
    client = TestClient(console.app)

    first = client.get("/console")
    assert first.status_code == 200
    assert "max-age=10" in first.headers["cache-control"]
    assert first.headers["x-content-type-options"] == "nosniff"
    assert first.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in first.headers["content-security-policy"]

    unchanged = client.get("/console", headers={"If-None-Match": first.headers["etag"]})
    assert unchanged.status_code == 304


def test_console_failure_is_unknown_not_empty_success(monkeypatch, caplog):
    def fail():
        raise RuntimeError("secret diagnostic detail")
    monkeypatch.setattr(console, "cached_snapshot", fail)
    with caplog.at_level("WARNING", logger="remediation_zero.console"):
        response = TestClient(console.app).get("/console")
    assert response.status_code == 503
    assert response.headers["cache-control"] == "no-store"
    assert "unknown" in response.text.lower()
    assert "secret diagnostic" not in response.text + caplog.text
    logged = [json.loads(r.getMessage()) for r in caplog.records
              if r.name == "remediation_zero.console"]
    assert logged == [{"event": "console_snapshot_failed", "error": "RuntimeError"}]


def test_a_read_that_never_returns_is_bounded(monkeypatch):
    # An expired Google login made the Firestore read block forever, and the
    # page hung with it. The read is bounded, so the page says "unknown".
    release = threading.Event()
    monkeypatch.setattr(console, "_snapshot_cache", None)
    monkeypatch.setattr(console, "SNAPSHOT_TIMEOUT_SECONDS", 0.2)
    monkeypatch.setattr(console, "snapshot", lambda: release.wait(5) or {})
    try:
        started = time.monotonic()
        response = TestClient(console.app).get("/console")
        assert response.status_code == 503
        assert time.monotonic() - started < 2
        # A second request while the first read is still stuck is bounded
        # too, rather than queueing behind it without limit.
        assert TestClient(console.app).get("/console").status_code == 503
    finally:
        release.set()
