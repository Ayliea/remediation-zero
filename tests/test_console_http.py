# Copyright 2026 Daviyon Daniels
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.

"""The public evidence console is cheap to read and difficult to embed."""

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


def test_root_has_cache_validators_and_defensive_headers(monkeypatch):
    monkeypatch.setattr(console, "cached_snapshot", lambda: {})
    monkeypatch.setattr(console, "render", lambda _data: "<html>evidence</html>")
    client = TestClient(console.app)

    first = client.get("/")
    assert first.status_code == 200
    assert "max-age=10" in first.headers["cache-control"]
    assert first.headers["x-content-type-options"] == "nosniff"
    assert first.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in first.headers["content-security-policy"]

    unchanged = client.get("/", headers={"If-None-Match": first.headers["etag"]})
    assert unchanged.status_code == 304
