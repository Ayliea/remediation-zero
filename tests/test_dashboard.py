# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
import pytest
from fastapi.testclient import TestClient
from ui import dashboard


@pytest.mark.parametrize("view", dashboard.VIEWS)
def test_demo_navigation_without_cloud(monkeypatch, view):
    monkeypatch.setenv("RZ_DASHBOARD_DEMO", "1")
    monkeypatch.setattr(dashboard, "cached_snapshot", lambda: pytest.fail("cloud read in demo"))
    response = TestClient(dashboard.app).get("/", params={"view": view})
    assert response.status_code == 200
    assert "Illustrative data only" in response.text
    assert response.headers["cache-control"] == "no-store"
    assert "script-src 'none'" in response.headers["content-security-policy"]
    assert 'alt="Remediation Zero by Ayliea"' in response.text
    assert '--heading:#1b2a4a' in response.text
    assert '<details open' not in response.text


def test_failure_is_not_empty_success(monkeypatch):
    monkeypatch.delenv("RZ_DASHBOARD_DEMO", raising=False)
    def fail():
        raise RuntimeError("secret diagnostic detail")
    monkeypatch.setattr(dashboard, "cached_snapshot", fail)
    response = TestClient(dashboard.app).get("/")
    assert response.status_code == 503
    assert "Security status is unknown" in response.text
    assert "secret diagnostic" not in response.text


def test_unreviewed_proposal_is_not_actionable_and_text_is_escaped():
    data = {"decisions": [{"finding_id": "<script>alert(1)</script>",
                          "outcome": "unavailable", "proposed_remediation": "UNAPPROVED_FIX",
                          "verdicts": [{"reason": "<img src=x onerror=alert(1)>"}]}]}
    page = dashboard.render(data, "actions")
    assert "UNAPPROVED_FIX" not in page
    assert "Check incomplete" in page
    assert "&lt;script&gt;" in page
    assert "<script>" not in page and "<img src=x" not in page
    assert "&lt;img" in page


def test_recent_history_deduplicates_but_activity_preserves_rejection():
    data = {"decisions": [{"finding_id": "A", "outcome": "ratified"},
                          {"finding_id": "A", "outcome": "human_queue", "note": "earlier rejection"}]}
    assert len(dashboard.recent_decisions(data)) == 1
    assert "earlier rejection" in dashboard.render(data, "activity")
    assert "not a complete list" in dashboard.render(data, "actions")


def test_no_write_endpoints(monkeypatch):
    monkeypatch.setenv("RZ_DASHBOARD_DEMO", "1")
    client = TestClient(dashboard.app)
    assert client.post("/").status_code == 405
    assert client.get("/?view=invalid").status_code == 404
    assert client.get("/openapi.json").status_code == 404
