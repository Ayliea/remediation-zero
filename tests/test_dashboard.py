# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
import json

import pytest
from fastapi.testclient import TestClient
from ui import app as console
from ui import dashboard_view


@pytest.mark.parametrize("view", dashboard_view.VIEWS)
def test_demo_navigation_without_cloud(monkeypatch, view):
    monkeypatch.setenv("RZ_DASHBOARD_DEMO", "1")
    monkeypatch.setattr(console, "cached_snapshot", lambda: pytest.fail("cloud read in demo"))
    response = TestClient(console.app).get("/dashboard", params={"view": view})
    assert response.status_code == 200
    assert "Illustrative data only" in response.text
    assert response.headers["cache-control"] == "no-store"
    assert "script-src 'none'" in response.headers["content-security-policy"]
    assert 'alt="Remediation Zero by Ayliea"' in response.text
    assert 'src="/dashboard/logo.png"' in response.text and "base64," not in response.text
    assert 'href="/dashboard?view=' in response.text and 'href="/?view=' not in response.text
    assert '--heading:#1b2a4a' in response.text
    assert '<details open' not in response.text


def test_failure_is_not_empty_success(monkeypatch, caplog):
    monkeypatch.delenv("RZ_DASHBOARD_DEMO", raising=False)
    def fail():
        raise RuntimeError("secret diagnostic detail")
    monkeypatch.setattr(console, "cached_snapshot", fail)
    with caplog.at_level("WARNING", logger="remediation_zero.console"):
        response = TestClient(console.app).get("/dashboard")
    assert response.status_code == 503
    assert response.headers["cache-control"] == "no-store"
    logged = [json.loads(r.getMessage()) for r in caplog.records
              if r.name == "remediation_zero.console"]
    assert logged == [{"event": "dashboard_snapshot_failed",
                       "error": "RuntimeError", "view": "overview"}]
    assert "secret diagnostic" not in caplog.text
    assert "Security status is unknown" in response.text
    assert "secret diagnostic" not in response.text


def test_unreviewed_proposal_is_not_actionable_and_text_is_escaped():
    data = {"decisions": [{"finding_id": "<script>alert(1)</script>",
                          "outcome": "unavailable", "proposed_remediation": "UNAPPROVED_FIX",
                          "verdicts": [{"reason": "<img src=x onerror=alert(1)>"}]}]}
    page = dashboard_view.render(data, "actions")
    assert "UNAPPROVED_FIX" not in page
    assert "Check incomplete" in page
    assert "&lt;script&gt;" in page
    assert "<script>" not in page and "<img src=x" not in page
    assert "&lt;img" in page


def test_recent_history_deduplicates_but_activity_preserves_rejection():
    data = {"decisions": [{"finding_id": "A", "outcome": "ratified"},
                          {"finding_id": "A", "outcome": "human_queue", "note": "earlier rejection"}]}
    assert len(dashboard_view.recent_decisions(data)) == 1
    assert "earlier rejection" in dashboard_view.render(data, "activity")
    assert "not a complete list" in dashboard_view.render(data, "actions")


def test_no_write_endpoints(monkeypatch):
    monkeypatch.setenv("RZ_DASHBOARD_DEMO", "1")
    client = TestClient(console.app)
    assert client.post("/dashboard").status_code == 405
    assert client.get("/dashboard?view=invalid").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_logo_is_served_cacheable():
    response = TestClient(console.app).get("/dashboard/logo.png")
    assert response.status_code == 200
    assert response.headers["content-type"] == "image/png"
    assert "max-age" in response.headers["cache-control"]


def test_local_edition_keeps_inline_logo_and_root_links():
    page = dashboard_view.render(dashboard_view.demo_snapshot(), "overview")
    assert "data:image/png;base64," in page
    assert 'href="/?view=actions"' in page


def test_dashboard_labels_same_family():
    data = {"decisions": [
        {"finding_id": "A", "outcome": "unreviewed"},
        {"finding_id": "B", "outcome": "held_for_approval", "proposed_remediation": "HELD_FIX"},
        {"finding_id": "C", "outcome": "ratified", "review_independence": "same_family"},
        {"finding_id": "D", "outcome": "ratified", "review_independence": "cross_family"},
        {"finding_id": "<b>E</b>", "outcome": "held_for_approval"},
    ]}
    page = dashboard_view.render(data, "activity")

    assert "Not reviewed · needs a person" in page
    assert "Reviewed by the same model family · waiting for your approval" in page
    assert "Reviewed by the same model family</span>" in page
    assert page.count("Recommendation reviewed") == 1
    assert "HELD_FIX" not in page
    assert "<b>E</b>" not in page and "&lt;b&gt;E&lt;/b&gt;" in page
