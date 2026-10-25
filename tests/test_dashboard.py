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
    response = TestClient(console.app).get("/", params={"view": view})
    assert response.status_code == 200
    assert "Illustrative data only" in response.text
    assert response.headers["cache-control"] == "no-store"
    assert "script-src 'none'" in response.headers["content-security-policy"]
    assert 'alt="Remediation Zero by Ayliea"' in response.text
    assert 'src="/logo.png"' in response.text and "base64," not in response.text
    assert 'href="/?view=' in response.text and 'href="/dashboard?view=' not in response.text
    assert '--heading:#1b2a4a' in response.text
    assert '<details open' not in response.text


def test_failure_is_not_empty_success(monkeypatch, caplog):
    monkeypatch.delenv("RZ_DASHBOARD_DEMO", raising=False)
    def fail():
        raise RuntimeError("secret diagnostic detail")
    monkeypatch.setattr(console, "cached_snapshot", fail)
    with caplog.at_level("WARNING", logger="remediation_zero.console"):
        response = TestClient(console.app).get("/")
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
    assert client.post("/").status_code == 405
    assert client.get("/?view=invalid").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_logo_is_served_cacheable():
    response = TestClient(console.app).get("/logo.png")
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


def test_old_dashboard_url_redirects_permanently_and_keeps_the_view():
    client = TestClient(console.app)
    response = client.get("/dashboard?view=actions", follow_redirects=False)
    assert response.status_code == 308
    assert response.headers["location"] == "/?view=actions"
    bare = client.get("/dashboard", follow_redirects=False)
    assert bare.status_code == 308 and bare.headers["location"] == "/"


@pytest.mark.parametrize("screening, phrase", [
    ({"screened": True, "blocked": False}, "checked for unsafe content"),
    ({"screened": True, "blocked": True}, "flagged as unsafe and withheld"),
    ({"screened": False, "blocked": True}, "triaged on limited evidence"),
    (None, "was not recorded"),
])
def test_both_pages_say_whether_scanner_notes_were_screened(screening, phrase):
    row = {"finding_id": "RZ-1", "outcome": "ratified", "cycle": 1}
    if screening is not None:
        row["screening"] = screening
    assert phrase in dashboard_view.render({"decisions": [row]}, "activity")
    empty = {"decisions": [row], "human_queue": [], "sla": [], "tickets": [],
             "exceptions": [], "cycles": [], "reports": [], "scans": [],
             "latest_scan": {}, "counts": {}, "sim_now": 0, "resolved_total": 0}
    assert phrase in console.render(empty)


def test_limited_evidence_wording():
    text = dashboard_view.screening_text({"screening": {"screened": False, "blocked": True}})
    assert text == ("Scanner notes were not checked, so they were withheld; "
                    "triaged on limited evidence.")


# --- scanner status on the infrastructure view (local edition only) ------------------------

TASK = "11111111-1111-4111-8111-111111111111"
TASK_2 = "22222222-2222-4222-8222-222222222222"
REPORT_ID = "33333333-3333-4333-8333-000000000001"


def scanner_page(rows, chosen=None, **extra):
    data = {"counts": {"assets": 1}, "scans": [], "scanner_state": rows}
    return dashboard_view.render(data, "infrastructure", chosen_tasks=chosen, **extra)


def pulled(**fields):
    return {"task_id": TASK, "last_pull_real_ts": 1793145600.0, "last_pull_sim_ts": 1793145600.0, **fields}


def test_infrastructure_shows_failed_pull_as_failed():
    page = scanner_page([pulled(last_result="failed", last_error_class="GmpError")], [TASK])
    assert "Failed: GmpError" in page
    assert "The last pull failed. This is not the same as no new findings." in page
    assert "Nothing new" not in page and "Imported" not in page
    assert "Wall time: 2026-10-28 00:00 UTC" in page


def test_infrastructure_says_when_no_tasks_are_chosen():
    assert "No scan tasks chosen — nothing is imported" in scanner_page([], [])
    unpulled = scanner_page([], [TASK])
    assert "Not pulled yet" in unpulled and "No scan tasks chosen" not in unpulled


def test_imported_task_shows_report_changes_and_skips():
    row = pulled(task_name="Weekly <b>LAN</b>", last_result="imported", last_imported_report_id=REPORT_ID,
                 last_imported_scan_end="2026-10-20T01:30:00Z",
                 last_counts={"new": 3, "resolved": 2, "regressed": 1, "persisting": 4, "unverifiable": 5},
                 last_skipped={"log": 7, "below_qod": 6, "rejected": 1, "not_finished": 2},
                 last_uncovered_all=True, deferred=2, baseline_not_imported=3)
    page = scanner_page([row], [TASK])
    assert "Weekly &lt;b&gt;LAN&lt;/b&gt;" in page and "<b>LAN</b>" not in page
    assert "Result: Imported" in page and REPORT_ID in page
    assert "3 new, 2 resolved, 1 reopened, 4 kept, 5 unverifiable" in page
    assert "7 log-level, 6 below the quality floor, 1 rejected, 2 not finished" in page
    assert "This report could not be trusted for coverage, so it closed nothing." in page
    assert "2 newer reports are waiting" in page
    assert "3 older reports were not imported when this task started." in page


def test_skipped_counts_are_shown():
    page = scanner_page([pulled(last_result="imported", last_imported_report_id=REPORT_ID,
                                last_skipped={"log": 11, "below_qod": 12, "rejected": 13, "not_finished": 14})])
    for number in ("11 log-level", "12 below the quality floor", "13 rejected", "14 not finished"):
        assert number in page


def test_refused_reports_are_listed_newest_first_at_most_five_in_plain_words():
    refused = [{"report_id": f"33333333-3333-4333-8333-{n:012d}", "reason": "too_large" if n == 1 else "not_newer"}
               for n in range(1, 8)]
    page = scanner_page([pulled(last_result="refused", refused=refused)], [TASK])
    assert "Result: Refused: the report is not newer than the last one imported" in page
    assert page.count("<li>Refused:") == 5 and "Recently refused reports: 7 (the last 20 are kept)" in page
    assert "larger than the size limit" not in page  # the oldest is not among the newest five
    assert "not_newer" not in page and "too_large" not in page


def test_every_closed_reason_has_plain_words():
    for reason in ("unsafe_xml", "too_large", "malformed", "no_scan_time", "not_newer",
                   "scan_time_in_future", "already_imported_this_cycle"):
        line = dashboard_view.refusal_line(reason)
        assert line.startswith("Refused: ") and reason not in line


def test_unknown_refusal_reason_is_not_echoed():
    evil = "<script>alert(1)</script>_zz-secret"
    page = scanner_page([pulled(last_result="refused", last_refusal={"report_id": REPORT_ID, "reason": evil},
                                refused=[{"report_id": REPORT_ID, "reason": evil}])], [TASK])
    assert "Refused (reason not recognised)" in page
    assert "zz-secret" not in page and "<script>" not in page and "alert(1)" not in page


def test_enrichment_status_and_failures_are_shown():
    enrichment = {"last_run_real_ts": 1793145600.0, "last_run_sim_ts": 1793145600.0, "kev": "ok",
                  "epss": "failed", "nvd_fetched": 4, "failed": ["epss", "CVE-2021-44228"]}
    page = scanner_page([enrichment], [])
    assert "Advisories fetched: 4" in page and "Failures: epss, CVE-2021-44228" in page
    assert "Enrichment has not run." in scanner_page([], [])


def test_cloud_render_without_scanner_state_is_unchanged():
    data = {"counts": {"assets": 2}, "scans": [{"scan_id": "s1", "real_ts": 1793145600.0, "sim_ts": 1793145600.0}]}
    plain = dashboard_view.render(data, "infrastructure")
    assert plain == dashboard_view.render(data, "infrastructure", upload_token=None, upload_code="imported",
                                          chosen_tasks=[TASK])
    for marker in ("Scanner imports", "Upload a report", "multipart", "No scan tasks chosen", "Enrichment"):
        assert marker not in plain
    assert "2 assets recorded" in plain and "Scan recorded:" in plain


def test_upload_form_only_when_a_token_is_supplied():
    assert "Upload a report" not in scanner_page([], [])
    page = scanner_page([], [], upload_token="tok-123")
    assert 'enctype="multipart/form-data"' in page and 'action="/upload"' in page
    assert 'name="report"' in page and 'name="add_task"' in page and 'name="token" value="tok-123"' in page
    assert "Also add this report's scan task to the tasks this install imports" in page
    assert "checked before anything is imported" in page


def test_upload_code_in_url_is_closed_set():
    codes = ("imported", "not_chosen", "too_many_tasks", "saved_failed", "parse_refused", "bad_request",
             "refused_other", "refused_not_newer")
    for code in codes:
        assert 'role="status"' in scanner_page([], [], upload_token="t", upload_code=code)
    for code in ("<script>x</script>", "refused_<img>", "refused_made_up", "", None, "IMPORTED"):
        page = scanner_page([], [], upload_token="t", upload_code=code)
        assert 'role="status"' not in page and "made_up" not in page and "<img>" not in page


def test_cloud_render_matches_the_base_commit_golden_output():
    """Snapshots without scanner_state render byte-for-byte as dashboard_view did at c5e2f98
    (fixtures/dashboard_cloud_golden.json, generated from that commit's file), whatever the new arguments."""
    from pathlib import Path
    from tests.golden_snapshots import SNAPSHOTS
    golden = json.loads((Path(__file__).parent / "fixtures" / "dashboard_cloud_golden.json").read_text())
    assert len(golden) == len(SNAPSHOTS) * (len(dashboard_view.VIEWS) + 1)
    for name, data in SNAPSHOTS.items():
        for view in dashboard_view.VIEWS:
            assert dashboard_view.render(data, view, logo_url="/logo.png") == golden[f"{name}/{view}"]
            assert dashboard_view.render(data, view, logo_url="/logo.png", upload_token="t", upload_code="imported",
                                         chosen_tasks=[TASK]) == golden[f"{name}/{view}"]
        assert dashboard_view.render(data, "actions", logo_url="/logo.png",
                                     approve_command="cmd") == golden[f"{name}/approve"]


def test_state_row_without_a_result_says_result_unknown_not_not_pulled():
    page = scanner_page([pulled()], [TASK])
    assert "Result unknown" in page and "Not pulled yet" not in page
    assert "Not pulled yet" in scanner_page([], [TASK])


def test_a_malformed_row_costs_only_its_own_card():
    rows = [pulled(last_result="imported", last_imported_report_id=REPORT_ID, last_counts="oops", last_skipped=[1]),
            {"task_id": TASK_2, "last_result": "imported", "last_pull_real_ts": "not-a-number"},
            {"task_id": "33333333-3333-4333-8333-333333333333", "last_result": "nothing_new",
             "last_pull_real_ts": 1793145600.0, "last_pull_sim_ts": 1793145600.0},
            {"last_run_real_ts": "bad", "failed": 5}]
    page = scanner_page(rows, [TASK, TASK_2, "33333333-3333-4333-8333-333333333333"])
    assert page.count("This task's status could not be read.") == 2
    assert "Result: Nothing new" in page
    assert "The enrichment status could not be read." in page


def test_upload_form_needs_scanner_state_not_just_a_token():
    data = {"counts": {}, "scans": []}
    assert "Upload a report" not in dashboard_view.render(data, "infrastructure", upload_token="t")
