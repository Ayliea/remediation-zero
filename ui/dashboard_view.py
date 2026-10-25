# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Pure dashboard rendering without cloud packages."""
import base64
import json
import shlex
from functools import lru_cache
from pathlib import Path
from html import escape
from datetime import datetime, timezone


@lru_cache(maxsize=1)
def branding():
    root = Path(__file__).resolve().parent
    logo = base64.b64encode((root / "assets/remediation-zero-logo.png").read_bytes()).decode()
    return (root / "theme.css").read_text(), logo


def stamp(real_ts, sim_ts):
    def show(value):
        return datetime.fromtimestamp(value, timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if value is not None else "Not recorded"
    result = "Wall time: " + show(real_ts)
    if sim_ts != real_ts:
        result += " · Scenario time: " + show(sim_ts)
    return result


VIEWS = {"overview": "Overview", "infrastructure": "My infrastructure",
         "actions": "Action list", "activity": "Activity"}


def text(value):
    return escape(str(value if value is not None else "Not recorded"), quote=True)


def demo_snapshot():
    """Illustrative records, with no invented lifecycle timestamps."""
    return {"counts": {"assets": 4, "findings": 3}, "resolved_total": 1,
            "scans": [], "human_queue": [], "cycles": [],
            "decisions": [
                {"finding_id": "DEMO-WEB-01", "outcome": "ratified",
                 "proposed_severity": "high", "cycle": 1,
                 "rationale": "An outdated component on the example website needs attention.",
                 "proposed_remediation": "Ask your hosting provider to update the affected component, then request a new scan.",
                 "cited_evidence": ["Illustrative scanner finding; not a real assessment."],
                 "screening": {"screened": True, "blocked": False}},
                {"finding_id": "DEMO-SERVER-02", "outcome": "unavailable",
                 "proposed_severity": "medium", "cycle": 1,
                 "note": "The independent review could not finish.",
                 "screening": {"screened": False, "blocked": True}}]}


def recent_decisions(data):
    # Input is newest-first from the existing snapshot query. Only deduplicate
    # within that bounded window; never imply this is the full open backlog.
    found = {}
    for row in data.get("decisions", []):
        found.setdefault(row.get("finding_id", "Unknown finding"), row)
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(found.values(), key=lambda r: rank.get(r.get("proposed_severity"), 4))


PERSON_APPROVABLE = {"unreviewed": "Not reviewed", "held_for_approval": "Reviewed by the same model family"}


def approve_hint(row, approve_command):
    """The exact local command that approves this decision; empty when none applies."""
    if not approve_command or row.get("outcome") not in PERSON_APPROVABLE or row.get("person_approval"):
        return ""
    command = (f"{approve_command} approve {shlex.quote(str(row.get('finding_id')))} "
               f"--cycle {shlex.quote(str(row.get('cycle')))} --by 'Your name'")
    return (f'<h4>Approve this recommendation</h4><p>No model has independently confirmed it. '
            f'If you have checked it and accept it, run:</p><pre><code>{text(command)}</code></pre>'
            f'<p>The next cycle then assigns it. Your approval is recorded separately; the review record is not changed.</p>')


def screening_text(row):
    """Whether the scanner's own notes were screened before a model read them.

    Records written before the flags existed carry no `screening`, and say so
    rather than guessing in either direction.
    """
    screening = row.get("screening")
    if not isinstance(screening, dict):
        return "Whether scanner notes were checked was not recorded."
    if not screening.get("screened"):
        return "Scanner notes were not checked, so they were withheld; triaged on limited evidence."
    if screening.get("blocked"):
        return "Scanner notes were flagged as unsafe and withheld from the models."
    return "Scanner notes were checked for unsafe content before any model read them."


def decision_card(row, approve_command=None):
    outcome = row.get("outcome")
    approved = outcome == "ratified"
    person = row.get("person_approval") if outcome in PERSON_APPROVABLE else None
    label = {"ratified": "Recommendation reviewed", "unavailable": "Check incomplete",
             "unreviewed": "Not reviewed · needs a person",
             "held_for_approval": "Reviewed by the same model family · waiting for your approval",
             "human_queue": "Needs a person’s review"}.get(outcome, "Review status unknown")
    if approved and row.get("review_independence") == "same_family":
        label = "Reviewed by the same model family"
    if person:
        # A person's approval, never shown as a ratification or an independent review.
        label = PERSON_APPROVABLE[outcome] + " · approved by " + str(person.get("approved_by") or "Not recorded")
    next_step = (row.get("proposed_remediation") or "No remediation instructions recorded.") if approved or person else (
        "Ask a trusted IT provider to review this before making changes.")
    evidence = "".join(f"<li>{text(item)}</li>" for item in row.get("cited_evidence", []))
    verdicts = "".join(f"<li>{text(v.get('reason'))}</li>" for v in row.get("verdicts", []))
    return f'''<article class="card"><div class="row"><h3>{text(row.get('finding_id'))}</h3>
<span class="badge{' badge--reviewed' if approved else ''}">{text(label)}</span></div>
<p class="muted">Recorded priority: {text(row.get('proposed_severity'))} · Cycle {text(row.get('cycle'))}</p>
<p>{text(row.get('rationale') or row.get('note') or 'Business impact has not been recorded. Ask your IT provider to assess this finding.')}</p>
<h4>Your next step</h4><p>{text(next_step)}</p>{approve_hint(row, approve_command)}
<details><summary>Technical evidence and review history</summary><ul>{evidence or '<li>No supporting evidence recorded.</li>'}</ul>
<ul>{verdicts}</ul><p>{text(row.get('note'))}</p><p>{text(screening_text(row))}</p>
{('<h4>Unreviewed model suggestion</h4><p>' + text(row.get('proposed_remediation')) + '</p>') if outcome == 'unreviewed' else ''}
<p>Recorded time (UTC): {stamp(row.get('real_ts'), row.get('sim_ts'))}</p>
<p>A reviewed recommendation does not mean the fix was applied or verified.</p></details></article>'''


def failed_runs_section(data):
    """Runs that stopped partway: finding, cycle, error class and time. Never a message."""
    if "failed_runs" not in data:
        return ""  # this edition does not record them
    body = ('<h2>Runs that did not finish</h2><p>A finding whose run stopped with an error. '
            'Only the error type is recorded; details stay in the local logs. Run the cycle again to retry.</p>')
    for row in data.get("failed_runs") or []:
        body += (f'<article class="card"><h3>{text(row.get("finding_id"))}</h3>'
                 f'<p>Cycle {text(row.get("cycle"))} · Error type: {text(row.get("error_class"))}</p>'
                 f'<p>Recorded time (UTC): {stamp(row.get("real_ts"), row.get("sim_ts"))}</p></article>')
    if not data.get("failed_runs"):
        body += '<p>No failed runs recorded.</p>'
    return body


#: Every closed refusal reason, in plain words. The only place a reason becomes text:
#: an unknown value never reaches the page as itself.
REFUSAL_WORDS = {
    "unsafe_xml": "the report contained markup that is never accepted",
    "too_large": "the report was larger than the size limit",
    "malformed": "the report was not a well-formed Greenbone report",
    "no_scan_time": "the report has no scan time",
    "not_newer": "the report is not newer than the last one imported",
    "scan_time_in_future": "the report's scan time is in the future",
    "already_imported_this_cycle": "this task already imported a report in this cycle",
}
UNKNOWN_REFUSAL = "Refused (reason not recognised)"

#: What the page says after an upload, by the closed code in the redirect URL.
#: Nothing from the request or the report ever reaches the URL or these messages.
UPLOAD_MESSAGES = {
    "imported": "The report was checked and imported.",
    "not_chosen": "This report is from a scan task that is not chosen for this install. Nothing was imported. "
                  "Tick the box to add the task, then upload again.",
    "too_many_tasks": "At most 500 scan tasks can be chosen. Nothing was saved or imported.",
    "saved_failed": "The report was imported, but its task could not be saved to the settings. "
                    "Add the task in Settings.",
    "parse_refused": "The report was refused: it could not be read as a Greenbone report. Nothing was imported.",
    "bad_request": "The upload was not accepted. Nothing was imported.",
    "refused_other": "The report was refused. Nothing was imported.",
}
UPLOAD_MESSAGES.update({f"refused_{reason}": f"The report was refused: {words}. Nothing was imported."
                        for reason, words in REFUSAL_WORDS.items()})


def refusal_line(reason):
    """"Refused: <plain words>" for a closed reason; anything else is not echoed."""
    words = REFUSAL_WORDS.get(reason) if isinstance(reason, str) else None
    return f"Refused: {words}" if words else UNKNOWN_REFUSAL


def _result_words(state):
    result = state.get("last_result")
    if result == "imported":
        return "Imported"
    if result == "nothing_new":
        return "Nothing new"
    if result == "refused":
        refusal = state.get("last_refusal")
        refused = state.get("refused")
        reason = (refusal or {}).get("reason") if isinstance(refusal, dict) else None
        if reason is None and isinstance(refused, list) and refused and isinstance(refused[-1], dict):
            reason = refused[-1].get("reason")
        return refusal_line(reason)
    if result == "failed":
        return "Failed: " + str(state.get("last_error_class") or "unknown error")
    return "Not pulled yet"


def _task_card(state, task_id):
    name = state.get("task_name") or task_id
    body = f'<article class="card"><h3>{text(name)}</h3>'
    if name != task_id:
        body += f'<p>Task: {text(task_id)}</p>'
    if state.get("last_pull_real_ts") is None and not state.get("last_result"):
        return body + '<p>Result: Not pulled yet. Nothing has been imported for this task.</p></article>'
    body += f'<p>Last pull: {stamp(state.get("last_pull_real_ts"), state.get("last_pull_sim_ts"))}</p>'
    body += f'<p>Result: {text(_result_words(state))}</p>'
    if state.get("last_result") == "failed":
        body += '<p>The last pull failed. This is not the same as no new findings.</p>'
    if state.get("last_imported_report_id"):
        body += (f'<p>Last imported report: {text(state.get("last_imported_report_id"))} '
                 f'(scan ended {text(state.get("last_imported_scan_end"))})</p>')
        counts = state.get("last_counts") or {}
        labels = (("new", "new"), ("resolved", "resolved"), ("regressed", "reopened"),
                  ("persisting", "kept"), ("unverifiable", "unverifiable"))
        body += ('<p>What it changed: ' + ", ".join(f'{text(counts.get(key, 0))} {label}' for key, label in labels)
                 + '.</p>')
        if state.get("last_uncovered_all"):
            body += '<p>This report could not be trusted for coverage, so it closed nothing.</p>'
        skipped = state.get("last_skipped") or {}
        body += ('<p>Skipped: ' + ", ".join(f'{text(skipped.get(key, 0))} {label}' for key, label in (
            ("log", "log-level"), ("below_qod", "below the quality floor"), ("rejected", "rejected"),
            ("not_finished", "not finished"))) + '.</p>')
    refused = [r for r in (state.get("refused") or []) if isinstance(r, dict)]
    if refused:
        body += f'<p>Refused reports: {text(len(refused))}. Newest first:</p><ul>'
        for item in list(reversed(refused))[:5]:
            body += f'<li>{text(refusal_line(item.get("reason")))}</li>'
        body += '</ul>'
    if state.get("deferred"):
        body += f'<p>{text(state.get("deferred"))} newer reports are waiting for a later pull.</p>'
    if state.get("baseline_not_imported"):
        body += f'<p>{text(state.get("baseline_not_imported"))} older reports were not imported when this task started.</p>'
    return body + '</article>'


def scanner_section(data, chosen_tasks=None):
    """Per chosen task: last pull and what it did. Only when the snapshot carries `scanner_state`."""
    if "scanner_state" not in data:
        return ""  # the cloud edition does not supply it
    rows = [r for r in (data.get("scanner_state") or []) if isinstance(r, dict)]
    by_task = {r.get("task_id"): r for r in rows if r.get("task_id")}
    enrichment = next((r for r in rows if not r.get("task_id") and "last_run_real_ts" in r), None)
    body = '<h2>Scanner imports</h2>'
    ids = list(chosen_tasks) if chosen_tasks is not None else list(by_task)
    if not ids:
        body += '<p class="card">No scan tasks chosen — nothing is imported.</p>'
    for task_id in ids:
        body += _task_card(by_task.get(task_id, {}), task_id)
    body += '<h3>Enrichment</h3>'
    if enrichment is None:
        body += '<p>Enrichment has not run.</p>'
    else:
        body += (f'<p>Last run: {stamp(enrichment.get("last_run_real_ts"), enrichment.get("last_run_sim_ts"))}</p>'
                 f'<p>Known-exploited list: {text(enrichment.get("kev"))} · Exploit-probability scores: '
                 f'{text(enrichment.get("epss"))} · Advisories fetched: {text(enrichment.get("nvd_fetched"))}</p>')
        failed = enrichment.get("failed") or []
        body += (f'<p>Failures: {text(", ".join(str(f) for f in failed))}</p>' if failed
                 else '<p>No failures in the last run.</p>')
    return body


def upload_form(token, base="/"):
    """The report upload form; rendered only by an edition that supplies a token."""
    return (f'<h2>Upload a report</h2><form class="card" method="post" action="{base}upload" enctype="multipart/form-data">'
            f'<input type="hidden" name="token" value="{text(token)}">'
            '<p>The report is checked before anything is imported.</p>'
            '<label>Greenbone report (XML) <input type="file" name="report" required></label>'
            '<p><label><input type="checkbox" name="add_task" value="yes"> '
            "Also add this report's scan task to the tasks this install imports</label></p>"
            '<button type="submit">Check and import</button></form>')


def render(data, view="overview", demo=False, unavailable=False, settings_html=None,
           base="/", logo_url=None, approve_command=None, upload_token=None, upload_code=None,
           chosen_tasks=None):
    # base: where this page is mounted. logo_url: a served, cacheable logo; the
    # local server has no static route, so it falls back to an inline data URI.
    # approve_command: the local edition's command prefix for approving a
    # decision; the cloud console passes none and shows no approval guidance.
    counts = data.get("counts", {})
    rows = recent_decisions(data)
    views = dict(VIEWS, settings="Settings") if settings_html is not None else VIEWS
    nav = "".join(f'<a href="{base}?view={key}" aria-current="{"page" if key == view else "false"}">{label}</a>' for key, label in views.items())
    notice = ("Demo · Illustrative data only. No infrastructure is connected." if demo else
              "Synthetic environment · Read-only. These records do not assess your business infrastructure.")
    if unavailable:
        body = f'<section class="card"><h2>We couldn’t load your records</h2><p>Security status is unknown. Refresh to try again. An unavailable check does not mean there are no issues.</p><a href="{base}">Try again</a></section>'
    elif view == "settings":
        body = settings_html
    elif view == "overview":
        focus = decision_card(rows[0], approve_command) if rows else '<section class="card"><h2>No recent recommendations yet</h2><p>We still need evidence to understand what needs attention.</p></section>'
        body = f'''<div class="overview-grid"><section class="overview-main">{focus}
<a class="button" href="{base}?view=actions">Review next steps</a><p class="muted">No changes will be made.</p>
<h2>Also needs attention</h2><div class="task-links"><a href="{base}?view=actions">Review incomplete checks</a>
<a href="{base}?view=infrastructure">Confirm what has been scanned</a><a href="{base}?view=activity">See previous reviews</a></div></section>
<section class="notice"><h2>What we still need to check</h2><p>A few gaps need a closer look.</p>
<ul class="coverage-list"><li><strong>Scan coverage</strong><span>Not confirmed in this view</span></li>
<li><strong>Current exposure</strong><span>Unknown</span></li><li><strong>Connection health</strong><span>Not available in this view</span></li></ul>
<p>No issues shown does not mean everything is secure.</p><a href="{base}?view=infrastructure">Review coverage</a></section></div>
<details><summary>Recorded totals</summary><p>Assets: {text(counts.get('assets', 'Unknown'))} · Findings: {text(counts.get('findings', 'Unknown'))} · Marked resolved: {text(data.get('resolved_total', 'Unknown'))}</p></details>'''
    elif view == "actions":
        body = '<p>Latest decision per finding within the most recent 60 decisions. This is not a complete list of open issues; resolved findings may still appear.</p>'
        body += "".join(decision_card(r, approve_command) for r in rows) or '<p class="card">No recent recommendations available. This does not establish that there are no issues.</p>'
        body += '<h2>Requests for human review</h2><p>Up to 60 recorded requests. Queue records do not establish whether someone has already handled them.</p>'
        for row in data.get("human_queue", []):
            body += f'<article class="card"><h3>{text(row.get("finding_id"))}</h3><p>{text(row.get("reason"))}</p></article>'
        if not data.get("human_queue"):
            body += '<p>No requests returned in this snapshot.</p>'
        body += failed_runs_section(data)
    elif view == "infrastructure":
        body = f'<section class="card"><h2>{text(counts.get("assets", "Unknown"))} assets recorded</h2><p>Asset names, connection health, and a complete coverage comparison are not supplied by this snapshot. Inventory count alone does not prove these assets have been checked.</p></section><section class="notice"><h2>Coverage needs confirmation</h2><p>Ask your IT provider to compare your infrastructure inventory with scan coverage. Scan freshness is not evaluated here.</p></section><h2>Recent scan evidence</h2>'
        for scan in data.get("scans", []):
            body += f'<details class="card"><summary>Scan recorded: {stamp(scan.get("real_ts"), scan.get("sim_ts"))}</summary><pre>{text(json.dumps(scan, indent=2, default=str))}</pre></details>'
        if not data.get("scans"):
            body += '<p class="card">No scan records returned. We cannot confirm what was checked.</p>'
        body += scanner_section(data, chosen_tasks)
        if upload_token is not None:
            message = UPLOAD_MESSAGES.get(upload_code) if isinstance(upload_code, str) else None
            if message:
                body += f'<section class="notice" role="status"><p>{text(message)}</p></section>'
            body += upload_form(upload_token, base)
    else:
        body = '<p>Recent decision history, including previous reviews. Times are UTC; scenario time is labeled separately when it differs from wall time.</p>'
        body += "".join(decision_card(r, approve_command) for r in data.get("decisions", [])) or '<p class="card">No decision activity returned.</p>'
    theme, logo = branding()
    title = 'Your next security step' if view == 'overview' else views[view]
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{views[view]} · Remediation Zero</title><style>
{theme}\n</style></head><body><div class="shell"><aside><div class="brand"><img src="{logo_url or "data:image/png;base64," + logo}" alt="Remediation Zero by Ayliea"></div><nav aria-label="Main navigation">{nav}</nav></aside><main><div class="banner">{notice}</div><h1>{title}</h1><p class="intro">Let’s make the next step clear.</p>{body}<footer>Remediation Zero by Ayliea · Synthetic preview · Infrastructure changes disabled · Model connection optional.</footer></main></div></body></html>'''
