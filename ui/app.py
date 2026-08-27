# Copyright 2026 Daviyon Daniels
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Read-only console for the remediation fleet.

This is an evidence ledger, not a dashboard. The system's claim is that every
behaviour it performs is observable and verifiable by someone who did not build
it, so the console's job is to make the record legible rather than to summarise
it flatteringly.

One convention runs through the whole page and carries most of its meaning:
every timestamp is coloured by which clock produced it. Teal is `real_ts`, wall
clock, never falsified. Indigo is `sim_ts`, scenario time. Where the two
disagree, the console shows the gap rather than hiding it, because the gap is
the honest part of the demonstration.

The console writes nothing. It holds no credentials that could write. Its
service account is read-only by construction, which is the point: the interface
a stranger can reach must not be able to change the record it displays.
"""

import os
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, Response
from google.cloud import firestore

REPO_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(REPO_ROOT / ".env")

app = FastAPI(title="Remediation Zero", docs_url=None, redoc_url=None)

SESSION_CREATED = float(os.environ.get("SESSION_CREATED_REAL_TS", "0") or 0)
SESSION_ID = os.environ.get("ORCHESTRATOR_SESSION_ID", "unknown")

_client: firestore.Client | None = None
_reports_client: firestore.Client | None = None

#: Reports live in their own database. See tools/reports.py for why.
REPORTS_DATABASE = "reports"


def db() -> firestore.Client:
    global _client
    if _client is None:
        _client = firestore.Client()
    return _client


def reports_db() -> firestore.Client:
    global _reports_client
    if _reports_client is None:
        _reports_client = firestore.Client(database=REPORTS_DATABASE)
    return _reports_client


# --- formatting -------------------------------------------------------------

def iso(ts: float | None) -> str:
    if not ts:
        return "—"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M")


def duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    if d:
        return f"{d}d {h}h {m}m"
    if h:
        return f"{h}h {m}m"
    return f"{m}m"


def esc(text) -> str:
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def stamp(real_ts: float | None, sim_ts: float | None) -> str:
    """The signature element: one timestamp, both clocks, colour-coded.

    Rendered everywhere a time appears. When the two agree the drift is
    omitted, so divergence is visually loud precisely when it exists.
    """
    if real_ts is None and sim_ts is None:
        return '<span class="t t--none">—</span>'

    diverged = bool(real_ts and sim_ts and abs(sim_ts - real_ts) > 3600)

    # When the clocks agree, show one time. Printing the same value twice in
    # two colours is noise, and it spends the reader's attention in the case
    # that carries no information. Splitting only on divergence is what makes
    # divergence loud.
    if not diverged:
        only = real_ts or sim_ts
        return f'<span class="t t--agree" title="wall clock and scenario agree">{iso(only)}</span>'

    return (
        '<span class="t-pair">'
        f'<span class="t t--real" title="wall clock, never falsified">{iso(real_ts)}</span>'
        f'<span class="t t--sim" title="scenario time">{iso(sim_ts)}</span>'
        f'<span class="t-drift">simulation ahead by {(sim_ts - real_ts) / 86400:.0f}d</span>'
        '</span>'
    )


# --- data -------------------------------------------------------------------

def snapshot() -> dict:
    """Everything the page needs, in one pass."""
    client = db()

    def rows(name, limit=60):
        return [d.to_dict() for d in client.collection(name).limit(limit).stream()]

    human_queue = rows("human_queue")
    sla = rows("sla_clocks")
    decisions = sorted(rows("decisions"), key=lambda d: d.get("real_ts", 0), reverse=True)
    tickets = rows("tickets")
    exceptions = rows("exceptions")
    cycles = rows("cycles")
    reports = sorted(
        (d.to_dict() for d in reports_db().collection("reports").limit(10).stream()),
        key=lambda r: r.get("real_ts", 0),
        reverse=True,
    )

    # Scenario time is the furthest point the simulation has reached, taken
    # from the record rather than from this process's clock. The console never
    # advances time; it only reports where the fleet left it.
    sim_now = max(
        [0.0]
        + [t.get("last_contact_sim_ts", 0) or 0 for t in tickets]
        + [s.get("due_sim_ts", 0) or 0 for s in sla]
        + [e.get("expires_sim_ts", 0) or 0 for e in exceptions]
    )

    counts = {
        name: client.collection(name).count().get()[0][0].value
        for name in ("findings", "assets", "owners", "decisions", "tickets",
                     "human_queue", "idempotency")
    }

    return {
        "human_queue": human_queue,
        "sla": sla,
        "decisions": decisions,
        "tickets": tickets,
        "exceptions": exceptions,
        "cycles": cycles,
        "reports": reports,
        "counts": counts,
        "sim_now": sim_now,
    }


# --- page -------------------------------------------------------------------

STYLE = """
:root{
  --paper:#EDEEF0; --paper-2:#E3E5E9; --card:#F7F8F9;
  --ink:#16181D; --ink-2:#4A5058; --ink-3:#767D87;
  --rule:#C7CBD1; --rule-2:#D8DBE0;
  --real:#0B7A6B;      /* wall clock. evidence. */
  --sim:#3B5BDB;       /* scenario time. */
  --breach:#A33A2A; --pending:#9A6608; --ok:#2F6B3A;
}
*{box-sizing:border-box}
body{
  margin:0;background:var(--paper);color:var(--ink);
  font-family:"Source Sans 3","Segoe UI",system-ui,sans-serif;
  font-size:15px;line-height:1.55;
  -webkit-font-smoothing:antialiased;
}
.mono,.t,.k,.tag,th,.num{font-family:"IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,monospace}
.wrap{max-width:1240px;margin:0 auto;padding:0 28px 96px}

/* ---- masthead ---- */
.mast{border-bottom:2px solid var(--ink);padding:26px 0 14px;margin-bottom:0}
.mast-row{display:flex;align-items:baseline;justify-content:space-between;gap:24px;flex-wrap:wrap}
.wordmark{font-family:"IBM Plex Mono",monospace;font-weight:600;font-size:20px;
  letter-spacing:.16em;text-transform:uppercase;margin:0}
.mast-sub{color:var(--ink-2);font-size:13.5px;max-width:52ch;margin:6px 0 0}
.live{display:inline-flex;align-items:center;gap:7px;font-family:"IBM Plex Mono",monospace;
  font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:var(--ink-2)}
.dot{width:7px;height:7px;border-radius:50%;background:var(--real);
  animation:pulse 2.4s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.25}}
@media (prefers-reduced-motion:reduce){.dot{animation:none}}

/* ---- the two clocks: the thesis of the page ---- */
.clocks{display:grid;grid-template-columns:1fr 1fr;border-bottom:1px solid var(--rule)}
.clock{padding:26px 0 24px}
.clock + .clock{border-left:1px solid var(--rule);padding-left:32px}
.clock-k{font-family:"IBM Plex Mono",monospace;font-size:10.5px;letter-spacing:.18em;
  text-transform:uppercase;margin:0 0 10px;display:flex;align-items:center;gap:8px}
.clock-k::before{content:"";width:22px;height:2px;display:inline-block}
.clock--real .clock-k{color:var(--real)} .clock--real .clock-k::before{background:var(--real)}
.clock--sim .clock-k{color:var(--sim)} .clock--sim .clock-k::before{background:var(--sim)}
.clock-v{font-family:"IBM Plex Mono",monospace;font-weight:600;
  font-size:clamp(30px,5.4vw,46px);line-height:1;letter-spacing:-.02em;margin:0}
.clock--real .clock-v{color:var(--real)} .clock--sim .clock-v{color:var(--sim)}
.clock-n{color:var(--ink-2);font-size:13px;margin:11px 0 0;max-width:44ch}

/* ---- ledger sections ---- */
.sec{padding:38px 0 0}
.sec-h{display:flex;align-items:baseline;gap:14px;border-bottom:1px solid var(--ink);
  padding-bottom:8px;margin-bottom:0}
.sec-t{font-family:"IBM Plex Mono",monospace;font-weight:600;font-size:13px;
  letter-spacing:.15em;text-transform:uppercase;margin:0}
.sec-c{font-family:"IBM Plex Mono",monospace;font-size:12px;color:var(--ink-3)}
.sec-d{color:var(--ink-2);font-size:13.5px;margin:10px 0 16px;max-width:66ch}

table{width:100%;border-collapse:collapse;font-size:13.5px}
th{font-size:10.5px;letter-spacing:.13em;text-transform:uppercase;color:var(--ink-3);
  text-align:left;font-weight:500;padding:10px 12px 8px 0;border-bottom:1px solid var(--rule-2)}
td{padding:11px 12px 11px 0;border-bottom:1px solid var(--rule-2);vertical-align:top}
tr:last-child td{border-bottom:0}
.k{font-size:12.5px;color:var(--ink)}
.prose{color:var(--ink-2);max-width:60ch}

/* ---- timestamps ---- */
.t-pair{display:inline-flex;flex-direction:column;gap:1px;line-height:1.35}
.t{font-size:11.5px;white-space:nowrap}
.t--real{color:var(--real)} .t--sim{color:var(--sim)}
.t--none{color:var(--ink-3)} .t--agree{color:var(--ink-3)}
.t-drift{font-family:"IBM Plex Mono",monospace;font-size:10.5px;color:var(--sim);
  opacity:.8;letter-spacing:.04em}

.tag{display:inline-block;font-size:10.5px;letter-spacing:.1em;text-transform:uppercase;
  padding:3px 8px;border:1px solid currentColor;white-space:nowrap}
.tag--breach{color:var(--breach)} .tag--pending{color:var(--pending)}
.tag--ok{color:var(--ok)} .tag--mute{color:var(--ink-3)}

/* ---- SLA pressure bar ---- */
.bar{height:6px;background:var(--paper-2);position:relative;margin-top:7px;min-width:120px}
.bar > i{position:absolute;inset:0 auto 0 0;background:var(--sim);display:block}
.bar--breach > i{background:var(--breach)}

/* ---- disagreement ---- */
.verdict{border-left:2px solid var(--rule);padding:2px 0 2px 12px;margin:7px 0 0}
.verdict--reject{border-left-color:var(--breach)}
.verdict--ratify{border-left-color:var(--ok)}
.verdict-k{font-family:"IBM Plex Mono",monospace;font-size:10px;letter-spacing:.13em;
  text-transform:uppercase;display:block;margin-bottom:2px}
.verdict--reject .verdict-k{color:var(--breach)}
.verdict--ratify .verdict-k{color:var(--ok)}
.verdict p{margin:0;font-size:13px;color:var(--ink-2)}

.report{display:grid;grid-template-columns:1.7fr 1fr;gap:36px;padding-top:6px}
.report-prose p{margin:0 0 13px;max-width:62ch;font-size:14.5px}
.report-prose p:first-child{font-size:16px;color:var(--ink)}
.report-figures{display:flex;flex-direction:column;gap:18px;
  border-left:1px solid var(--rule);padding-left:24px}
.fig{display:flex;flex-direction:column;gap:2px}
.fig-k{font-family:"IBM Plex Mono",monospace;font-size:10px;letter-spacing:.13em;
  text-transform:uppercase;color:var(--ink-3)}
.fig-v{font-family:"IBM Plex Mono",monospace;font-weight:600;font-size:26px;
  line-height:1.1;color:var(--ink)}
.fig-n{font-size:12px;color:var(--ink-2)}
@media(max-width:760px){.report{grid-template-columns:1fr}
  .report-figures{border-left:0;border-top:1px solid var(--rule);padding-left:0;padding-top:18px}}
.empty{color:var(--ink-3);font-size:13.5px;padding:20px 0;border-bottom:1px solid var(--rule-2)}
.foot{margin-top:56px;padding-top:16px;border-top:1px solid var(--rule);
  color:var(--ink-3);font-size:12px;display:flex;gap:22px;flex-wrap:wrap}
.counts{display:flex;gap:26px;flex-wrap:wrap;padding:16px 0;border-bottom:1px solid var(--rule)}
.count-i{font-family:"IBM Plex Mono",monospace;font-size:12px;color:var(--ink-2)}
.count-i b{color:var(--ink);font-weight:600}
@media(max-width:760px){
  .clocks{grid-template-columns:1fr}
  .clock + .clock{border-left:0;border-top:1px solid var(--rule);padding-left:0}
  .wrap{padding:0 18px 72px}
  table{font-size:12.5px}
}
"""


def render(data: dict) -> str:
    now = datetime.now(tz=timezone.utc).timestamp()
    session_age = now - SESSION_CREATED if SESSION_CREATED else 0
    sim_now = data["sim_now"]
    counts = data["counts"]

    # --- human queue: the terminal state, so it leads -----------------------
    hq_rows = []
    for item in sorted(data["human_queue"], key=lambda x: x.get("real_ts", 0), reverse=True):
        kind = item.get("kind", "adjudication")
        tone = {"acceptance_refused": "pending", "acceptance_expired": "pending",
                "escalated_unresolved": "breach", "unassigned": "breach"}.get(kind, "mute")
        hq_rows.append(f"""<tr>
          <td class="k">{esc(item.get('finding_id','—'))}</td>
          <td><span class="tag tag--{tone}">{esc(kind.replace('_',' '))}</span></td>
          <td class="prose">{esc(item.get('reason',''))[:260]}</td>
          <td>{stamp(item.get('real_ts'), item.get('sim_ts'))}</td>
        </tr>""")

    # --- SLA clocks ---------------------------------------------------------
    sla_rows = []
    for clock in sorted(data["sla"], key=lambda x: x.get("due_sim_ts", 0)):
        due = clock.get("due_sim_ts", 0)
        started = clock.get("started_sim_ts", 0)
        window = max(1.0, due - started)
        elapsed = max(0.0, (sim_now or started) - started)
        pct = min(100.0, elapsed / window * 100)
        breached = (sim_now or 0) >= due and due > 0
        status = clock.get("status", "open")
        tone = {"breached": "breach", "accepted": "pending",
                "reopened_pending_triage": "pending"}.get(status, "ok")
        sla_rows.append(f"""<tr>
          <td class="k">{esc(clock.get('finding_id','—'))}</td>
          <td class="k">{esc(clock.get('owner_id','—'))}</td>
          <td><span class="tag tag--{tone}">{esc(status.replace('_',' '))}</span></td>
          <td style="width:26%">
            <span class="t t--sim">due {iso(due)}</span>
            <span class="bar {'bar--breach' if breached else ''}"><i style="width:{pct:.0f}%"></i></span>
          </td>
          <td>{stamp(clock.get('started_real_ts'), started)}</td>
        </tr>""")

    # --- decision log: the disagreements are the evidence -------------------
    dec_rows = []
    for d in data["decisions"][:14]:
        verdicts = "".join(
            f"""<div class="verdict verdict--{'ratify' if v.get('ratified') else 'reject'}">
                  <span class="verdict-k">reviewer · {'ratified' if v.get('ratified') else 'rejected'}</span>
                  <p>{esc(v.get('reason',''))[:230]}</p>
                </div>"""
            for v in d.get("verdicts", [])
        )
        outcome = d.get("outcome", "—")
        tone = {"ratified": "ok", "human_queue": "breach", "unavailable": "pending"}.get(outcome, "mute")
        cites = ", ".join(d.get("cited_evidence", [])) or "none cited"
        dec_rows.append(f"""<tr>
          <td class="k">{esc(d.get('finding_id','—'))}<br>
              <span class="t t--none">cycle {esc(d.get('cycle','—'))}</span></td>
          <td><span class="tag tag--{tone}">{esc(outcome.replace('_',' '))}</span></td>
          <td class="prose">
            <b class="k">{esc(d.get('proposed_severity','—'))} · SLA {esc(d.get('proposed_sla_days','—'))}d</b><br>
            {esc(d.get('proposed_remediation',''))[:150]}<br>
            <span class="t t--none">cites: {esc(cites)}</span>
            {verdicts}
          </td>
          <td>{stamp(d.get('real_ts'), d.get('sim_ts'))}</td>
        </tr>""")

    # --- ticket lifecycle ---------------------------------------------------
    tk_rows = []
    for t in data["tickets"]:
        history = sorted(t.get("history", []), key=lambda e: e.get("sim_ts", 0))
        trail = " → ".join(esc(e.get("action", "")) for e in history) or "—"
        first, last = (history[0], history[-1]) if history else ({}, {})
        real_span = (last.get("real_ts", 0) - first.get("real_ts", 0)) / 60
        sim_span = (last.get("sim_ts", 0) - first.get("sim_ts", 0)) / 86400
        tk_rows.append(f"""<tr>
          <td class="k">{esc(t.get('finding_id','—'))}</td>
          <td class="k">{esc(t.get('owner_id','—'))}</td>
          <td><span class="tag tag--{'breach' if t.get('escalated') else 'ok'}">{esc(t.get('status','—').replace('_',' '))}</span></td>
          <td class="k" style="font-size:11.5px">{trail}</td>
          <td><span class="t t--real">{real_span:.1f} min real</span>
              <span class="t t--sim">{sim_span:.0f} days simulated</span></td>
        </tr>""")

    # --- the week, in prose --------------------------------------------
    latest = data["reports"][0] if data["reports"] else None
    if latest:
        m = latest.get("metrics", {})
        paragraphs = "".join(
            f"<p>{esc(par.strip())}</p>"
            for par in (latest.get("summary") or "").split("\n")
            if par.strip()
        )
        report_block = f"""<section class="sec">
          <div class="sec-h"><h2 class="sec-t">This period</h2>
            <span class="sec-c">{esc(latest.get('report_id',''))}</span></div>
          <p class="sec-d">Written by the reporting agent from figures it was given and did
          not compute. The counts below are the ones it was handed, kept beside the prose so
          the narrative can be checked against them.</p>
          <div class="report">
            <div class="report-prose">{paragraphs}</div>
            <div class="report-figures">
              <div class="fig"><span class="fig-k">reviewer disagreement</span>
                <span class="fig-v">{m.get('disagreement_rate', 0) * 100:.0f}%</span>
                <span class="fig-n">{m.get('rejections', 0)} rejections of {m.get('verdicts_total', 0)} verdicts</span></div>
              <div class="fig"><span class="fig-k">ratified</span>
                <span class="fig-v">{m.get('ratification_rate', 0) * 100:.0f}%</span>
                <span class="fig-n">{m.get('ratified', 0)} of {m.get('decisions_total', 0)} decisions</span></div>
              <div class="fig"><span class="fig-k">needing a person</span>
                <span class="fig-v">{m.get('human_queue_total', 0)}</span>
                <span class="fig-n">{m.get('sla_breached', 0)} SLA breached</span></div>
            </div>
          </div>
        </section>"""
    else:
        report_block = ""

    def section(title, count, description, headers, rows, empty):
        head = "".join(f"<th>{h}</th>" for h in headers)
        body = "".join(rows) if rows else ""
        table = (f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"
                 if rows else f'<p class="empty">{empty}</p>')
        return f"""<section class="sec">
          <div class="sec-h"><h2 class="sec-t">{title}</h2><span class="sec-c">{count}</span></div>
          <p class="sec-d">{description}</p>{table}</section>"""

    count_items = "".join(
        f'<span class="count-i">{k} <b>{v}</b></span>' for k, v in counts.items()
    )

    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Remediation Zero — evidence ledger</title>
<meta http-equiv="refresh" content="30">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Source+Sans+3:wght@400;600&display=swap" rel="stylesheet">
<style>{STYLE}</style></head>
<body><div class="wrap">

<header class="mast">
  <div class="mast-row">
    <div>
      <h1 class="wordmark">Remediation Zero</h1>
      <p class="mast-sub">Every action this fleet takes is recorded here with the clock that
      produced it. Nothing on this page is summarised on the fleet's behalf.</p>
    </div>
    <span class="live"><span class="dot"></span>reading firestore · refreshes every 30s</span>
  </div>
</header>

<div class="clocks">
  <div class="clock clock--real">
    <p class="clock-k">real elapsed · never falsified</p>
    <p class="clock-v">{duration(session_age)}</p>
    <p class="clock-n">The orchestrator session has been alive this long in wall-clock time,
    since {iso(SESSION_CREATED)}. This number can only be earned by waiting.</p>
  </div>
  <div class="clock clock--sim">
    <p class="clock-k">scenario time · simulated</p>
    <p class="clock-v">{iso(sim_now).split(' ')[0] if sim_now else '—'}</p>
    <p class="clock-n">The furthest point the simulation has reached. Where this runs ahead of
    wall clock, the gap is shown on every record rather than smoothed over.</p>
  </div>
</div>

<div class="counts">{count_items}</div>

{report_block}

{section("Human queue", f"{len(data['human_queue'])} waiting",
  "The terminal state for anything the fleet could not resolve safely. No agent reads from here; "
  "a person does. A finding arriving here is a successful outcome, not a failure.",
  ["Finding", "Reason class", "What happened", "Recorded"], hq_rows,
  "Nothing is waiting on a person.")}

{section("SLA clocks", f"{len(data['sla'])} tracked",
  "Deadlines run in scenario time so a six-week window can be demonstrated in minutes. "
  "The start time is recorded in both clocks and the wall-clock reading is never adjusted to match.",
  ["Finding", "Owner", "Status", "Deadline", "Started"], sla_rows,
  "No clocks running.")}

{section("Decision log", f"{counts.get('decisions', 0)} recorded",
  "Triage runs on Gemini and proposes. The reviewer runs on Gemma, a different model family, and "
  "must ratify or reject with a stated reason. The rejections are kept: a decision log containing "
  "only agreements would be indistinguishable from one produced without a reviewer.",
  ["Finding", "Outcome", "Proposal and adjudication", "Recorded"], dec_rows,
  "No decisions yet.")}

{section("Ticket lifecycle", f"{len(data['tickets'])} open",
  "What chase did, and how long it really took. The two figures in the last column are the "
  "honest pair: minutes actually elapsed, against the days of scenario being demonstrated.",
  ["Finding", "Owner", "Status", "Trail", "Elapsed"], tk_rows,
  "No tickets opened.")}

<footer class="foot">
  <span>session {esc(SESSION_ID)}</span>
  <span>read-only · this console holds no credential that can write</span>
  <span>synthetic corpus · real CVE identifiers</span>
</footer>
</div></body></html>"""


@app.get("/favicon.svg")
def favicon():
    """Two marks, one teal and one indigo: the two clocks, at 16 pixels."""
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16">'
        '<rect width="16" height="16" fill="#EDEEF0"/>'
        '<rect x="3" y="3" width="3" height="10" fill="#0B7A6B"/>'
        '<rect x="9" y="3" width="3" height="10" fill="#3B5BDB"/></svg>'
    )
    return Response(content=svg, media_type="image/svg+xml")


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/", response_class=HTMLResponse)
def index():
    return HTMLResponse(render(snapshot()))
