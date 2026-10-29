# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Settings -> Context: what matters to this business, set by the owner. Pure rendering.

The server (scripts/local_context.py) works out the state and passes it in. Every value from
a host, a label or a spreadsheet is escaped. A tech sees the same page without forms. The
page runs no script: every change is a plain form post with the session's form token.
"""
from datetime import datetime, timezone
from html import escape

from tools.context import FACT_NAMES

#: The tiles, in order: each built-in statement and the fact value it counts.
TILES = (("Crown jewels", "The business stops if this goes down", "criticality", "high"),
         ("Internet-facing", "Reachable from outside", "internet_facing", True),
         ("Production", "Real work runs here", "environment", "production"),
         ("Sensitive data", "Patient, client or payment records", "sensitive_data", True),
         ("Development", "Testing or development only", "environment", "development"))
#: The four questions, verbatim from the design, and the fact each answer sets.
QUESTIONS = (("Which of these would stop the business if they went down?", "criticality", "high"),
             ("Which can be reached from the internet?", "internet_facing", True),
             ("Which hold patient, client or payment records?", "sensitive_data", True),
             ("Which are for testing or development only?", "environment", "development"))
EFFECT_NAMES = {"crown_jewels": "Treat as Crown jewels", "sensitive_data": "Treat as Sensitive data",
                "grouping": "For grouping only"}
SOURCE_NAMES = {"questions": "Questions", "spreadsheet": "Spreadsheet", "rule": "Rule", "direct": "Edited"}
_CHOICES = {"criticality": (("high", "High (Crown jewels)"), ("medium", "Medium"), ("low", "Low")),
            "internet_facing": (("yes", "Yes"), ("no", "No")),
            "environment": (("production", "Production"), ("development", "Development")),
            "sensitive_data": (("yes", "Yes"), ("no", "No"))}
MESSAGES = {"saved": "Saved.", "applied": "The spreadsheet was applied.",
            "decided": "Recorded.", "removed": "Removed."}


def e(value) -> str:
    return escape(str(value), quote=True)


def _show(value) -> str:
    return "not known" if value is None else "yes" if value is True else "no" if value is False else str(value)


def _day(sim_ts) -> str:
    return datetime.fromtimestamp(sim_ts, tz=timezone.utc).strftime("%Y-%m-%d") if sim_ts else ""


def _form(path: str, token: str, inner: str, button: str) -> str:
    return (f'<form method="post" action="{path}"><input type="hidden" name="token" value="{e(token)}">'
            f'{inner}<button type="submit">{e(button)}</button></form>')


def _fact_select(fact: str, current=None, *, blank="Leave as it is") -> str:
    options = f'<option value="">{e(blank)}</option>' + "".join(
        f'<option value="{v}">{e(label)}</option>' for v, label in _CHOICES[fact])
    options += '<option value="unknown">Not known</option>' if blank == "Leave as it is" else ""
    return f'<label>{e(FACT_NAMES[fact])}<select name="{fact}">{options}</select></label>'


def render_context(state: dict, token: str, *, owner: bool, message: str = "") -> str:
    hosts, labels = state["hosts"], state["labels"]
    out = ['<h2>What matters to this business</h2>',
           '<p>Labels tell triage which hosts matter most. Crown jewels with a vulnerability on '
           "CISA's actively-exploited list is never ranked below High. Changing a label re-ranks "
           "that host's open findings on the next cycle and moves their deadlines.</p>"]
    if not owner:
        out.append('<p class="notice">Only an owner can change business context. Ask the owner to label hosts.</p>')
    if message:
        out.append(f'<p role="status" class="notice">{e(message)}</p>')
    tiles = "".join(
        f'<div class="tile"><b>{sum(1 for h in hosts if h["facts"].get(fact) == value)}</b> {e(name)}'
        f'<br><small>{e(hint)}</small></div>' for name, hint, fact, value in TILES)
    tiles += "".join(f'<div class="tile"><b>{row["count"]}</b> {e(row["name"])}<br><small>'
                     f'{e(EFFECT_NAMES.get(row["effect"], ""))}</small></div>' for row in labels)
    out.append(f'<div class="tiles">{tiles}</div>')
    unknown = state["unknown"]
    if unknown:
        out.append(f'<p class="notice">{unknown} host{"s have" if unknown != 1 else " has"} no business context yet.</p>')
    if owner:
        out.append(_owner_tools(state, token))
    out.append(_suggestions(state, token, owner))
    out.append(_host_table(state, token, owner))
    if state["rules"]:
        rows = "".join(
            f'<li><code>{e(r["pattern"])}</code> ({"IP range" if r["kind"] == "cidr" else "host names ending"}): '
            f'{e(", ".join(f"{FACT_NAMES[f]} {_show(v)}" for f, v in r["facts"].items()))}'
            + (_form("/context/rule-remove", token, f'<input type="hidden" name="rule" value="{e(r["rule_id"])}">',
                     "Remove rule") if owner else "") + "</li>" for r in state["rules"])
        out.append(f"<h3>Rules</h3><ul>{rows}</ul>")
    return "".join(out)


def _owner_tools(state: dict, token: str) -> str:
    hosts = state["hosts"]
    parts = ["<h3>Add context</h3>"]
    questions = []
    for number, (question, fact, value) in enumerate(QUESTIONS, start=1):
        ticks = "".join(f'<label class="check"><input type="checkbox" name="asset" value="{e(h["asset_id"])}"'
                        f'{" checked" if h["facts"].get(fact) == value else ""}> {e(h["name"])}</label>'
                        for h in hosts)
        questions.append(f'<fieldset class="role-block"><legend>{e(question)}</legend>'
                         + _form("/context/questions", token,
                                 f'<input type="hidden" name="question" value="{number}">{ticks}',
                                 "Save this answer") + "</fieldset>")
    parts.append('<details><summary>Answer a few questions</summary><p>Tick the hosts that fit. '
                 'Hosts left unticked stay as they are.</p>' + "".join(questions) + "</details>")
    parts.append('<details><summary>Upload a spreadsheet</summary><p>Any CSV, such as one saved from '
                 'Excel or exported from an asset tool, up to 5 MB and 10,000 rows. You match its columns '
                 'next, and see every change before anything is saved.</p>'
                 '<form method="post" action="/context/upload" enctype="multipart/form-data">'
                 f'<input type="hidden" name="token" value="{e(token)}">'
                 '<input type="file" name="report" accept=".csv,text/csv" required>'
                 '<button type="submit">Read the file</button></form></details>')
    rule_facts = "".join(_fact_select(f, blank="No change") for f in _CHOICES)
    parts.append('<details><summary>Add a rule that suggests</summary><p>A rule never applies itself: '
                 'each host it covers is suggested below for you to approve or deny.</p>'
                 + _form("/context/rule", token,
                         '<label>Match<select name="kind"><option value="cidr">IP range</option>'
                         '<option value="suffix">Host names ending</option></select></label>'
                         '<label>Pattern<input name="pattern" required maxlength="253" '
                         'placeholder="192.0.2.0/24 or files.example.com"></label>' + rule_facts,
                         "Save rule") + "</details>")
    effects = "".join(f'<option value="{k}">{e(v)}</option>' for k, v in EFFECT_NAMES.items())
    parts.append('<details><summary>Create a custom label</summary>'
                 + _form("/context/label", token,
                         '<label>Name<input name="name" required maxlength="40" '
                         'pattern="[A-Za-z0-9 ._\\-]{1,40}"></label>'
                         f'<label>What it does<select name="effect">{effects}</select></label>',
                         "Create label")
                 + "".join(f'<p>{e(row["name"])} '
                           + _form("/context/label-remove", token,
                                   f'<input type="hidden" name="label" value="{e(row["label_id"])}">',
                                   "Delete label") + "</p>" for row in state["labels"])
                 + "</details>")
    return "".join(parts)


def _suggestions(state: dict, token: str, owner: bool) -> str:
    found = state["suggestions"]
    if not found:
        return ""
    rows = []
    for s in found:
        what = ", ".join(f"{FACT_NAMES[f]}: {_show(v)}" for f, v in s["facts"].items())
        buttons = ""
        if owner:
            hidden = (f'<input type="hidden" name="source" value="{e(s["source_id"])}">'
                      f'<input type="hidden" name="asset" value="{e(s["asset_id"])}">')
            buttons = (_form("/context/decide", token, hidden + '<input type="hidden" name="decision" value="approve">', "Approve")
                       + _form("/context/decide", token, hidden + '<input type="hidden" name="decision" value="deny">', "Deny"))
        rows.append(f'<li>{e(s["name"])} — {e(what)} <small>({e(s["from"])})</small>{buttons}</li>')
    return f'<h3>Suggested ({len(found)})</h3><ul>{"".join(rows)}</ul>'


def _host_table(state: dict, token: str, owner: bool) -> str:
    rows = []
    label_options = "".join(f'<option value="{e(r["label_id"])}">{e(r["name"])}</option>' for r in state["labels"])
    for h in state["hosts"]:
        facts = ", ".join(f"{FACT_NAMES[f]}: {_show(v)}" for f, v in h["facts"].items() if v is not None) or "Not known yet"
        origin = "; ".join(f'{FACT_NAMES[f]} — {SOURCE_NAMES.get(p.get("source"), "")} by {p.get("account")}, {_day(p.get("sim_ts"))}'
                           for f, p in h["provenance"].items()) or "—"
        edit = ""
        if owner:
            hidden = f'<input type="hidden" name="asset" value="{e(h["asset_id"])}">'
            edit = ('<details><summary>Edit</summary>'
                    + _form("/context/facts", token, hidden + "".join(_fact_select(f) for f in _CHOICES), "Save")
                    + (_form("/context/tag", token, hidden + f'<select name="label">{label_options}</select>'
                             '<select name="action"><option value="add">Add label</option>'
                             '<option value="remove">Remove label</option></select>', "Apply")
                       if label_options else "")
                    + "</details>")
        labels = ", ".join(h["labels"])
        rows.append(f'<tr><td>{e(h["name"])}</td><td>{e(facts)}{" · " + e(labels) if labels else ""}</td>'
                    f'<td><small>{e(origin)}</small></td><td>{edit}</td></tr>')
    if not rows:
        return '<p>No hosts yet. Hosts appear here once a scan is imported.</p>'
    return ('<h3>Hosts</h3><table><thead><tr><th>Host</th><th>Context</th><th>Where it came from</th>'
            f'<th></th></tr></thead><tbody>{"".join(rows)}</tbody></table>')


def render_mapping(header: list, saved, preview_id: str, token: str) -> str:
    """Match the uploaded file's columns to ours."""
    def select(name, chosen, blank):
        options = f'<option value="">{e(blank)}</option>' + "".join(
            f'<option value="{e(c)}"{" selected" if c == chosen else ""}>{e(c)}</option>' for c in header)
        return f'<select name="{name}">{options}</select>'
    host = saved.host_column if saved else None
    facts = saved.fact_columns if saved else {}
    inner = (f'<input type="hidden" name="preview" value="{e(preview_id)}">'
             f'<label>Host name or IP column{select("host_column", host, "Choose a column")}</label>'
             + "".join(f'<label>{e(FACT_NAMES[f])} column{select("col_" + f, facts.get(f), "Not in this file")}</label>'
                       for f in _CHOICES))
    return ('<h2>Match the columns</h2><p>Criticality reads high, medium or low. Environment reads '
            'production or development (prod, dev and test work too). The other two read yes or no. '
            'Blank cells change nothing.</p>' + _form("/context/preview", token, inner, "Show what will change"))


def render_preview(preview, names: dict, preview_id: str, mapping, token: str) -> str:
    """Every change, problem and unmatched row, before anything is saved."""
    changes = "".join(f'<li>{e(names.get(a, a))}: {e(", ".join(f"{FACT_NAMES[f]} {_show(v)}" for f, v in c.items()))}</li>'
                      for a, c in preview.changes.items())
    problems = "".join(f"<li>{e(p)}</li>" for p in preview.problems)
    waiting = "".join(f'<li>{e(k)}: {e(", ".join(f"{FACT_NAMES[f]} {_show(v)}" for f, v in c.items()))}</li>'
                      for k, c in preview.unmatched)
    hidden = (f'<input type="hidden" name="preview" value="{e(preview_id)}">'
              f'<input type="hidden" name="host_column" value="{e(mapping.host_column)}">'
              + "".join(f'<input type="hidden" name="col_{f}" value="{e(c)}">' for f, c in mapping.fact_columns.items()))
    return ('<h2>What will change</h2>'
            + (f"<h3>Changes ({len(preview.changes)})</h3><ul>{changes}</ul>" if changes else "<p>No host changes.</p>")
            + (f"<h3>Not used ({len(preview.problems)})</h3><ul>{problems}</ul>" if problems else "")
            + (f"<h3>Waiting for a scan ({len(preview.unmatched)})</h3><p>No scanned host matches these "
               "rows yet. They are kept for 90 days and suggested when a scan reports the host.</p>"
               f"<ul>{waiting}</ul>" if waiting else "")
            + _form("/context/upload-apply", token, hidden, "Apply these changes")
            + '<p><a href="/?view=settings&amp;section=context">Cancel</a></p>')
