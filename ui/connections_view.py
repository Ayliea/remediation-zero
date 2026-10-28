# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Settings -> Models: the list of model connections, the coverage strip, and the add popup.

Pure rendering, standard library only. Every value from the settings, the catalogue or the
server is written through `html.escape(..., quote=True)`; the data the popup's script needs is
one JSON block (`<script type="application/json">`, never executed) with `<`, `>` and `&`
escaped, so no value can end it. The one executable script is SCRIPT, the exact text of
assets/connections.js; the page's CSP allows it by SCRIPT_HASH and nothing else. A tech gets
the list and the coverage strip only: no controls, no dialog, no script.
"""
import base64
import hashlib
import json
import re
from html import escape
from pathlib import Path

from tools.local_settings import MAX_CONNECTION_NAME
from tools.model_catalogue import JOB_NAMES, JOB_ORDER
from tools.model_roles import FAMILIES
from tools.models import FORMATS

SCRIPT = (Path(__file__).parent / 'assets' / 'connections.js').read_text(encoding='utf-8')
SCRIPT_HASH = 'sha256-' + base64.b64encode(hashlib.sha256(SCRIPT.encode('utf-8')).digest()).decode('ascii')
if '</script' in SCRIPT.lower() or '<!--' in SCRIPT:
    raise ValueError('assets/connections.js cannot be embedded in a <script> element')
#: The list's and the popup's look, in this section's own <style>: ui/theme.css is shared with the
#: cloud console, whose output must not change.
STYLE = (Path(__file__).parent / 'assets' / 'connections.css').read_text(encoding='utf-8')
if '</style' in STYLE.lower():
    raise ValueError('assets/connections.css cannot be embedded in a <style> element')

#: The tile colour used when a preset's colour is not #rrggbb (the catalogue refuses one at load).
NEUTRAL = '#a1a1aa'
_COLOUR = re.compile(r'#[0-9a-f]{6}')
_KEY_PAGE = re.compile(r'https://[a-z0-9.-]+(/[A-Za-z0-9._~/-]*)?')
FORMAT_LABELS = {'openai_chat': 'OpenAI-compatible chat', 'anthropic_messages': 'Anthropic Messages',
                 'gemini_api': 'Gemini API'}

# Simple drawn icons (inline SVG markup, not loaded images). Decorative: the text beside says it all.
_SVG = '<svg class="rz-icon" width="56" height="56" viewBox="0 0 64 64" aria-hidden="true" focusable="false">'
_STROKE = 'stroke="#111" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" fill="none"'
ICONS = {
    'add': f'{_SVG}<circle cx="32" cy="32" r="27" fill="#dbeafe" stroke="#111" stroke-width="2.5"/>'
           f'<path d="M22 32h20M32 22v20" {_STROKE}/></svg>',
    'lock': f'{_SVG}<rect x="15" y="28" width="34" height="25" rx="6" fill="#e0e7ff" stroke="#111" stroke-width="2.5"/>'
            f'<path d="M22 28v-6a10 10 0 0 1 20 0v6M32 38v6" {_STROKE}/></svg>',
    'jobs': f'{_SVG}<rect x="10" y="12" width="44" height="40" rx="10" fill="#fef3c7" stroke="#111" stroke-width="2.5"/>'
            f'<path d="M20 26l5 5 9-10M20 40h24" {_STROKE}/></svg>',
    'plug': f'{_SVG}<circle cx="32" cy="32" r="27" fill="#ede9fe" stroke="#111" stroke-width="2.5"/>'
            f'<path d="M26 20v8M38 20v8M22 28h20v6a10 10 0 0 1-20 0zM32 44v6" {_STROKE}/></svg>',
    'done': f'{_SVG}<circle cx="32" cy="32" r="27" fill="#bbf7d0" stroke="#111" stroke-width="2.5"/>'
            f'<path d="M20 33l8 8 16-17" {_STROKE}/></svg>',
    'warn': f'{_SVG}<path d="M32 9 57 53H7z" fill="#fee2e2" stroke="#111" stroke-width="2.5" stroke-linejoin="round"/>'
            f'<path d="M32 26v12M32 45v1" {_STROKE}/></svg>',
}
_SMALL = '<svg width="22" height="22" viewBox="0 0 24 24" aria-hidden="true" focusable="false">'
_THIN = 'stroke="#111" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" fill="none"'
#: One per job, cloned by the script from <template id="rz-icon-ROLE">.
JOB_ICONS = {
    'proposer': ('#fee2e2', f'{_SMALL}<path d="M5 4v6a5 5 0 0 0 10 0V4M15 15a4 4 0 0 0 4-4V9" {_THIN}/>'
                            f'<circle cx="19" cy="7" r="2" {_THIN}/></svg>'),
    'reviewer': ('#ede9fe', f'{_SMALL}<circle cx="10.5" cy="10.5" r="6" {_THIN}/><path d="M15 15l5 5" {_THIN}/></svg>'),
    'guard': ('#dcfce7', f'{_SMALL}<path d="M12 3l7 3v5c0 5-3 8-7 10-4-2-7-5-7-10V6z" {_THIN}/></svg>'),
    'summarizer': ('#e0f2fe', f'{_SMALL}<path d="M6 3h9l4 4v14H6zM9 11h7M9 15h7" {_THIN}/></svg>'),
}


#: A job's own key, said only where it differs from its connection's (an environment key wins).
_JOB_KEY = {'set on the server': 'key set on the server', 'key missing': 'key missing'}


def _e(value):
    return escape(str(value), quote=True)


def _colour(value):
    return value if isinstance(value, str) and _COLOUR.fullmatch(value) else NEUTRAL


def _key_page(value):
    return value if isinstance(value, str) and _KEY_PAGE.fullmatch(value) else ''


def _mark(letter, colour, extra=''):
    return f'<span class="rz-mark{extra}" style="background:{_colour(colour)}" aria-hidden="true">{_e(letter)}</span>'


def _json_block(value):
    """JSON that an HTML parser cannot end early: `<`, `>` and `&` become \\u escapes."""
    text = json.dumps(value, ensure_ascii=True, separators=(',', ':'))
    text = text.replace('<', '\\u003c').replace('>', '\\u003e').replace('&', '\\u0026')
    return f'<script type="application/json" id="rz-connections">{text}</script>'


def _job_line(job, key_hint):
    """A job: its model, then its family and timeout, and its own key where that differs."""
    notes = [f'family {job["family"]}', f'timeout {job["timeout_seconds"]} s']
    if job['key'] in _JOB_KEY and job['key'] != key_hint:
        notes.append(_JOB_KEY[job['key']])
    return (f'<li><strong>{_e(job["job"])}</strong> {_e(job["model"])} '
            f'<span class="rz-muted">({" · ".join(_e(note) for note in notes)})</span></li>')


def _row(row, owner):
    jobs = ''.join(_job_line(job, row['key_hint']) for job in row['jobs'])
    jobs = f'<ul class="rz-jobs">{jobs}</ul>' if jobs else '<p class="rz-muted">Does no jobs yet.</p>'
    actions = ''
    if owner:
        cid = _e(row['id'])
        name = _e(row['name'])
        buttons = [('edit', 'Edit')]
        if row['can_replace_key']:
            buttons.append(('replace', 'Replace key'))
        if row['jobs']:
            buttons.append(('test', 'Test again'))
        buttons.append(('delete', 'Delete'))
        actions = '<div class="rz-actions">' + ''.join(
            f'<button type="button" class="rz-btn" data-action="{action}" data-connection="{cid}" '
            f'aria-label="{label} {name}">{label}</button>' for action, label in buttons) + '</div>'
    return (f'<article class="rz-row">{_mark(row["letter"], row["colour"])}<div class="rz-row-main">'
            f'<h3>{_e(row["name"])}</h3><p class="rz-muted">Key: {_e(row["key_hint"])} · {_e(row["last_test_text"])}</p>'
            f'<p class="rz-muted">Address: {_e(row["base_url"])}'
            + (f' · CA file: {_e(row["ca_file"])}' if row['ca_file'] else '') + '</p>'
            f'{jobs}</div>{actions}</article>')


def coverage_strip(coverage):
    items = ''
    for job in coverage:
        if job['overridden']:   # RZ_MODEL or RZ_MODEL_ENDPOINT: the saved choice is not what runs
            text, kind = 'set on the server' + (f' · {job["model"]}' if job['model'] else ''), 'ok'
        elif job['connection'] is None and job['model'] is None:
            text, kind = 'nobody', 'gap'
        else:
            text, kind = f'{job["connection"] or "set on the server"} · {job["model"]}', 'ok'
        if job['family_note']:
            text += f' · {job["family_note"]}'
        items += f'<li class="rz-pill rz-{kind}"><strong>{_e(job["job"])}</strong> {_e(text)}</li>'
    return f'<ul class="rz-cover" aria-label="Who does each job">{items}</ul>'


def _policy_form(policy, token):
    option = lambda value, label: f'<option value="{value}"{" selected" if policy == value else ""}>{label}</option>'
    return ('<section id="rz-policy" class="rz-policy"><h3>Same-family reviews</h3>'
            f'<form method="post" action="/settings"><input type="hidden" name="token" value="{_e(token)}">'
            '<input type="hidden" name="section" value="model">'
            '<label>When Review is the same model family as Triage<select name="same_family_policy">'
            f'{option("wait", "Wait for a person (recommended)")}{option("proceed", "Proceed automatically")}</select></label>'
            '<p>A model reviewing reasoning from its own family shares its blind spots.</p>'
            '<div class="row"><button type="submit">Save preferences</button></div></form></section>')


def _buttons(*items):
    """(do, label, dark) per button; a dark button is the card's primary one (Enter presses it)."""
    return '<div class="rz-btns">' + ''.join(
        f'<button type="button" class="rz-btn{" rz-dark" if dark else ""}" data-do="{do}"'
        f'{" data-primary" if dark else ""}>{label}</button>' for do, label, dark in items) + '</div>'


_STEPS = '<p class="rz-steps" data-steps></p>'
_STATUS = '<p class="rz-status" role="status" data-status></p>'
_ERROR = '<p class="rz-error" role="alert" data-error hidden></p><p class="rz-small" data-hint hidden></p>'


def _dialog(presets):
    tiles = ''.join(
        f'<button type="button" class="rz-tile" data-provider="{_e(p.id)}">{_mark(p.letter, p.colour)}'
        f'<span>{_e(p.name)}</span></button>' for p in presets)
    formats = ''.join(f'<option value="{_e(f)}">{_e(FORMAT_LABELS.get(f, f))}</option>' for f in FORMATS)
    families = '<option value="">Detect from model name</option>' + ''.join(
        f'<option value="{_e(f)}">{_e(f)}</option>' for f in FAMILIES)
    plain = 'autocomplete="off" spellcheck="false" autocapitalize="off"'
    cards = [
        ('confirm', f'{ICONS["lock"]}<h2 id="rz-t-confirm">Confirm it\'s you</h2>'
                    '<p>Before this change, enter your password, or a new code from your authenticator app. '
                    'Fill in one box.</p>'
                    '<label class="rz-label">Password<input id="rz-password" type="password" '
                    'autocomplete="current-password" maxlength="1024"></label>'
                    '<label class="rz-label">Or a code from your authenticator app<input id="rz-code" '
                    'autocomplete="one-time-code" inputmode="numeric" maxlength="6"></label>'
                    f'{_ERROR}{_buttons(("cancel", "Cancel", False), ("confirm", "Confirm", True))}'),
        ('provider', f'{_STEPS}{ICONS["add"]}<h2 id="rz-t-provider">Connect a model</h2>'
                     '<p>Pick where your AI comes from. You can add more later.</p>'
                     f'<label class="rz-sr" for="rz-search">Search providers</label>'
                     f'<input id="rz-search" class="rz-search" type="search" placeholder="Search providers" {plain}>'
                     f'<div class="rz-grid">{tiles}</div>'
                     '<p class="rz-small" data-none hidden>No provider matches. Other connects any server that '
                     'speaks one of the supported formats.</p>'
                     f'{_buttons(("cancel", "Cancel", False))}'),
        ('key', f'{_STEPS}<span class="rz-mark rz-big" data-mark aria-hidden="true"></span>'
                '<h2 id="rz-t-key" data-title>Your key</h2><p data-line></p>'
                f'<label class="rz-label" data-field="format">Request format<select id="rz-format">{formats}</select></label>'
                f'<label class="rz-label" data-field="address"><span data-address-label>Address</span>'
                f'<input id="rz-address" type="url" maxlength="2048" {plain}></label>'
                f'<label class="rz-label" data-field="key"><span data-key-label>API key</span>'
                f'<input id="rz-key" type="password" autocomplete="new-password" spellcheck="false" '
                'autocapitalize="off" data-1p-ignore data-lpignore="true" maxlength="4096"></label>'
                '<p class="rz-small"><a data-keypage href="#" target="_blank" rel="noopener noreferrer" hidden>'
                'Where do I find this? (opens in a new tab)</a></p>'
                '<details class="rz-advanced"><summary>Advanced options</summary>'
                f'<label class="rz-label" data-field="base">Address override<input id="rz-base" type="url" '
                f'maxlength="2048" {plain}></label>'
                f'<label class="rz-label">CA certificate file on this server<input id="rz-ca" maxlength="4096" {plain} '
                'placeholder="/etc/remediation-zero/model-ca.pem"></label>'
                '<p class="rz-small">An address uses HTTPS unless it is on this machine, and carries no user name, '
                'password, query or fragment. A CA file is only for an HTTPS address whose certificate is '
                'self-signed or from your own CA: its absolute path on this server.</p></details>'
                f'{_ERROR}{_buttons(("back", "Back", False), ("next", "Continue", True))}'),
        ('model', f'{_STEPS}<span class="rz-mark rz-big" data-mark aria-hidden="true"></span>'
                  '<h2 id="rz-t-model">Pick a model</h2><p>These are the models it lists. Pick one, or type its name.</p>'
                  f'{_STATUS}<div class="rz-models" data-models role="group" aria-label="Listed models"></div>'
                  f'<label class="rz-label">Type a model name<input id="rz-model" maxlength="200" {plain}></label>'
                  '<p class="rz-small" data-note hidden></p>'
                  '<details class="rz-advanced"><summary>Advanced options</summary>'
                  f'<label class="rz-label">Model family<select id="rz-family">{families}</select></label>'
                  '<label class="rz-label">Timeout in seconds<input id="rz-timeout" type="number" min="5" max="600" '
                  'value="60"></label><p class="rz-small">How long to wait for an answer, 5 to 600. A local model on '
                  'a CPU-only server, or one loading for its first request, can need several minutes.</p></details>'
                  f'{_ERROR}{_buttons(("back", "Back", False), ("next", "Continue", True))}'),
        ('jobs', f'{_STEPS}{ICONS["jobs"]}<h2 id="rz-t-jobs">What should it do?</h2>'
                 '<p>We\'ve switched on what we suggest. Change anything.</p>'
                 f'<ul class="rz-cover" data-cover aria-label="Who does each job now"></ul>{_STATUS}'
                 '<div data-jobs></div>'
                 f'{_ERROR}{_buttons(("back", "Back", False), ("next", "Continue", True))}'),
        ('test', f'{_STEPS}{ICONS["plug"]}<h2 id="rz-t-test">Test and save</h2>'
                 '<p>Test sends one short request for each job below, with its model. It may use a little provider '
                 'credit. Nothing is saved unless every test passes.</p>'
                 f'<label class="rz-label" data-field="name">Connection name<input id="rz-name" '
                 f'maxlength="{MAX_CONNECTION_NAME}" {plain}></label>'
                 f'<ul class="rz-summary" data-summary></ul>{_STATUS}'
                 f'{_ERROR}{_buttons(("back", "Back", False), ("test", "Test", True))}'),
        ('wait', f'{ICONS["plug"]}<h2 id="rz-t-wait" data-title>Testing</h2>{_STATUS}'),
        ('done', f'<span data-icon-ok>{ICONS["done"]}</span><span data-icon-bad hidden>{ICONS["warn"]}</span>'
                 '<h2 id="rz-t-done" data-title></h2><p data-line></p>'
                 '<p class="rz-small" data-hint hidden></p>'
                 '<p class="rz-error" data-audit hidden>This change was saved, but the audit trail could not record '
                 'it. Check the server log.</p>'
                 f'{_buttons(("another", "Add another", False), ("done", "Done", True))}'),
        ('delete', f'{ICONS["warn"]}<h2 id="rz-t-delete" data-title>Delete this connection?</h2>'
                   '<p data-line></p><p>Its stored key is deleted too. This cannot be undone.</p>'
                   f'{_ERROR}{_buttons(("cancel", "Cancel", False), ("delete", "Delete", True))}'),
    ]
    templates = ''.join(f'<template id="rz-icon-{role}"><span class="rz-ico" style="background:{colour}" '
                        f'aria-hidden="true">{svg}</span></template>' for role, (colour, svg) in JOB_ICONS.items())
    return ('<dialog id="rz-dialog" class="rz-dialog" aria-labelledby="rz-t-provider">'
            + ''.join(f'<section class="rz-card" data-card="{name}" hidden>{body}</section>' for name, body in cards)
            + templates + '</dialog>')


def _data(rows, presets, token, confirmed, deletions):
    return {
        'token': token, 'confirmed': bool(confirmed),
        'presets': [{'id': p.id, 'name': p.name, 'letter': p.letter, 'colour': _colour(p.colour),
                     'format': p.format, 'base_url': p.base_url, 'needs_key': p.needs_key,
                     'key_page': _key_page(p.key_page)} for p in presets],
        'connections': [{'id': r['id'], 'name': r['name'], 'provider': r['provider'], 'base_url': r['base_url'],
                         'can_replace_key': r['can_replace_key'],
                         'jobs': [{'role': j['role'], 'job': j['job'], 'model': j['model'], 'family': j['family'],
                                   'timeout_seconds': j['timeout_seconds']} for j in r['jobs']]} for r in rows],
        'deletions': dict(deletions), 'formats': list(FORMATS), 'families': list(FAMILIES),
        'jobs': [{'role': role, 'job': JOB_NAMES[role]} for role in JOB_ORDER],
    }


def models_section(rows, coverage, presets, policy, token, *, owner: bool, confirmed: bool,
                   deletions: dict[str, str]) -> str:
    """The Models section's body. `rows` and `coverage` are tools.connections.rows and coverage;
    `presets` tools.model_catalogue.presets(); `deletions` each connection id's
    deletion_consequences sentence; `confirmed` whether the session's re-confirm window is open."""
    body = (f'<style>{STYLE}</style><h2>Your models, your choice</h2><p>Each connection is one provider account: a hosted model with '
            'your own key, or a model you run. Below it, which connection and model does each job. Opening this '
            'page makes no model calls.</p>')
    body += '<div class="rz-list">' + (''.join(_row(row, owner) for row in rows)
                                         or '<p class="rz-muted">No model connections yet.</p>') + '</div>'
    if owner:
        body += ('<p><button type="button" class="rz-btn rz-dark" data-action="add">+ Add a connection</button></p>')
    body += '<h3>Who does each job</h3>' + coverage_strip(coverage)
    if any(job['role'] == 'reviewer' and job['model'] is None for job in coverage):
        body += '<p class="notice">No reviewer configured: every suggestion waits for a person.</p>'
    body += _policy_form(policy, token)
    body += ('<details><summary>Keys set on the server</summary><p>A key can also come from the environment '
             'Remediation Zero starts in: RZ_PROPOSER_API_KEY (or RZ_MODEL_API_KEY) for Triage, '
             'RZ_REVIEWER_API_KEY for Review, RZ_GUARD_API_KEY for Screening and RZ_SUMMARIZER_API_KEY for '
             'Summaries. One set there is used instead of a stored key, and the list says "set on the server". '
             'No key is ever shown here.</p></details>')
    body += ('<details><summary>Run an optional sample check</summary><p>From your installation folder, run '
             '<code>python3 -m scripts.local check-models</code> (add <code>--role reviewer</code> to check one '
             'role). This sends the bundled synthetic example to each configured model and may incur provider '
             'charges. On Windows, use <code>py -3.12</code>. Use the same database and environment as the '
             'dashboard. No check runs when you open this page.</p></details>')
    if owner:
        body += _dialog(presets) + _json_block(_data(rows, presets, token, confirmed, deletions))
        body += f'<script>{SCRIPT}</script>'
    return body
