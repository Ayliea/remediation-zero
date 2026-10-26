# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Pure rendering for the pages that work without a session: sign-in, the first
account, invite links, re-confirm, and the first-account-only page.

Standard library only; no request handling, no reads. Every value is escaped.
The QR code arrives as an inline <svg> string made by tools.qr_svg, which holds
no script, link or external reference, so the page CSP needs nothing new."""
from html import escape

from ui.dashboard_view import branding


def _e(value):
    return escape(str(value), quote=True)


def page(title, body):
    theme, logo = branding()
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_e(title)} · Remediation Zero</title><style>
{theme}
.account-card{{max-width:34rem}}.account-card label{{display:block;margin:.8rem 0}}.account-card input,.account-card select{{display:block;width:100%;max-width:28rem;padding:.5rem;margin-top:.25rem}}
.qr svg{{width:12rem;height:12rem}}.codes{{columns:2;font-size:1.1rem}}.totp-key{{word-break:break-all}}
</style></head><body><div class="shell"><aside><div class="brand"><img src="data:image/png;base64,{logo}" alt="Remediation Zero by Ayliea"></div></aside><main><h1>{_e(title)}</h1>{body}<footer>Remediation Zero by Ayliea</footer></main></div></body></html>'''


def _message(message):
    return f'<section class="notice" role="alert"><p>{_e(message)}</p></section>' if message else ''


def _pre(pre):
    return f'<input type="hidden" name="pre" value="{_e(pre)}">'


def _enrol(secret, uri, qr):
    """The authenticator-app step: QR code, the key to type, and the otpauth link."""
    return (f'<h2>Set up your authenticator app</h2><p>Scan this code, or type the key into the app.</p>'
            f'<div class="qr">{qr}</div><p>Key: <code class="totp-key">{_e(secret)}</code></p>'
            f'<p><a href="{_e(uri)}">Open in an authenticator app on this device</a></p>')


def sign_in_page(pre, message=''):
    body = (f'{_message(message)}<form class="card account-card" method="post" action="/signin">{_pre(pre)}'
            '<label>Email <input name="email" type="email" autocomplete="username" required maxlength="254"></label>'
            '<label>Password <input name="password" type="password" autocomplete="current-password" required maxlength="1024"></label>'
            '<label>Code from your authenticator app, or a recovery code <input name="code" autocomplete="one-time-code" required maxlength="32"></label>'
            '<button type="submit">Sign in</button></form>')
    return page('Sign in', body)


def setup_page(pre, secret, uri, qr, *, email='', role='owner', message=''):
    roles = ''.join(f'<option value="{value}"{" selected" if value == role else ""}>{label}</option>'
                    for value, label in (('owner', 'The business owner'), ('tech', 'An IT provider setting it up for a client')))
    body = (f'<p>No account exists yet. This one is created on the server itself; everyone else is invited.</p>{_message(message)}'
            f'<form class="card account-card" method="post" action="/setup">{_pre(pre)}'
            f'<input type="hidden" name="secret" value="{_e(secret)}">'
            f'<label>Email <input name="email" type="email" autocomplete="username" required maxlength="254" value="{_e(email)}"></label>'
            f'<label>You are <select name="role">{roles}</select></label>'
            '<label>Password (12 to 128 characters) <input name="password" type="password" autocomplete="new-password" required minlength="12" maxlength="128"></label>'
            f'{_enrol(secret, uri, qr)}'
            '<label>Code from the app <input name="code" autocomplete="one-time-code" inputmode="numeric" required maxlength="6"></label>'
            '<button type="submit">Create the first account</button></form>')
    return page('Create the first account', body)


def first_account_page(command):
    body = ('<section class="card account-card"><p>No account exists yet, and the first one can only be created on the server itself. '
            'On the server, run:</p>'
            f'<pre>{_e(command)}</pre>'
            '<p>Then sign in here. Until then, nothing else is shown.</p></section>')
    return page('Create the first account', body)


def recovery_codes_page(codes, title):
    items = ''.join(f'<li><code>{_e(code)}</code></li>' for code in codes)
    body = ('<section class="card account-card"><h2>Your recovery codes</h2>'
            '<p>Each code signs you in once in place of an authenticator code. Keep them somewhere safe: '
            'they are shown only now.</p>'
            f'<ul class="codes">{items}</ul><p><a class="button" href="/">Open the dashboard</a></p></section>')
    return page(title, body)


def done_page():
    return page('Done', '<section class="card account-card"><p>Saved. You are signed in.</p>'
                        '<p><a class="button" href="/">Open the dashboard</a></p></section>')


_INVITE_TITLES = {'join': 'Join Remediation Zero', 'recover': 'Set a new password and authenticator',
                  'reset_password': 'Set a new password', 'reset_mfa': 'Set up a new authenticator'}


def invite_page(pre, kind, email, role, secret, uri, qr, message=''):
    who = f'<p>For <strong>{_e(email)}</strong>, as {"owner" if role == "owner" else "tech"}.</p>'
    new_password = ('<label>New password (12 to 128 characters) <input name="password" type="password" '
                    'autocomplete="new-password" required minlength="12" maxlength="128"></label>')
    code = '<label>Code from the app <input name="code" autocomplete="one-time-code" inputmode="numeric" required maxlength="6"></label>'
    if kind == 'reset_password':
        fields = new_password + code.replace('Code from the app', 'Code from your authenticator app')
    elif kind == 'reset_mfa':
        fields = ('<label>Your current password <input name="current_password" type="password" '
                  'autocomplete="current-password" required maxlength="1024"></label>' + _enrol(secret, uri, qr) + code)
    else:
        fields = new_password + _enrol(secret, uri, qr) + code
    body = (f'{who}{_message(message)}<form class="card account-card" method="post">{_pre(pre)}'
            f'{fields}<button type="submit">Save</button></form>'
            '<p class="muted">This link works once and expires after 7 days.</p>')
    return page(_INVITE_TITLES.get(kind, 'Join Remediation Zero'), body)


def invalid_link_page():
    return page('This link does not work', '<section class="card account-card"><p>The link has been used, has expired, '
                                           'or was revoked. Ask the person who sent it for a new one.</p></section>')


def confirm_page(pre, next_path, message=''):
    body = ('<p>Confirm it is you before changing settings. Enter your password, or a new code from your authenticator app.</p>'
            f'{_message(message)}<form class="card account-card" method="post">{_pre(pre)}'
            '<label>Password <input name="password" type="password" autocomplete="current-password" maxlength="1024"></label>'
            '<label>Or a code from your authenticator app <input name="code" autocomplete="one-time-code" inputmode="numeric" maxlength="6"></label>'
            f'<button type="submit">Confirm</button> <a href="{_e(next_path)}">Cancel</a></form>')
    return page('Confirm it is you', body)


def too_many_page(seconds):
    return page('Too many attempts', f'<section class="card account-card"><p>Too many attempts from this address. '
                                     f'Wait {_e(seconds)} seconds, then try again.</p></section>')
