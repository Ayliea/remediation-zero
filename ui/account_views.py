# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Pure rendering for the account pages: sign-in, the first account, invite
links, re-confirm, the first-account-only page, and the owners' Accounts page
with its one-time link page.

Standard library only; no request handling, no reads. Every value is escaped.
The QR code arrives as an inline <svg> string made by tools.qr_svg, which holds
no script, link or external reference, so the page CSP needs nothing new."""
import json
from html import escape

from ui.dashboard_view import branding, utc_time


def _e(value):
    return escape(str(value), quote=True)


def page(title, body):
    theme, logo = branding()
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_e(title)} · Remediation Zero</title><style>
{theme}
.account-card{{max-width:34rem}}.account-card label{{display:block;margin:.8rem 0}}.account-card input,.account-card select{{display:block;width:100%;max-width:28rem;padding:.5rem;margin-top:.25rem}}
.inline-form{{display:inline-block;margin:.15rem .3rem .15rem 0}}table{{border-collapse:collapse;width:100%}}td,th{{text-align:left;padding:.3rem .5rem;vertical-align:top}}
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


def invite_page(pre, kind, email, role, secret, uri, qr, message='', secret_mac=None):
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
    sealed = (f'<input type="hidden" name="secret" value="{_e(secret)}">'
              f'<input type="hidden" name="secret_mac" value="{_e(secret_mac)}">') if secret and secret_mac else ''
    body = (f'{who}{_message(message)}<form class="card account-card" method="post">{_pre(pre)}{sealed}'
            f'{fields}<button type="submit">Save</button></form>'
            '<p class="muted">This link works once and expires after 7 days.</p>')
    return page(_INVITE_TITLES.get(kind, 'Join Remediation Zero'), body)


def expired_page():
    """A link page's form that no longer verifies, most often after a restart."""
    return page('This page has expired', '<section class="card account-card"><p>This page has expired. '
                                          'Open the link again.</p></section>')


def invalid_link_page():
    return page('This link does not work', '<section class="card account-card"><p>The link has been used, has expired, '
                                           'or was revoked. Ask the person who sent it for a new one.</p></section>')


def confirm_page(pre, next_path, message=''):
    body = ('<p>Confirm it is you before this change. Enter your password, or a new code from your authenticator app.</p>'
            f'{_message(message)}<form class="card account-card" method="post">{_pre(pre)}'
            '<label>Password <input name="password" type="password" autocomplete="current-password" maxlength="1024"></label>'
            '<label>Or a code from your authenticator app <input name="code" autocomplete="one-time-code" inputmode="numeric" maxlength="6"></label>'
            f'<button type="submit">Confirm</button> <a href="{_e(next_path)}">Cancel</a></form>')
    return page('Confirm it is you', body)


def too_many_page(seconds):
    return page('Too many attempts', f'<section class="card account-card"><p>Too many attempts from this address. '
                                     f'Wait {_e(seconds)} seconds, then try again.</p></section>')


# --- the owners' Accounts page ---------------------------------------------------

#: One fixed sentence per tools.accounts.AccountRefused code. A page never shows the code
#: itself; a code not listed here gets the sentence under None.
REFUSALS = {
    'accounts_exist': 'An account already exists, so the first account cannot be created again.',
    'not_allowed': 'Your account is not allowed to do that. Nothing was changed.',
    'last_owner': 'This is the last owner. Make another account an owner first. Nothing was changed.',
    'no_such_account': 'That account no longer exists or is not active. Nothing was changed.',
    'invalid_link': 'That link has already been used, has expired, or was revoked. Nothing was changed.',
    'bad_code': 'That authenticator code did not match. Nothing was changed.',
    'password': 'That password cannot be used. Nothing was changed.',
    'email_taken': 'That email already has an account or a live invite. Nothing was changed.',
    'locked': 'That account is locked after too many attempts. Wait 15 minutes. Nothing was changed.',
    None: 'That could not be done. Nothing was changed.',
}
#: A form that is not one of this page's own: an unknown role or link kind, a malformed email.
INVALID_FORM = 'Check the email address and the choices, then try again. Nothing was changed.'

_ROLE_NAMES = {'owner': 'owner', 'tech': 'tech'}
_STATUS_NAMES = {'active': 'active', 'invited': 'invited', 'removed': 'removed'}
_LINK_KINDS = {'join': 'Invite', 'reset_password': 'Password reset', 'reset_mfa': 'Authenticator reset',
               'recover': 'Owner recovery'}
_EVENT_NAMES = {
    'setup': 'First account created', 'sign_in': 'Signed in', 'sign_in_failed': 'Sign-in failed',
    'locked': 'Locked out', 'sign_out': 'Signed out', 'invite_created': 'Invite created',
    'invite_accepted': 'Invite accepted', 'invite_revoked': 'Link revoked',
    'reset_link_created': 'Reset link created', 'password_reset': 'Password reset',
    'mfa_reset': 'Authenticator reset', 'role_changed': 'Role changed', 'removed': 'Account removed',
    'recover_owner': 'Owner recovery link made on the server', 'owner_recovered': 'Owner recovery completed',
}
#: The only part of an event's detail a page shows: a reason from this closed set. Nothing
#: else in detail (never email_hmac) is read.
_REASONS = {'malformed': 'what was typed as the email was not an address',
            'maker_not_allowed': 'whoever made it can no longer issue it',
            'reinvited': 'invited again after being removed'}


def refusal_sentence(code):
    return REFUSALS[code] if code in REFUSALS else REFUSALS[None]


def _hidden(name, value):
    return f'<input type="hidden" name="{name}" value="{_e(value)}">'


def _form(action, token, fields, button):
    return (f'<form class="inline-form" method="post" action="{action}">{_hidden("token", token)}{fields}'
            f'<button type="submit">{_e(button)}</button></form>')


def _account_actions(row, token):
    if row['status'] == 'removed':
        return ''
    who = _hidden('account', row['id'])
    remove = _form('/accounts/remove', token, who, 'Remove')
    if row['status'] != 'active':
        return remove
    other = 'tech' if row['role'] == 'owner' else 'owner'
    return (_form('/accounts/role', token, who + _hidden('role', other), f'Make {other}')
            + _form('/accounts/reset', token, who + _hidden('kind', 'reset_password'), 'Password reset link')
            + _form('/accounts/reset', token, who + _hidden('kind', 'reset_mfa'), 'Authenticator reset link')
            + remove)


#: Events whose note says the role change they made, from `from` and `to` in their detail.
_ROLE_CHANGES = frozenset({'role_changed', 'recover_owner'})


def _note(event, detail):
    """The Note column. It reads only `reason` (from the closed set _REASONS) and, for a role
    change, `from` and `to` (each from the closed role set); no other detail key is ever read,
    so email_hmac never shows."""
    try:
        found = json.loads(detail) if detail else None
    except ValueError:
        return ''
    if not isinstance(found, dict):
        return ''
    reason = found.get('reason')
    notes = [_REASONS[reason]] if isinstance(reason, str) and reason in _REASONS else []
    if event in _ROLE_CHANGES:
        old, new = found.get('from'), found.get('to')
        if isinstance(old, str) and isinstance(new, str) and old in _ROLE_NAMES and new in _ROLE_NAMES:
            notes.append(f'{_ROLE_NAMES[old]} to {_ROLE_NAMES[new]}')
    return '; '.join(notes)


#: The Audit trail's columns, in order; `account events` prints the same ones. `from` is the
#: address the event was recorded from (the client address the rate limit uses), as stored.
EVENT_COLUMNS = ('time', 'event', 'by', 'account', 'via', 'from', 'note')


def event_columns(row, emails):
    """One audit event as the Audit trail shows it, in plain text: EVENT_COLUMNS to values.
    `emails` maps account ids to emails. Only `_note` reads the detail. The page escapes every
    value; `account events` prints them as JSON."""
    def person(account_id):
        return emails.get(account_id, 'unknown account') if account_id else '—'
    subject = person(row['subject_id'])
    if row['event'] == 'sign_in_failed' and not row['subject_id']:
        subject = 'no such account'
    return {'time': utc_time(row['real_ts']), 'event': _EVENT_NAMES.get(row['event'], row['event']),
            'by': person(row['actor_id']), 'account': subject, 'via': row['via'] or '—',
            'from': row['source'] or '—', 'note': _note(row['event'], row['detail'])}


def _event_row(row, emails):
    columns = event_columns(row, emails)
    return '<tr>' + ''.join(f'<td>{_e(columns[name])}</td>' for name in EVENT_COLUMNS) + '</tr>'


def accounts_page(overview, token, *, email, message=''):
    """The owners' page: accounts, live links and the newest events. `overview` is
    tools.accounts.Accounts.overview(); `token` is the session's form token."""
    emails = {row['id']: row['email'] for row in overview['accounts']}
    accounts = ''.join(
        f'<tr><td>{_e(row["email"])}</td><td>{_e(_ROLE_NAMES.get(row["role"], "unknown"))}</td>'
        f'<td>{_e(_STATUS_NAMES.get(row["status"], "unknown"))}</td><td>{_account_actions(row, token)}</td></tr>'
        for row in overview['accounts'])
    invites = ''.join(
        f'<tr><td>{_e(row["email"])}</td><td>{_e(_LINK_KINDS.get(row["kind"], "Link"))}</td>'
        f'<td>{_e(_ROLE_NAMES.get(row["role"], "unknown"))}</td><td>{_e(utc_time(row["expires_at"]))}</td>'
        f'<td>{_form("/accounts/revoke", token, _hidden("invite", row["id"]), "Revoke")}</td></tr>'
        for row in overview['invites'])
    events = ''.join(_event_row(row, emails) for row in overview['events'])
    invite_form = _form('/accounts/invite', token,
                        '<label>Email <input name="email" type="email" required maxlength="254"></label>'
                        '<label>Role <select name="role"><option value="tech">tech</option>'
                        '<option value="owner">owner</option></select></label>', 'Make an invite link')
    body = (f'<p>Signed in as <strong>{_e(email)}</strong>. <a href="/">Back to the dashboard</a></p>{_message(message)}'
            '<p class="muted">Inviting, changing a role, making a reset link and removing someone ask you to confirm '
            'it is you first. A link is shown once, when it is made.</p>'
            '<section class="card" id="accounts"><h2>Accounts</h2><table><tr><th>Email</th><th>Role</th><th>Status</th>'
            f'<th>Actions</th></tr>{accounts}</table></section>'
            f'<section class="card account-card" id="invite"><h2>Invite someone</h2>{invite_form}</section>'
            '<section class="card" id="invites"><h2>Links not yet used</h2><table><tr><th>Email</th><th>Link</th>'
            f'<th>Role</th><th>Expires</th><th>Revoke</th></tr>{invites}</table></section>'
            '<section class="card" id="events"><h2>Audit trail</h2><p class="muted">The newest 200 events, newest '
            'first. Times are wall time.</p><table><tr><th>Time</th><th>Event</th><th>By</th><th>Account</th>'
            f'<th>Via</th><th>From</th><th>Note</th></tr>{events}</table></section>')
    return page('Accounts', body)


def link_page(link, kind, back):
    """The one-time link, on the response to the POST that made it (served no-store)."""
    what = 'invite' if kind == 'join' else 'reset'
    body = (f'<section class="card account-card"><p>Send this {what} link to the person it is for. It works once '
            'and expires after 7 days. It is shown only now: only its hash is stored, so it cannot be shown again.</p>'
            f'<p><code class="totp-key">{_e(link)}</code></p><p><a class="button" href="{_e(back)}">Done</a></p></section>')
    return page('Invite link' if kind == 'join' else 'Reset link', body)


def refusal_page(message, back):
    """A refused account form for someone without the Accounts page (the installing tech)."""
    return page('Not done', f'{_message(message)}<p><a href="{_e(back)}">Back</a></p>')
