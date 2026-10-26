# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""The `account` commands, for someone with shell access to the server, and the `--as` rule.

Every account action the dashboard offers has a command here, so an owner reached over
SSH can do it without a browser: setup, invite, list, remove, set-role, reset-password,
reset-mfa, events, and recover-owner (the last resort when no owner can sign in). The
rules are tools.accounts' own; this module only asks, calls and prints.

Commands that change something take `--as EMAIL`, an active account, and act with that
account's role: a tech `--as` cannot remove anyone, just as on the dashboard. Shell access
already reaches every file in the workspace, so there is no password prompt, re-confirm or
lockout here; what is recorded says so: `via` is `command_line`, and a record outside the
accounts file carries `{'via': 'command_line', 'account_id': ..., 'verified': False}`, the
named account, not proof that its person typed the command. `setup` and `recover-owner` take
no `--as`: access to the server is their authority, as the design says.

A refusal is one fixed sentence (ui.account_views.REFUSALS where the dashboard has one, so
both say the same thing), printed on stderr with exit status 1. Links go to stdout only and
are never logged; only their hashes are stored. Standard library only.
"""
import argparse
import getpass
import json

from tools import passwords, totp
from tools.accounts import AccountRefused, normalise_email
from ui import account_views

VIA = 'command_line'
AS_REFUSED = '--as must name an active account. Nothing was changed.'
NOT_AN_EMAIL = 'That is not an email address. Nothing was changed.'
NOT_A_ROLE = 'The role must be owner or tech. Nothing was changed.'
MISMATCH = 'The passwords did not match. Nothing was changed.'
NO_ANSWER = 'No answer was given. Nothing was changed.'
#: The password rule's reasons (tools.passwords.PasswordRefused), said in full.
PASSWORD_REFUSALS = {
    'too_short': 'That password is shorter than 12 characters. Nothing was changed.',
    'too_long': 'That password is longer than 128 characters. Nothing was changed.',
    'breached': 'That password is on a list of breached passwords; choose another. Nothing was changed.',
}
CODE_ATTEMPTS = 3
LINK_SENTENCES = {
    'join': 'Send this invite link to the person it is for.',
    'reset_password': 'Send this link to the person it is for, to set a new password.',
    'reset_mfa': 'Send this link to the person it is for, to set up a new authenticator.',
    'recover': 'Open this link to set a new password and authenticator for the owner account.',
}
LINK_TERMS = 'It works once and expires after 7 days. It is shown only now: only its hash is stored.'
EVENTS_DEFAULT, EVENTS_MAX = 50, 1000


class CommandRefused(Exception):
    """The command was refused; the message is the one sentence printed."""


def command_line_actor(account):
    """The `actor` a record made by a command names: the account `--as` named, not verified."""
    return {'via': VIA, 'account_id': account['id'], 'verified': False}


def resolve_as(store, email):
    """The active account `--as` names (a row of tools.account_store), or CommandRefused."""
    try:
        row = store.account_by_email(normalise_email(email))
    except ValueError:
        row = None
    if row is None or row['status'] != 'active':
        raise CommandRefused(AS_REFUSED)
    return row


def _target(store, email):
    try:
        row = store.account_by_email(normalise_email(email))
    except ValueError:
        raise CommandRefused(NOT_AN_EMAIL) from None
    if row is None:
        raise CommandRefused(account_views.refusal_sentence('no_such_account'))
    return row


def _refused(error):
    return CommandRefused(account_views.refusal_sentence(error.code))


def _link(origin, kind, token):
    return f'{LINK_SENTENCES[kind]} {LINK_TERMS}\n{origin}/invite/{token}'


def setup(accounts, origin, *, ask=None, ask_secret=None):
    """Create the first account, asking on the terminal; return what to print after it.

    Refused before anything is asked once any account exists. The password is read with
    getpass (never echoed), twice; the key and the otpauth link are printed for the
    authenticator app, then a code is asked for (up to CODE_ATTEMPTS times)."""
    ask = ask or input
    ask_secret = ask_secret or getpass.getpass
    if accounts.store.count_accounts() > 0:
        raise CommandRefused(account_views.refusal_sentence('accounts_exist'))
    try:
        try:
            email = normalise_email(ask('Email: '))
        except ValueError:
            raise CommandRefused(NOT_AN_EMAIL) from None
        role = ask('Are you the business owner (owner) or an IT provider setting it up for a client (tech)? '
                   '[owner]: ').strip().lower() or 'owner'
        if role not in ('owner', 'tech'):
            raise CommandRefused(NOT_A_ROLE)
        password = ask_secret('Password (12 to 128 characters): ')
        if ask_secret('The same password again: ') != password:
            raise CommandRefused(MISMATCH)
        try:
            passwords.check_new(password)
        except passwords.PasswordRefused as refusal:
            raise CommandRefused(PASSWORD_REFUSALS.get(refusal.reason,
                                                       account_views.refusal_sentence('password'))) from None
        secret = totp.new_secret()
        print('Add this account to your authenticator app: type the key, or open the link on this device.')
        print(f'Key: {secret}')
        print(f'Link: {totp.otpauth_uri(secret, email)}', flush=True)
        for attempt in range(CODE_ATTEMPTS):
            code = ask('Code from the app: ')
            try:
                codes = accounts.setup_first(email, role, password, secret, code, via=VIA)
                break
            except AccountRefused as error:
                if error.code != 'bad_code' or attempt == CODE_ATTEMPTS - 1:
                    raise _refused(error) from None
                print('That code did not match. Try the newest code from the app.', flush=True)
    except EOFError:
        raise CommandRefused(NO_ANSWER) from None
    return '\n'.join(['The first account is ready.',
                      'Recovery codes: each signs you in once in place of an authenticator code. '
                      'Keep them somewhere safe; they are shown only now.', *codes,
                      f'Sign in at {origin}/signin'])


def _events(accounts, limit):
    overview = accounts.overview(limit)
    emails = {row['id']: row['email'] for row in overview['accounts']}
    return [account_views.event_columns(row, emails) for row in overview['events']]


def run(args, accounts, origin):
    """Run one `account` command; return the lines to print. CommandRefused on refusal.

    `accounts`: tools.accounts.Accounts on the workspace's accounts file. `origin`: the
    address links start with (see scripts.local.link_origin)."""
    action = args.account_action
    store = accounts.store
    try:
        if action == 'setup':
            return [setup(accounts, origin)]
        if action == 'list':
            return [json.dumps({'email': r['email'], 'role': r['role'], 'status': r['status']}, sort_keys=True)
                    for r in store.account_list()]
        if action == 'events':
            return [json.dumps(row, sort_keys=True) for row in _events(accounts, args.limit)]
        if action == 'recover-owner':
            try:
                token = accounts.recover_owner(args.email, promote=args.promote)
            except ValueError:
                raise CommandRefused(NOT_AN_EMAIL) from None
            except AccountRefused as error:
                if error.code == 'not_allowed':
                    raise CommandRefused('That account is a tech. To make it the owner and make a recovery link, '
                                         'add --promote. Nothing was changed.') from None
                raise
            return [_link(origin, 'recover', token)]
        actor = resolve_as(store, args.as_email)
        if action == 'invite':
            try:
                token = accounts.invite(actor['id'], args.email, args.role, via=VIA)
            except ValueError:
                raise CommandRefused(NOT_AN_EMAIL) from None
            return [_link(origin, 'join', token)]
        target = _target(store, args.email)
        if action == 'remove':
            accounts.remove(actor['id'], target['id'], via=VIA)
            return [f'Removed {target["email"]}.']
        if action == 'set-role':
            accounts.set_role(actor['id'], target['id'], args.role, via=VIA)
            return [f'{target["email"]} is now {args.role}.']
        kind = {'reset-password': 'reset_password', 'reset-mfa': 'reset_mfa'}[action]
        return [_link(origin, kind, accounts.reset_link(actor['id'], target['id'], kind, via=VIA))]
    except AccountRefused as error:
        raise _refused(error) from None


def events_limit(value):
    """argparse type for `account events --limit`: 1 to EVENTS_MAX."""
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f'a number from 1 to {EVENTS_MAX}') from None
    if not 1 <= number <= EVENTS_MAX:
        raise argparse.ArgumentTypeError(f'a number from 1 to {EVENTS_MAX}')
    return number


def add_parsers(commands):
    """The `account` command and its actions, on scripts.local's subparsers."""
    account = commands.add_parser('account', help='Accounts for people who sign in: set up, invite, roles, '
                                                  'resets, recovery and the audit trail')
    actions = account.add_subparsers(dest='account_action', required=True)
    actions.add_parser('setup', help='Create the first account, on this server; asks for the password and a code')
    inviting = actions.add_parser('invite', help='Make a one-time invite link')
    inviting.add_argument('--email', required=True)
    inviting.add_argument('--role', required=True, choices=('owner', 'tech'))
    actions.add_parser('list', help='List accounts: email, role, status')
    removing = actions.add_parser('remove', help='Remove an account')
    removing.add_argument('email', metavar='EMAIL')
    role = actions.add_parser('set-role', help="Change an account's role")
    role.add_argument('email', metavar='EMAIL')
    role.add_argument('role', choices=('owner', 'tech'))
    for name, what in (('reset-password', 'set a new password'), ('reset-mfa', 'set up a new authenticator')):
        reset = actions.add_parser(name, help=f'Make a one-time link for someone to {what}')
        reset.add_argument('email', metavar='EMAIL')
    for parser in (inviting, removing, role, *(actions.choices[n] for n in ('reset-password', 'reset-mfa'))):
        parser.add_argument('--as', dest='as_email', required=True, metavar='EMAIL',
                            help='The active account doing this; its role decides what is allowed')
    events = actions.add_parser('events', help='The audit trail, newest first')
    events.add_argument('--limit', type=events_limit, default=EVENTS_DEFAULT, metavar='N',
                        help=f'How many events, 1 to {EVENTS_MAX} (default {EVENTS_DEFAULT})')
    recover = actions.add_parser('recover-owner', help='Last resort when no owner can sign in: clear the '
                                                       "owner's password and MFA and make a link to set new ones")
    recover.add_argument('--email', required=True)
    recover.add_argument('--promote', action='store_true', help='Make an active tech the owner')
    return account
