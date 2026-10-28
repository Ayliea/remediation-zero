# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""The `connection` commands: list, add, replace-key, test and remove model connections.

The same operations as Settings -> Models, from the server's command line, through the same
functions (tools.connections) and the same order: validate, test the jobs, save the settings,
then store the key. A key is never a command-line argument (it would reach shell history and
`ps`): it is typed at a hidden prompt, or read from an environment variable the command names
(`--key-env`). Nothing printed here carries a key or its ending beyond what `list` shows from
connections.rows. A change needs `--as EMAIL`, an active owner, and is an audit event with
via `command_line`; `list` and `test` need no account.

This runs in its own process, so it cannot take the dashboard server's settings lock. It
re-reads the settings just before saving and refuses if they changed during the test, as the
server does; a Settings save that lands in the same instant can still be overwritten. Standard
library only.
"""
import copy
import getpass
import logging
import re
import sys
import time

from scripts import local_accounts
from scripts.local_connections import (FAILED, KEY_NEEDED, KEY_NOT_DELETED, KEY_NOT_STORED, KEY_NOT_STORED_NOT_RESTORED,
                                       KEY_ON_SERVER, NOT_AS_ENTERED, NOT_SAVED, NOTHING_TO_TEST, UNREADABLE,
                                       restore_settings)
from tools import connections, local_settings
from tools.connections import ConnectionRefused, Draft, JobChoice
from tools.local_secrets import Overlay, SecretsFile, SecretsFileUnsafe
from tools.model_catalogue import JOB_NAMES, JOB_ORDER, family_for, presets, preset
from tools.model_roles import ModelRoles, key_source
from tools.models import FORMATS

#: What `--jobs` accepts: the names the dashboard uses, lower case.
JOB_WORDS = {name.lower(): role for role, name in JOB_NAMES.items()}
KEY_PROMPT = 'API key (not shown): '
NAME_PROMPT = 'Type the name to delete: '
CHANGED = 'Settings changed while testing. Nothing was saved.'
CANCELLED = 'Cancelled. Nothing was changed.'
NOT_DELETED = 'Nothing was deleted.'
NO_CONNECTIONS = 'No connections.'
ENV_NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,63}')


class Stop(Exception):
    """End the command with this sentence on stderr and exit status 1."""


def add_parsers(commands):
    connection = commands.add_parser(
        'connection', help='List, add, test or remove model connections, as Settings -> Models does',
        description='A key is never an argument: it is typed at a hidden prompt, or read from the '
                    'environment variable --key-env names. Changes need --as EMAIL, an active owner.',
        allow_abbrev=False)  # so a mistyped `--key KEY` is refused, not read as --key-env
    actions = connection.add_subparsers(dest='connection_action', required=True)
    actions.add_parser('list', help='One line per connection: name, provider, key, jobs')
    adding = actions.add_parser(
        'add', help='Test a new connection, then save it', allow_abbrev=False,
        description='Asks for the API key at a hidden prompt when the provider needs one (empty: the '
                    'RZ_<ROLE>_API_KEY set on the server is used), or reads it from --key-env. '
                    'Tests every chosen job first; saves nothing if one fails.')
    adding.add_argument('provider', choices=[item.id for item in presets()])
    adding.add_argument('--name', help="Default: the provider's name")
    adding.add_argument('--endpoint', metavar='BASE_URL', help="Default: the provider's address")
    adding.add_argument('--ca-file', default='', metavar='PATH',
                        help='Absolute path of the certificate or CA to trust for an HTTPS endpoint')
    adding.add_argument('--format', choices=sorted(FORMATS), help='Model format; for provider other only')
    adding.add_argument('--jobs', required=True, metavar='JOBS',
                        help='Comma-separated: ' + ', '.join(JOB_WORDS) + ' (may be empty to test nothing)')
    adding.add_argument('--model', required=True, metavar='MODEL', help='The model every chosen job uses')
    adding.add_argument('--family', help="The model's family (default: the catalogue's guess)")
    adding.add_argument('--timeout', type=int, default=60, metavar='SECONDS', help='Per call; 5 to 600 (default 60)')
    adding.add_argument('--key-env', metavar='VARIABLE', help='Read the key from this environment variable')
    adding.add_argument('--as', dest='as_email', required=True, metavar='EMAIL', help='An active owner account')
    replacing = actions.add_parser('replace-key', help='Test a new key for a connection, then store it',
                                   allow_abbrev=False)
    replacing.add_argument('name')
    replacing.add_argument('--key-env', metavar='VARIABLE',
                           help='Read the key from this environment variable instead of the hidden prompt')
    replacing.add_argument('--as', dest='as_email', required=True, metavar='EMAIL', help='An active owner account')
    testing = actions.add_parser('test', help='Test a connection again and record the result')
    testing.add_argument('name')
    removing = actions.add_parser('remove', help='Delete a connection and its stored key')
    removing.add_argument('name')
    removing.add_argument('--yes', action='store_true', help='Do not ask for the name to be typed')
    removing.add_argument('--as', dest='as_email', required=True, metavar='EMAIL', help='An active owner account')


def _sentence(text):
    return text.rstrip('.') + '.'


def _and(items):
    return items[0] if len(items) == 1 else ', '.join(items[:-1]) + ' and ' + items[-1]


def _jobs_named(text):
    wanted = []
    for word in (part.strip().lower() for part in text.split(',') if part.strip()):
        if word not in JOB_WORDS:
            raise Stop(f'Unknown job: {word}. Use {_and(list(JOB_WORDS))}. Nothing was saved.')
        wanted.append(JOB_WORDS[word])
    return [role for role in JOB_ORDER if role in wanted]


def _settings(config_path):
    try:
        return local_settings.load(config_path)
    except (OSError, ValueError):
        raise Stop(UNREADABLE) from None


def _find(settings, name):
    try:
        return connections.find_by_name(settings, name)
    except ConnectionRefused as refusal:
        raise Stop(_sentence(str(refusal))) from None


def _roles(settings, environ, secrets):
    try:
        return ModelRoles.from_settings(settings, environ, secrets=secrets)
    except ValueError:
        raise Stop(NOT_AS_ENTERED) from None


def _key(args, environ, *, asked):
    """The key typed or named for storing, or None for none. `asked`: the provider takes one."""
    if args.key_env:
        value = environ.get(args.key_env)
        if not value:
            # The name is echoed only if it is shaped like one: a key typed here by mistake is not.
            name = args.key_env if ENV_NAME.fullmatch(args.key_env) else 'That variable'
            raise Stop(f'{name} is not set. Nothing was saved.')
        return value
    if not asked:
        return None
    return getpass.getpass(KEY_PROMPT) or None


def _test(roles, jobs, conn_id, log):
    try:
        result = connections.test_jobs(roles, jobs)
    except Exception as exc:  # the class name only: a message could carry anything
        result = connections.TestResult(False, jobs[0], type(exc).__name__, 0.0)
    if not result.ok:
        log('connection_test_failed', connection=conn_id, role=result.failed_job, error=result.error)
    return result


def _failure(result):
    return FAILED.format(JOB_NAMES.get(result.failed_job, 'A job'), result.error)


def _save(config_path, secrets, before, after, conn_id, log, *, key=None):
    """Save `after` if the settings are still `before`, then store `key`; a key that cannot be
    stored puts the earlier settings file back."""
    if _settings(config_path) != before:
        raise Stop(CHANGED)
    earlier = config_path.read_bytes() if config_path.exists() else None
    try:
        local_settings.save(config_path, after)
    except (OSError, ValueError) as exc:
        log('connection_save_failed', connection=conn_id, error=type(exc).__name__)
        raise Stop(NOT_SAVED) from None
    if key is None:
        return
    try:
        secrets.put(conn_id, key)
    except (SecretsFileUnsafe, OSError, ValueError) as exc:
        log('connection_key_store_failed', connection=conn_id, error=type(exc).__name__)
        if not restore_settings(config_path, earlier, conn_id, log):
            raise Stop(KEY_NOT_STORED_NOT_RESTORED) from None
        raise Stop(KEY_NOT_STORED) from None


def _audit(accounts, person, event, name, jobs, log, conn_id):
    """False (and a sentence on stderr) when the audit row could not be written; the change
    is saved by then."""
    log('connection_changed', connection=conn_id, change=event, roles=list(jobs))
    try:
        accounts.record_change(person['id'], event, detail={'connection': name, 'jobs': list(jobs)},
                               via='command_line', source=None)
    except Exception as exc:
        log('connection_audit_failed', connection=conn_id, change=event, error=type(exc).__name__,
            level=logging.ERROR)
        print('The change was saved, but the audit event could not be written.', file=sys.stderr)
        return False
    return True


def _list(settings, environ, secrets, out):
    shown = connections.rows(settings, environ, secrets, now_real_ts=time.time())
    if not shown:
        out(NO_CONNECTIONS)
    for row in shown:
        jobs = ', '.join(f'{job["job"]}: {job["model"]}' for job in row['jobs']) or 'no jobs'
        out(f'{row["name"]}  {row["provider"]}  {row["key_hint"]}  {jobs}')


def _add(args, config_path, secrets, environ, acting, log, out):
    jobs = _jobs_named(args.jobs)
    person, accounts = acting(args.as_email)
    chosen = preset(args.provider)
    asked = chosen.needs_key or chosen.id == 'other'
    if args.key_env and not asked:
        raise Stop(f'{chosen.name} needs no key. Nothing was saved.')
    format = args.format or chosen.format
    endpoint = args.endpoint or chosen.base_url
    if chosen.id == 'other' and not (format and endpoint):
        raise Stop('Other needs --format and --endpoint. Nothing was saved.')
    model = args.model.strip()
    family = args.family or family_for(chosen.id, model)
    settings = _settings(config_path)
    key = _key(args, environ, asked=asked)
    draft = Draft(chosen.id, args.name or chosen.name, format, endpoint, args.ca_file, key,
                  {role: JobChoice(model, family, args.timeout) for role in jobs})
    try:
        draft = connections.validate_draft(settings, draft)
    except ConnectionRefused as refusal:
        raise Stop(_sentence(str(refusal)) + ' Nothing was saved.') from None
    if not jobs:
        raise Stop('Choose at least one job, so the connection can be tested before it is saved. Nothing was saved.')
    conn_id = local_settings.new_connection_id()
    pending = connections.with_connection(settings, conn_id, draft)
    roles = _roles(pending, environ, Overlay(secrets, {conn_id: draft.key} if draft.key else {}))
    result = _test(roles, jobs, conn_id, log)
    if not result.ok:
        raise Stop(_sentence(_failure(result)) + ' Nothing was saved.')
    after = connections.record_test(pending, conn_id, result, jobs, accounts.clock.now())
    _save(config_path, secrets, settings, after, conn_id, log, key=draft.key)
    audited = _audit(accounts, person, 'connection_added', draft.name, jobs, log, conn_id)
    out(f'{draft.name} is connected. It now does {_and([JOB_NAMES[r] for r in jobs])}.')
    return 0 if audited else 1


def _replace_key(args, config_path, secrets, environ, acting, log, out):
    person, accounts = acting(args.as_email)
    settings = _settings(config_path)
    conn_id = _find(settings, args.name)
    conn = settings['connections'][conn_id]
    current = {role: settings['roles'][role] for role in JOB_ORDER
               if (settings['roles'].get(role) or {}).get('connection') == conn_id}
    if conn['key_source'] == 'none':
        raise Stop(f'{conn["name"]} needs no key. Nothing was changed.')
    if current and all(key_source(settings, role, environ) == 'environment' for role in current):
        raise Stop(KEY_ON_SERVER)
    key = _key(args, environ, asked=True)
    if key is None:
        raise Stop(KEY_NEEDED)
    draft = Draft(conn['provider'], conn['name'], conn['format'], conn['base_url'], conn['ca_file'], key,
                  {role: JobChoice(raw['model'], raw['family'], raw['timeout_seconds'])
                   for role, raw in current.items()})
    before = copy.deepcopy(settings)
    try:
        draft = connections.validate_draft(settings, draft, replacing=conn_id)
    except ConnectionRefused as refusal:
        raise Stop(_sentence(str(refusal)) + ' Nothing was saved.') from None
    pending = connections.with_connection(settings, conn_id, draft)
    jobs = list(current)
    if jobs:
        result = _test(_roles(pending, environ, Overlay(secrets, {conn_id: draft.key})), jobs, conn_id, log)
        if not result.ok:
            raise Stop(_sentence(_failure(result)) + ' Nothing was saved.')
        pending = connections.record_test(pending, conn_id, result, jobs, accounts.clock.now())
    _save(config_path, secrets, before, pending, conn_id, log, key=draft.key)
    audited = _audit(accounts, person, 'connection_key_replaced', draft.name, jobs, log, conn_id)
    out(f'{draft.name} has a new key.')
    return 0 if audited else 1


def _test_again(args, config_path, secrets, environ, clock, log, out):
    settings = _settings(config_path)
    conn_id = _find(settings, args.name)
    name = settings['connections'][conn_id]['name']
    jobs = [role for role in JOB_ORDER if (settings['roles'].get(role) or {}).get('connection') == conn_id]
    if not jobs:
        raise Stop(NOTHING_TO_TEST)
    result = _test(_roles(settings, environ, secrets), jobs, conn_id, log)
    _save(config_path, secrets, settings, connections.record_test(settings, conn_id, result, jobs, clock.now()),
          conn_id, log)
    if not result.ok:
        raise Stop(_sentence(_failure(result)))
    out(f'{name} works. {_and([JOB_NAMES[r] for r in jobs])} answered in {result.seconds:.1f} seconds.')
    return 0


def _remove(args, config_path, secrets, acting, log, out):
    person, accounts = acting(args.as_email)
    settings = _settings(config_path)
    conn_id = _find(settings, args.name)
    conn = settings['connections'][conn_id]
    jobs = [role for role in JOB_ORDER if (settings['roles'].get(role) or {}).get('connection') == conn_id]
    out(connections.deletion_consequences(settings, conn_id))
    if not args.yes and input(NAME_PROMPT).strip() != conn['name']:
        raise Stop(NOT_DELETED)
    try:
        local_settings.save(config_path, connections.without_connection(settings, conn_id))
    except (OSError, ValueError) as exc:
        log('connection_save_failed', connection=conn_id, error=type(exc).__name__)
        raise Stop(NOT_SAVED) from None
    key_kept = False
    try:
        secrets.delete(conn_id)
    except (SecretsFileUnsafe, OSError, ValueError) as exc:
        log('connection_key_delete_failed', connection=conn_id, error=type(exc).__name__,
            level=logging.ERROR if conn['key_source'] == 'stored' else logging.WARNING)
        key_kept = conn['key_source'] == 'stored'
    audited = _audit(accounts, person, 'connection_removed', conn['name'], jobs, log, conn_id)
    if key_kept:
        raise Stop(KEY_NOT_DELETED)
    out(f'{conn["name"]} was deleted.')
    return 0 if audited else 1


def run(args, config_path, secrets_file, environ, *, acting, clock, log, out=print):
    """Run one `connection` command; the exit status. `acting(email)` returns (account row,
    Accounts) for an active owner, or raises local_accounts.CommandRefused; `clock` is a
    SimClock for the commands that have no Accounts."""
    secrets = secrets_file if isinstance(secrets_file, SecretsFile) else SecretsFile(secrets_file)
    action = args.connection_action
    try:
        if action == 'list':
            _list(_settings(config_path), environ, secrets, out)
            return 0
        if action == 'add':
            return _add(args, config_path, secrets, environ, acting, log, out)
        if action == 'replace-key':
            return _replace_key(args, config_path, secrets, environ, acting, log, out)
        if action == 'test':
            return _test_again(args, config_path, secrets, environ, clock, log, out)
        return _remove(args, config_path, secrets, acting, log, out)
    except Stop as stop:
        print(stop, file=sys.stderr)
    except local_accounts.CommandRefused as refusal:
        print(refusal, file=sys.stderr)
    except (KeyboardInterrupt, EOFError):
        print(CANCELLED, file=sys.stderr)
    return 1
