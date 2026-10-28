# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Add, edit, test and delete model connections as pure changes to the settings dict.

Every function takes plain settings and returns new ones (the input is never changed); nothing
here writes a file, reads the network on its own, or returns a key. Callers (the Settings routes
and the CLI) validate, test, then save. Standard library only.
"""
import copy
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from tools import model_check
from tools.local_secrets import SecretsFileUnsafe
from tools.local_settings import MAX_CONNECTION_NAME, check_ca_file
from tools.model_catalogue import JOB_NAMES, JOB_ORDER, preset, presets
from tools.model_endpoints import call_endpoint
from tools.model_roles import ROLES, ModelRoles, RoleConfig, key_present, key_source
from tools.secrets_port import check_key


class ConnectionRefused(ValueError):
    """A sentence fit to show the person; never carries a key."""


@dataclass(frozen=True)
class JobChoice:
    model: str
    family: str
    timeout_seconds: int = 60


@dataclass(frozen=True)
class Draft:
    provider: str
    name: str
    format: str
    base_url: str
    ca_file: str
    #: Never shown (repr=False). None keeps whatever key the connection already has.
    key: str | None = field(repr=False)
    jobs: dict[str, JobChoice]


@dataclass(frozen=True)
class TestResult:
    __test__ = False  # not a pytest class

    ok: bool
    failed_job: str | None
    #: An exception class name or a short failure name from model_check, never a message.
    error: str
    seconds: float


def _refuse(exc):
    return ConnectionRefused(str(exc) if isinstance(exc, ValueError) else 'Invalid connection')


def validate_draft(settings, draft, *, replacing=None):
    """The draft, cleaned (name and key stripped), or ConnectionRefused with a sentence."""
    name = draft.name.strip() if isinstance(draft.name, str) else ''
    if (not 1 <= len(name) <= MAX_CONNECTION_NAME
            or any(ord(c) < 32 or 127 <= ord(c) < 160 for c in name)):
        raise ConnectionRefused(f'A connection name is 1 to {MAX_CONNECTION_NAME} characters on one line')
    for cid, other in settings['connections'].items():
        if cid != replacing and other['name'].casefold() == name.casefold():
            raise ConnectionRefused('Each connection needs its own name')
    old = settings['connections'].get(replacing) if replacing else None
    if (old and old['key_source'] == 'stored' and draft.key is None
            and any(old[f] != getattr(draft, f) for f in ('base_url', 'ca_file', 'format', 'provider'))):
        # A stored key goes only to the address it was entered for.
        raise ConnectionRefused("Enter the key again to change this connection's address or certificate.")
    try:
        chosen = preset(draft.provider)
    except KeyError:
        raise ConnectionRefused('Unknown provider') from None
    if chosen.format and draft.format != chosen.format:
        raise ConnectionRefused('That provider uses a different model format')
    key = draft.key
    if key is not None:
        try:
            key = check_key(key) if chosen.needs_key or chosen.id == 'other' else None
        except ValueError as exc:
            raise ConnectionRefused(str(exc)) from None
    try:
        for role, choice in draft.jobs.items():
            if role not in ROLES:
                raise ValueError('Unknown model role')
            # RoleConfig applies every rule the saved settings will: model, family, timeout, endpoint, CA file.
            RoleConfig(role, draft.format, call_endpoint(draft.format, draft.base_url, choice.model.strip()),
                       choice.model.strip(), choice.family, draft.ca_file, choice.timeout_seconds)
        if not draft.jobs:
            call_endpoint(draft.format, draft.base_url, 'model')  # still hold the address to the rules
        if draft.ca_file:
            check_ca_file(draft.ca_file)
    except (ValueError, KeyError, AttributeError, TypeError) as exc:
        raise _refuse(exc) from None
    jobs = {role: JobChoice(c.model.strip(), c.family, c.timeout_seconds) for role, c in draft.jobs.items()}
    return Draft(draft.provider, name, draft.format, draft.base_url, draft.ca_file, key, jobs)


def with_connection(settings, conn_id, draft):
    """The settings as they would be with this connection added (or edited) and its jobs assigned.
    A key-needing provider with no key becomes key_source 'environment'. Callers save only after
    test_jobs passes.
    Jobs the connection had before and the draft drops are unassigned. Editing clears last_test."""
    new = copy.deepcopy(settings)
    old = new['connections'].get(conn_id)
    chosen = preset(draft.provider)
    if chosen.id == 'ollama' or (not chosen.needs_key and chosen.id != 'other'):
        source = 'none'
    elif draft.key is not None:
        source = 'stored'
    else:
        source = old['key_source'] if old and old['key_source'] != 'none' else 'environment'
    # A migrated connection keeps its exact address, unless the address is changed.
    style = old['endpoint_style'] if old and old['base_url'] == draft.base_url else 'base'
    new['connections'][conn_id] = {'name': draft.name, 'provider': draft.provider, 'format': draft.format,
                                   'base_url': draft.base_url, 'endpoint_style': style,
                                   'ca_file': draft.ca_file, 'key_source': source, 'last_test': None}
    for role, raw in new['roles'].items():
        if raw and raw['connection'] == conn_id:
            new['roles'][role] = None
    for role, choice in draft.jobs.items():
        new['roles'][role] = {'connection': conn_id, 'model': choice.model, 'family': choice.family,
                              'timeout_seconds': choice.timeout_seconds}
    return new


def test_jobs(roles: ModelRoles, jobs: list[str], *, now: Callable[[], float] = time.monotonic):
    """Run the sample check for each listed job, in job order, stopping at the first failure."""
    started = now()
    for role in JOB_ORDER:
        if role not in jobs:
            continue
        try:
            problem = model_check._run(role, roles.adapter(role))
        except Exception as exc:  # the class name is all that is kept: a message could carry anything
            problem = type(exc).__name__
        if problem:
            return TestResult(False, role, problem, now() - started)
    return TestResult(True, None, '', now() - started)


test_jobs.__test__ = False  # not a pytest test


def record_test(settings, conn_id, result, jobs, stamp):
    new = copy.deepcopy(settings)
    new['connections'][conn_id]['last_test'] = {
        'ok': result.ok, 'error': result.error, 'seconds': result.seconds,
        'jobs': [role for role in dict.fromkeys(jobs)], 'real_ts': stamp.real_ts, 'sim_ts': stamp.sim_ts}
    return new


def without_connection(settings, conn_id):
    new = copy.deepcopy(settings)
    del new['connections'][conn_id]
    for role, raw in new['roles'].items():
        if raw and raw['connection'] == conn_id:
            new['roles'][role] = None
    return new


_GONE = {'proposer': 'nobody triages, so no cycle runs',
         'reviewer': 'nobody reviews, so new triage waits for a person',
         'guard': 'nobody screens scanner text, so it is withheld from the models',
         'summarizer': 'nobody writes the cycle summary'}


def _jobs_of(settings, conn_id):
    return [role for role in JOB_ORDER
            if (settings['roles'].get(role) or {}).get('connection') == conn_id]


def _and(items):
    return items[0] if len(items) == 1 else ', '.join(items[:-1]) + ' and ' + items[-1]


def deletion_consequences(settings, conn_id):
    name = settings['connections'][conn_id]['name']
    jobs = _jobs_of(settings, conn_id)
    if not jobs:
        return f'{name} does no jobs. Deleting it changes nothing else.'
    return (f'{name} does {_and([JOB_NAMES[r] for r in jobs])}. After deleting, '
            + '; '.join(_GONE[r] for r in jobs) + '.')


def _stored_hint(secrets, conn_id):
    """The stored key's ending: text (possibly ''), or None when there is no key to show. An
    unreadable key file counts as no key; the reason is not repeated."""
    try:
        return secrets.hint(conn_id) if secrets is not None else None
    except (SecretsFileUnsafe, OSError, ValueError):
        return None


def _job_key(settings, role, conn_id, environ, secrets):
    source = key_source(settings, role, environ)
    if source == 'none':
        return 'no key needed'
    if source == 'environment':
        return 'set on the server' if key_present(role, environ) else 'key missing'
    hint = _stored_hint(secrets, conn_id)
    if hint is None:
        return 'key missing'
    return f'stored …{hint}' if hint else 'stored'


def _last_test_text(test, now_real_ts):
    if test is None:
        return 'Not tested'
    if not test['ok']:
        return f'Failed: {test["error"]}' if test['error'] else 'Failed'
    return f'Tested {max(0, int((now_real_ts - test["real_ts"]) // 60))} min ago'


def rows(settings, environ, secrets, *, now_real_ts):
    """One dict per connection for the list page. Names come back raw: the view escapes them.
    `now_real_ts` (the caller's time.time()) only words "Tested n min ago" and is never stored."""
    out = []
    for conn_id, conn in settings['connections'].items():
        look = preset(conn['provider'])
        jobs = [{'role': role, 'job': JOB_NAMES[role], 'model': settings['roles'][role]['model'],
                 'family': settings['roles'][role]['family'],
                 'timeout_seconds': settings['roles'][role]['timeout_seconds'],
                 'key': _job_key(settings, role, conn_id, environ, secrets)}
                for role in _jobs_of(settings, conn_id)]
        all_env = bool(jobs) and all(key_source(settings, j['role'], environ) == 'environment' for j in jobs)
        if conn['key_source'] == 'none':
            hint = 'no key needed'
        elif all_env or conn['key_source'] == 'environment':
            hint = 'set on the server'
        else:
            ending = _stored_hint(secrets, conn_id)
            hint = 'key missing' if ending is None else (f'ends in …{ending}' if ending else 'key stored')
        out.append({'id': conn_id, 'name': conn['name'], 'provider': conn['provider'], 'letter': look.letter,
                    'colour': look.colour, 'jobs': jobs, 'key_hint': hint,
                    'last_test_text': _last_test_text(conn['last_test'], now_real_ts),
                    'can_replace_key': conn['key_source'] != 'none' and not all_env})
    return out


def coverage(settings, environ):
    """Per job, in order: the connection and model it will use, or None for nobody."""
    roles = ModelRoles.from_settings(settings, environ)
    overridden = bool(environ.get('RZ_MODEL') or environ.get('RZ_MODEL_ENDPOINT'))
    note = None
    if roles.reviewer is not None:  # independence() counts no proposer, like family 'other', as same family
        note = 'different family' if roles.independence() == 'cross_family' else 'same family'
    out = []
    for role in JOB_ORDER:
        config = getattr(roles, role)
        conn = settings['connections'].get(config.connection) if config else None
        out.append({'role': role, 'job': JOB_NAMES[role], 'connection': conn['name'] if conn else None,
                    'model': config.model if config else None,
                    'family_note': note if role == 'reviewer' else None,
                    'overridden': role == 'proposer' and overridden})
    return out


def find_by_name(settings, name):
    wanted = name.strip().casefold()
    found = [cid for cid, conn in settings['connections'].items() if conn['name'].casefold() == wanted]
    if not found:
        raise ConnectionRefused('No connection has that name')
    if len(found) > 1:
        raise ConnectionRefused('More than one connection has that name')
    return found[0]
