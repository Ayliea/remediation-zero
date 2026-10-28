# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""The /connections/* routes of the local dashboard server: model connections, owner only.

JSON in, JSON out, for the Models page's popup. scripts/local.py has already checked the Host,
Origin and Sec-Fetch-Site, that the session's role may `manage_connections`, the body's size,
and that no other /connections/* request of this session is in flight. Here: the body is JSON
carrying the session's form token; a change needs a recent re-confirm (else 401
{"confirm": true} and nothing is done); model lists and tests are rate limited per account.

A model list or test can take minutes, so it runs with `serial` released: the settings are read
under `serial` and kept, the call is made, then `serial` is taken again and the settings read
again; if they differ, 409 and nothing is saved. A key is stored only after its settings are
saved, and the settings file is put back if the key cannot be stored. Just before the save the
session is resolved again: a session that ended, or an account demoted or removed while the
test ran, gets 403 and nothing is saved. `confirmed` is not checked again there: the owner
confirmed when the request arrived, and the test that follows is bounded by the server.

The busy reply (another /connections/* request of this session is still in flight) is a 409
with `Retry-After` and an empty body that is not JSON; scripts/local.py sends it before the
body is read.

No reply carries a key, or anything else the client sent: failures are fixed sentences, and
a failed test names the job and the error class only. Log lines carry the connection id, the
job and the error class. Standard library only.
"""
import copy
import json
import logging
import os
import secrets
import tempfile
from dataclasses import asdict
from pathlib import Path

from scripts import local_auth
from tools import access, connection_advice, connections, local_settings, model_endpoints
from tools.accounts import RateLimiter
from tools.connections import ConnectionRefused, Draft, JobChoice, TestResult
from tools.local_secrets import Overlay, SecretsFile, SecretsFileUnsafe
from tools.model_catalogue import JOB_NAMES, JOB_ORDER, entries, family_for, match, preset
from tools.model_check import PROBLEM_HINTS
from tools.model_roles import FAMILIES, ROLES, ModelRoles, key_present, key_source
from tools.model_transport import validate_endpoint
from tools.models import FORMATS
from tools.secrets_port import KEY_MESSAGE, check_key

ACTION = 'manage_connections'
PATHS = frozenset({'/connections/confirm', '/connections/models', '/connections/recommend',
                   '/connections/save', '/connections/edit', '/connections/replace-key',
                   '/connections/test', '/connections/delete'})
#: Changes: each needs a re-confirm within its window.
RECONFIRM = frozenset({'/connections/save', '/connections/edit', '/connections/replace-key',
                       '/connections/delete'})
#: The routes that call a provider, rate limited per account (one limiter for all of them).
LIMITED = frozenset({'/connections/models', '/connections/test', '/connections/save',
                     '/connections/edit', '/connections/replace-key'})
PER_MINUTE = 6
_CONTENT_TYPES = ('application/json', 'application/json; charset=utf-8')
_TEXT_LIMIT = 4096
_ECHO_MIN = 3   # a typed value this long or longer never appears inside an error sentence

NOT_ALLOWED = 'Only an owner can change model connections.'
INVALID = 'That request could not be read. Nothing was changed.'
TOO_LARGE = 'That request is too large. Nothing was changed.'
NOT_AS_ENTERED = 'That connection could not be used as entered. Nothing was changed.'
CHANGED = 'Settings changed while testing. Nothing was saved.'
TOO_MANY = 'Too many tries in a minute. Wait a moment and try again.'
GONE = 'That connection no longer exists. Reload the page.'
NO_JOBS = 'Switch on at least one job, so the connection can be tested before it is saved.'
NOTHING_TO_TEST = 'This connection does no jobs, so there is nothing to test.'
KEY_NEEDED = 'Enter the new key.'
KEY_ON_SERVER = "This connection's key is set on the server, so it cannot be replaced here."
EXACT_MODEL = "This connection's address names its model. Use Replace key to set a new address."
NO_LIST = "This connection's address is used exactly as typed, so it has no model list. Type a model name."
UNKNOWN_PROVIDER = 'Unknown provider.'
UNKNOWN_FORMAT = 'Unknown model format.'
UNKNOWN_FAMILY = 'Unknown model family.'
MODEL_NAME = 'A model name is required (at most 200 characters).'
UNREADABLE = 'Settings could not be read. Nothing was changed.'
NOT_SAVED = 'Settings could not be saved. Nothing was changed. Check local file permissions.'
KEY_NOT_STORED = ('The key could not be stored, so nothing was saved. Check the key file beside the '
                  'settings file.')
KEY_NOT_STORED_NOT_RESTORED = ('The key could not be stored, and the earlier settings could not be put back, '
                               'so this connection may be saved without its key. Check the key file and the '
                               'settings file beside the database, then replace the key or delete the connection.')
NO_ENV_LIST = ("This connection's Triage key is set on the server for another address, so its model list "
               "cannot be fetched here. Type a model name.")
KEY_NOT_DELETED = ('The connection was removed, but its key could not be deleted from the key file. '
                   'Check the key file beside the settings file.')
LIST_FAILED = 'The model list could not be fetched: {}'
FAILED = '{} failed: {}'


def secrets_beside(config_path):
    """The key file for this settings file: `<database>.secrets.json` (tools.local_secrets)."""
    path = Path(config_path)
    if path.name.endswith('.settings.json'):
        return path.with_name(path.name.removesuffix('.settings.json') + '.secrets.json')
    return path.with_suffix('.secrets.json')


def restore_settings(config_path, earlier, conn_id, log):
    """Put the settings file back as `earlier` (its bytes, or None for no file); False (logged
    at error) if that failed too. The server and the `connection` command share this."""
    try:
        if earlier is None:
            config_path.unlink(missing_ok=True)
            return True
        fd, name = tempfile.mkstemp(prefix='.rz-settings-', dir=config_path.parent)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(earlier)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, config_path)
        finally:
            if os.path.exists(name):
                os.unlink(name)
    except OSError as exc:
        log('connection_restore_failed', connection=conn_id, error=type(exc).__name__, level=logging.ERROR)
        return False
    return True


class _Reply(Exception):
    """Answer now with `status` and `payload` (JSON); nothing further is done."""

    def __init__(self, status, payload, headers=()):
        super().__init__(status)
        self.status, self.payload, self.headers = status, payload, tuple(headers)


def _refused(sentence, status=400):
    return _Reply(status, {'error': sentence})


def _no_duplicates(pairs):
    out = {}
    for name, value in pairs:
        if name in out:
            raise ValueError('duplicate field')
        out[name] = value
    return out


def _no_constant(name):
    raise ValueError('not JSON')


def _fields(body, required, optional=()):
    if not isinstance(body, dict) or not set(required) <= set(body) <= set(required) | set(optional):
        raise _refused(INVALID)


def _encodable(value):
    try:
        value.encode('utf-8')
    except UnicodeEncodeError:  # a lone surrogate
        return False
    return True


def _text(value, *, limit=_TEXT_LIMIT, plain=True):
    """A string field. `plain` (every field that may reach a page) also refuses control
    characters; a key, password or code is checked by its own rules instead."""
    if not isinstance(value, str) or len(value) > limit or not _encodable(value):
        raise _refused(INVALID)
    if plain and any(ord(c) < 32 or 127 <= ord(c) < 160 for c in value):
        raise _refused(INVALID)
    return value


def _optional_text(value, **kwargs):
    return None if value is None else _text(value, **kwargs)


def _sent(value):
    """Every string the client sent, at any depth."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for name, item in value.items():
            yield name
            yield from _sent(item)
    elif isinstance(value, list):
        for item in value:
            yield from _sent(item)


def _safe(sentence, body):
    """The sentence, unless it carries something the client sent (it never should: every
    refusal is fixed text). Then a generic one, so nothing typed is ever echoed."""
    for value in _sent(body):
        for part in {value, value.strip()}:
            if len(part) >= _ECHO_MIN and part in sentence:
                return NOT_AS_ENTERED
    return sentence


def _jobs_of(settings, conn_id):
    return {role: raw for role in JOB_ORDER
            if (raw := settings['roles'].get(role)) and raw['connection'] == conn_id}


def send_json(h, status, payload, headers=()):
    body = json.dumps(payload).encode()
    h.send_response(status)
    h.send_header('Content-Type', 'application/json')
    h.send_header('Content-Length', str(len(body)))
    h.send_header('Cache-Control', 'no-store')
    h.send_header('X-Content-Type-Options', 'nosniff')
    h.send_header('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'")
    for name, value in headers:
        h.send_header(name, value)
    h.end_headers()
    h.wfile.write(body)


class ConnectionRoutes:
    """`accounts` (tools.accounts.Accounts) re-confirms, audits and stamps (its SimClock);
    `serial` is the server's one lock for settings work; `sign_in_limiter` is the limiter the
    sign-in forms use, for /connections/confirm; `limiter` (default PER_MINUTE a minute) is for
    LIMITED. `log` is scripts.local._log. The environment is read on each request."""

    def __init__(self, accounts, config_path, serial, sign_in_limiter, *, log, limiter=None, environ=None):
        self.accounts = accounts
        self.config_path = Path(config_path)
        self.serial = serial
        self.sign_in_limiter = sign_in_limiter
        self.limiter = limiter if limiter is not None else RateLimiter(per_minute=PER_MINUTE)
        self.log = log
        self._environ = environ
        self.secrets = SecretsFile(secrets_beside(config_path))

    @property
    def environ(self):
        return os.environ if self._environ is None else self._environ

    def post(self, h, req, path):
        try:
            status, payload, headers = self._route(h, req, path)
        except _Reply as reply:
            status, payload, headers = reply.status, reply.payload, reply.headers
        send_json(h, status, payload, headers)

    # --- the checks every route makes ---------------------------------------------------

    def _route(self, h, req, path):
        session = req.session
        if session is None or not access.allowed(session.role, ACTION):
            raise _refused(NOT_ALLOWED, 403)
        body = self._body(h)
        token = body.pop('token', None)
        if (not isinstance(token, str) or not _encodable(token)
                or not secrets.compare_digest(token.encode(), session.csrf.encode())):
            raise _refused(NOT_ALLOWED, 403)
        if path in RECONFIRM and not session.confirmed:
            # Nothing is done: the popup asks in place, then sends the same body again.
            raise _Reply(401, {'confirm': True})
        handler = {'/connections/confirm': self._confirm, '/connections/models': self._models,
                   '/connections/recommend': self._recommend, '/connections/save': self._save,
                   '/connections/edit': self._edit, '/connections/replace-key': self._replace_key,
                   '/connections/test': self._test_again, '/connections/delete': self._delete}[path]
        return 200, handler(req, session, body), ()

    def _body(self, h):
        length = h.headers.get('Content-Length')
        if length is None or not (length.isascii() and length.isdigit()) or h.headers.get('Transfer-Encoding'):
            h.close_connection = True
            raise _refused(INVALID)
        if int(length) > local_auth.FORM_LIMIT:
            h.close_connection = True                   # the body was never read
            raise _refused(TOO_LARGE, 413)
        raw = h._take_body()
        if (h.headers.get('Content-Type') or '').strip().lower() not in _CONTENT_TYPES:
            raise _refused(INVALID)
        if not raw or len(raw) != int(length):
            raise _refused(INVALID)
        try:
            body = json.loads(raw.decode('utf-8'), object_pairs_hook=_no_duplicates, parse_constant=_no_constant)
        except (ValueError, UnicodeError, RecursionError):
            raise _refused(INVALID) from None
        if not isinstance(body, dict):
            raise _refused(INVALID)
        return body

    def _limit(self, session):
        wait = self.limiter.hit(session.account_id)
        if wait is not None:
            raise _Reply(429, {'error': TOO_MANY}, (('Retry-After', str(wait)),))

    def _read(self):
        """The saved settings, under `serial`."""
        try:
            return local_settings.load(self.config_path)
        except (OSError, ValueError):
            raise _refused(UNREADABLE, 503) from None

    def _connection(self, settings, value):
        conn_id = _text(value, limit=64)
        if not local_settings.CONNECTION_ID_RE.fullmatch(conn_id) or conn_id not in settings['connections']:
            raise _refused(GONE)
        return conn_id

    # --- tests and saving ---------------------------------------------------------------

    def _run(self, roles, jobs, conn_id):
        """test_jobs, with `serial` released. A tester that raises is a failure of the first
        job, kept by class name only."""
        try:
            result = connections.test_jobs(roles, jobs)
        except Exception as exc:
            result = TestResult(False, jobs[0], type(exc).__name__, 0.0)
        if not result.ok:
            self.log('connection_test_failed', connection=conn_id, role=result.failed_job, error=result.error)
        return result

    @staticmethod
    def _failure(result):
        return {'ok': False, 'failed_job': result.failed_job,
                'error': FAILED.format(JOB_NAMES.get(result.failed_job, 'A job'), result.error),
                'hint': PROBLEM_HINTS.get(result.error), 'seconds': result.seconds}

    def _still_allowed(self, req):
        """Under `serial`, just before a save: the session again, as it is now. `confirmed` is
        not checked again on purpose: it was checked when the request arrived, and the test in
        between is bounded by the server."""
        live = self.accounts.session(req.token)
        if live is None or not access.allowed(live.role, ACTION):
            raise _refused(NOT_ALLOWED, 403)

    def _commit(self, req, before, after, conn_id, *, key=None):
        """Save `after` if the session may still and the settings are still `before`, then store
        `key`; a key that cannot be stored puts the earlier settings file back. Takes `serial`."""
        with self.serial:
            self._still_allowed(req)
            if self._read() != before:
                raise _refused(CHANGED, 409)
            earlier = self.config_path.read_bytes() if self.config_path.exists() else None
            try:
                local_settings.save(self.config_path, after)
            except (OSError, ValueError) as exc:
                self.log('connection_save_failed', connection=conn_id, error=type(exc).__name__)
                raise _refused(NOT_SAVED, 503) from None
            if key is None:
                return
            try:
                self.secrets.put(conn_id, key)    # put is read-modify-write: only under `serial`
            except (SecretsFileUnsafe, OSError, ValueError) as exc:
                self.log('connection_key_store_failed', connection=conn_id, error=type(exc).__name__)
                if not self._restore(earlier, conn_id):
                    raise _refused(KEY_NOT_STORED_NOT_RESTORED, 503) from None
                raise _refused(KEY_NOT_STORED, 503) from None

    def _restore(self, earlier, conn_id):
        """Put the settings file back as it was; False (logged at error) if that failed too."""
        return restore_settings(self.config_path, earlier, conn_id, self.log)

    def _audit(self, req, session, event, conn_id, name, jobs):
        """Write the audit row; False when it could not be (the change is saved by then, so this
        is logged at error and the reply says `"audit": false`, rather than a failure)."""
        self.log('connection_changed', connection=conn_id, change=event, roles=list(jobs))
        try:
            self.accounts.record_change(session.account_id, event, detail={'connection': name, 'jobs': list(jobs)},
                                        via='dashboard', source=req.client)
        except Exception as exc:
            self.log('connection_audit_failed', connection=conn_id, change=event, error=type(exc).__name__,
                     level=logging.ERROR)
            return False
        return True

    @staticmethod
    def _done(payload, audited):
        return payload if audited else dict(payload, audit=False)

    def _roles(self, settings, overlay):
        try:
            return ModelRoles.from_settings(settings, self.environ, secrets=overlay)
        except ValueError:
            raise _refused(NOT_AS_ENTERED) from None

    def _validate(self, settings, draft, body, replacing=None):
        try:
            return connections.validate_draft(settings, draft, replacing=replacing)
        except ConnectionRefused as refusal:
            raise _refused(_safe(str(refusal), body)) from None

    @staticmethod
    def _choices(raw, provider):
        """The jobs a request switches on: {role: {model, family?, timeout_seconds?}}."""
        if not isinstance(raw, dict) or not set(raw) <= set(ROLES):
            raise _refused(INVALID)
        out = {}
        for role, choice in raw.items():
            _fields(choice, {'model'}, {'family', 'timeout_seconds'})
            model = _text(choice['model'], limit=256)
            family = choice.get('family')
            if family is None:
                family = family_for(provider, model.strip())
            timeout = choice.get('timeout_seconds', 60)
            if type(timeout) is not int:
                raise _refused(INVALID)
            family = _text(family, limit=64)
            out[role] = JobChoice(model, family, timeout)
        return out

    # --- the routes ---------------------------------------------------------------------

    def _confirm(self, req, session, body):
        _fields(body, (), ('password', 'code'))
        password = _optional_text(body.get('password'), limit=local_auth.PASSWORD_LIMIT + 1, plain=False) or None
        code = _optional_text(body.get('code'), limit=64, plain=False) or None
        wait = self.sign_in_limiter.hit(req.client)
        if wait is not None:
            raise _Reply(429, {'error': TOO_MANY}, (('Retry-After', str(wait)),))
        if password is not None and code is not None:
            raise _refused(local_auth.CONFIRM_ONE_ONLY)
        ok = False
        if (password is None) != (code is None) and (password is None or len(password) <= local_auth.PASSWORD_LIMIT):
            ok = self.accounts.confirm(req.token, password=password, code=code, source=req.client)
        if not ok:
            raise _refused(local_auth.CONFIRM_FAILED)
        return {'ok': True}

    def _models(self, req, session, body):
        by_connection = 'connection' in body
        if by_connection:
            _fields(body, {'connection'})
        else:
            _fields(body, {'provider', 'base_url', 'ca_file', 'key'}, {'format'})
        self._limit(session)
        with self.serial:
            settings = self._read()
            conn_id = self._connection(settings, body['connection']) if by_connection else None
        if by_connection:
            conn = settings['connections'][conn_id]
            if conn['endpoint_style'] == 'exact':
                return {'error': NO_LIST}
            provider, format, base_url, ca_file = conn['provider'], conn['format'], conn['base_url'], conn['ca_file']
            try:
                key = self._saved_key(settings, conn_id, conn)
            except _Reply:
                raise
            except Exception as exc:  # an unreadable key file: class only
                self.log('connection_models_failed', connection=conn_id, error=type(exc).__name__)
                return {'error': LIST_FAILED.format(type(exc).__name__), 'hint': PROBLEM_HINTS.get(type(exc).__name__)}
        else:
            provider, format, base_url, ca_file, key = self._typed_address(body)
        try:
            models = model_endpoints.list_models(format, base_url, key, ca_file or None)
        except Exception as exc:  # the class name is all that is kept: a message could carry anything
            name = type(exc).__name__
            self.log('connection_models_failed', connection=conn_id or '-', error=name)
            return {'error': LIST_FAILED.format(name), 'hint': PROBLEM_HINTS.get(name)}
        return {'models': models, 'suggested': suggest(settings, provider, models), 'lines': lines(provider, models)}

    def _saved_key(self, settings, conn_id, conn):
        """The key a saved connection's model list is fetched with: a job's environment key
        first, as its calls use, else the stored one. An environment key goes only where a cycle
        sends it: with RZ_MODEL_ENDPOINT set, Triage's key belongs to that address, not to this
        connection, so it is never used here. _Reply when no key may be used."""
        skipped = False
        for role in _jobs_of(settings, conn_id):
            if role == 'proposer' and self.environ.get('RZ_MODEL_ENDPOINT'):
                skipped = skipped or key_present(role, self.environ)
                continue
            if key_present(role, self.environ):
                names = ['RZ_%s_API_KEY' % role.upper()] + (['RZ_MODEL_API_KEY'] if role == 'proposer' else [])
                return next(self.environ[n] for n in names if self.environ.get(n))
        if conn['key_source'] == 'stored':
            return self.secrets.get(conn_id)
        if skipped:
            raise _Reply(200, {'error': NO_ENV_LIST})
        return None

    def _typed_address(self, body):
        provider = _text(body['provider'], limit=64)
        try:
            chosen = preset(provider)
        except KeyError:
            raise _refused(UNKNOWN_PROVIDER) from None
        format = _text(body.get('format') or chosen.format, limit=64)
        if (chosen.format and format != chosen.format) or format not in FORMATS:
            raise _refused(UNKNOWN_FORMAT)
        base_url = _text(body['base_url'], limit=2048) or chosen.base_url
        ca_file = _text(body['ca_file'])
        key = _text(body['key'], plain=False)
        try:
            validate_endpoint(base_url)
            if ca_file:
                if not os.path.isabs(ca_file) or not base_url.lower().startswith('https://'):
                    raise ValueError('The CA certificate file must be an absolute path, for an HTTPS endpoint')
                local_settings.check_ca_file(ca_file)
        except ValueError as exc:
            raise _refused(_safe(str(exc), body)) from None
        if key.strip() and (chosen.needs_key or chosen.id == 'other'):
            try:
                key = check_key(key)
            except ValueError:
                raise _refused(KEY_MESSAGE) from None
        else:
            key = None
        return provider, format, base_url, ca_file, key

    def _recommend(self, req, session, body):
        _fields(body, {'provider', 'model'}, {'family', 'editing'})
        provider = _text(body['provider'], limit=64)
        model = _text(body['model'], limit=256).strip()
        family, editing = body.get('family'), body.get('editing')
        try:
            preset(provider)
        except KeyError:
            raise _refused(UNKNOWN_PROVIDER) from None
        if not 0 < len(model) <= 200:
            raise _refused(MODEL_NAME)
        if family is not None and family not in FAMILIES:
            raise _refused(UNKNOWN_FAMILY)
        with self.serial:
            settings = self._read()
            if editing is not None:
                editing = self._connection(settings, editing)
        cards = connection_advice.recommend(settings, provider=provider, model=model,
                                            family=family or family_for(provider, model), editing=editing)
        return {'cards': [asdict(card) for card in cards], 'coverage': connections.coverage(settings, self.environ)}

    def _save(self, req, session, body):
        _fields(body, {'draft'})
        raw = body['draft']
        _fields(raw, {'provider', 'name', 'format', 'base_url', 'ca_file', 'key', 'jobs'})
        provider = _text(raw['provider'], limit=64)
        try:
            chosen = preset(provider)
        except KeyError:
            raise _refused(UNKNOWN_PROVIDER) from None
        key = _optional_text(raw['key'], plain=False) or None
        draft = Draft(provider, _text(raw['name'], limit=256), _text(raw['format'], limit=64) or chosen.format,
                      _text(raw['base_url'], limit=2048) or chosen.base_url, _text(raw['ca_file']), key,
                      self._choices(raw['jobs'], provider))
        if not draft.jobs:
            raise _refused(NO_JOBS)
        self._limit(session)
        with self.serial:
            settings = self._read()
            before = copy.deepcopy(settings)
            draft = self._validate(settings, draft, body)
            conn_id = local_settings.new_connection_id()
            pending = connections.with_connection(settings, conn_id, draft)
            roles = self._roles(pending, Overlay(self.secrets, {conn_id: draft.key} if draft.key else {}))
        jobs = [role for role in JOB_ORDER if role in draft.jobs]
        result = self._run(roles, jobs, conn_id)
        if not result.ok:
            return self._failure(result)
        after = connections.record_test(pending, conn_id, result, jobs, self.accounts.clock.now())
        self._commit(req, before, after, conn_id, key=draft.key)
        audited = self._audit(req, session, 'connection_added', conn_id, draft.name, jobs)
        return self._done({'ok': True, 'connection': conn_id, 'provider': chosen.name, 'name': draft.name,
                           'seconds': result.seconds, 'jobs': [JOB_NAMES[role] for role in jobs]}, audited)

    def _edit(self, req, session, body):
        _fields(body, {'connection', 'jobs'})
        self._limit(session)
        with self.serial:
            settings = self._read()
            before = copy.deepcopy(settings)
            conn_id = self._connection(settings, body['connection'])
            conn = settings['connections'][conn_id]
            choices = self._choices(body['jobs'], conn['provider'])
            current = _jobs_of(settings, conn_id)
            if conn['endpoint_style'] == 'exact' and conn['format'] == 'gemini_api' and current:
                models = {raw['model'] for raw in current.values()}
                if any(choice.model.strip() not in models for choice in choices.values()):
                    raise _refused(EXACT_MODEL)
            # The key is not asked again; the address cannot change here (validate_draft holds that).
            draft = self._validate(settings, Draft(conn['provider'], conn['name'], conn['format'], conn['base_url'],
                                                   conn['ca_file'], None, choices), body, replacing=conn_id)
            pending = connections.with_connection(settings, conn_id, draft)
            changed = [role for role in JOB_ORDER if role in draft.jobs and (
                role not in current or (current[role]['model'], current[role]['family'],
                                        current[role]['timeout_seconds']) != tuple(
                    getattr(draft.jobs[role], f) for f in ('model', 'family', 'timeout_seconds')))]
            roles = self._roles(pending, self.secrets) if changed else None
        seconds = 0.0
        if changed:
            result = self._run(roles, changed, conn_id)
            if not result.ok:
                return self._failure(result)
            after = connections.record_test(pending, conn_id, result, changed, self.accounts.clock.now())
            seconds = result.seconds
        else:
            # Nothing was re-tested, so the last test still says what it said.
            after = copy.deepcopy(pending)
            after['connections'][conn_id]['last_test'] = conn['last_test']
        self._commit(req, before, after, conn_id)
        jobs = [role for role in JOB_ORDER if role in draft.jobs]
        audited = self._audit(req, session, 'connection_edited', conn_id, draft.name, jobs)
        return self._done({'ok': True, 'connection': conn_id, 'provider': preset(draft.provider).name,
                           'name': draft.name, 'seconds': seconds, 'jobs': [JOB_NAMES[role] for role in jobs]},
                          audited)

    def _replace_key(self, req, session, body):
        _fields(body, {'connection', 'key'}, {'base_url', 'ca_file'})
        key = _text(body['key'], plain=False)
        base_url = _optional_text(body.get('base_url'), limit=2048)
        ca_file = _optional_text(body.get('ca_file'))
        self._limit(session)
        with self.serial:
            settings = self._read()
            before = copy.deepcopy(settings)
            conn_id = self._connection(settings, body['connection'])
            conn = settings['connections'][conn_id]
            current = _jobs_of(settings, conn_id)
            if (current and conn['key_source'] != 'none'
                    and all(key_source(settings, role, self.environ) == 'environment' for role in current)):
                raise _refused(KEY_ON_SERVER)
            chosen = preset(conn['provider'])
            if not key.strip() and (chosen.needs_key or conn['key_source'] == 'stored'):
                raise _refused(KEY_NEEDED)
            choices = {role: JobChoice(raw['model'], raw['family'], raw['timeout_seconds'])
                       for role, raw in current.items()}
            draft = Draft(conn['provider'], conn['name'], conn['format'],
                          base_url or conn['base_url'],
                          conn['ca_file'] if ca_file is None else ca_file, key if key.strip() else None,
                          choices)
            draft = self._validate(settings, draft, body, replacing=conn_id)
            pending = connections.with_connection(settings, conn_id, draft)
            roles = self._roles(pending, Overlay(self.secrets, {conn_id: draft.key} if draft.key else {}))
        jobs = list(current)
        result = None
        if jobs:
            result = self._run(roles, jobs, conn_id)
            if not result.ok:
                return self._failure(result)
            after = connections.record_test(pending, conn_id, result, jobs, self.accounts.clock.now())
        else:
            after = pending
        self._commit(req, before, after, conn_id, key=draft.key)
        # A connection that needs no key only had its address changed.
        event = 'connection_key_replaced' if draft.key is not None else 'connection_edited'
        audited = self._audit(req, session, event, conn_id, draft.name, jobs)
        return self._done({'ok': True, 'connection': conn_id, 'provider': chosen.name, 'name': draft.name,
                           'seconds': result.seconds if result else 0.0, 'jobs': [JOB_NAMES[role] for role in jobs]},
                          audited)

    def _test_again(self, req, session, body):
        """Records the result in last_test and changes nothing else; needs no re-confirm."""
        _fields(body, {'connection'})
        self._limit(session)
        with self.serial:
            settings = self._read()
            before = copy.deepcopy(settings)
            conn_id = self._connection(settings, body['connection'])
            jobs = list(_jobs_of(settings, conn_id))
            if not jobs:
                raise _refused(NOTHING_TO_TEST)
            roles = self._roles(settings, self.secrets)
        result = self._run(roles, jobs, conn_id)
        after = connections.record_test(settings, conn_id, result, jobs, self.accounts.clock.now())
        self._commit(req, before, after, conn_id)
        if not result.ok:
            return self._failure(result)
        return {'ok': True, 'connection': conn_id, 'seconds': result.seconds,
                'jobs': [JOB_NAMES[role] for role in jobs]}

    def _delete(self, req, session, body):
        _fields(body, {'connection'})
        with self.serial:
            self._still_allowed(req)
            settings = self._read()
            conn_id = self._connection(settings, body['connection'])
            conn = settings['connections'][conn_id]
            jobs = list(_jobs_of(settings, conn_id))
            try:
                local_settings.save(self.config_path, connections.without_connection(settings, conn_id))
            except (OSError, ValueError) as exc:
                self.log('connection_save_failed', connection=conn_id, error=type(exc).__name__)
                raise _refused(NOT_SAVED, 503) from None
            key_kept = False
            try:
                self.secrets.delete(conn_id)       # after the settings save, and under `serial`
            except (SecretsFileUnsafe, OSError, ValueError) as exc:
                self.log('connection_key_delete_failed', connection=conn_id, error=type(exc).__name__,
                         level=logging.ERROR if conn['key_source'] == 'stored' else logging.WARNING)
                key_kept = conn['key_source'] == 'stored'
        audited = self._audit(req, session, 'connection_removed', conn_id, conn['name'], jobs)
        if key_kept:
            raise _Reply(503, self._done({'error': KEY_NOT_DELETED}, audited))
        return self._done({'ok': True}, audited)


def lines(provider, models):
    """Each listed model's catalogue line (tier, speed, relative cost), None when unknown."""
    return {model: entry.strengths if (entry := match(provider, model)) else None for model in models}


def suggest(settings, provider, models):
    """The catalogue's pick among `models` for the jobs nobody does yet: a large model while
    Triage or Review is a gap (or nothing is), else a small or local one. None when the
    catalogue knows none of them."""
    gaps = {role for role in ROLES if not settings['roles'].get(role)}
    tiers = ('large', 'small', 'local') if not gaps or gaps & {'proposer', 'reviewer'} else ('small', 'local', 'large')
    catalogue = entries()
    ranked = []
    for place, model in enumerate(models):
        entry = match(provider, model)   # each model's own entry: 'gpt-*' does not make a mini large
        if entry is not None and entry in catalogue:   # not the generic Ollama entry
            ranked.append((tiers.index(entry.tier), catalogue.index(entry), place, model))
    return min(ranked)[-1] if ranked else None
