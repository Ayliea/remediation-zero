# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""The /connections/* JSON routes of the local dashboard server, over real sockets.

Owner-only; every change re-confirmed and audited; every test runs with `serial` released
and saves only if the settings did not change meanwhile; a key never comes back. The two
network seams (connections.test_jobs and model_endpoints.list_models) are replaced here, so
no test reaches a model. Synthetic data only: `.invalid` hosts, invented keys."""
import http.client
import json
import logging
import socket
import threading

import pytest

from scripts import local, local_connections
from tests.test_accounts import PW_OWNER
from tools import access, connections, local_settings, model_endpoints
from tools.accounts import CONNECTION_EVENTS, AccountRefused, RateLimiter
from tools.local_secrets import SecretsFile, secrets_path
from tools.model_transport import ModelTimedOut
from ui import account_views

KEY = 'sk-sweep-QX7Z9'
OTHER_KEY = 'sk-test-otherkey0042'
BASE = 'https://api.example.invalid/v1'
PATHS = ('/connections/confirm', '/connections/models', '/connections/recommend', '/connections/save',
         '/connections/edit', '/connections/replace-key', '/connections/test', '/connections/delete')


@pytest.fixture(autouse=True)
def no_reverse_lookup(monkeypatch):
    monkeypatch.setattr(socket, 'getfqdn', lambda name='': name)


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch):
    for name in ('RZ_MODEL', 'RZ_MODEL_ENDPOINT', 'RZ_MODEL_API_KEY', 'RZ_PROPOSER_API_KEY',
                 'RZ_REVIEWER_API_KEY', 'RZ_SUMMARIZER_API_KEY', 'RZ_GUARD_API_KEY'):
        monkeypatch.delenv(name, raising=False)


class Tester:
    __test__ = False  # not a pytest class
    """Stands in for connections.test_jobs: records what it was asked and the keys it could
    read, and answers `result` (a TestResult, or a callable taking roles and jobs)."""

    def __init__(self):
        self.calls = []
        self.result = None

    def __call__(self, roles, jobs):
        keys = {}
        for role in jobs:
            config = getattr(roles, role)
            keys[role] = roles.secrets.get(config.connection) if roles.secrets and config.connection else None
        self.calls.append({'jobs': list(jobs), 'keys': keys, 'models': {r: getattr(roles, r).model for r in jobs}})
        if callable(self.result):
            return self.result(roles, jobs)
        return self.result or connections.TestResult(True, None, '', 1.25)


class Server:
    def __init__(self, httpd, config_path, site, store, responses):
        self.httpd, self.config_path, self.site, self.store = httpd, config_path, site, store
        self.port = httpd.server_port
        self.responses = responses

    @property
    def secrets(self):
        return SecretsFile(secrets_path(self.config_path.parent / 'ws'))

    def csrf(self, who='owner'):
        token = {'owner': self.site.owner_token, 'tech': self.site.tech_token,
                 'unconfirmed': self.site.unconfirmed_token}[who]
        return self.site.accounts.session(token).csrf

    def post(self, path, payload=None, *, who='owner', token=True, raw=None, content_type='application/json',
             origin=None, headers=None):
        if raw is None:
            body = dict(payload or {})
            if token is True:
                body['token'] = self.csrf(who)
            elif token is not None:
                body['token'] = token
            raw = json.dumps(body).encode()
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=10)
        host = f'127.0.0.1:{self.port}'
        sent = {'Host': host, 'Origin': origin or f'http://{host}', 'Sec-Fetch-Site': 'same-origin',
                'Content-Type': content_type, 'Cookie': self.site.cookie(who)}
        sent.update(headers or {})
        conn.request('POST', path, body=raw, headers={k: v for k, v in sent.items() if v is not None})
        response = conn.getresponse()
        text = response.read().decode()
        conn.close()
        self.responses.append((response.status, response.getheaders(), text))
        try:
            data = json.loads(text) if response.getheader('Content-Type') == 'application/json' else None
        except ValueError:
            data = None
        return response, data, text

    def settings(self):
        return local_settings.load(self.config_path)

    def file_bytes(self):
        return self.config_path.read_bytes() if self.config_path.exists() else None


@pytest.fixture
def tester(monkeypatch):
    fake = Tester()
    monkeypatch.setattr(connections, 'test_jobs', fake)
    monkeypatch.setattr(model_endpoints, 'list_models',
                        lambda *a, **k: pytest.fail('list_models was not expected here'))
    return fake


@pytest.fixture
def make_server(tmp_path, fake_endpoints, signed_in, tester):
    started = []

    def run(connection_limiter=None):
        ws = local.open_workspace(tmp_path / 'ws')
        config_path = local_settings.settings_path(ws.root)
        docs = ws.docs_for('dashboard')
        view = local._View(docs)
        cls = local.handler(view, False, config_path, 'python3 -S -m scripts.local --database /srv/rz', None,
                            accounts=signed_in.accounts, connection_limiter=connection_limiter)
        httpd = local.DashboardServer(('127.0.0.1', 0), cls)
        fake_endpoints.tcp(httpd.socket)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        started.append((httpd, docs))
        return Server(httpd, config_path, signed_in, view, [])

    yield run
    for httpd, docs in started:
        httpd.shutdown()
        httpd.server_close()
        docs.close()


@pytest.fixture
def server(make_server):
    return make_server()


def job(model='gpt-x', family='gpt', timeout_seconds=60):
    return {'model': model, 'family': family, 'timeout_seconds': timeout_seconds}


def draft(**changes):
    value = {'provider': 'openai', 'name': 'OpenAI', 'format': 'openai_chat', 'base_url': BASE,
             'ca_file': '', 'key': KEY, 'jobs': {'reviewer': job(), 'summarizer': job('gpt-x-mini')}}
    value.update(changes)
    return value


def added(server, **changes):
    response, data, text = server.post('/connections/save', {'draft': draft(**changes)})
    assert response.status == 200 and data['ok'] is True, text
    return data['connection']


def events(server, name=None):
    rows = [dict(r) for r in server.site.accounts.store.events(1000)]
    return [r for r in rows if name is None or r['event'] == name]


# --- the audit event ------------------------------------------------------------

def test_record_change_writes_one_stamped_event_with_name_and_jobs(signed_in):
    owner = signed_in.accounts.session(signed_in.owner_token).account_id
    signed_in.accounts.record_change(owner, 'connection_added', detail={'connection': 'OpenAI', 'jobs': ['reviewer']},
                                     via='dashboard', source='192.0.2.10')
    row = dict(signed_in.accounts.store.events(1)[0])
    assert row['event'] == 'connection_added' and row['actor_id'] == owner and row['via'] == 'dashboard'
    assert json.loads(row['detail']) == {'connection': 'OpenAI', 'jobs': ['reviewer']}
    stamp = signed_in.accounts.clock.now()
    assert row['real_ts'] > 0 and row['sim_ts'] > 0 and row['sim_ts'] <= stamp.sim_ts


def test_record_change_refuses_other_events_and_a_tech(signed_in):
    owner = signed_in.accounts.session(signed_in.owner_token).account_id
    tech = signed_in.accounts.session(signed_in.tech_token).account_id
    before = len(signed_in.accounts.store.events(1000))
    with pytest.raises(ValueError):
        signed_in.accounts.record_change(owner, 'role_changed', detail={'connection': 'x', 'jobs': []},
                                         via='dashboard', source=None)
    with pytest.raises(ValueError):
        signed_in.accounts.record_change(owner, 'connection_added', detail={'connection': 'x', 'key': 'k'},
                                         via='dashboard', source=None)
    with pytest.raises(AccountRefused):
        signed_in.accounts.record_change(tech, 'connection_added', detail={'connection': 'x', 'jobs': []},
                                         via='dashboard', source=None)
    assert len(signed_in.accounts.store.events(1000)) == before


def test_the_audit_trail_names_the_four_events():
    assert CONNECTION_EVENTS == ('connection_added', 'connection_edited', 'connection_key_replaced',
                                 'connection_removed')
    words = {e: account_views.event_columns({'event': e, 'real_ts': 0, 'actor_id': None, 'subject_id': None,
                                             'via': 'dashboard', 'source': None, 'detail': None}, {})['event']
             for e in CONNECTION_EVENTS}
    assert words == {'connection_added': 'Model connection added', 'connection_edited': 'Model connection edited',
                     'connection_key_replaced': 'Model connection key replaced',
                     'connection_removed': 'Model connection removed'}


def test_only_an_owner_may_manage_connections():
    assert access.allowed('owner', 'manage_connections')
    assert not access.allowed('tech', 'manage_connections')
    assert not access.allowed(None, 'manage_connections')


def test_the_key_file_is_the_one_beside_the_database(tmp_path):
    database = tmp_path / 'ws'
    assert local_connections.secrets_beside(local_settings.settings_path(database)) == secrets_path(database)


# --- add ------------------------------------------------------------------------

def test_save_tests_then_stores_the_connection_its_jobs_and_key_and_audits(server, tester):
    response, data, text = server.post('/connections/save', {'draft': draft()})
    assert response.status == 200, text
    assert response.getheader('Cache-Control') == 'no-store'
    assert response.getheader('Content-Type') == 'application/json'
    conn = data['connection']
    assert data == {'ok': True, 'connection': conn, 'provider': 'OpenAI', 'name': 'OpenAI', 'seconds': 1.25,
                    'jobs': ['Review', 'Summaries']}
    assert tester.calls == [{'jobs': ['reviewer', 'summarizer'], 'keys': {'reviewer': KEY, 'summarizer': KEY},
                             'models': {'reviewer': 'gpt-x', 'summarizer': 'gpt-x-mini'}}]
    saved = server.settings()
    assert saved['connections'][conn]['key_source'] == 'stored'
    assert saved['connections'][conn]['last_test']['ok'] is True
    assert saved['roles']['reviewer'] == {'connection': conn, 'model': 'gpt-x', 'family': 'gpt', 'timeout_seconds': 60}
    assert saved['roles']['summarizer']['model'] == 'gpt-x-mini' and saved['roles']['proposer'] is None
    assert server.secrets.get(conn) == KEY
    [event] = events(server, 'connection_added')
    assert json.loads(event['detail']) == {'connection': 'OpenAI', 'jobs': ['reviewer', 'summarizer']}
    assert event['actor_id'] == server.site.accounts.session(server.site.owner_token).account_id


def test_save_with_one_failing_job_writes_nothing(server, tester):
    first = added(server, name='Existing', jobs={'proposer': job()})
    before, keys = server.file_bytes(), server.secrets.path.read_bytes()
    tester.result = connections.TestResult(False, 'reviewer', 'ModelTimedOut', 2.0)
    response, data, text = server.post('/connections/save', {'draft': draft(key=OTHER_KEY)})
    assert response.status == 200, text
    assert data['ok'] is False and data['failed_job'] == 'reviewer'
    assert data['error'] == 'Review failed: ModelTimedOut'
    assert data['hint'] == local_connections.PROBLEM_HINTS['ModelTimedOut']
    assert server.file_bytes() == before and server.secrets.path.read_bytes() == keys
    assert list(server.settings()['connections']) == [first]
    assert len(events(server, 'connection_added')) == 1


def test_a_test_that_raises_is_a_failure_by_class_only(server, tester):
    def boom(roles, jobs):
        raise RuntimeError(f'leaked {KEY} at {BASE}')
    tester.result = boom
    response, data, text = server.post('/connections/save', {'draft': draft()})
    assert response.status == 200 and data['ok'] is False
    assert data['error'] == 'Review failed: RuntimeError'
    assert KEY not in text and BASE not in text
    assert not server.config_path.exists()


def test_save_needs_at_least_one_job(server, tester):
    response, data, _ = server.post('/connections/save', {'draft': draft(jobs={})})
    assert response.status == 400 and data['error'] and tester.calls == []
    assert not server.config_path.exists()


def test_an_unconfirmed_save_asks_in_place_then_the_same_body_saves(server, tester):
    body = {'draft': draft()}
    response, data, _ = server.post('/connections/save', body, who='unconfirmed')
    assert response.status == 401 and data == {'confirm': True}
    assert tester.calls == [] and not server.config_path.exists() and not server.secrets.path.exists()
    response, data, _ = server.post('/connections/confirm', {'password': PW_OWNER}, who='unconfirmed')
    assert response.status == 200 and data == {'ok': True}
    response, data, _ = server.post('/connections/save', body, who='unconfirmed')
    assert response.status == 200 and data['ok'] is True
    assert server.secrets.get(data['connection']) == KEY


def test_confirm_takes_one_box_and_refuses_a_wrong_password(server):
    response, data, _ = server.post('/connections/confirm', {'password': PW_OWNER, 'code': '123456'},
                                    who='unconfirmed')
    assert response.status == 400 and data['error'] == local_auth_sentence('CONFIRM_ONE_ONLY')
    response, data, text = server.post('/connections/confirm', {'password': 'not the password'}, who='unconfirmed')
    assert response.status == 400 and data['error'] == local_auth_sentence('CONFIRM_FAILED')
    assert 'not the password' not in text
    assert not server.site.accounts.session(server.site.unconfirmed_token).confirmed


def local_auth_sentence(name):
    from scripts import local_auth
    return getattr(local_auth, name)


def test_a_refused_draft_answers_a_fixed_sentence_without_what_was_sent(server, tester):
    for bad in (draft(base_url='http://remote.example.invalid/v1'), draft(key='sk test with spaces'),
                draft(provider='nobody'), draft(name='<b>' * 30), draft(jobs={'reviewer': job(family='martian')}),
                draft(ca_file='relative/ca.pem')):
        response, data, text = server.post('/connections/save', {'draft': bad})
        assert response.status == 400, (bad, text)
        assert set(data) == {'error'}
        for value in (bad['base_url'], bad['key'], bad['name'], 'martian', 'relative/ca.pem'):
            assert value not in text
    assert tester.calls == [] and not server.config_path.exists()


# --- the guards every route shares ---------------------------------------------

@pytest.mark.parametrize('path', PATHS)
def test_a_tech_is_refused_every_route(server, tester, path):
    response, _, _ = server.post(path, {'connection': 'conn-000000000000'}, who='tech')
    assert response.status == 403
    assert tester.calls == [] and not server.config_path.exists()


@pytest.mark.parametrize('path', PATHS)
def test_a_missing_or_wrong_token_is_refused(server, tester, path):
    for token in (None, 'not-the-token', ''):
        response, _, _ = server.post(path, {'draft': draft(), 'password': PW_OWNER}, token=token)
        assert response.status == 403, (path, token)
    assert tester.calls == [] and not server.config_path.exists()


@pytest.mark.parametrize('path', PATHS)
def test_a_wrong_origin_is_refused(server, tester, path):
    response, _, _ = server.post(path, {'draft': draft()}, origin='https://elsewhere.example.invalid')
    assert response.status == 403
    response, _, _ = server.post(path, {'draft': draft()}, headers={'Sec-Fetch-Site': 'cross-site'})
    assert response.status == 403
    assert tester.calls == []


@pytest.mark.parametrize('path', PATHS)
def test_a_body_that_is_not_json_is_refused(server, tester, path):
    token = server.csrf()
    form = f'token={token}'.encode()
    assert server.post(path, raw=form, content_type='application/x-www-form-urlencoded')[0].status == 400
    assert server.post(path, raw=b'{"token": ', content_type='application/json')[0].status == 400
    assert server.post(path, raw=json.dumps([token]).encode())[0].status == 400
    dup = ('{"token": "%s", "token": "%s"}' % (token, token)).encode()
    assert server.post(path, raw=dup)[0].status == 400
    assert tester.calls == [] and not server.config_path.exists()


def test_unknown_fields_are_refused(server, tester):
    response, _, _ = server.post('/connections/test', {'connection': 'conn-000000000000', 'extra': 1})
    assert response.status == 400
    response, _, _ = server.post('/connections/save', {'draft': dict(draft(), extra='x')})
    assert response.status == 400
    assert tester.calls == []


def test_an_oversized_body_is_refused_unread(server, tester):
    response, _, _ = server.post('/connections/save', {'draft': draft(name='x' * 9000)})
    assert response.status in (400, 413)
    assert tester.calls == [] and not server.config_path.exists()


def test_one_connection_request_in_flight_per_session(server, tester):
    conn = added(server)
    entered, release = threading.Event(), threading.Event()

    def slow(roles, jobs):
        entered.set()
        assert release.wait(10)
        return connections.TestResult(True, None, '', 0.5)
    tester.result = slow
    results = {}
    worker = threading.Thread(target=lambda: results.setdefault('first', server.post('/connections/test',
                                                                                     {'connection': conn})))
    worker.start()
    assert entered.wait(10)
    try:
        response, _, _ = server.post('/connections/recommend', {'provider': 'openai', 'model': 'gpt-x'})
        assert response.status == 409 and response.getheader('Retry-After')
        # Another person's session is not held up, and nothing holds `serial` across the test.
        other = server.site.accounts.session(server.site.tech_token)
        assert other is not None
    finally:
        release.set()
        worker.join(10)
    assert results['first'][0].status == 200
    assert server.post('/connections/recommend', {'provider': 'openai', 'model': 'gpt-x'})[0].status == 200


def test_a_page_load_is_not_blocked_while_a_test_runs(server, tester):
    conn = added(server)
    entered, release = threading.Event(), threading.Event()

    def slow(roles, jobs):
        entered.set()
        assert release.wait(10)
        return connections.TestResult(True, None, '', 0.5)
    tester.result = slow
    worker = threading.Thread(target=lambda: server.post('/connections/test', {'connection': conn}))
    worker.start()
    assert entered.wait(10)
    try:
        page = http.client.HTTPConnection('127.0.0.1', server.port, timeout=5)
        page.request('GET', '/?view=settings&section=scanner',
                     headers={'Host': f'127.0.0.1:{server.port}', 'Cookie': server.site.cookie('tech')})
        assert page.getresponse().status == 200
        page.close()
    finally:
        release.set()
        worker.join(10)


def test_the_seventh_rate_limited_call_in_a_minute_is_refused(server, tester):
    conn = added(server)                      # the first of six
    for _ in range(5):
        assert server.post('/connections/test', {'connection': conn})[0].status == 200
    response, data, _ = server.post('/connections/test', {'connection': conn})
    assert response.status == 429 and int(response.getheader('Retry-After')) >= 1
    assert data['error']
    assert len(tester.calls) == 6
    # Not rate-limited: recommend and delete.
    assert server.post('/connections/recommend', {'provider': 'openai', 'model': 'gpt-x'})[0].status == 200
    assert server.post('/connections/delete', {'connection': conn})[0].status == 200


# --- the revision check ----------------------------------------------------------

def test_a_delete_in_another_tab_while_an_edit_tests_is_a_409(server, tester):
    conn = added(server)

    def deleted_meanwhile(roles, jobs):
        local_settings.save(server.config_path, connections.without_connection(server.settings(), conn))
        return connections.TestResult(True, None, '', 0.5)
    tester.result = deleted_meanwhile
    response, data, _ = server.post('/connections/edit', {'connection': conn, 'jobs': {'reviewer': job('gpt-y')}})
    assert response.status == 409
    assert data == {'error': 'Settings changed while testing. Nothing was saved.'}
    assert conn not in server.settings()['connections']
    assert events(server, 'connection_edited') == []


def test_a_settings_change_while_a_save_tests_is_a_409_and_stores_no_key(server, tester):
    def changed_meanwhile(roles, jobs):
        values = server.settings()
        values['same_family_policy'] = 'proceed'
        local_settings.save(server.config_path, values)
        return connections.TestResult(True, None, '', 0.5)
    tester.result = changed_meanwhile
    response, data, _ = server.post('/connections/save', {'draft': draft()})
    assert response.status == 409 and data['error'] == 'Settings changed while testing. Nothing was saved.'
    assert server.settings()['connections'] == {} and not server.secrets.path.exists()


def test_a_key_that_cannot_be_stored_puts_the_settings_file_back(server, tester, monkeypatch):
    first = added(server, name='Existing', jobs={'proposer': job()})
    before = server.file_bytes()

    def refuse(self, connection_id, key):
        raise OSError('disk full')
    monkeypatch.setattr(SecretsFile, 'put', refuse)
    response, data, text = server.post('/connections/save', {'draft': draft(key=OTHER_KEY)})
    assert response.status == 503 and data['error'] and 'disk full' not in text
    assert server.file_bytes() == before
    assert list(server.settings()['connections']) == [first]
    assert len(events(server, 'connection_added')) == 1


# --- edit, replace key, test again, delete -------------------------------------

def test_edit_retests_only_the_changed_jobs_and_never_asks_for_the_key(server, tester):
    conn = added(server)
    tester.calls.clear()
    jobs = {'reviewer': job(), 'summarizer': job('gpt-x-nano'), 'guard': job('gpt-x-nano')}
    response, data, text = server.post('/connections/edit', {'connection': conn, 'jobs': jobs})
    assert response.status == 200 and data['ok'] is True, text
    assert tester.calls == [{'jobs': ['guard', 'summarizer'], 'keys': {'guard': KEY, 'summarizer': KEY},
                             'models': {'guard': 'gpt-x-nano', 'summarizer': 'gpt-x-nano'}}]
    saved = server.settings()
    assert saved['roles']['summarizer']['model'] == 'gpt-x-nano' and saved['roles']['guard']['connection'] == conn
    assert server.secrets.get(conn) == KEY
    [event] = events(server, 'connection_edited')
    assert json.loads(event['detail']) == {'connection': 'OpenAI', 'jobs': ['reviewer', 'guard', 'summarizer']}


def test_edit_that_drops_a_job_tests_nothing_and_unassigns_it(server, tester):
    conn = added(server)
    tester.calls.clear()
    response, data, _ = server.post('/connections/edit', {'connection': conn, 'jobs': {'reviewer': job()}})
    assert response.status == 200 and data['ok'] is True
    assert tester.calls == []
    assert server.settings()['roles']['summarizer'] is None


def test_a_failing_edit_changes_nothing(server, tester):
    conn = added(server)
    before = server.file_bytes()
    tester.result = connections.TestResult(False, 'reviewer', 'CertificateNotTrusted', 0.1)
    response, data, _ = server.post('/connections/edit', {'connection': conn, 'jobs': {'reviewer': job('gpt-y')}})
    assert response.status == 200 and data['ok'] is False and data['error'] == 'Review failed: CertificateNotTrusted'
    assert server.file_bytes() == before and events(server, 'connection_edited') == []


def test_edit_of_a_connection_that_is_gone_is_refused(server, tester):
    response, data, _ = server.post('/connections/edit', {'connection': 'conn-0123456789ab', 'jobs': {}})
    assert response.status == 400 and data['error']


def test_replace_key_tests_every_job_with_the_new_key_then_replaces_it(server, tester):
    conn = added(server)
    tester.calls.clear()
    response, data, text = server.post('/connections/replace-key', {'connection': conn, 'key': OTHER_KEY})
    assert response.status == 200 and data['ok'] is True, text
    assert tester.calls[0]['jobs'] == ['reviewer', 'summarizer']
    assert tester.calls[0]['keys'] == {'reviewer': OTHER_KEY, 'summarizer': OTHER_KEY}
    assert server.secrets.get(conn) == OTHER_KEY
    assert len(events(server, 'connection_key_replaced')) == 1


def test_replace_key_can_move_the_address_only_with_a_key(server, tester):
    conn = added(server)
    moved = 'https://moved.example.invalid/v1'
    response, data, _ = server.post('/connections/replace-key', {'connection': conn, 'key': '', 'base_url': moved})
    assert response.status == 400 and data['error'] and moved not in json.dumps(data)
    response, data, _ = server.post('/connections/replace-key', {'connection': conn, 'key': OTHER_KEY,
                                                                 'base_url': moved})
    assert response.status == 200 and data['ok'] is True
    assert server.settings()['connections'][conn]['base_url'] == moved


def test_a_failing_key_replacement_keeps_the_old_key(server, tester):
    conn = added(server)
    tester.result = connections.TestResult(False, 'summarizer', 'ModelTimedOut', 0.1)
    response, data, _ = server.post('/connections/replace-key', {'connection': conn, 'key': OTHER_KEY})
    assert response.status == 200 and data['ok'] is False and data['error'] == 'Summaries failed: ModelTimedOut'
    assert server.secrets.get(conn) == KEY


def test_test_again_records_last_test_only(server, tester):
    conn = added(server)
    before = server.settings()
    tester.result = connections.TestResult(False, 'summarizer', 'ModelTimedOut', 3.5)
    response, data, _ = server.post('/connections/test', {'connection': conn})
    assert response.status == 200 and data['ok'] is False and data['error'] == 'Summaries failed: ModelTimedOut'
    after = server.settings()
    assert after['connections'][conn]['last_test']['ok'] is False
    assert after['connections'][conn]['last_test']['error'] == 'ModelTimedOut'
    assert after['connections'][conn]['last_test']['jobs'] == ['reviewer', 'summarizer']
    for value in (before, after):
        value['connections'][conn]['last_test'] = None
    assert after == before
    assert events(server, 'connection_edited') == []


def test_test_again_on_an_unconfirmed_session_needs_no_confirm(server, tester):
    conn = added(server)
    response, data, _ = server.post('/connections/test', {'connection': conn}, who='unconfirmed')
    assert response.status == 200 and data['ok'] is True


def test_a_failed_test_is_logged_by_connection_job_and_class(server, tester, caplog):
    conn = added(server)
    tester.result = connections.TestResult(False, 'reviewer', 'ModelTimedOut', 0.1)
    with caplog.at_level(logging.INFO):
        server.post('/connections/test', {'connection': conn})
    lines = [json.loads(r.getMessage()) for r in caplog.records if 'connection_test_failed' in r.getMessage()]
    assert lines and lines[0]['connection'] == conn and lines[0]['role'] == 'reviewer'
    assert lines[0]['error'] == 'ModelTimedOut'


def test_delete_removes_the_connection_its_jobs_and_its_key(server, tester):
    conn = added(server)
    keep = added(server, name='Kept', key=OTHER_KEY, jobs={'proposer': job()})
    response, data, _ = server.post('/connections/delete', {'connection': conn}, who='unconfirmed')
    assert response.status == 401 and data == {'confirm': True}
    assert conn in server.settings()['connections']
    response, data, _ = server.post('/connections/delete', {'connection': conn})
    assert response.status == 200 and data == {'ok': True}
    saved = server.settings()
    assert list(saved['connections']) == [keep]
    assert saved['roles']['reviewer'] is None and saved['roles']['summarizer'] is None
    assert server.secrets.get(conn) is None and server.secrets.get(keep) == OTHER_KEY
    [event] = events(server, 'connection_removed')
    assert json.loads(event['detail']) == {'connection': 'OpenAI', 'jobs': ['reviewer', 'summarizer']}


# --- models and recommend --------------------------------------------------------

def test_models_lists_with_the_key_just_typed_and_suggests_one(server, monkeypatch):
    seen = []

    def listed(format, base_url, key, ca_file=None):
        seen.append((format, base_url, key, ca_file))
        return ['gpt-unknown', 'gpt-x']
    monkeypatch.setattr(model_endpoints, 'list_models', listed)
    response, data, _ = server.post('/connections/models', {'provider': 'openai', 'base_url': BASE,
                                                            'ca_file': '', 'key': KEY})
    assert response.status == 200
    assert data['models'] == ['gpt-unknown', 'gpt-x']
    assert data['suggested'] is None or data['suggested'] in data['models']
    assert seen == [('openai_chat', BASE, KEY, None)]
    assert not server.config_path.exists()


def test_models_carry_each_model_s_catalogue_line(server, monkeypatch):
    # The Models popup shows one line per listed model from the catalogue; an unknown model has none.
    monkeypatch.setattr(model_endpoints, 'list_models', lambda *a, **k: ['gpt-x', 'gpt-x-mini', 'whatever-1'])
    response, data, _ = server.post('/connections/models', {'provider': 'openai', 'base_url': BASE,
                                                            'ca_file': '', 'key': KEY})
    assert response.status == 200
    assert data['lines'] == {'gpt-x': 'Larger model; slower, higher cost.',
                             'gpt-x-mini': 'Smaller model; faster, lower cost.', 'whatever-1': None}


def test_models_for_a_saved_connection_use_its_stored_key(server, tester, monkeypatch):
    conn = added(server)
    seen = []
    monkeypatch.setattr(model_endpoints, 'list_models',
                        lambda format, base_url, key, ca_file=None: seen.append(key) or ['gpt-x'])
    response, data, _ = server.post('/connections/models', {'connection': conn})
    assert response.status == 200 and data['models'] == ['gpt-x'] and seen == [KEY]


def test_a_model_list_failure_names_the_class_only(server, monkeypatch):
    def fails(*args, **kwargs):
        raise ModelTimedOut(f'{BASE} with {KEY}')
    monkeypatch.setattr(model_endpoints, 'list_models', fails)
    response, data, text = server.post('/connections/models', {'provider': 'openai', 'base_url': BASE,
                                                               'ca_file': '', 'key': KEY})
    assert response.status == 200
    assert data['error'] == 'The model list could not be fetched: ModelTimedOut'
    assert KEY not in text and BASE not in text


def test_models_refuses_a_bad_key_before_any_call(server, monkeypatch):
    monkeypatch.setattr(model_endpoints, 'list_models', lambda *a, **k: pytest.fail('called with a bad key'))
    for key in ('sk test spaces', 'sk-\nnewline', 'sk-ключ', 'k' * 5000):
        response, data, text = server.post('/connections/models', {'provider': 'openai', 'base_url': BASE,
                                                                   'ca_file': '', 'key': key})
        assert response.status == 400 and set(data) == {'error'}
        assert key not in text


def test_recommend_gives_cards_and_coverage(server):
    response, data, _ = server.post('/connections/recommend', {'provider': 'openai', 'model': 'gpt-x'})
    assert response.status == 200
    assert [c['role'] for c in data['cards']] == ['proposer', 'reviewer', 'guard', 'summarizer']
    assert {'badge', 'on', 'reason', 'job', 'description'} <= set(data['cards'][0])
    assert [c['role'] for c in data['coverage']] == ['proposer', 'reviewer', 'guard', 'summarizer']
    assert not server.config_path.exists()


def test_recommend_refuses_an_unknown_provider_or_connection(server):
    assert server.post('/connections/recommend', {'provider': 'nobody', 'model': 'x'})[0].status == 400
    assert server.post('/connections/recommend', {'provider': 'openai', 'model': 'x',
                                                  'editing': 'conn-0123456789ab'})[0].status == 400


# --- the key sweep -----------------------------------------------------------------

def test_the_key_never_leaves_the_key_file(make_server, tester, monkeypatch, caplog, capfd):
    """The spec's first test that matters: across add, edit, replace, test, delete, a failing
    test and refused bodies, the key is in no response, log, audit row, settings file,
    `settings show` or snapshot; it is in the key file only between add and delete."""
    caplog.set_level(logging.DEBUG)
    server = make_server(connection_limiter=RateLimiter(per_minute=1000))
    listed_keys = []
    printed = []

    def listed(format, base_url, key, ca_file=None):
        listed_keys.append(key)
        return ['gpt-x']

    def list_fails(*args, **kwargs):
        raise ValueError(f'provider said no to {KEY}')

    def test_fails(roles, jobs):
        raise RuntimeError(f'bad key {KEY}')

    def everywhere_but_the_key_file():
        texts = [json.dumps(server.responses), server.file_bytes().decode() if server.file_bytes() else '',
                 json.dumps(local.settings_shown(server.config_path)), json.dumps(server.store.snapshot(), default=str),
                 json.dumps([dict(r) for r in server.site.accounts.store.events(10000)], default=str)]
        for record in caplog.records:
            texts.append(record.getMessage())
            texts.append(repr(record.__dict__))
        out, err = capfd.readouterr()       # anything written to stdout or stderr, by anyone
        printed.extend([out, err])
        return texts + printed

    def assert_absent(where):
        for text in everywhere_but_the_key_file():
            assert KEY not in text, where
        # Nothing else in the workspace holds it either: only the key file.
        holders = [p for p in server.config_path.parent.rglob('*') if p.is_file() and KEY.encode() in p.read_bytes()]
        assert holders == ([server.secrets.path] if server.secrets.path.exists()
                           and KEY.encode() in server.secrets.path.read_bytes() else []), where

    def step(path, payload=None, expect=200, **kwargs):
        response, data, text = server.post(path, payload, **kwargs)
        assert response.status == expect, (path, text)
        return data

    # Refused before anything exists: a bad address, a key with a space, an unknown field, a wrong
    # token, an unconfirmed session, a tech, a body that is not JSON.
    step('/connections/save', {'draft': draft(base_url='http://remote.example.invalid/v1')}, 400)
    step('/connections/save', {'draft': draft(key=KEY + ' x')}, 400)
    step('/connections/save', {'draft': dict(draft(), stray=KEY)}, 400)
    step('/connections/save', {'draft': draft()}, 403, token='wrong')
    step('/connections/save', {'draft': draft()}, 401, who='unconfirmed')
    step('/connections/save', {'draft': draft()}, 403, who='tech')
    step('/connections/save', raw=json.dumps({'draft': draft()}).encode(), content_type='text/plain', expect=400)
    step('/connections/models', {'provider': 'openai', 'base_url': BASE, 'ca_file': '', 'key': KEY + '\x07'}, 400)
    step('/connections/models', {'provider': 'openai', 'base_url': 'ftp://x.example.invalid', 'ca_file': '',
                                 'key': KEY}, 400)
    # A model list, failing and passing, with the typed key.
    monkeypatch.setattr(model_endpoints, 'list_models', list_fails)
    assert 'error' in step('/connections/models', {'provider': 'openai', 'base_url': BASE, 'ca_file': '', 'key': KEY})
    monkeypatch.setattr(model_endpoints, 'list_models', listed)
    assert step('/connections/models', {'provider': 'openai', 'base_url': BASE, 'ca_file': '',
                                        'key': KEY})['models'] == ['gpt-x']
    # A failing first test (whose exception text carries the key), then the add.
    tester.result = test_fails
    assert step('/connections/save', {'draft': draft()})['ok'] is False
    assert not server.secrets.path.exists()
    assert_absent('before add')
    tester.result = None
    conn = step('/connections/save', {'draft': draft()})['connection']
    assert server.secrets.get(conn) == KEY
    assert_absent('after add')
    assert step('/connections/models', {'connection': conn})['models'] == ['gpt-x']
    step('/connections/recommend', {'provider': 'openai', 'model': 'gpt-x', 'editing': conn})
    assert step('/connections/edit', {'connection': conn, 'jobs': {'reviewer': job('gpt-y')}})['ok'] is True
    assert step('/connections/test', {'connection': conn})['ok'] is True
    tester.result = test_fails
    assert step('/connections/test', {'connection': conn})['ok'] is False
    assert step('/connections/replace-key', {'connection': conn, 'key': KEY})['ok'] is False
    tester.result = connections.TestResult(False, 'reviewer', 'ModelTimedOut', 0.1)
    assert step('/connections/test', {'connection': conn})['ok'] is False
    step('/connections/replace-key', {'connection': conn, 'key': KEY + ' \x07'}, 400)
    step('/connections/replace-key', {'connection': conn, 'key': KEY}, 401, who='unconfirmed')
    tester.result = None
    assert step('/connections/replace-key', {'connection': conn, 'key': KEY})['ok'] is True
    assert server.secrets.get(conn) == KEY
    assert_absent('after edit, test and replace')
    # The failure paths, each with the key in the body: a revision race, a key file that cannot
    # be written (settings put back), an oversized body, a busy session, the key as a password.

    def race(roles, jobs):
        values = server.settings()
        values['same_family_policy'] = 'proceed' if values['same_family_policy'] == 'wait' else 'wait'
        local_settings.save(server.config_path, values)
        return connections.TestResult(True, None, '', 0.1)
    tester.result = race
    step('/connections/save', {'draft': draft(name='Raced')}, 409)
    step('/connections/replace-key', {'connection': conn, 'key': KEY}, 409)
    tester.result = None
    real_put = SecretsFile.put

    def put_fails(self, connection_id, key):
        raise OSError(f'cannot write {key}')
    monkeypatch.setattr(SecretsFile, 'put', put_fails)
    step('/connections/save', {'draft': draft(name='Unstored')}, 503)
    step('/connections/replace-key', {'connection': conn, 'key': KEY}, 503)
    monkeypatch.setattr(SecretsFile, 'put', real_put)
    step('/connections/save', {'draft': draft(name='Large ' + KEY * 700)}, 413)
    entered, release = threading.Event(), threading.Event()

    def slow(roles, jobs):
        entered.set()
        assert release.wait(10)
        return connections.TestResult(True, None, '', 0.1)
    tester.result = slow
    worker = threading.Thread(target=lambda: server.post('/connections/test', {'connection': conn}))
    worker.start()
    assert entered.wait(10)
    try:
        step('/connections/save', {'draft': draft(name='Busy')}, 409)
    finally:
        release.set()
        worker.join(10)
    tester.result = None
    step('/connections/confirm', {'password': KEY}, 400)
    assert server.secrets.get(conn) == KEY
    assert_absent('after the failure paths')
    # A key delete that fails (its exception text carries the key): 503, connection gone.
    second = step('/connections/save', {'draft': draft(name='Second', jobs={'guard': job()})})['connection']
    real_delete = SecretsFile.delete

    def delete_fails(self, connection_id):
        raise OSError(f'cannot delete {KEY}')
    monkeypatch.setattr(SecretsFile, 'delete', delete_fails)
    assert step('/connections/delete', {'connection': second}, 503)['error'] == local_connections.KEY_NOT_DELETED
    monkeypatch.setattr(SecretsFile, 'delete', real_delete)
    assert_absent('after a failed key delete')
    server.secrets.delete(second)          # the owner's clean-up, by hand
    assert step('/connections/delete', {'connection': conn}) == {'ok': True}
    assert server.secrets.get(conn) is None
    assert KEY.encode() not in server.secrets.path.read_bytes()
    assert_absent('after delete')
    assert listed_keys == [KEY, KEY]   # the typed key, then the stored one
    assert {event['event'] for event in events(server)} >= set(CONNECTION_EVENTS)
    # Every response came back, so the sweep looked at real replies.
    assert len(server.responses) >= 20
    for status, headers, _ in server.responses:
        assert all(KEY not in f'{k}: {v}' for k, v in headers)


def test_the_suggestion_fills_the_gaps_with_the_right_tier():
    empty = local_settings.load('/nonexistent/settings.json')
    models = ['gpt-x-mini', 'gpt-x', 'unknown-model']
    assert local_connections.suggest(empty, 'openai', models) == 'gpt-x'          # triage and review are gaps
    covered = connections.with_connection(empty, 'conn-0123456789ab', connections.Draft(
        'openai', 'Big', 'openai_chat', BASE, '', None,
        {'proposer': connections.JobChoice('gpt-x', 'gpt'), 'reviewer': connections.JobChoice('o3', 'gpt')}))
    assert local_connections.suggest(covered, 'openai', models) == 'gpt-x-mini'   # only small jobs are left
    assert local_connections.suggest(empty, 'openai', ['unknown-model']) is None
    assert local_connections.suggest(empty, 'ollama', ['llama3']) is None


# --- fix round 1 ---------------------------------------------------------------

def _demote(server):
    owner = server.site.accounts.session(server.site.owner_token).account_id
    with server.site.accounts.store.transaction() as cur:
        cur.execute("UPDATE accounts SET role = 'tech' WHERE id = ?", (owner,))


def _remove(server):
    owner = server.site.accounts.session(server.site.owner_token).account_id
    with server.site.accounts.store.transaction() as cur:
        cur.execute("UPDATE accounts SET status = 'removed' WHERE id = ?", (owner,))


def _sign_out(server):
    server.site.accounts.sign_out(server.site.owner_token)


@pytest.mark.parametrize('change', [_demote, _remove, _sign_out])
def test_an_owner_who_stops_being_one_during_the_test_saves_nothing(server, tester, change):
    csrf = server.csrf()

    def meanwhile(roles, jobs):
        change(server)
        return connections.TestResult(True, None, '', 0.1)
    tester.result = meanwhile
    response, data, _ = server.post('/connections/save', {'draft': draft()}, token=csrf)
    assert response.status == 403
    assert tester.calls                      # the test did run; the save was refused after it
    assert not server.config_path.exists() and not server.secrets.path.exists()
    assert events(server, 'connection_added') == []


def test_a_demotion_during_an_edit_test_saves_nothing(server, tester):
    conn = added(server)
    before = server.file_bytes()
    tester.result = lambda roles, jobs: (_demote(server), connections.TestResult(True, None, '', 0.1))[1]
    response, _, _ = server.post('/connections/edit', {'connection': conn, 'jobs': {'reviewer': job('gpt-y')}})
    assert response.status == 403 and server.file_bytes() == before
    assert events(server, 'connection_edited') == []


def test_an_audit_that_cannot_be_written_is_an_error_and_the_reply_says_so(server, tester, monkeypatch, caplog):
    import sqlite3

    def refuse(*args, **kwargs):
        raise sqlite3.OperationalError('disk I/O error')
    monkeypatch.setattr(server.site.accounts, 'record_change', refuse)
    with caplog.at_level(logging.INFO):
        response, data, text = server.post('/connections/save', {'draft': draft()})
    assert response.status == 200 and data['ok'] is True and data['audit'] is False
    assert server.secrets.get(data['connection']) == KEY        # the change itself is saved
    failed = [r for r in caplog.records if 'connection_audit_failed' in r.getMessage()]
    assert failed and failed[0].levelno == logging.ERROR
    assert json.loads(failed[0].getMessage())['error'] == 'OperationalError' and 'disk' not in text
    response, data, _ = server.post('/connections/delete', {'connection': data['connection']})
    assert response.status == 200 and data == {'ok': True, 'audit': False}


def test_a_successful_change_does_not_say_audit(server, tester):
    response, data, _ = server.post('/connections/save', {'draft': draft()})
    assert 'audit' not in data


ENV_KEY = 'sk-test-envtriage-0099'


def _env_connection(server, monkeypatch):
    monkeypatch.setenv('RZ_MODEL_API_KEY', ENV_KEY)
    return added(server, key=None, jobs={'proposer': job()})


def test_a_triage_environment_key_lists_models_at_its_own_address(server, tester, monkeypatch):
    conn = _env_connection(server, monkeypatch)
    seen = []
    monkeypatch.setattr(model_endpoints, 'list_models',
                        lambda format, base_url, key, ca_file=None: seen.append((base_url, key)) or ['gpt-x'])
    response, data, _ = server.post('/connections/models', {'connection': conn})
    assert response.status == 200 and data['models'] == ['gpt-x'] and seen == [(BASE, ENV_KEY)]


def test_a_triage_environment_key_is_never_sent_to_the_connection_when_an_endpoint_override_is_set(
        server, tester, monkeypatch):
    conn = _env_connection(server, monkeypatch)
    monkeypatch.setenv('RZ_MODEL_ENDPOINT', 'https://override.example.invalid/v1/chat/completions')
    monkeypatch.setattr(model_endpoints, 'list_models', lambda *a, **k: pytest.fail('the override key was sent'))
    response, data, text = server.post('/connections/models', {'connection': conn})
    assert response.status == 200 and data == {'error': local_connections.NO_ENV_LIST}
    assert ENV_KEY not in text


def test_with_an_override_a_stored_key_still_lists_its_own_models(server, tester, monkeypatch):
    conn = added(server, jobs={'proposer': job()})
    monkeypatch.setenv('RZ_MODEL_API_KEY', ENV_KEY)
    monkeypatch.setenv('RZ_MODEL_ENDPOINT', 'https://override.example.invalid/v1/chat/completions')
    seen = []
    monkeypatch.setattr(model_endpoints, 'list_models',
                        lambda format, base_url, key, ca_file=None: seen.append(key) or ['gpt-x'])
    assert server.post('/connections/models', {'connection': conn})[1]['models'] == ['gpt-x']
    assert seen == [KEY]


def test_another_jobs_environment_key_is_still_used_with_an_override(server, tester, monkeypatch):
    monkeypatch.setenv('RZ_MODEL_API_KEY', ENV_KEY)
    monkeypatch.setenv('RZ_REVIEWER_API_KEY', OTHER_KEY)
    conn = added(server, key=None, jobs={'proposer': job(), 'reviewer': job()})
    monkeypatch.setenv('RZ_MODEL_ENDPOINT', 'https://override.example.invalid/v1/chat/completions')
    seen = []
    monkeypatch.setattr(model_endpoints, 'list_models',
                        lambda format, base_url, key, ca_file=None: seen.append(key) or ['gpt-x'])
    assert server.post('/connections/models', {'connection': conn})[1]['models'] == ['gpt-x']
    assert seen == [OTHER_KEY]


@pytest.mark.parametrize('name', ['bad\\ud800name', 'bell\\u0007name', 'line\\nname', 'c1\\u0085name'])
def test_a_name_with_a_surrogate_or_control_character_is_refused(server, tester, name):
    body = json.dumps({'draft': draft()}).replace('"name": "OpenAI"', '"name": "%s"' % name)
    body = body[:-1] + ', "token": "%s"}' % server.csrf()
    response, data, _ = server.post('/connections/save', raw=body.encode())
    assert response.status == 400 and set(data) == {'error'}
    assert tester.calls == [] and not server.config_path.exists()


def test_a_model_with_a_control_character_is_refused(server, tester):
    response, _, _ = server.post('/connections/save', {'draft': draft(jobs={'reviewer': job('gpt\u0007x')})})
    assert response.status == 400
    response, _, _ = server.post('/connections/recommend', {'provider': 'openai', 'model': 'gpt\u0007x'})
    assert response.status == 400


def test_a_token_with_a_lone_surrogate_is_a_403(server, tester):
    raw = b'{"token": "\\ud800", "connection": "conn-000000000000"}'
    response, _, _ = server.post('/connections/test', raw=raw)
    assert response.status == 403


@pytest.mark.parametrize('field', ['password', 'code'])
def test_confirm_refuses_a_value_that_is_not_text(server, field):
    for value in (1, True, ['x'], {'a': 1}):
        response, _, _ = server.post('/connections/confirm', {field: value}, who='unconfirmed')
        assert response.status == 400
    assert not server.site.accounts.session(server.site.unconfirmed_token).confirmed


@pytest.mark.parametrize('field', ['base_url', 'ca_file', 'key'])
def test_replace_key_refuses_a_value_that_is_not_text(server, tester, field):
    conn = added(server)
    tester.calls.clear()
    body = {'connection': conn, 'key': OTHER_KEY, field: 5}
    assert server.post('/connections/replace-key', body)[0].status == 400
    assert tester.calls == [] and server.secrets.get(conn) == KEY


@pytest.mark.parametrize('raw', [b'\xff\xfe{}', b'{"token": NaN}', b'[' * 5000, b'"\xed\xa0\x80"'],
                         ids=['not-utf8', 'nan', 'deep-array', 'encoded-surrogate'])
def test_bodies_that_cannot_be_read_are_a_400(server, tester, raw):
    response, data, _ = server.post('/connections/test', raw=raw)
    assert response.status == 400 and data == {'error': local_connections.INVALID}


def test_a_deep_object_within_the_size_cap_is_read_and_refused_for_its_token(server, tester):
    # As deep as 8 KB allows still parses (no RecursionError); it carries no token, so 403, not 503.
    response, _, _ = server.post('/connections/test', raw=b'{"a": ' * 1100 + b'1' + b'}' * 1100)
    assert response.status == 403


def test_a_key_file_that_cannot_be_put_back_says_so(server, tester, monkeypatch, caplog):
    import tempfile
    added(server, name='Existing', jobs={'proposer': job()})

    def put_fails(self, connection_id, key):
        def no_temp(*args, **kwargs):
            raise OSError('no space')
        monkeypatch.setattr(tempfile, 'mkstemp', no_temp)
        raise OSError('no space')
    monkeypatch.setattr(SecretsFile, 'put', put_fails)
    with caplog.at_level(logging.INFO):
        response, data, _ = server.post('/connections/save', {'draft': draft(key=OTHER_KEY)})
    assert response.status == 503 and data == {'error': local_connections.KEY_NOT_STORED_NOT_RESTORED}
    failed = [r for r in caplog.records if 'connection_restore_failed' in r.getMessage()]
    assert failed and failed[0].levelno == logging.ERROR and json.loads(failed[0].getMessage())['error'] == 'OSError'


def test_a_key_delete_failure_is_logged_by_class_for_any_key_source(server, tester, monkeypatch, caplog):
    monkeypatch.setenv('RZ_GUARD_API_KEY', ENV_KEY)
    conn = added(server, key=None, jobs={'guard': job()})          # key_source environment

    def delete_fails(self, connection_id):
        raise ValueError('not a valid key file')
    monkeypatch.setattr(SecretsFile, 'delete', delete_fails)
    with caplog.at_level(logging.INFO):
        response, data, _ = server.post('/connections/delete', {'connection': conn})
    assert response.status == 200 and data == {'ok': True}       # it held no key
    failed = [json.loads(r.getMessage()) for r in caplog.records if 'connection_key_delete_failed' in r.getMessage()]
    assert failed == [{'event': 'connection_key_delete_failed', 'connection': conn, 'error': 'ValueError',
                       'cycle_id': '-', 'finding_id': '-'}]
