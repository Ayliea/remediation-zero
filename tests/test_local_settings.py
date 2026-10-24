# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
import copy
import io
import json
import os
import re
from types import SimpleNamespace
from urllib.parse import urlencode
import pytest
from scripts.local import handler
from tools import local_settings as config
from tools.model_endpoint import ModelEndpoint


LOCAL = 'http://localhost:11434/v1/chat/completions'


def proposer(**change):
    return dict(dict(format='openai_chat', endpoint=LOCAL, model='test', family='other'), **change)


def with_proposer(**fields):
    value = copy.deepcopy(config.DEFAULTS)
    value['roles']['proposer'] = proposer(**fields)
    return value


@pytest.mark.parametrize('make', [
    lambda: dict(config.DEFAULTS, port=True), lambda: dict(config.DEFAULTS, port=80),
    lambda: dict(config.DEFAULTS, port=65536), lambda: dict(config.DEFAULTS, mode='other'),
    lambda: dict(config.DEFAULTS, open_browser=1), lambda: dict(config.DEFAULTS, api_key='secret'),
    lambda: dict(config.DEFAULTS, cycle_interval_minutes=1441),
    lambda: dict(config.DEFAULTS, same_family_policy='skip'),
    lambda: with_proposer(endpoint='http://example.invalid/v1'),
    lambda: with_proposer(endpoint='https://user:secret@example.invalid/v1'),
    lambda: with_proposer(endpoint='https://example.invalid:bad/v1'),
    lambda: with_proposer(endpoint='https://example.invalid/\n'),
    lambda: with_proposer(model=''), lambda: with_proposer(format='vertex'),
    lambda: with_proposer(api_key='secret'),
    lambda: dict(config.DEFAULTS, endpoint=LOCAL, model='m')])
def test_invalid_settings_never_replace_file(tmp_path, make):
    path = tmp_path / 'prefs.json'
    config.save(path, config.DEFAULTS)
    before = path.read_bytes()
    with pytest.raises(ValueError):
        config.save(path, make())
    assert path.read_bytes() == before


def test_flat_v1_keys_in_v2_dict_are_unexpected_fields(tmp_path):
    path = tmp_path / 'prefs.json'
    config.save(path, config.DEFAULTS)
    before = path.read_bytes()
    with pytest.raises(ValueError, match='Unexpected settings fields'):
        config.save(path, dict(config.DEFAULTS, endpoint=LOCAL, model='m'))
    assert path.read_bytes() == before


def test_atomic_preferences_and_private_permissions(tmp_path, monkeypatch):
    path = tmp_path / 'prefs.json'
    values = dict(with_proposer(), port=8082)
    config.save(path, values)
    assert config.load(path) == values
    if os.name != 'nt':
        assert path.stat().st_mode & 0o777 == 0o600
    monkeypatch.setattr(config.os, 'replace', lambda *args: (_ for _ in ()).throw(OSError()))
    with pytest.raises(OSError):
        config.save(path, config.DEFAULTS)
    assert config.load(path) == values
    assert list(tmp_path.iterdir()) == [path]


def test_v1_settings_upgrade_to_proposer_role(tmp_path):
    path = tmp_path / 'prefs.json'
    path.write_text(json.dumps({'endpoint': 'http://127.0.0.1:11434/v1/chat/completions', 'model': 'llama3.1',
                                'mode': 'saved', 'open_browser': False, 'port': 8083}))
    loaded = config.load(path)
    assert loaded['version'] == 2
    assert loaded['roles']['proposer'] == dict(format='openai_chat', model='llama3.1', family='llama',
        endpoint='http://127.0.0.1:11434/v1/chat/completions')
    assert [loaded['roles'][r] for r in ('reviewer', 'summarizer', 'guard')] == [None] * 3
    assert loaded['same_family_policy'] == 'wait'
    assert (loaded['mode'], loaded['open_browser'], loaded['port']) == ('saved', False, 8083)
    config.save(path, loaded)
    assert json.loads(path.read_text())['version'] == 2


def test_blank_v1_connection_upgrades_to_no_proposer(tmp_path):
    path = tmp_path / 'prefs.json'
    path.write_text(json.dumps({'endpoint': '', 'model': '', 'mode': 'demo', 'open_browser': True, 'port': 8081}))
    assert config.load(path)['roles']['proposer'] is None


def test_save_never_writes_keys(tmp_path, monkeypatch):
    monkeypatch.setenv('RZ_MODEL_API_KEY', 'sk-never-saved')
    monkeypatch.setenv('RZ_PROPOSER_API_KEY', 'sk-never-saved')
    path = tmp_path / 'prefs.json'
    config.save(path, with_proposer())
    assert 'sk-never-saved' not in path.read_text()
    assert 'api_key' not in path.read_text()


ROLES = ('proposer', 'reviewer', 'summarizer', 'guard')


def model_form(token, **given):
    fields = {'token': token, 'section': 'model', 'same_family_policy': 'wait'}
    for role in ROLES:
        fields.update({role + '_format': 'openai_chat', role + '_endpoint': '', role + '_model': '', role + '_family': ''})
    fields.update(given)
    return fields


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(ModelEndpoint, 'propose', lambda *args: pytest.fail('Settings invoked model'))
    path = tmp_path / 'test.settings.json'
    cls = handler(SimpleNamespace(snapshot=lambda: {}), False, path)
    def request(method='GET', route='/?view=settings', fields=None, origin='http://127.0.0.1:8081', host='127.0.0.1:8081'):
        obj = object.__new__(cls)
        obj.server = SimpleNamespace(server_port=8081)
        obj.path = route
        raw = urlencode(fields or {}).encode()
        obj.headers = {'Host': host, 'Origin': origin, 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': str(len(raw))}
        obj.rfile, obj.wfile = io.BytesIO(raw), io.BytesIO()
        status, headers = [], {}
        obj.send_response = status.append
        obj.send_header = lambda k, v: headers.update({k:v})
        obj.end_headers = lambda: None
        obj.send_error = lambda code, *args: status.append(code)
        getattr(obj, 'do_' + method)()
        return status[0], obj.wfile.getvalue().decode(), headers
    return path, request


def test_all_settings_pages_and_save_without_model(app):
    path, request = app
    assert config.load(path)['roles']['proposer'] is None
    for section in ('model', 'storage', 'application', 'safety', 'updates'):
        status, body, headers = request(route='/?view=settings&section='+section)
        assert status == 200
        assert 'Settings' in body
        assert 'form-action \'self\'' in headers['Content-Security-Policy']
        assert '<details open' not in body
    _, body, _ = request()
    token = re.search('name="token" value="([^"]+)"', body)[1]
    legacy = dict(token=token, section='model', endpoint=LOCAL, model='test')
    assert request('POST', '/settings', legacy)[0] == 400
    assert not path.exists()
    fields = model_form(token, proposer_format='openai_chat', proposer_endpoint=LOCAL, proposer_model='test')
    assert request('POST', '/settings', fields)[0] == 303
    assert config.load(path)['roles']['proposer']['model'] == 'test'
    assert request('POST', '/settings', model_form(token))[0] == 303
    assert config.load(path)['roles']['proposer'] is None
    assert request('POST', '/settings', fields)[0] == 303
    fields = dict(token=token, section='application', mode='saved', port='8082')
    assert request('POST', '/settings', fields)[0] == 303
    assert config.load(path)['open_browser'] is False
    assert config.load(path)['roles']['proposer']['model'] == 'test'
    assert config.load(path)['roles']['reviewer'] is None
    assert 'value="test"' in request()[1]


@pytest.mark.parametrize('attack', ['origin', 'host', 'token', 'unicode-token', 'duplicate', 'unknown', 'invalid'])
def test_forged_or_invalid_saves_do_not_mutate(app, attack):
    path, request = app
    token = re.search('name="token" value="([^"]+)"', request()[1])[1]
    fields = dict(token=token, section='application', mode='saved', port='8082')
    kwargs = {}
    if attack == 'origin': kwargs['origin'] = 'https://evil.invalid'
    if attack == 'host': kwargs['host'] = 'evil.invalid'
    if attack == 'token': fields['token'] = 'wrong'
    if attack == 'unicode-token': fields['token'] = 'é'
    if attack == 'duplicate': fields = list(fields.items()) + [('port', '8083')]
    if attack == 'unknown': fields['api_key'] = 'secret'
    if attack == 'invalid': fields['port'] = '0'
    assert request('POST', '/settings', fields, **kwargs)[0] in {400, 403}
    assert not path.exists()


def test_key_is_never_rendered(app, monkeypatch):
    monkeypatch.setenv('RZ_MODEL_API_KEY', 'private-secret-value')
    body = app[1]()[1]
    assert 'Environment key: present' in body
    assert 'private-secret-value' not in body


def test_cli_uses_saved_connection_with_environment_precedence(tmp_path, monkeypatch):
    from scripts import local
    database = tmp_path / 'workspace.sqlite3'
    config.save(config.settings_path(database), with_proposer(model='saved-model'))
    monkeypatch.delenv('RZ_MODEL_ENDPOINT', raising=False)
    monkeypatch.delenv('RZ_MODEL', raising=False)
    monkeypatch.setenv('RZ_MODEL_API_KEY', 'environment-only-secret')
    monkeypatch.setattr('sys.argv', ['local', '--database', str(database), 'suggest-demo'])
    seen = []
    def inspect_endpoint(store, endpoint, cycle):
        seen.append((endpoint.url, endpoint.model, endpoint.api_key))
        return 'unreviewed'
    monkeypatch.setattr(local, 'suggest', inspect_endpoint)
    local.main()
    assert seen[-1] == ('http://localhost:11434/v1/chat/completions', 'saved-model', 'environment-only-secret')
    monkeypatch.setenv('RZ_MODEL', 'override-model')
    local.main()
    assert seen[-1][1] == 'override-model'
    assert 'environment-only-secret' not in config.settings_path(database).read_text()


def _token(request):
    return re.search('name="token" value="([^"]+)"', request()[1])[1]


def test_settings_renders_four_role_blocks(app):
    _, request = app
    body = request()[1]
    for role in ROLES:
        for part in ('format', 'endpoint', 'model', 'family'):
            assert f'name="{role}_{part}"' in body
    assert 'name="same_family_policy"' in body
    assert 'Same-family reviews' in body
    assert 'Wait for a person (recommended)' in body and 'Proceed automatically' in body
    assert 'A model reviewing reasoning from its own family shares its blind spots.' in body
    assert 'No reviewer configured: every suggestion waits for a person.' in body
    assert 'value="vertex"' not in body
    assert 'value="anthropic_messages"' in body and 'value="gemma"' in body


def test_no_reviewer_notice_only_when_reviewer_is_none(app):
    path, request = app
    value = copy.deepcopy(config.DEFAULTS)
    value['roles']['reviewer'] = proposer(model='gemma-4', family='gemma')
    config.save(path, value)
    body = request()[1]
    assert 'No reviewer configured' not in body
    assert 'value="gemma-4"' in body


def test_post_saves_roles_and_policy(app):
    path, request = app
    fields = model_form(_token(request), same_family_policy='proceed',
                        proposer_endpoint=LOCAL, proposer_model='gemini-x',
                        reviewer_format='anthropic_messages', reviewer_endpoint='https://example.invalid/v1/messages',
                        reviewer_model='claude-x', reviewer_family='claude')
    assert request('POST', '/settings', fields)[0] == 303
    saved = config.load(path)
    assert saved['same_family_policy'] == 'proceed'
    assert saved['roles']['proposer']['family'] == 'gemini'  # blank family is suggested from the model
    assert saved['roles']['reviewer'] == dict(format='anthropic_messages', endpoint='https://example.invalid/v1/messages',
                                              model='claude-x', family='claude')
    assert saved['roles']['summarizer'] is None and saved['roles']['guard'] is None


@pytest.mark.parametrize('change', [
    dict(proposer_format='vertex', proposer_endpoint=LOCAL, proposer_model='m'),
    dict(proposer_format='nope', proposer_endpoint=LOCAL, proposer_model='m'),
    dict(reviewer_endpoint='http://example.invalid/v1', reviewer_model='m'),
    dict(proposer_endpoint=LOCAL),  # endpoint without a model
    dict(proposer_family='bogus', proposer_endpoint=LOCAL, proposer_model='m'),
    dict(same_family_policy='skip')])
def test_post_rejects_invalid_role_fields(app, change):
    path, request = app
    config.save(path, with_proposer())
    before = path.read_bytes()
    assert request('POST', '/settings', model_form(_token(request), **change))[0] == 400
    assert path.read_bytes() == before


def test_post_rejects_http_hosted_reviewer(app):
    path, request = app
    fields = model_form(_token(request), reviewer_endpoint='http://example.invalid/v1/chat/completions', reviewer_model='m')
    assert request('POST', '/settings', fields)[0] == 400
    assert not path.exists()


def test_post_rejects_unknown_format(app):
    path, request = app
    fields = model_form(_token(request), guard_format='carrier_pigeon', guard_endpoint=LOCAL, guard_model='m')
    assert request('POST', '/settings', fields)[0] == 400
    assert not path.exists()


def test_post_rejects_21_fields(app):
    path, request = app
    fields = model_form(_token(request))
    assert len(fields) == 19
    fields.update(extra_a='1', extra_b='2')
    assert len(fields) == 21
    assert request('POST', '/settings', fields)[0] == 400
    assert not path.exists()


def test_settings_never_renders_key_values(app, monkeypatch):
    for name in ('RZ_PROPOSER_API_KEY', 'RZ_REVIEWER_API_KEY', 'RZ_SUMMARIZER_API_KEY', 'RZ_MODEL_API_KEY'):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv('RZ_GUARD_API_KEY', 'secret-x')
    body = app[1]()[1]
    assert 'secret-x' not in body
    assert body.count('Environment key: present') == 1
    assert body.count('Environment key: not set') == 3


def test_endpoint_model_and_family_are_escaped(app):
    path, request = app
    value = copy.deepcopy(config.DEFAULTS)
    value['roles']['proposer'] = proposer(model='m"><script>alert(1)</script>')
    config.save(path, value)
    body = request()[1]
    assert '<script>alert(1)' not in body
    assert '&lt;script&gt;' in body


def test_saving_makes_no_model_call(app):
    # The fixture already fails ModelEndpoint.propose, and the offline guard fails any socket.
    _, request = app
    fields = model_form(_token(request), reviewer_endpoint=LOCAL, reviewer_model='m')
    assert request('POST', '/settings', fields)[0] == 303
