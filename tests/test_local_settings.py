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
    fields = dict(token=token, section='model', endpoint='http://localhost:11434/v1/chat/completions', model='test')
    assert request('POST', '/settings', fields)[0] == 303
    assert config.load(path)['roles']['proposer']['model'] == 'test'
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
