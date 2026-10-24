# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
import io
import os
import re
from types import SimpleNamespace
from urllib.parse import urlencode
import pytest
from scripts.local import handler
from tools import local_settings as config
from tools.model_endpoint import ModelEndpoint


@pytest.mark.parametrize('change', [dict(port=True), dict(port=80), dict(port=65536), dict(mode='other'),
    dict(open_browser=1), dict(endpoint='http://example.invalid/v1', model='m'),
    dict(endpoint='https://user:secret@example.invalid/v1', model='m'),
    dict(endpoint='https://example.invalid:bad/v1', model='m'),
    dict(endpoint='https://example.invalid/\n', model='m'), dict(api_key='secret')])
def test_invalid_settings_never_replace_file(tmp_path, change):
    path = tmp_path / 'prefs.json'
    config.save(path, config.DEFAULTS)
    before = path.read_bytes()
    with pytest.raises(ValueError):
        config.save(path, dict(config.DEFAULTS, **change))
    assert path.read_bytes() == before


def test_atomic_preferences_and_private_permissions(tmp_path, monkeypatch):
    path = tmp_path / 'prefs.json'
    values = dict(config.DEFAULTS, endpoint='http://localhost:11434/v1/chat/completions', model='test', port=8082)
    config.save(path, values)
    assert config.load(path) == values
    if os.name != 'nt':
        assert path.stat().st_mode & 0o777 == 0o600
    monkeypatch.setattr(config.os, 'replace', lambda *args: (_ for _ in ()).throw(OSError()))
    with pytest.raises(OSError):
        config.save(path, config.DEFAULTS)
    assert config.load(path) == values
    assert list(tmp_path.iterdir()) == [path]


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
    assert config.load(path)['model'] == 'test'
    fields = dict(token=token, section='application', mode='saved', port='8082')
    assert request('POST', '/settings', fields)[0] == 303
    assert config.load(path)['open_browser'] is False
    assert config.load(path)['model'] == 'test'
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
    config.save(config.settings_path(database), dict(config.DEFAULTS,
        endpoint='http://localhost:11434/v1/chat/completions', model='saved-model'))
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
