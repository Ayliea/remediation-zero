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
    return dict(dict(format='openai_chat', endpoint=LOCAL, model='test', family='other', ca_file='', timeout_seconds=60), **change)


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
    assert loaded['version'] == 5
    assert loaded['roles']['proposer'] == dict(format='openai_chat', model='llama3.1', family='llama',
        endpoint='http://127.0.0.1:11434/v1/chat/completions', ca_file='', timeout_seconds=60)
    assert [loaded['roles'][r] for r in ('reviewer', 'summarizer', 'guard')] == [None] * 3
    assert loaded['same_family_policy'] == 'wait'
    assert (loaded['mode'], loaded['open_browser'], loaded['port']) == ('saved', False, 8083)
    config.save(path, loaded)
    assert json.loads(path.read_text())['version'] == 5


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
        fields.update({role + '_format': 'openai_chat', role + '_endpoint': '', role + '_model': '', role + '_family': '',
                       role + '_ca_file': '', role + '_timeout_seconds': ''})
    fields.update(given)
    return fields


@pytest.fixture
def app(tmp_path, monkeypatch, signed_in):
    monkeypatch.setattr(ModelEndpoint, 'propose', lambda *args: pytest.fail('Settings invoked model'))
    path = tmp_path / 'test.settings.json'
    cls = handler(SimpleNamespace(snapshot=lambda: {}), False, path, accounts=signed_in.accounts)
    def request(method='GET', route='/?view=settings', fields=None, origin='http://127.0.0.1:8081', host='127.0.0.1:8081'):
        obj = object.__new__(cls)
        obj.server = SimpleNamespace(server_port=8081)
        obj.client_address = ('127.0.0.1', 50000)
        obj.path = route
        raw = urlencode(fields or {}).encode()
        obj.headers = {'Host': host, 'Origin': origin, 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': str(len(raw)),
                       'Cookie': signed_in.cookie()}
        obj.rfile, obj.wfile = io.BytesIO(raw), io.BytesIO()
        status, headers = [], {}
        obj.send_response = status.append
        obj.send_header = lambda k, v: headers.update({k:v})
        obj.end_headers = lambda: None
        obj.send_error = lambda code, *args: (status.append(code), request.errors.append(args))
        getattr(obj, 'do_' + method)()
        return status[0], obj.wfile.getvalue().decode(), headers
    request.errors = []
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
    # suggest-demo is retired; the cycle command now builds the proposer the same way.
    monkeypatch.setattr('sys.argv', ['local', '--database', str(database), 'cycle', '--cycle', '1'])
    import tools.model_roles as model_roles
    monkeypatch.setattr(model_roles, 'build_adapter', lambda fmt, url, model, key, ca_file=None, timeout_seconds=None: SimpleNamespace(
        url=url, model=model, api_key=key))
    seen = []
    def inspect_endpoint(ws, cycle, *, roles):
        endpoint = roles.adapter('proposer')
        seen.append((endpoint.url, endpoint.model, endpoint.api_key))
        return {}
    monkeypatch.setattr(local, 'run_local_cycle', inspect_endpoint)
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
        for part in ('format', 'endpoint', 'model', 'family', 'ca_file', 'timeout_seconds'):
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
                                              model='claude-x', family='claude', ca_file='', timeout_seconds=60)
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


def test_post_rejects_extra_fields(app):
    path, request = app
    fields = model_form(_token(request))
    assert len(fields) == 27
    fields.update(extra_a='1', extra_b='2')
    assert len(fields) == 29
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


def test_field_limit_is_enforced_by_the_parse_not_the_field_set(app, monkeypatch):
    from urllib.parse import urlencode as encode
    from scripts import local
    path, request = app
    token = _token(request)
    valid = list(model_form(token).items())
    pairs = valid + valid[:41 - len(valid)]  # only valid field names, 41 pairs in all
    assert len(pairs) == 41 and {k for k, _ in pairs} == {k for k, _ in valid}
    seen = []
    real = local.parse_qs
    def spy(*args, **kwargs):
        seen.append(kwargs.get('max_num_fields'))
        try:
            return real(*args, **kwargs)
        except ValueError:
            seen.append('limit-raised')
            raise
    monkeypatch.setattr(local, 'parse_qs', spy)
    assert request('POST', '/settings', pairs)[0] == 400
    assert seen[-2:] == [40, 'limit-raised']
    assert not path.exists()


def test_endpoint_is_escaped_in_the_page(app):
    path, request = app
    value = copy.deepcopy(config.DEFAULTS)
    value['roles']['proposer'] = proposer()
    value['roles']['proposer']['endpoint'] = 'http://localhost:11434/v1/a"onfocus="x<b>'
    path.write_text(json.dumps(value))
    body = request()[1]
    assert 'a"onfocus="x<b>' not in body
    assert 'a&quot;onfocus=&quot;x&lt;b&gt;' in body


def test_proposer_key_hint_names_the_fallback(app):
    body = app[1]()[1]
    assert 'RZ_PROPOSER_API_KEY (or RZ_MODEL_API_KEY)' in body
    assert 'Set RZ_REVIEWER_API_KEY before' in body


# --- Ruling 2: the cycle interval ---------------------------------------------


def test_application_page_renders_the_interval_field(app):
    _, request = app
    body = request(route='/?view=settings&section=application')[1]
    assert 'name="cycle_interval_minutes"' in body
    assert 'min="0"' in body and 'max="1440"' in body
    assert 'Run a cycle automatically every N minutes (0 = off)' in body


def test_valid_interval_is_saved(app):
    path, request = app
    token = _token(request)
    fields = dict(token=token, section='application', mode='saved', port='8082',
                  cycle_interval_minutes='30')
    assert request('POST', '/settings', fields)[0] == 303
    assert config.load(path)['cycle_interval_minutes'] == 30
    assert 'value="30"' in request(route='/?view=settings&section=application')[1]
    for edge in ('0', '1440'):
        fields['cycle_interval_minutes'] = edge
        assert request('POST', '/settings', fields)[0] == 303
        assert config.load(path)['cycle_interval_minutes'] == int(edge)


def test_application_save_without_interval_keeps_it(app):
    path, request = app
    token = _token(request)
    with_interval = dict(token=token, section='application', mode='saved', port='8082',
                         cycle_interval_minutes='15')
    assert request('POST', '/settings', with_interval)[0] == 303
    without = dict(token=token, section='application', mode='demo', port='8082')
    assert request('POST', '/settings', without)[0] == 303
    assert config.load(path)['cycle_interval_minutes'] == 15
    assert config.load(path)['mode'] == 'demo'


@pytest.mark.parametrize('value', ['-1', '1441', '99999', '', ' 5', '5.0', '+5', '1e3',
                                   'five', '٥', '0x10'])
def test_invalid_interval_is_rejected_and_nothing_written(app, value):
    path, request = app
    token = _token(request)
    fields = dict(token=token, section='application', mode='saved', port='8082',
                  cycle_interval_minutes=value)
    assert request('POST', '/settings', fields)[0] == 400
    assert not path.exists()


def test_invalid_interval_leaves_a_saved_file_unchanged(app):
    path, request = app
    token = _token(request)
    good = dict(token=token, section='application', mode='saved', port='8082',
                cycle_interval_minutes='10')
    assert request('POST', '/settings', good)[0] == 303
    before = path.read_bytes()
    assert request('POST', '/settings', dict(good, cycle_interval_minutes='2000'))[0] == 400
    assert path.read_bytes() == before


# --- Scanner settings (v3) ------------------------------------------------------------------

TASK_1 = 'abcdef12-aaaa-4aaa-8aaa-aaaaaaaaaaa1'
TASK_2 = '22222222-2222-4222-8222-222222222222'
TASK_3 = '33333333-3333-4333-8333-333333333333'
SCANNER_DEFAULTS = {'transport': 'unix', 'socket_path': '', 'host': '', 'port': 9390, 'ca_file': '',
                    'task_ids': [], 'qod_floor': 70, 'auto_enrichment': False}


def with_scanner(**change):
    value = copy.deepcopy(config.DEFAULTS)
    value['scanner'] = dict(value['scanner'], **change)
    return value


def _v2_file(**change):
    v2 = {k: v for k, v in copy.deepcopy(config.DEFAULTS).items() if k not in {'scanner', 'listen_address', 'server_names', 'certificate'}}
    v2.update(version=2)
    v2.update(change)
    return v2


def test_v2_settings_upgrade_to_v5_with_scanner_defaults(tmp_path):
    path = tmp_path / 'prefs.json'
    v2 = _v2_file(port=8090, mode='saved')
    # v2 roles had no ca_file; the upgrade adds an empty one.
    v2['roles']['proposer'] = {k: v for k, v in proposer(model='kept').items() if k not in ('ca_file', 'timeout_seconds')}
    path.write_text(json.dumps(v2))
    loaded = config.load(path)
    assert loaded['version'] == 5
    assert loaded['roles']['proposer']['ca_file'] == ''
    assert loaded['scanner'] == SCANNER_DEFAULTS
    assert (loaded['port'], loaded['mode'], loaded['roles']['proposer']['model']) == (8090, 'saved', 'kept')
    # load() never writes: the file is still v2 until the next save, as for v1.
    assert json.loads(path.read_text())['version'] == 2
    config.save(path, loaded)
    on_disk = json.loads(path.read_text())
    assert on_disk['version'] == 5 and on_disk['scanner'] == SCANNER_DEFAULTS
    assert list(tmp_path.iterdir()) == [path]


def test_v1_settings_reach_v5(tmp_path):
    path = tmp_path / 'prefs.json'
    path.write_text(json.dumps({'endpoint': '', 'model': '', 'mode': 'demo', 'open_browser': True, 'port': 8081}))
    loaded = config.load(path)
    assert loaded['version'] == 5 and loaded['scanner'] == SCANNER_DEFAULTS


def test_v2_file_with_unknown_key_is_refused(tmp_path):
    path = tmp_path / 'prefs.json'
    path.write_text(json.dumps(_v2_file(api_key='x')))
    with pytest.raises(ValueError):
        config.load(path)


def test_v3_file_with_unknown_key_is_refused(tmp_path):
    path = tmp_path / 'prefs.json'
    path.write_text(json.dumps(dict(v4_settings(), version=3, api_key='x')))
    with pytest.raises(ValueError):
        config.load(path)


def test_scanner_defaults():
    assert config.DEFAULTS['version'] == 5
    assert config.DEFAULTS['scanner'] == SCANNER_DEFAULTS


def test_empty_task_list_is_valid_and_means_pull_nothing():
    value = config.validate(with_scanner(task_ids=[]))
    assert value['scanner']['task_ids'] == []


def test_valid_scanner_round_trips(tmp_path):
    path = tmp_path / 'prefs.json'
    value = with_scanner(transport='tls', host='gvm.example.invalid', port=9391, ca_file='/etc/ssl/gvm-ca.pem',
                         task_ids=[TASK_1, TASK_2], qod_floor=80, auto_enrichment=True)
    config.save(path, value)
    assert config.load(path) == value


@pytest.mark.parametrize('bad', ['not-a-uuid', TASK_1.upper(), TASK_1 + ' ', TASK_1[:-1], '', 5, None])
def test_bad_task_id_is_rejected(bad):
    with pytest.raises(ValueError):
        config.validate(with_scanner(task_ids=[bad]))


def test_duplicate_task_ids_are_rejected():
    with pytest.raises(ValueError):
        config.validate(with_scanner(task_ids=[TASK_1, TASK_1]))


@pytest.mark.parametrize('key', ['password', 'username', 'Password', 'USERNAME', 'token'])
def test_credentials_cannot_be_saved(key):
    value = with_scanner()
    value['scanner'][key] = 'hunter2'
    with pytest.raises(ValueError):
        config.validate(value)


def test_tls_requires_host():
    with pytest.raises(ValueError):
        config.validate(with_scanner(transport='tls', host=''))
    config.validate(with_scanner(transport='tls', host='203.0.113.7'))


@pytest.mark.parametrize('change', [
    dict(transport='http'), dict(transport='UNIX'), dict(transport=None),
    dict(port=0), dict(port=65536), dict(port=True), dict(port='9390'),
    dict(qod_floor=-1), dict(qod_floor=101), dict(qod_floor=True), dict(qod_floor=70.5),
    dict(auto_enrichment=1), dict(auto_enrichment='yes'),
    dict(socket_path='relative/gvmd.sock'), dict(ca_file='ca.pem'),
    dict(socket_path='/run/gvmd.sock\n'), dict(task_ids='abc'), dict(task_ids=None),
    dict(host='https://gvm.example.invalid'), dict(host='gvm.example.invalid/x'),
    dict(host='gvm example'), dict(host='gvm.example.invalid\n'), dict(host='gvm.example.invalid:9390')])
def test_invalid_scanner_values_are_rejected(change):
    with pytest.raises(ValueError):
        config.validate(with_scanner(**change))


@pytest.mark.parametrize('change', [
    dict(qod_floor=0), dict(qod_floor=100), dict(port=1), dict(port=65535),
    dict(socket_path='/run/gvmd/gvmd.sock'), dict(host='gvm.example.invalid'), dict(host='198.51.100.9'),
    dict(host='2001:db8::1')])
def test_valid_scanner_values_are_accepted(change):
    config.validate(with_scanner(**change))


def test_missing_scanner_field_is_rejected():
    value = with_scanner()
    del value['scanner']['qod_floor']
    with pytest.raises(ValueError):
        config.validate(value)


def test_gmp_target_unix_and_tls():
    unix = config.gmp_target(with_scanner(socket_path='/run/gvmd/gvmd.sock'))
    assert (unix.transport, unix.socket_path, unix.host, unix.ca_file, unix.timeout) == (
        'unix', '/run/gvmd/gvmd.sock', None, None, 30.0)
    tls = config.gmp_target(with_scanner(transport='tls', host='gvm.example.invalid', port=9391,
                                         ca_file='/etc/ssl/ca.pem'), timeout=5.0)
    assert (tls.transport, tls.host, tls.port, tls.ca_file, tls.timeout, tls.socket_path) == (
        'tls', 'gvm.example.invalid', 9391, '/etc/ssl/ca.pem', 5.0, None)


def test_gmp_target_refuses_an_unconfigured_connection():
    with pytest.raises(ValueError):
        config.gmp_target(with_scanner())  # unix with no socket path


# --- the served Scanner section ---------------------------------------------------------------

USER_VAR, PASS_VAR = 'RZ_GREENBONE_USERNAME', 'RZ_GREENBONE_PASSWORD'
SECRET = 'synthetic-greenbone-password'


def scanner_form(token, **given):
    fields = {'token': token, 'section': 'scanner', 'transport': 'unix', 'socket_path': '/run/gvmd/gvmd.sock',
              'host': '', 'port': '9390', 'ca_file': '', 'task_ids': '', 'qod_floor': '70'}
    fields.update(given)
    return fields


class FakeClient:
    """Stands in for GmpClient: records its target, never opens a socket."""
    instances = []
    tasks = []
    error = None

    def __init__(self, target, username, password, total_timeout=None):
        self.target, self.username, self.password, self.total_timeout = target, username, password, total_timeout
        self.skipped_tasks = 0
        FakeClient.instances.append(self)

    def __enter__(self):
        if FakeClient.error:
            raise FakeClient.error
        return self

    def __exit__(self, *exc):
        return None

    def list_tasks(self):
        return list(FakeClient.tasks)


@pytest.fixture
def gmp(app, monkeypatch):
    from scripts import local
    FakeClient.instances, FakeClient.error = [], None
    FakeClient.tasks = [{'task_id': TASK_1, 'name': 'Weekly LAN'}, {'task_id': TASK_2, 'name': 'DMZ <b>'}]
    monkeypatch.setattr(local, 'GmpClient', FakeClient)
    monkeypatch.setenv(USER_VAR, 'reader')
    monkeypatch.setenv(PASS_VAR, SECRET)
    return app


def scanner_page(request):
    return request(route='/?view=settings&section=scanner')


def scanner_test_page(request):
    return request('POST', '/settings', dict(token=_token(request), section='scanner_test'))


def _task_inputs(body):
    return re.findall(r'<input[^>]*name="task_ids"[^>]*>', body)


def test_scanner_section_renders_and_saves(app, monkeypatch):
    monkeypatch.delenv(USER_VAR, raising=False)
    monkeypatch.delenv(PASS_VAR, raising=False)
    path, request = app
    status, body, _ = scanner_page(request)
    assert status == 200 and '>Scanner</a>' in body
    for name in ('transport', 'socket_path', 'host', 'port', 'ca_file', 'task_ids', 'qod_floor', 'auto_enrichment'):
        assert f'name="{name}"' in body
    assert 'name="username"' not in body.lower() and 'name="password"' not in body.lower()
    assert 'RZ_GREENBONE_USERNAME' in body and 'RZ_GREENBONE_PASSWORD' in body
    assert re.search(r'<input[^>]*name="auto_enrichment"(?![^>]*checked)[^>]*>', body)
    token = re.search('name="token" value="([^"]+)"', body)[1]
    fields = scanner_form(token, transport='tls', host='gvm.example.invalid', port='9391', ca_file='/etc/ssl/ca.pem',
                          task_ids=f'{TASK_1.upper()}\n\n{TASK_2}\r\n{TASK_1}\n', qod_floor='80', auto_enrichment='yes')
    status, _, headers = request('POST', '/settings', fields)
    assert status == 303 and headers['Location'] == '/?view=settings&section=scanner&saved=1'
    saved = config.load(path)['scanner']
    assert saved == {'transport': 'tls', 'socket_path': '/run/gvmd/gvmd.sock', 'host': 'gvm.example.invalid',
                     'port': 9391, 'ca_file': '/etc/ssl/ca.pem', 'task_ids': [TASK_1, TASK_2],
                     'qod_floor': 80, 'auto_enrichment': True}
    body = scanner_page(request)[1]
    assert 'value="gvm.example.invalid"' in body and 'value="80"' in body and TASK_2 in body
    # Saving without the checkbox turns auto-enrichment off; other sections are untouched.
    assert request('POST', '/settings', scanner_form(token))[0] == 303
    after = config.load(path)
    assert after['scanner']['auto_enrichment'] is False and after['scanner']['task_ids'] == []
    assert after['roles'] == config.DEFAULTS['roles']


def test_unset_credentials_name_both_variables_and_make_no_connection(app, monkeypatch):
    from scripts import local
    monkeypatch.delenv(USER_VAR, raising=False)
    monkeypatch.delenv(PASS_VAR, raising=False)
    monkeypatch.setattr(local, 'GmpClient', lambda *a: pytest.fail('connected without credentials'))
    path, request = app
    config.save(path, with_scanner(socket_path='/run/gvmd/gvmd.sock', task_ids=[TASK_1]))
    body = scanner_page(request)[1]
    assert 'Set RZ_GREENBONE_USERNAME and RZ_GREENBONE_PASSWORD' in body
    assert TASK_1 in body  # task IDs can still be typed and kept by hand
    token = re.search('name="token" value="([^"]+)"', body)[1]
    test = request('POST', '/settings', dict(token=token, section='scanner_test'))
    assert test[0] == 200 and 'RZ_GREENBONE_USERNAME' in test[1]


def test_scanner_section_never_shows_the_password(gmp):
    path, request = gmp
    config.save(path, with_scanner(socket_path='/run/gvmd/gvmd.sock'))
    for route in ('/?view=settings&section=scanner', '/?view=settings&section=model'):
        assert SECRET not in request(route=route)[1]
    token = _token(request)
    assert SECRET not in request('POST', '/settings', dict(token=token, section='scanner_test'))[1]
    FakeClient.error = RuntimeError(f'boom {SECRET}')
    assert SECRET not in scanner_test_page(request)[1]
    assert SECRET not in path.read_text()


def test_task_list_is_read_with_a_short_timeout_and_names_are_escaped(gmp):
    path, request = gmp
    config.save(path, with_scanner(socket_path='/run/gvmd/gvmd.sock', task_ids=[TASK_2]))
    body = scanner_test_page(request)[1]
    assert len(FakeClient.instances) == 1
    client = FakeClient.instances[0]
    assert client.target.timeout == 5.0 and (client.username, client.password) == ('reader', SECRET)
    assert 'Weekly LAN' in body and 'DMZ &lt;b&gt;' in body and 'DMZ <b>' not in body
    ticks = _task_inputs(body)
    assert any(TASK_2 in t and 'checked' in t for t in ticks)
    assert any(TASK_1 in t and 'checked' not in t for t in ticks)


def test_ticked_and_typed_tasks_are_united_and_deduplicated(gmp):
    path, request = gmp
    config.save(path, with_scanner(socket_path='/run/gvmd/gvmd.sock'))
    token = _token(request)
    pairs = list(scanner_form(token, task_ids=f'{TASK_3}\n{TASK_1}').items()) + [('task_ids', TASK_1), ('task_ids', TASK_2)]
    assert request('POST', '/settings', pairs)[0] == 303
    assert config.load(path)['scanner']['task_ids'] == [TASK_3, TASK_1, TASK_2]


def test_a_chosen_task_greenbone_no_longer_lists_stays_chosen(gmp):
    path, request = gmp
    config.save(path, with_scanner(socket_path='/run/gvmd/gvmd.sock', task_ids=[TASK_3]))
    body = scanner_test_page(request)[1]
    assert 'not found on Greenbone' in body
    assert any(TASK_3 in t and 'checked' in t for t in _task_inputs(body))


def test_unreachable_greenbone_shows_only_the_error_class(gmp):
    path, request = gmp
    config.save(path, with_scanner(socket_path='/run/gvmd/gvmd.sock', task_ids=[TASK_1]))
    from tools.gmp import GmpError
    FakeClient.error = GmpError('server said: ' + SECRET + ' <script>alert(1)</script>')
    status, body, _ = scanner_test_page(request)
    assert status == 200
    assert 'Could not reach Greenbone: GmpError' in body
    assert 'server said' not in body and 'alert(1)' not in body
    assert TASK_1 in body and 'name="task_ids"' in body  # still usable by hand


def test_test_connection_uses_saved_settings_and_never_saves(gmp):
    path, request = gmp
    config.save(path, with_scanner(socket_path='/run/gvmd/gvmd.sock'))
    before = path.read_bytes()
    FakeClient.instances.clear()
    token = _token(request)
    status, body, _ = request('POST', '/settings', dict(token=token, section='scanner_test'))
    assert status == 200 and path.read_bytes() == before
    assert 'Connected: yes' in body and 'Signed in: yes' in body and 'Tasks listed: yes (2)' in body
    assert 'saved settings' in body
    assert FakeClient.instances[0].target.timeout == 5.0 and FakeClient.instances[0].total_timeout == 5.0
    assert FakeClient.instances[0].target.socket_path == '/run/gvmd/gvmd.sock'
    FakeClient.error = RuntimeError('zq-secret-text')
    body = request('POST', '/settings', dict(token=token, section='scanner_test'))[1]
    assert 'Could not reach Greenbone: RuntimeError' in body and 'zq-secret-text' not in body
    assert path.read_bytes() == before


def test_test_connection_needs_the_csrf_token_and_origin(gmp):
    path, request = gmp
    assert request('POST', '/settings', dict(token='wrong', section='scanner_test'))[0] == 403
    token = _token(request)
    assert request('POST', '/settings', dict(token=token, section='scanner_test'), origin='https://evil.invalid')[0] == 403
    assert not FakeClient.instances


@pytest.mark.parametrize('key', ['username', 'password', 'Username', 'PASSWORD'])
def test_posting_a_credential_is_refused_and_saves_nothing(gmp, key):
    path, request = gmp
    fields = scanner_form(_token(request), **{key: 'hunter2'})
    assert request('POST', '/settings', fields)[0] == 400
    assert not path.exists()


@pytest.mark.parametrize('change', [
    dict(task_ids='nope'), dict(port='0'), dict(port='99999'), dict(port='9 '), dict(port='٣'),
    dict(qod_floor='101'), dict(qod_floor='-1'), dict(qod_floor='x'), dict(transport='tls', host=''),
    dict(transport='http'), dict(socket_path='relative.sock'), dict(ca_file='ca.pem'),
    dict(host='https://gvm.example.invalid'), dict(auto_enrichment='on')])
def test_invalid_scanner_posts_are_refused_and_save_nothing(gmp, change):
    path, request = gmp
    assert request('POST', '/settings', scanner_form(_token(request), **change))[0] == 400
    assert not path.exists()


def test_scanner_post_requires_exactly_the_scanner_fields(gmp):
    path, request = gmp
    token = _token(request)
    missing = scanner_form(token)
    del missing['qod_floor']
    assert request('POST', '/settings', missing)[0] == 400
    assert request('POST', '/settings', scanner_form(token, extra='1'))[0] == 400
    assert not path.exists()


def test_other_sections_still_reject_repeated_fields(app):
    path, request = app
    token = _token(request)
    pairs = [('token', token), ('section', 'application'), ('mode', 'saved'), ('port', '8082'), ('task_ids', TASK_1)]
    assert request('POST', '/settings', pairs)[0] == 400
    assert not path.exists()


@pytest.fixture
def fake_gvmd(tmp_path_factory, fake_endpoints):
    import socket as socket_module
    from tests.test_gmp import FakeGvmd, default_handler
    sock_dir = tmp_path_factory.mktemp('g')
    sock_path = str(sock_dir / 'gvmd.sock')
    listener = socket_module.socket(socket_module.AF_UNIX, socket_module.SOCK_STREAM)
    listener.bind(sock_path)
    listener.listen(4)
    fake_endpoints.unix(sock_path)
    server = FakeGvmd(listener, default_handler())
    yield sock_path, server
    server.close()


def test_task_list_from_a_real_fake_gvmd_over_a_unix_socket(app, fake_gvmd, monkeypatch):
    from tests.test_gmp import TASK_A, TASK_B, USER, PASSWORD
    sock_path, server = fake_gvmd
    monkeypatch.setenv(USER_VAR, USER)
    monkeypatch.setenv(PASS_VAR, PASSWORD)
    path, request = app
    config.save(path, with_scanner(socket_path=sock_path))
    body = scanner_test_page(request)[1]
    assert 'Weekly LAN' in body and 'DMZ' in body and TASK_A in body and TASK_B in body
    assert PASSWORD not in body
    sent = b''.join(server.requests)
    assert b'get_tasks' in sent and b'authenticate' in sent


# --- review fixes: no GET contacts Greenbone, bounded sessions, limits --------------------------

def test_get_scanner_section_never_contacts_greenbone(app, monkeypatch):
    from scripts import local
    monkeypatch.setenv(USER_VAR, 'reader')
    monkeypatch.setenv(PASS_VAR, SECRET)
    monkeypatch.setattr(local, 'GmpClient', lambda *a, **k: pytest.fail('a GET contacted Greenbone'))
    path, request = app
    config.save(path, with_scanner(socket_path='/run/gvmd/gvmd.sock', task_ids=[TASK_1]))
    for route in ('/?view=settings&section=scanner', '/?view=settings&section=scanner&saved=1', '/?view=settings'):
        status, body, _ = request(route=route)
        assert status == 200
    body = scanner_page(request)[1]
    assert TASK_1 in body  # saved chosen IDs are shown from the settings file
    assert 'Test connection and list tasks' in body
    assert 'name="section" value="scanner_test"' in body


def test_scanner_test_lists_tasks_as_tickboxes(gmp):
    path, request = gmp
    config.save(path, with_scanner(socket_path='/run/gvmd/gvmd.sock', task_ids=[TASK_2, TASK_3]))
    status, body, _ = scanner_test_page(request)
    assert status == 200
    assert 'Connected: yes' in body and 'Signed in: yes' in body and 'Tasks listed: yes' in body
    ticks = _task_inputs(body)
    assert any(TASK_1 in t and 'checked' not in t for t in ticks)
    assert any(TASK_2 in t and 'checked' in t for t in ticks)
    assert any(TASK_3 in t and 'checked' in t for t in ticks)
    assert 'not found on Greenbone' in body
    assert 'name="section" value="scanner"' in body  # the save form is on the result page
    assert config.load(path)['scanner']['task_ids'] == [TASK_2, TASK_3]


def test_wrong_credentials_are_signed_in_no(gmp):
    from tools.gmp import GmpAuthError
    path, request = gmp
    config.save(path, with_scanner(socket_path='/run/gvmd/gvmd.sock'))
    FakeClient.error = GmpAuthError('authenticate failed: ' + SECRET)
    body = scanner_test_page(request)[1]
    assert 'Connected: yes' in body and 'Signed in: no' in body and 'Tasks listed: no' in body
    assert 'Could not reach Greenbone' not in body and SECRET not in body


@pytest.mark.parametrize('error', [OSError('zq-secret-text'), __import__('tools.gmp', fromlist=['GmpError']).GmpError('zq-secret-text')])
def test_other_failures_are_could_not_reach_with_the_class(gmp, error):
    path, request = gmp
    config.save(path, with_scanner(socket_path='/run/gvmd/gvmd.sock'))
    FakeClient.error = error
    body = scanner_test_page(request)[1]
    assert f'Could not reach Greenbone: {type(error).__name__}' in body
    assert 'zq-secret-text' not in body and 'Signed in: no' in body


def test_more_than_500_chosen_tasks_are_refused(gmp):
    path, request = gmp
    token = _token(request)

    def ids(n):
        return [f'{i:08x}-0000-4000-8000-000000000000' for i in range(n)]
    pairs = list(scanner_form(token).items()) + [('task_ids', i) for i in ids(501)]
    assert request('POST', '/settings', pairs)[0] == 400
    assert not path.exists()
    pairs = list(scanner_form(token, task_ids='\n'.join(ids(250))).items()) + [('task_ids', i) for i in ids(500)[250:]]
    assert request('POST', '/settings', pairs)[0] == 303  # 500 is allowed, and exceeds the old 8 KiB body cap
    assert len(config.load(path)['scanner']['task_ids']) == 500


def test_the_refusal_message_is_explicit(gmp):
    path, request = gmp
    pairs = list(scanner_form(_token(request)).items()) + [('task_ids', f'{i:08x}-0000-4000-8000-000000000000') for i in range(501)]
    assert request('POST', '/settings', pairs)[0] == 400
    assert 'At most 500 scan tasks can be chosen.' in request.errors[-1][0]
    assert not path.exists()


def test_large_unchosen_list_is_truncated_with_a_note(gmp):
    path, request = gmp
    config.save(path, with_scanner(socket_path='/run/gvmd/gvmd.sock', task_ids=[TASK_1]))
    FakeClient.tasks = [{'task_id': f'{i:08x}-0000-4000-8000-000000000000', 'name': f'Task {i}'} for i in range(150)] \
        + [{'task_id': TASK_1, 'name': 'Chosen one'}]
    body = scanner_test_page(request)[1]
    assert 'Showing 101 of 151 tasks.' in body
    assert any(TASK_1 in t and 'checked' in t for t in _task_inputs(body))
    assert len([t for t in _task_inputs(body) if 'type="checkbox"' in t]) == 101


def test_an_account_with_no_tasks_says_so(gmp):
    path, request = gmp
    config.save(path, with_scanner(socket_path='/run/gvmd/gvmd.sock'))
    FakeClient.tasks = []
    body = scanner_test_page(request)[1]
    assert 'This account can see no tasks.' in body and 'add it as an observer' in body
    assert 'Tasks listed: yes (0)' in body


def test_a_trickling_gvmd_cannot_hold_the_settings_page(app, tmp_path_factory, fake_endpoints, monkeypatch):
    import socket as socket_module
    import time
    from tests.test_gmp import FakeGvmd, OK_AUTH, USER, PASSWORD

    def trickle(conn):
        for byte in OK_AUTH:
            conn.sendall(bytes([byte]))
            time.sleep(0.4)  # slow enough that the whole reply takes about 20 s
        return None

    def handler_fn(tag, raw):
        return [trickle]
    sock_path = str(tmp_path_factory.mktemp('g') / 'gvmd.sock')
    listener = socket_module.socket(socket_module.AF_UNIX, socket_module.SOCK_STREAM)
    listener.bind(sock_path)
    listener.listen(4)
    fake_endpoints.unix(sock_path)
    server = FakeGvmd(listener, handler_fn)
    try:
        monkeypatch.setenv(USER_VAR, USER)
        monkeypatch.setenv(PASS_VAR, PASSWORD)
        path, request = app
        config.save(path, with_scanner(socket_path=sock_path))
        started = time.monotonic()
        status, body, _ = scanner_test_page(request)
        assert time.monotonic() - started < 7
        assert status == 200 and 'Could not reach Greenbone: GmpError' in body
    finally:
        server.close()


# --- Listening and certificate settings (v5) --------------------------------------------------

def v4_settings():
    old = copy.deepcopy(config.DEFAULTS)
    for key in ('listen_address', 'server_names', 'certificate'):
        del old[key]
    return dict(old, version=4)


def test_v4_settings_upgrade_to_v5_with_loopback_defaults(tmp_path):
    path = tmp_path / 'prefs.json'
    old = dict(v4_settings(), port=8090)
    path.write_text(json.dumps(old))
    loaded = config.load(path)
    assert loaded['version'] == 5 and loaded['port'] == 8090
    assert loaded['listen_address'] == '127.0.0.1' and loaded['server_names'] == []
    assert loaded['certificate'] == {'mode': 'self-signed', 'cert_file': '', 'key_file': ''}
    assert config.exposed(loaded) is False
    assert json.loads(path.read_text())['version'] == 4  # in memory only until the next save
    old['extra'] = 1
    path.write_text(json.dumps(old))
    with pytest.raises(ValueError):
        config.load(path)


@pytest.mark.parametrize('address', ['localhost', 'example.test', '', '1.2.3', '127.0.0.1:80', 5, None, '0.0.0.0/0'])
def test_listen_address_must_be_an_ip_literal(address):
    with pytest.raises(ValueError):
        config.validate(dict(config.DEFAULTS, listen_address=address))


@pytest.mark.parametrize('address, exposed', [('127.0.0.1', False), ('::1', False), ('0.0.0.0', True),
                                              ('::', True), ('192.0.2.7', True)])
def test_exposed_is_true_for_any_non_loopback_address(address, exposed):
    value = config.validate(dict(config.DEFAULTS, listen_address=address))
    assert config.exposed(value) is exposed


def test_own_certificate_needs_two_absolute_paths():
    def with_cert(**change):
        return dict(config.DEFAULTS, certificate=dict(config.DEFAULTS['certificate'], **change))
    config.validate(with_cert(mode='own', cert_file='/etc/ssl/c.pem', key_file='/etc/ssl/k.pem'))
    for bad in (dict(mode='own'), dict(mode='own', cert_file='/etc/ssl/c.pem'),
                dict(mode='own', cert_file='c.pem', key_file='/etc/ssl/k.pem'),
                dict(mode='own', cert_file='/etc/ssl/c.pem', key_file='k.pem'), dict(mode='other')):
        with pytest.raises(ValueError):
            config.validate(with_cert(**bad))
    with pytest.raises(ValueError):
        config.validate(dict(config.DEFAULTS, certificate={'mode': 'self-signed'}))


def test_server_names_are_lowercased_unique_and_capped():
    assert config.parse_server_names('RZ.Example.test, 192.0.2.10  rz.example.test\n::1') == [
        'rz.example.test', '192.0.2.10', '::1']
    assert config.parse_server_names('') == []
    for bad in ('bad name!', 'a_b.test', '-x.test', 'https://x.test', ','.join(f'h{i}.test' for i in range(21))):
        with pytest.raises(ValueError):
            config.parse_server_names(bad)
    with pytest.raises(ValueError):
        config.validate(dict(config.DEFAULTS, server_names=['Upper.test']))
    with pytest.raises(ValueError):
        config.validate(dict(config.DEFAULTS, server_names=['a.test', 'a.test']))


def test_check_bindable_leaves_nothing_open_and_refuses_an_address_not_on_this_machine():
    config.check_bindable('127.0.0.1', 0)
    with pytest.raises(ValueError):
        config.check_bindable('192.0.2.1', 0)  # TEST-NET-1: not assigned to this machine


def test_settings_page_says_restart_required(app):
    path, request = app
    status, body, _ = request(route='/?view=settings&section=application')
    assert status == 200
    assert 'Listen address, names and certificate take effect when Remediation Zero restarts.' in body
    for name in ('listen_address', 'server_names', 'certificate_mode', 'cert_file', 'key_file'):
        assert f'name="{name}"' in body


def test_application_form_saves_the_listening_fields_and_refuses_bad_ones(app):
    path, request = app
    token = re.search('name="token" value="([^"]+)"', request()[1])[1]
    base = dict(token=token, section='application', mode='saved', port='8082')
    good = dict(base, listen_address='0.0.0.0', server_names='RZ.example.test 192.0.2.10',
                certificate_mode='self-signed', cert_file='', key_file='')
    assert request('POST', '/settings', good)[0] == 303
    saved = config.load(path)
    assert saved['listen_address'] == '0.0.0.0' and saved['server_names'] == ['rz.example.test', '192.0.2.10']
    before = path.read_text()
    for bad in (dict(base, listen_address='not-an-ip'), dict(base, server_names='bad name!'),
                dict(base, certificate_mode='own', cert_file='/nonexistent/c.pem', key_file='/nonexistent/k.pem'),
                dict(base, listen_address='192.0.2.1')):
        request.errors.clear()
        assert request('POST', '/settings', bad)[0] == 400
        assert path.read_text() == before
    assert request.errors[-1][0].endswith('Nothing was saved.')


def test_ipv6_scope_ids_are_refused():
    with pytest.raises(ValueError):
        config.normalize_server_name('fe80::1%eth0')
    with pytest.raises(ValueError):
        config.parse_server_names('::1%x,dns:evil.test')
    with pytest.raises(ValueError):
        config.validate(dict(config.DEFAULTS, listen_address='fe80::1%eth0'))
    with pytest.raises(ValueError):
        config.validate(dict(config.DEFAULTS, server_names=['fe80::1%eth0']))


def test_a_hand_edited_name_with_a_comma_is_refused(tmp_path):
    for bad in ('a.test,DNS:evil.test', 'a.test evil.test', '::1%x,dns:evil.test', 'a.test\n'):
        with pytest.raises(ValueError):
            config.validate(dict(config.DEFAULTS, server_names=[bad]))
    path = tmp_path / 'prefs.json'
    path.write_text(json.dumps(dict(config.DEFAULTS, server_names=['a.test,DNS:evil.test'])))
    with pytest.raises(ValueError):
        config.load(path)
