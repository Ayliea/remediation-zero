# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Settings version 6: connections that jobs point at, the v5 migration, and where keys come from."""
import copy
import json
from dataclasses import replace

import pytest

from scripts import local
from tools import local_settings as config
from tools.local_secrets import SecretsFile, StoredKeyMissing, secrets_path
from tools.model_roles import ROLES, ModelRoles, key_source

OLLAMA = 'http://127.0.0.1:11434/v1/chat/completions'
ANTHROPIC = 'https://api.anthropic.com/v1/messages'
CUSTOM = 'https://guard.example.invalid/screen/v2/'  # a trailing slash is kept as typed


def v5_settings():
    value = {k: copy.deepcopy(v) for k, v in config.DEFAULTS.items() if k != 'connections'}
    value['version'] = 5
    value['roles'] = {
        'proposer': {'format': 'openai_chat', 'endpoint': OLLAMA, 'model': 'qwen2.5:7b', 'family': 'qwen',
                     'ca_file': '', 'timeout_seconds': 300},
        'reviewer': {'format': 'anthropic_messages', 'endpoint': ANTHROPIC, 'model': 'claude-test-1',
                     'family': 'claude', 'ca_file': '', 'timeout_seconds': 60},
        'summarizer': None,
        'guard': {'format': 'openai_chat', 'endpoint': CUSTOM, 'model': 'guard-test', 'family': 'other',
                  'ca_file': '/etc/rz/guard-ca.pem', 'timeout_seconds': 45}}
    return value


def write_v5(tmp_path):
    path = tmp_path / 'ws.settings.json'
    path.write_text(json.dumps(v5_settings()))
    return path


def connection(**change):
    return dict({'name': 'Anthropic', 'provider': 'anthropic', 'format': 'anthropic_messages',
                 'base_url': 'https://api.anthropic.com/v1', 'endpoint_style': 'base', 'ca_file': '',
                 'key_source': 'stored', 'last_test': None}, **change)


def v6_settings(**connection_change):
    value = copy.deepcopy(config.DEFAULTS)
    value['connections'] = {'conn-0123456789ab': connection(**connection_change)}
    value['roles']['reviewer'] = {'connection': 'conn-0123456789ab', 'model': 'claude-test-1', 'family': 'claude',
                                  'timeout_seconds': 60}
    return value


def by_name(settings):
    return {c['name']: (cid, c) for cid, c in settings['connections'].items()}


def test_v5_file_migrates_with_no_change_to_any_job(tmp_path):
    before = ModelRoles.from_settings(v5_settings(), {})
    loaded = config.load(write_v5(tmp_path))
    assert loaded['version'] == 6
    after = ModelRoles.from_settings(loaded, {})
    for role in ROLES:
        old, new = getattr(before, role), getattr(after, role)
        if old is None:
            assert new is None
            continue
        assert new.connection in loaded['connections']
        assert replace(new, connection='') == old
        assert new.as_settings() == old.as_settings()
    assert after.provenance() == before.provenance()
    guard = by_name(loaded)['Other (Screening)'][1]
    assert (guard['base_url'], guard['endpoint_style'], guard['ca_file']) == (CUSTOM, 'exact', '/etc/rz/guard-ca.pem')


@pytest.mark.parametrize('format, endpoint, model', [
    ('openai_chat', 'https://api.openai.com/v1/chat/completions', 'gpt-test'),
    ('openai_chat', 'https://a.example.invalid/v1/chat/completions/', 'm'),             # trailing slash
    ('openai_chat', 'https://a.example.invalid/v1//chat/completions', 'm'),             # double slash
    ('anthropic_messages', 'https://a.example.invalid/v1/messages/', 'claude-test-1'),
    ('gemini_api', 'https://generativelanguage.googleapis.com/v1beta/models/gemini-test:generateContent', 'gemini-test'),
    ('gemini_api', 'https://generativelanguage.googleapis.com/v1beta/models/other-model:generateContent', 'gemini-test'),
    ('openai_chat', 'https://a.example.invalid/custom/path', 'm'),
    ('openai_chat', 'http://localhost:8080/v1/chat/completions', 'm')])
def test_every_endpoint_shape_migrates_to_the_same_string(tmp_path, format, endpoint, model):
    value = v5_settings()
    value['roles'] = dict.fromkeys(ROLES)
    value['roles']['reviewer'] = {'format': format, 'endpoint': endpoint, 'model': model, 'family': 'other',
                                  'ca_file': '', 'timeout_seconds': 60}
    path = tmp_path / 'ws.settings.json'
    path.write_text(json.dumps(value))
    loaded = config.load(path)
    assert ModelRoles.from_settings(loaded, {}).reviewer.endpoint == endpoint
    assert ModelRoles.from_settings(value, {}).reviewer.endpoint == endpoint
    assert config.role_settings(loaded, 'reviewer')['endpoint'] == endpoint
    config.save(path, loaded)  # and it survives a save and a reload
    assert ModelRoles.from_settings(config.load(path), {}).reviewer.endpoint == endpoint


def test_migrated_names_and_key_sources(tmp_path):
    loaded = config.load(write_v5(tmp_path))
    names = by_name(loaded)
    assert set(names) == {'Ollama (Triage)', 'Anthropic (Review)', 'Other (Screening)'}
    ollama, anthropic = names['Ollama (Triage)'][1], names['Anthropic (Review)'][1]
    assert (ollama['provider'], ollama['key_source'], ollama['base_url'], ollama['endpoint_style']) == (
        'ollama', 'none', 'http://127.0.0.1:11434/v1', 'base')
    assert (anthropic['provider'], anthropic['key_source'], anthropic['base_url']) == (
        'anthropic', 'environment', 'https://api.anthropic.com/v1')
    assert names['Other (Screening)'][1]['key_source'] == 'environment'
    assert all(c['last_test'] is None for c in loaded['connections'].values())
    assert all(config.CONNECTION_ID_RE.fullmatch(cid) for cid in loaded['connections'])
    assert loaded['roles']['reviewer'] == {'connection': names['Anthropic (Review)'][0], 'model': 'claude-test-1',
                                           'family': 'claude', 'timeout_seconds': 60}


def test_two_loads_of_one_v5_file_are_equal_and_ids_never_collide(tmp_path):
    path = write_v5(tmp_path)
    first, second = config.load(path), config.load(path)
    assert first == second
    ids = [raw['connection'] for raw in first['roles'].values() if raw]
    assert len(ids) == len(set(ids)) == 3 and all(config.CONNECTION_ID_RE.fullmatch(cid) for cid in ids)


def test_save_writes_v6_and_validate_refuses_v5(tmp_path):
    path = write_v5(tmp_path)
    loaded = config.load(path)
    config.save(path, loaded)
    assert json.loads(path.read_text())['version'] == 6
    assert config.load(path) == loaded
    with pytest.raises(ValueError):
        config.validate(v5_settings())
    with pytest.raises(ValueError):
        config.save(tmp_path / 'other.json', v5_settings())


def test_role_must_point_at_an_existing_connection():
    value = v6_settings()
    config.validate(value)
    value['roles']['reviewer']['connection'] = 'conn-ba9876543210'
    with pytest.raises(ValueError):
        config.validate(value)


def test_connection_names_are_unique_ignoring_case():
    value = v6_settings()
    value['connections']['conn-111111111111'] = connection(name='ANTHROPIC')
    with pytest.raises(ValueError):
        config.validate(value)
    value['connections']['conn-111111111111'] = connection(name='Anthropic (work)')
    config.validate(value)


@pytest.mark.parametrize('change', [
    {'key': 'sk-test-1111'}, {'api_key': 'sk-test-1111'}, {'name': ''}, {'name': 'x' * 61},
    {'name': 'bad\nname'}, {'provider': 'nobody'}, {'format': 'vertex'}, {'endpoint_style': 'loose'},
    {'key_source': 'browser'}, {'base_url': 'http://example.invalid/v1'}, {'ca_file': 'relative.pem'},
    {'last_test': {'ok': True}},
    {'last_test': {'ok': True, 'error': '', 'seconds': 1.5, 'jobs': ['reviewer'], 'real_ts': 1.0, 'sim_ts': 1.0,
                   'detail': 'x'}},
    {'last_test': {'ok': False, 'error': 'it said sk-test-1111', 'seconds': 1.5, 'jobs': ['reviewer'],
                   'real_ts': 1.0, 'sim_ts': 1.0}},
    {'last_test': {'ok': True, 'error': '', 'seconds': 1.5, 'jobs': ['nobody'], 'real_ts': 1.0, 'sim_ts': 1.0}}])
def test_connection_fields_are_exact(change):
    with pytest.raises(ValueError):
        config.validate(v6_settings(**change))


def test_connection_ids_have_one_shape():
    value = v6_settings()
    value['connections']['anthropic'] = connection(name='Second')
    with pytest.raises(ValueError):
        config.validate(value)
    assert config.CONNECTION_ID_RE.fullmatch(config.new_connection_id())
    passed = v6_settings(last_test={'ok': False, 'error': 'TimeoutError', 'seconds': 2.0, 'jobs': ['reviewer'],
                                    'real_ts': 1787792678.1, 'sim_ts': 1787792678.1})
    assert config.validate(passed) == passed


def stored(tmp_path, key='sk-stored-1111'):
    secrets = SecretsFile(secrets_path(tmp_path / 'ws'))
    if key:
        secrets.put('conn-0123456789ab', key)
    return secrets


def test_environment_key_wins_over_a_stored_key(tmp_path):
    environ = {'RZ_REVIEWER_API_KEY': 'sk-env-2222'}
    roles = ModelRoles.from_settings(v6_settings(), environ, stored(tmp_path))
    assert roles.adapter('reviewer').api_key == 'sk-env-2222'
    assert key_source(v6_settings(), 'reviewer', environ) == 'environment'


def test_stored_key_is_used_when_no_environment_key(tmp_path):
    roles = ModelRoles.from_settings(v6_settings(), {}, stored(tmp_path))
    assert roles.adapter('reviewer').api_key == 'sk-stored-1111'
    assert key_source(v6_settings(), 'reviewer', {}) == 'stored'
    assert 'sk-stored' not in repr(roles)


def test_no_stored_key_is_read_unless_the_connection_says_stored(tmp_path):
    for source in ('environment', 'none'):
        roles = ModelRoles.from_settings(v6_settings(key_source=source), {}, stored(tmp_path))
        assert roles.adapter('reviewer').api_key is None
        # 'environment' only when the job's variable is set: without it the key is missing.
        assert key_source(v6_settings(key_source=source), 'reviewer', {}) == (
            'missing' if source == 'environment' else source)


def test_missing_stored_key_raises_stored_key_missing(tmp_path):
    with pytest.raises(StoredKeyMissing):
        ModelRoles.from_settings(v6_settings(), {}, stored(tmp_path, key=None)).adapter('reviewer')
    with pytest.raises(StoredKeyMissing):
        ModelRoles.from_settings(v6_settings(), {}).adapter('reviewer')


def test_an_endpoint_override_never_gets_the_stored_key(tmp_path):
    value = v6_settings()
    value['roles']['proposer'] = dict(value['roles'].pop('reviewer'))
    value['roles']['reviewer'] = None
    roles = ModelRoles.from_settings(value, {'RZ_MODEL_ENDPOINT': 'https://other.example.invalid/v1/messages'},
                                     stored(tmp_path))
    assert roles.proposer.connection == '' and roles.adapter('proposer').api_key is None


def test_load_roles_reads_the_workspace_key_file(tmp_path):
    database = tmp_path / 'ws'
    config.save(config.settings_path(database), v6_settings())
    stored(tmp_path)
    assert local.load_roles(database, {}).adapter('reviewer').api_key == 'sk-stored-1111'


def test_settings_set_model_reuses_or_creates_a_connection(tmp_path):
    path = write_v5(tmp_path)
    loaded = config.load(path)
    by_name(loaded)['Other (Screening)'][1]['ca_file'] = ''  # the form re-reads a CA file; this one is invented
    config.save(path, loaded)
    triage = by_name(loaded)['Ollama (Triage)'][0]
    local.settings_set(path, 'model', ['proposer.model=llama3.1:8b'])
    after = config.load(path)
    assert after['roles']['proposer']['connection'] == triage and after['roles']['proposer']['model'] == 'llama3.1:8b'
    assert after['connections'] == loaded['connections']
    # The same address for another job reuses the connection.
    local.settings_set(path, 'model', ['summarizer.endpoint=' + OLLAMA, 'summarizer.model=qwen2.5:7b'])
    after = config.load(path)
    assert after['roles']['summarizer']['connection'] == triage and len(after['connections']) == 3
    # A new address creates one, named as the migration names them.
    local.settings_set(path, 'model', ['summarizer.format=openai_chat', 'summarizer.endpoint=https://api.openai.com/v1/chat/completions',
                                       'summarizer.model=gpt-test'])
    after = config.load(path)
    cid, made = by_name(after)['OpenAI (Summaries)']
    assert after['roles']['summarizer']['connection'] == cid
    assert (made['provider'], made['base_url'], made['endpoint_style'], made['key_source']) == (
        'openai', 'https://api.openai.com/v1', 'base', 'environment')
    assert ModelRoles.from_settings(after, {}).summarizer.endpoint == 'https://api.openai.com/v1/chat/completions'
    # Clearing a job leaves its connection.
    local.settings_set(path, 'model', ['summarizer.endpoint=', 'summarizer.model='])
    after = config.load(path)
    assert after['roles']['summarizer'] is None and cid in after['connections']
    assert local.settings_form(after, 'model')['proposer_endpoint'] == OLLAMA


def test_page_form_saves_only_the_policy(tmp_path):
    value = v6_settings()
    saved = local.apply_settings_form(value, 'model', {'same_family_policy': 'proceed'})
    assert saved == dict(value, same_family_policy='proceed')
    with pytest.raises(ValueError):
        local.apply_settings_form(value, 'model', {'same_family_policy': 'wait', 'proposer_model': 'x'})


def test_settings_show_never_reads_the_secrets_file(tmp_path):
    path = config.settings_path(tmp_path / 'ws')
    config.save(path, v6_settings())
    stored(tmp_path)
    shown = local.settings_shown(path)
    assert 'sk-stored' not in json.dumps(shown) and '1111' not in json.dumps(shown)
    assert shown['connections']['conn-0123456789ab']['key_source'] == 'stored'
