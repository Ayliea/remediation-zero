# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""The `connection` commands (scripts/local_connection_cli.py, scripts/local.py).

Run in-process through scripts.local.main. The one network seam, connections.test_jobs, is
replaced; getpass is replaced so no terminal is needed. Synthetic data only: `.invalid` hosts,
invented keys."""
import getpass
import json

import pytest

from scripts import local, local_connections
from tests.signed_in import OWNER, TECH, site
from tools import connections, local_settings
from tools.account_store import AccountStore
from tools.local_layout import Workspace
from tools.local_secrets import SecretsFile, secrets_path

KEY = 'sk-sweep-QX7Z9'
NEW_KEY = 'sk-test-brandnewkey0042'
BASE = 'https://api.example.invalid/v1'


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch):
    for name in ('RZ_MODEL', 'RZ_MODEL_ENDPOINT', 'RZ_MODEL_API_KEY', 'RZ_PROPOSER_API_KEY',
                 'RZ_REVIEWER_API_KEY', 'RZ_SUMMARIZER_API_KEY', 'RZ_GUARD_API_KEY', 'MY_KEY'):
        monkeypatch.delenv(name, raising=False)


def cli(capsys, database, *argv):
    try:
        local.main(['--database', str(database), *argv])
        code = 0
    except SystemExit as exit_:
        code = exit_.code if isinstance(exit_.code, int) else (0 if exit_.code is None else 1)
    out, err = capsys.readouterr()
    return code, out, err


@pytest.fixture
def db(tmp_path):
    root = tmp_path / 'w'
    Workspace(root).init()
    return root


@pytest.fixture
def people(db, tmp_path_factory):
    return site(db, tmp_path_factory.getbasetemp())


@pytest.fixture
def tester(monkeypatch):
    calls = []

    def fake(roles, jobs):
        calls.append({'jobs': list(jobs), 'keys': {r: roles.secrets.get(getattr(roles, r).connection)
                                                    for r in jobs if roles.secrets}})
        return fake.result or connections.TestResult(True, None, '', 1.25)

    fake.result = None
    fake.calls = calls
    monkeypatch.setattr(connections, 'test_jobs', fake)
    return fake


@pytest.fixture
def typed(monkeypatch):
    """getpass answers; `typed.prompts` is what it was asked."""
    prompts = []
    answers = [KEY]

    def fake(prompt=''):
        prompts.append(prompt)
        return answers[0]

    monkeypatch.setattr(getpass, 'getpass', fake)
    fake.prompts, fake.answers = prompts, answers
    return fake


def settings(db):
    return local_settings.load(local_settings.settings_path(db))


def events(db):
    store = AccountStore(Workspace(db).accounts_path())
    return [dict(r) for r in store.events(1000) if r['event'].startswith('connection_')]


def add(capsys, db, *extra, who=OWNER):
    return cli(capsys, db, 'connection', 'add', 'openai', '--endpoint', BASE, '--jobs', 'review,summaries',
               '--model', 'gpt-x', '--as', who, *extra)


# --- add ---------------------------------------------------------------------------


def test_add_tests_then_saves_the_connection_its_key_and_an_audit_event(db, people, capsys, tester, typed):
    code, out, err = add(capsys, db)
    assert code == 0 and out.strip() == 'OpenAI is connected. It now does Review and Summaries.'
    assert typed.prompts == ['API key (not shown): ']
    saved = settings(db)
    (conn_id, conn), = saved['connections'].items()
    assert conn['name'] == 'OpenAI' and conn['key_source'] == 'stored' and conn['last_test']['ok'] is True
    assert saved['roles']['reviewer']['connection'] == conn_id and saved['roles']['summarizer']['model'] == 'gpt-x'
    assert SecretsFile(secrets_path(db)).get(conn_id) == KEY
    assert tester.calls[0]['jobs'] == ['reviewer', 'summarizer']
    assert tester.calls[0]['keys']['reviewer'] == KEY        # tested with the typed key before it was stored
    (event,) = events(db)
    assert event['event'] == 'connection_added' and event['via'] == 'command_line'
    assert json.loads(event['detail']) == {'connection': 'OpenAI', 'jobs': ['reviewer', 'summarizer']}


def test_no_key_flag_exists_and_a_mistyped_key_is_never_echoed(db, people, capsys, tester, typed):
    for flag in (['--key', KEY], [f'--key={KEY}'], ['--api-key', KEY], [KEY]):
        code, out, err = add(capsys, db, *flag)
        assert code == 2 and KEY not in out + err and 'Unrecognised or invalid option' in err
        assert settings(db)['connections'] == {}
    for argv in (('connection', 'add', KEY, '--jobs', 'review', '--model', 'm', '--as', OWNER),
                 ('connection', 'add', 'openai', '--jobs', 'review', '--model', 'm', '--timeout', KEY,
                  '--as', OWNER),
                 ('connection', KEY)):
        code, out, err = cli(capsys, db, *argv)
        assert code == 2 and KEY not in out + err
    code, out, err = add(capsys, db, '--key-env', KEY)       # a key typed where a name belongs
    assert code == 1 and KEY not in out + err and typed.prompts == []


def test_the_key_never_reaches_output_list_settings_or_audit(db, people, capsys, tester, typed):
    code, out, err = add(capsys, db)
    assert code == 0
    code, listed, err2 = cli(capsys, db, 'connection', 'list')
    shown = cli(capsys, db, 'settings', 'show')[1]
    for text in (out, err, listed, err2, shown, json.dumps(events(db), default=str)):
        assert KEY not in text
    assert 'sk-sweep' not in listed


def test_the_key_can_come_from_a_named_environment_variable(db, people, capsys, tester, typed, monkeypatch):
    monkeypatch.setenv('MY_KEY', NEW_KEY)
    code, out, err = add(capsys, db, '--key-env', 'MY_KEY')
    assert code == 0 and typed.prompts == []
    (conn_id,) = settings(db)['connections']
    assert SecretsFile(secrets_path(db)).get(conn_id) == NEW_KEY and NEW_KEY not in out + err


def test_a_named_variable_that_is_not_set_is_refused_with_one_sentence(db, people, capsys, tester, typed):
    code, out, err = add(capsys, db, '--key-env', 'MY_KEY')
    assert code == 1 and 'MY_KEY' in err and settings(db)['connections'] == {}


def test_a_failed_test_saves_nothing(db, people, capsys, tester, typed):
    tester.result = connections.TestResult(False, 'reviewer', 'ModelTimedOut', 3.0)
    code, out, err = add(capsys, db)
    assert code == 1 and err.strip() == 'Review failed: ModelTimedOut. Nothing was saved.'
    assert settings(db)['connections'] == {} and not secrets_path(db).exists() and events(db) == []


def test_a_tech_cannot_add(db, people, capsys, tester, typed):
    code, out, err = add(capsys, db, who=TECH)
    assert code == 1 and settings(db)['connections'] == {} and events(db) == [] and typed.prompts == []


def test_an_unknown_account_cannot_add(db, people, capsys, tester, typed):
    code, out, err = add(capsys, db, who='nobody@client.example')
    assert code == 1 and settings(db)['connections'] == {}


def test_a_refused_draft_names_the_reason_and_saves_nothing(db, people, capsys, tester, typed):
    code, out, err = cli(capsys, db, 'connection', 'add', 'openai', '--endpoint', 'http://api.example.invalid/v1',
                         '--jobs', 'review', '--model', 'gpt-x', '--as', OWNER)
    assert code == 1 and 'Nothing was saved' in err and settings(db)['connections'] == {}


def test_unknown_job_is_refused(db, people, capsys, tester, typed):
    code, out, err = cli(capsys, db, 'connection', 'add', 'openai', '--jobs', 'review,cooking', '--model', 'm',
                         '--as', OWNER)
    assert code == 1 and 'cooking' in err and settings(db)['connections'] == {}


def test_a_name_already_taken_is_refused(db, people, capsys, tester, typed):
    assert add(capsys, db)[0] == 0
    code, out, err = add(capsys, db)
    assert code == 1 and 'own name' in err and len(settings(db)['connections']) == 1


def test_a_provider_that_needs_no_key_is_not_asked_for_one(db, people, capsys, tester, typed):
    code, out, err = cli(capsys, db, 'connection', 'add', 'ollama', '--jobs', 'screening', '--model', 'llama3',
                         '--as', OWNER)
    assert code == 0 and typed.prompts == []
    assert 'It now does Screening' in out


def test_other_takes_a_format(db, people, capsys, tester, typed):
    code, out, err = cli(capsys, db, 'connection', 'add', 'other', '--name', 'Gateway', '--format', 'openai_chat',
                         '--endpoint', BASE, '--jobs', 'triage', '--model', 'm1', '--family', 'gpt', '--as', OWNER)
    assert code == 0 and out.strip() == 'Gateway is connected. It now does Triage.'
    conn, = settings(db)['connections'].values()
    assert conn['format'] == 'openai_chat' and conn['provider'] == 'other'


def test_format_is_refused_for_a_named_provider(db, people, capsys, tester, typed):
    code, out, err = cli(capsys, db, 'connection', 'add', 'openai', '--format', 'anthropic_messages',
                         '--jobs', 'review', '--model', 'm', '--as', OWNER)
    assert code == 1 and settings(db)['connections'] == {}


# --- list --------------------------------------------------------------------------


def test_list_needs_no_account_and_shows_name_provider_key_and_jobs(db, people, capsys, tester, typed):
    assert cli(capsys, db, 'connection', 'list')[1].strip() == 'No connections.'
    add(capsys, db)
    code, out, err = cli(capsys, db, 'connection', 'list')
    (line,) = out.strip().splitlines()
    assert code == 0 and line.startswith('OpenAI  openai  ends in …')
    assert line.endswith('Review: gpt-x, Summaries: gpt-x')


def test_list_says_set_on_the_server_for_an_environment_key(db, people, capsys, tester, typed, monkeypatch):
    typed.answers[0] = ''
    monkeypatch.setenv('RZ_REVIEWER_API_KEY', 'sk-test-fromenv0001')
    monkeypatch.setenv('RZ_SUMMARIZER_API_KEY', 'sk-test-fromenv0002')
    code, out, err = add(capsys, db)
    assert code == 0
    conn, = settings(db)['connections'].values()
    assert conn['key_source'] == 'environment'
    listed = cli(capsys, db, 'connection', 'list')[1]
    assert 'set on the server' in listed and 'fromenv' not in listed


# --- replace-key -------------------------------------------------------------------


def test_replace_key_tests_stores_and_audits(db, people, capsys, tester, typed):
    add(capsys, db)
    (conn_id,) = settings(db)['connections']
    typed.answers[0] = NEW_KEY
    code, out, err = cli(capsys, db, 'connection', 'replace-key', 'openai', '--as', OWNER)
    assert code == 0 and NEW_KEY not in out + err
    assert SecretsFile(secrets_path(db)).get(conn_id) == NEW_KEY
    assert tester.calls[-1]['keys']['reviewer'] == NEW_KEY
    assert [e['event'] for e in events(db)] == ['connection_key_replaced', 'connection_added']


def test_replace_key_with_a_failing_test_keeps_the_old_key(db, people, capsys, tester, typed):
    add(capsys, db)
    (conn_id,) = settings(db)['connections']
    typed.answers[0] = NEW_KEY
    tester.result = connections.TestResult(False, 'reviewer', 'ModelAuthError', 0.5)
    code, out, err = cli(capsys, db, 'connection', 'replace-key', 'OpenAI', '--as', OWNER)
    assert code == 1 and 'Nothing was saved' in err
    assert SecretsFile(secrets_path(db)).get(conn_id) == KEY


def test_replace_key_refused_for_a_tech_and_an_unknown_name(db, people, capsys, tester, typed):
    add(capsys, db)
    assert cli(capsys, db, 'connection', 'replace-key', 'OpenAI', '--as', TECH)[0] == 1
    code, out, err = cli(capsys, db, 'connection', 'replace-key', 'Nope', '--as', OWNER)
    assert code == 1 and err.strip() == 'No connection has that name.'


# --- test --------------------------------------------------------------------------


def test_test_records_the_result_without_an_account(db, people, capsys, tester, typed):
    add(capsys, db)
    (conn_id,) = settings(db)['connections']
    tester.result = connections.TestResult(False, 'summarizer', 'ModelTimedOut', 2.0)
    code, out, err = cli(capsys, db, 'connection', 'test', 'openai')
    conn = settings(db)['connections'][conn_id]
    assert code == 1 and err.strip() == 'Summaries failed: ModelTimedOut.'
    assert conn['last_test']['ok'] is False and conn['last_test']['real_ts'] and conn['last_test']['sim_ts']
    tester.result = None
    code, out, err = cli(capsys, db, 'connection', 'test', 'OpenAI')
    assert code == 0 and out.strip() == 'OpenAI works. Review and Summaries answered in 1.2 seconds.'
    assert settings(db)['connections'][conn_id]['last_test']['ok'] is True


@pytest.mark.parametrize('name', ['Nope', ''])
def test_test_on_an_unknown_name_prints_one_sentence(db, people, capsys, tester, typed, name):
    code, out, err = cli(capsys, db, 'connection', 'test', name)
    assert code == 1 and err.strip() == 'No connection has that name.' and out == ''


def test_test_on_an_ambiguous_name_prints_one_sentence(db, people, capsys, tester, typed, monkeypatch):
    add(capsys, db)

    def ambiguous(settings, name):
        raise connections.ConnectionRefused('More than one connection has that name')

    monkeypatch.setattr(connections, 'find_by_name', ambiguous)
    code, out, err = cli(capsys, db, 'connection', 'test', 'openai')
    assert code == 1 and err.strip() == 'More than one connection has that name.'


def test_test_on_a_connection_with_no_jobs_says_so(db, people, capsys, tester, typed):
    add(capsys, db)
    saved = settings(db)
    saved['roles'] = {role: None for role in saved['roles']}
    local_settings.save(local_settings.settings_path(db), saved)
    code, out, err = cli(capsys, db, 'connection', 'test', 'OpenAI')
    assert code == 1 and 'nothing to test' in err


# --- remove ------------------------------------------------------------------------


def test_remove_shows_the_consequences_and_needs_the_name_typed(db, people, capsys, tester, typed, monkeypatch):
    add(capsys, db)
    (conn_id,) = settings(db)['connections']
    asked = []
    monkeypatch.setattr('builtins.input', lambda prompt='': asked.append(prompt) or 'OpenAI')
    code, out, err = cli(capsys, db, 'connection', 'remove', 'OpenAI', '--as', OWNER)
    assert code == 0 and asked == ['Type the name to delete: ']
    assert 'OpenAI does Review and Summaries. After deleting,' in out
    assert settings(db)['connections'] == {} and all(v is None for v in settings(db)['roles'].values())
    assert SecretsFile(secrets_path(db)).get(conn_id) is None
    assert events(db)[0]['event'] == 'connection_removed'


def test_remove_with_a_wrong_name_changes_nothing(db, people, capsys, tester, typed, monkeypatch):
    add(capsys, db)
    (conn_id,) = settings(db)['connections']
    monkeypatch.setattr('builtins.input', lambda prompt='': 'openai-ish')
    code, out, err = cli(capsys, db, 'connection', 'remove', 'OpenAI', '--as', OWNER)
    assert code == 1 and 'Nothing was deleted' in err
    assert len(settings(db)['connections']) == 1 and SecretsFile(secrets_path(db)).get(conn_id) == KEY
    assert [e['event'] for e in events(db)] == ['connection_added']


def test_remove_yes_skips_the_prompt_and_deletes_the_key(db, people, capsys, tester, typed, monkeypatch):
    add(capsys, db)
    (conn_id,) = settings(db)['connections']
    monkeypatch.setattr('builtins.input', lambda prompt='': pytest.fail('asked'))
    code, out, err = cli(capsys, db, 'connection', 'remove', 'OpenAI', '--as', OWNER, '--yes')
    assert code == 0 and settings(db)['connections'] == {}
    assert SecretsFile(secrets_path(db)).get(conn_id) is None


def test_remove_refused_for_a_tech(db, people, capsys, tester, typed):
    add(capsys, db)
    code, out, err = cli(capsys, db, 'connection', 'remove', 'OpenAI', '--as', TECH, '--yes')
    assert code == 1 and len(settings(db)['connections']) == 1


def test_remove_needs_as(db, people, capsys, tester, typed):
    assert cli(capsys, db, 'connection', 'remove', 'OpenAI', '--yes')[0] == 2


def test_ctrl_c_at_the_key_prompt_changes_nothing(db, people, capsys, tester, monkeypatch):
    def interrupted(prompt=''):
        raise KeyboardInterrupt
    monkeypatch.setattr(getpass, 'getpass', interrupted)
    code, out, err = add(capsys, db)
    assert code == 1 and 'Cancelled. Nothing was changed.' in err and settings(db)['connections'] == {}


def test_the_key_file_and_the_servers_agree_on_where_it_lives(db):
    assert local_connections.secrets_beside(local_settings.settings_path(db)) == secrets_path(db)


def test_remove_refuses_when_settings_changed_during_the_prompt(db, people, capsys, tester, typed, monkeypatch):
    add(capsys, db)
    (conn_id,) = settings(db)['connections']

    def answer(prompt=''):
        changed = settings(db)
        changed['roles']['reviewer'] = None
        local_settings.save(local_settings.settings_path(db), changed)
        return 'OpenAI'

    monkeypatch.setattr('builtins.input', answer)
    code, out, err = cli(capsys, db, 'connection', 'remove', 'OpenAI', '--as', OWNER)
    assert code == 1 and 'Settings changed while testing' in err
    assert conn_id in settings(db)['connections'] and SecretsFile(secrets_path(db)).get(conn_id) == KEY
    assert [e['event'] for e in events(db)] == ['connection_added']


def test_the_storage_page_names_the_key_file_in_the_backup_steps():
    from ui.settings_view import render_settings
    body = render_settings(dict(local_settings.DEFAULTS), 'storage', 'form-token')
    assert '.secrets.json' in body and 'API keys you stored here' in body
    assert 'API keys come from the environment or from the owner-only key file' in body


# --- final review fixes ------------------------------------------------------------


def write_v5(db):
    """A version-5 settings file with two configured jobs, as an upgraded install has on disk."""
    value = {k: json.loads(json.dumps(v)) for k, v in local_settings.DEFAULTS.items() if k != 'connections'}
    value['version'] = 5
    value['roles'] = dict.fromkeys(local_settings.ROLES)
    value['roles']['proposer'] = {'format': 'openai_chat', 'endpoint': 'http://127.0.0.1:11434/v1/chat/completions',
                                  'model': 'qwen2.5:7b', 'family': 'qwen', 'ca_file': '', 'timeout_seconds': 300}
    value['roles']['reviewer'] = {'format': 'anthropic_messages', 'endpoint': 'https://api.anthropic.com/v1/messages',
                                  'model': 'claude-test-1', 'family': 'claude', 'ca_file': '', 'timeout_seconds': 60}
    local_settings.settings_path(db).write_text(json.dumps(value))


def test_an_upgraded_v5_install_can_test_add_and_remove_connections(db, people, capsys, tester, typed):
    write_v5(db)
    assert settings(db) == settings(db)                  # two loads of one v5 file are equal
    code, out, err = cli(capsys, db, 'connection', 'test', 'Ollama (Triage)')
    assert code == 0, err
    triage = settings(db)['roles']['proposer']['connection']
    assert settings(db)['connections'][triage]['last_test']['ok'] is True
    write_v5(db)
    code, out, err = add(capsys, db, '--jobs', 'summaries')
    assert code == 0, err
    write_v5(db)
    code, out, err = cli(capsys, db, 'connection', 'remove', 'Anthropic (Review)', '--as', OWNER, '--yes')
    assert code == 0, err
    assert settings(db)['roles']['reviewer'] is None and len(settings(db)['connections']) == 1


def test_an_environment_connection_whose_variable_is_unset_takes_a_replaced_key(db, people, capsys, tester, typed):
    write_v5(db)                                         # migrated: Review's key_source is 'environment'
    review = settings(db)['roles']['reviewer']['connection']
    listed = cli(capsys, db, 'connection', 'list')[1]
    assert 'Anthropic (Review)  anthropic  key missing' in listed
    typed.answers[0] = NEW_KEY
    code, out, err = cli(capsys, db, 'connection', 'replace-key', 'Anthropic (Review)', '--as', OWNER)
    assert code == 0, err
    assert tester.calls[-1]['keys'] == {'reviewer': NEW_KEY}
    assert settings(db)['connections'][review]['key_source'] == 'stored'
    assert SecretsFile(secrets_path(db)).get(review) == NEW_KEY
