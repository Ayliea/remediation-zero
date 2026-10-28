# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Connection operations: pure functions over the settings dict."""
import copy
import os

import pytest

from tools import connections as cx
from tools.clock import ClockMode, SimClock
from tools.connections import ConnectionRefused, Draft, JobChoice
from tools.local_secrets import Overlay, SecretsFile
from tools.local_settings import DEFAULTS, validate
from tools.model_roles import ModelRoles, key_source

AN = 'conn-aaaaaaaaaaaa'
OL = 'conn-bbbbbbbbbbbb'
NEW = 'conn-cccccccccccc'
KEY = 'sk-test-ABCDEFGH7Qx2'


def conn(name, provider, fmt, base, source, **kw):
    return {'name': name, 'provider': provider, 'format': fmt, 'base_url': base, 'endpoint_style': 'base',
            'ca_file': '', 'key_source': source, 'last_test': None, **kw}


def job(model='claude-test-model', family='claude', cid=AN):
    return {'connection': cid, 'model': model, 'family': family, 'timeout_seconds': 60}


def settings(**roles):
    value = copy.deepcopy(DEFAULTS)
    value['connections'] = {
        AN: conn('Anthropic', 'anthropic', 'anthropic_messages', 'https://api.anthropic.com/v1', 'stored'),
        OL: conn('Local', 'ollama', 'openai_chat', 'http://127.0.0.1:11434/v1', 'none'),
    }
    value['roles'].update(roles)
    return validate(value)


def draft(name='Gemini', **kw):
    base = dict(provider='gemini', name=name, format='gemini_api',
                base_url='https://generativelanguage.googleapis.com/v1beta', ca_file='', key=KEY,
                jobs={'summarizer': JobChoice('gemini-test', 'gemini')})
    base.update(kw)
    return Draft(**base)


# ---- names -------------------------------------------------------------------------------

@pytest.mark.parametrize('name', ['', '   ', 'x' * 61, 'a\nb', 'a\x00b', 'a\x7fb'])
def test_bad_names_are_refused(name):
    with pytest.raises(ConnectionRefused):
        cx.validate_draft(settings(), draft(name=name))


def test_name_is_stripped_and_markup_is_accepted_as_text():
    ok = cx.validate_draft(settings(), draft(name='  <b>Mine</b>  '))
    assert ok.name == '<b>Mine</b>'
    assert cx.validate_draft(settings(), draft(name='x' * 60)).name == 'x' * 60


def test_duplicate_name_ignoring_case_is_refused_except_the_one_replaced():
    s = settings()
    with pytest.raises(ConnectionRefused):
        cx.validate_draft(s, draft(name='anthropic'))
    cx.validate_draft(s, draft(name='anthropic'), replacing=AN)
    with pytest.raises(ConnectionRefused):
        cx.validate_draft(s, draft(name='LOCAL'), replacing=AN)


def test_rows_return_markup_raw_for_the_view_to_escape():
    s = settings()
    s['connections'][AN]['name'] = '<b>x</b>'
    row = cx.rows(s, {}, None, now_real_ts=0)[0]
    assert row['name'] == '<b>x</b>'


# ---- the rest of the draft ---------------------------------------------------------------

def test_endpoint_rules_apply_to_the_draft():
    for url in ('http://example.invalid/v1', 'https://user:pw@example.invalid/v1', 'https://example.invalid/v1?x=1'):
        with pytest.raises(ConnectionRefused):
            cx.validate_draft(settings(), draft(base_url=url, provider='other', format='openai_chat'))


def test_a_bad_key_a_bad_family_and_a_bad_timeout_are_refused():
    s = settings()
    with pytest.raises(ConnectionRefused):
        cx.validate_draft(s, draft(key='two words'))
    with pytest.raises(ConnectionRefused):
        cx.validate_draft(s, draft(jobs={'guard': JobChoice('m', 'nonsense')}))
    with pytest.raises(ConnectionRefused):
        cx.validate_draft(s, draft(jobs={'guard': JobChoice('m', 'gemini', 4)}))
    with pytest.raises(ConnectionRefused):
        cx.validate_draft(s, draft(jobs={'wizard': JobChoice('m', 'gemini')}))
    with pytest.raises(ConnectionRefused):
        cx.validate_draft(s, draft(jobs={'guard': JobChoice('  ', 'gemini')}))


def test_unknown_provider_and_format_mismatch_are_refused():
    with pytest.raises(ConnectionRefused):
        cx.validate_draft(settings(), draft(provider='nope'))
    with pytest.raises(ConnectionRefused):
        cx.validate_draft(settings(), draft(format='openai_chat'))


def test_a_missing_ca_file_is_refused_and_the_key_is_stripped():
    with pytest.raises(ConnectionRefused):
        cx.validate_draft(settings(), draft(ca_file='/nonexistent/ca.pem'))
    assert cx.validate_draft(settings(), draft(key=f'  {KEY}\n')).key == KEY


def test_the_draft_hides_its_key_from_repr():
    assert KEY not in repr(draft())


# ---- with_connection ---------------------------------------------------------------------

def test_with_connection_adds_and_assigns_without_touching_the_input():
    s = settings(summarizer=job())
    before = copy.deepcopy(s)
    new = cx.with_connection(s, NEW, draft())
    assert s == before
    c = new['connections'][NEW]
    assert (c['name'], c['provider'], c['key_source'], c['endpoint_style'], c['last_test']) == (
        'Gemini', 'gemini', 'stored', 'base', None)
    assert new['roles']['summarizer'] == {'connection': NEW, 'model': 'gemini-test',
                                          'family': 'gemini', 'timeout_seconds': 60}
    assert KEY not in repr(new)
    validate(new)


def test_with_connection_key_source_for_no_key_and_environment():
    s = settings()
    new = cx.with_connection(s, NEW, draft(provider='ollama', name='O2', format='openai_chat',
                                           base_url='http://127.0.0.1:11434/v1', key=None))
    assert new['connections'][NEW]['key_source'] == 'none'
    new = cx.with_connection(s, NEW, draft(key=None))
    assert new['connections'][NEW]['key_source'] == 'environment'


def test_editing_keeps_the_key_source_and_style_and_unassigns_dropped_jobs():
    s = settings(reviewer=job(), guard=job())
    s['connections'][AN]['endpoint_style'] = 'exact'
    s['connections'][AN]['base_url'] = 'https://api.anthropic.com/v1/messages/'
    s['connections'][AN]['last_test'] = {'ok': True, 'error': '', 'seconds': 1.0, 'jobs': ['guard'],
                                         'real_ts': 1.0, 'sim_ts': 1.0}
    d = draft(name='Anthropic', provider='anthropic', format='anthropic_messages',
              base_url='https://api.anthropic.com/v1/messages/', key=None,
              jobs={'reviewer': JobChoice('claude-test-model', 'claude')})
    new = cx.with_connection(s, AN, d)
    assert new['connections'][AN]['key_source'] == 'stored'
    assert new['connections'][AN]['endpoint_style'] == 'exact'
    assert new['connections'][AN]['last_test'] is None
    assert new['roles']['guard'] is None and new['roles']['reviewer']['connection'] == AN
    validate(new)


@pytest.mark.parametrize('field,value', [
    ('base_url', 'https://proxy.example.invalid/v1'), ('ca_file', '/etc/ssl/certs/ca-certificates.crt'),
    ('format', 'openai_chat'), ('provider', 'other')])
def test_changing_the_address_of_a_stored_key_connection_needs_the_key_again(field, value):
    s = settings(reviewer=job())
    same = dict(name='Anthropic', provider='anthropic', format='anthropic_messages',
                base_url='https://api.anthropic.com/v1', key=None,
                jobs={'reviewer': JobChoice('claude-other-model', 'claude', 90)})
    cx.validate_draft(s, draft(**same), replacing=AN)  # jobs and models alone may change
    with pytest.raises(ConnectionRefused, match='Enter the key again'):
        cx.validate_draft(s, draft(**{**same, field: value}), replacing=AN)


def test_a_typed_base_url_loses_its_trailing_slashes_and_a_retyped_one_needs_no_key():
    assert cx.validate_draft(settings(), draft(base_url='https://generativelanguage.googleapis.com/v1beta//')
                             ).base_url == 'https://generativelanguage.googleapis.com/v1beta'
    s = settings(reviewer=job())
    same = dict(name='Anthropic', provider='anthropic', format='anthropic_messages',
                base_url='https://api.anthropic.com/v1/', key=None, jobs={'reviewer': JobChoice('claude-x', 'claude')})
    assert cx.validate_draft(s, draft(**same), replacing=AN).base_url == 'https://api.anthropic.com/v1'


def test_an_unchanged_address_is_kept_byte_for_byte():
    s = settings(reviewer=job())
    s['connections'][AN].update(base_url='https://guard.example.invalid/screen/v2/', endpoint_style='exact',
                                key_source='environment')
    kept = cx.validate_draft(s, draft(name='Anthropic', provider='anthropic', format='anthropic_messages',
                                      base_url='https://guard.example.invalid/screen/v2/', key=None,
                                      jobs={'reviewer': JobChoice('claude-x', 'claude')}), replacing=AN)
    assert kept.base_url == 'https://guard.example.invalid/screen/v2/'
    new = cx.with_connection(s, AN, kept)
    assert new['connections'][AN]['endpoint_style'] == 'exact'


def test_a_key_needing_provider_with_no_key_becomes_environment_sourced():
    new = cx.with_connection(settings(), NEW, draft(key=None))
    assert new['connections'][NEW]['key_source'] == 'environment'


# ---- test_jobs ---------------------------------------------------------------------------

class Fake:
    def __init__(self, behaviour):
        self.behaviour = behaviour
        self.ran = []

    def adapter(self, role):
        return role

    def run(self, role, adapter):
        self.ran.append(role)
        out = self.behaviour[role]
        if isinstance(out, Exception):
            raise out
        return out


def test_test_jobs_stops_at_the_first_failure_in_job_order(monkeypatch):
    fake = Fake({'proposer': None, 'reviewer': 'ReviewFailed', 'guard': None, 'summarizer': None})
    monkeypatch.setattr(cx.model_check, '_run', fake.run)
    ticks = iter([10.0, 13.5, 99.0])
    result = cx.test_jobs(fake, ['summarizer', 'reviewer', 'proposer', 'guard'], now=lambda: next(ticks))
    assert fake.ran == ['proposer', 'reviewer']
    assert (result.ok, result.failed_job, result.error) == (False, 'reviewer', 'ReviewFailed')
    assert result.seconds == pytest.approx(3.5)


def test_test_jobs_reports_the_class_name_only(monkeypatch):
    fake = Fake({'guard': ValueError('sk-secret-9999 rejected')})
    monkeypatch.setattr(cx.model_check, '_run', fake.run)
    result = cx.test_jobs(fake, ['guard'])
    assert result.error == 'ValueError' and 'sk-secret-9999' not in repr(result)


def test_test_jobs_passes_when_every_job_does(monkeypatch):
    fake = Fake({'proposer': None, 'summarizer': None})
    monkeypatch.setattr(cx.model_check, '_run', fake.run)
    result = cx.test_jobs(fake, ['summarizer', 'proposer'])
    assert (result.ok, result.failed_job, result.error) == (True, None, '')
    assert fake.ran == ['proposer', 'summarizer']


def test_test_jobs_uses_the_drafts_key_without_storing_it(tmp_path, monkeypatch):
    s = cx.with_connection(settings(), NEW, draft())
    store = SecretsFile(tmp_path / 'ws.secrets.json')
    roles = ModelRoles.from_settings(s, {}, secrets=Overlay(store, {NEW: KEY}))
    seen = []
    monkeypatch.setattr(cx.model_check, '_run', lambda role, adapter: seen.append(adapter) or None)
    assert cx.test_jobs(roles, ['summarizer']).ok
    assert len(seen) == 1 and store.get(NEW) is None


# ---- record_test -------------------------------------------------------------------------

def test_record_test_stamps_both_times_and_keeps_the_input():
    s = settings()
    stamp = SimClock(ClockMode.REAL, source=lambda: 1000.0).now()
    fail = cx.record_test(s, AN, cx.TestResult(False, 'guard', 'ValueError', 2.5), ['guard', 'reviewer'], stamp)
    assert s['connections'][AN]['last_test'] is None
    assert fail['connections'][AN]['last_test'] == {'ok': False, 'error': 'ValueError', 'seconds': 2.5,
                                                    'jobs': ['guard', 'reviewer'], 'real_ts': stamp.real_ts,
                                                    'sim_ts': stamp.sim_ts}
    ok = cx.record_test(s, AN, cx.TestResult(True, None, '', 1.0), ['guard'], stamp)
    assert ok['connections'][AN]['last_test']['ok'] is True
    validate(fail), validate(ok)


# ---- deletion ----------------------------------------------------------------------------

def test_without_connection_removes_it_and_its_roles():
    s = settings(reviewer=job(), summarizer=job(), guard=job(cid=OL, model='m', family='llama'))
    new = cx.without_connection(s, AN)
    assert AN not in new['connections'] and new['roles']['reviewer'] is None
    assert new['roles']['summarizer'] is None and new['roles']['guard']['connection'] == OL
    assert AN in s['connections']
    validate(new)


def test_deletion_consequences_sentences():
    s = settings(reviewer=job())
    assert cx.deletion_consequences(s, AN) == (
        'Anthropic does Review. After deleting, nobody reviews, so new triage waits for a person.')
    s = settings(reviewer=job(), summarizer=job())
    assert cx.deletion_consequences(s, AN) == (
        'Anthropic does Review and Summaries. After deleting, nobody reviews, so new triage waits for a '
        'person; nobody writes the cycle summary.')
    s = settings(proposer=job(), guard=job(), reviewer=job())
    text = cx.deletion_consequences(s, AN)
    assert text.startswith('Anthropic does Triage, Review and Screening. After deleting, ')
    assert 'nobody triages, so no cycle runs' in text
    assert 'nobody screens scanner text, so it is withheld from the models' in text
    assert cx.deletion_consequences(settings(), OL) == 'Local does no jobs. Deleting it changes nothing else.'


# ---- rows --------------------------------------------------------------------------------

def stored(tmp_path, key=KEY):
    store = SecretsFile(tmp_path / 'ws.secrets.json')
    store.put(AN, key)
    return store


def test_rows_word_each_jobs_key_source(tmp_path):
    s = settings(reviewer=job(), summarizer=job(), guard=job(cid=OL, model='m', family='llama'))
    row, local = cx.rows(s, {'RZ_REVIEWER_API_KEY': 'sk-test-ENVENVENV'}, stored(tmp_path), now_real_ts=0)
    assert [(j['job'], j['key']) for j in row['jobs']] == [('Review', 'set on the server'),
                                                          ('Summaries', 'stored …7Qx2')]
    assert row['key_hint'] == 'ends in …7Qx2' and row['can_replace_key'] is True
    assert (row['id'], row['provider'], row['letter']) == (AN, 'anthropic', 'A')
    assert row['colour'] and row['jobs'][0]['role'] == 'reviewer' and row['jobs'][0]['model'] == 'claude-test-model'
    assert local['jobs'][0]['key'] == 'no key needed' and local['key_hint'] == 'no key needed'
    assert local['can_replace_key'] is False
    assert KEY not in repr([row, local])


def test_can_replace_key_is_false_when_every_job_takes_its_key_from_the_environment(tmp_path):
    s = settings(reviewer=job(), summarizer=job())
    env = {'RZ_REVIEWER_API_KEY': 'k', 'RZ_SUMMARIZER_API_KEY': 'k'}
    row = cx.rows(s, env, stored(tmp_path), now_real_ts=0)[0]
    assert row['can_replace_key'] is False and row['key_hint'] == 'set on the server'


def test_environment_sourced_connection_without_the_variable_is_key_missing():
    s = settings(reviewer=job())
    s['connections'][AN]['key_source'] = 'environment'
    # 'environment' counts only when the job's variable is set: else the key is missing and can be given.
    row = cx.rows(s, {}, None, now_real_ts=0)[0]
    assert row['jobs'][0]['key'] == 'key missing' and row['key_hint'] == 'key missing'
    assert row['can_replace_key'] is True
    assert key_source(s, 'reviewer', {}) == 'missing'
    row = cx.rows(s, {'RZ_REVIEWER_API_KEY': 'k'}, None, now_real_ts=0)[0]
    assert row['jobs'][0]['key'] == 'set on the server' and row['key_hint'] == 'set on the server'
    assert row['can_replace_key'] is False
    # With no jobs at all, nothing is set on the server for it either.
    s['roles']['reviewer'] = None
    row = cx.rows(s, {'RZ_REVIEWER_API_KEY': 'k'}, None, now_real_ts=0)[0]
    assert row['key_hint'] == 'key missing' and row['can_replace_key'] is True


def test_a_short_key_shows_no_ending(tmp_path):
    s = settings(reviewer=job())
    row = cx.rows(s, {}, stored(tmp_path, 'sk-short-12'), now_real_ts=0)[0]
    assert row['jobs'][0]['key'] == 'stored' and row['key_hint'] == 'key stored'


def test_missing_and_unreadable_key_files_show_key_missing(tmp_path):
    s = settings(reviewer=job())
    empty = SecretsFile(tmp_path / 'none.secrets.json')
    row = cx.rows(s, {}, empty, now_real_ts=0)[0]
    assert row['jobs'][0]['key'] == 'key missing' and row['key_hint'] == 'key missing'
    store = stored(tmp_path)
    os.chmod(store.path, 0o644)
    row = cx.rows(s, {}, store, now_real_ts=0)[0]
    assert row['jobs'][0]['key'] == 'key missing' and row['key_hint'] == 'key missing'
    assert str(tmp_path) not in repr(row)
    assert cx.rows(s, {}, None, now_real_ts=0)[0]['key_hint'] == 'key missing'


def test_last_test_text():
    s = settings()
    now = 10_000.0
    assert cx.rows(s, {}, None, now_real_ts=now)[0]['last_test_text'] == 'Not tested'
    s['connections'][AN]['last_test'] = {'ok': True, 'error': '', 'seconds': 1.0, 'jobs': [],
                                         'real_ts': now - 125, 'sim_ts': 1.0}
    assert cx.rows(s, {}, None, now_real_ts=now)[0]['last_test_text'] == 'Tested 2 min ago'
    s['connections'][AN]['last_test'] = {'ok': False, 'error': 'ModelTimedOut', 'seconds': 1.0, 'jobs': [],
                                         'real_ts': now - 5, 'sim_ts': 1.0}
    assert cx.rows(s, {}, None, now_real_ts=now)[0]['last_test_text'] == 'Failed: ModelTimedOut'


# ---- coverage ----------------------------------------------------------------------------

def test_coverage_lists_every_job_in_order():
    s = settings(proposer=job(model='p', family='gemini', cid=OL), reviewer=job(model='r', family='claude'))
    cov = cx.coverage(s, {})
    assert [c['job'] for c in cov] == ['Triage', 'Review', 'Screening', 'Summaries']
    assert cov[0] == {'role': 'proposer', 'job': 'Triage', 'connection': 'Local', 'model': 'p',
                      'family_note': None, 'overridden': False}
    assert cov[1]['connection'] == 'Anthropic' and cov[1]['family_note'] == 'different family'
    assert cov[2]['connection'] is None and cov[2]['model'] is None and cov[3]['connection'] is None


def test_coverage_same_family_and_override():
    s = settings(proposer=job(model='p', family='claude'), reviewer=job(model='r', family='claude'))
    assert cx.coverage(s, {})[1]['family_note'] == 'same family'
    cov = cx.coverage(s, {'RZ_MODEL': 'other-model'})
    assert cov[0]['overridden'] is True and cov[0]['model'] == 'other-model' and cov[1]['overridden'] is False
    cov = cx.coverage(settings(), {'RZ_MODEL_ENDPOINT': 'http://127.0.0.1:1/v1/chat/completions',
                                   'RZ_MODEL': 'm'})
    assert cov[0]['overridden'] is True and cov[0]['connection'] is None and cov[0]['model'] == 'm'


def test_coverage_other_family_and_no_proposer_count_as_same_family():
    only_reviewer = settings(reviewer=job(model='r', family='claude'))
    assert cx.coverage(only_reviewer, {})[1]['family_note'] == 'same family'
    s = settings(proposer=job(model='p', family='other'), reviewer=job(model='r', family='claude'))
    assert cx.coverage(s, {})[1]['family_note'] == 'same family'
    s = settings(proposer=job(model='p', family='gemini'), reviewer=job(model='r', family='other'))
    assert cx.coverage(s, {})[1]['family_note'] == 'same family'
    assert cx.coverage(settings(), {})[1]['family_note'] is None


# ---- find_by_name ------------------------------------------------------------------------

def test_find_by_name():
    s = settings()
    assert cx.find_by_name(s, ' anthropic ') == AN
    with pytest.raises(ConnectionRefused):
        cx.find_by_name(s, 'nobody')
    s['connections'][OL]['name'] = 'ANTHROPIC'  # not valid settings, but ambiguity must still be refused
    with pytest.raises(ConnectionRefused):
        cx.find_by_name(s, 'Anthropic')
