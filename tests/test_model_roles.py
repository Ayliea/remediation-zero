# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Role configuration, independence, provenance and the inference fingerprint."""
import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from tools.inference import inference_fingerprint
from tools.inference_journal import InferenceJournal
from tools.model_roles import ModelRoles, RoleConfig, suggest_family
from tools.sqlite_store import SQLiteStore

REPO_ROOT = Path(__file__).resolve().parents[1]
URL = 'http://127.0.0.1:11434/v1/chat/completions'


def role(name, model, family, endpoint=URL):
    return RoleConfig(name, 'openai_chat', endpoint, model, family)


def roles(proposer='gemini', reviewer='llama', **kw):
    return ModelRoles(proposer=role('proposer', 'p', proposer) if proposer else None,
                      reviewer=role('reviewer', 'r', reviewer) if reviewer else None, **kw)


def test_independence_cross_family():
    assert roles('gemini', 'llama').independence() == 'cross_family'


def test_independence_same_family():
    assert roles('llama', 'llama').independence() == 'same_family'


def test_independence_other_family_counts_as_same():
    assert roles('other', 'llama').independence() == 'same_family'
    assert roles('gemini', 'other').independence() == 'same_family'


def test_independence_unreviewed():
    assert roles('gemini', None).independence() == 'unreviewed'


def test_provenance_has_no_endpoint_or_key(monkeypatch):
    monkeypatch.setenv('RZ_REVIEWER_API_KEY', 'sk-test')
    configured = roles()
    configured.adapter('reviewer')
    text = json.dumps(configured.provenance())
    assert 'sk-test' not in text and URL not in text and '127.0.0.1' not in text
    assert configured.provenance()['reviewer'] == {'format': 'openai_chat', 'model': 'r', 'family': 'llama'}


def test_from_env_matches_current_cloud():
    configured = ModelRoles.from_env({'REASONING_MODEL': 'gemini-3.5-flash',
                                      'REVIEWER_MODEL': 'gemma-4-26b-a4b-it-maas'})
    assert (configured.proposer.format, configured.proposer.family) == ('vertex', 'gemini')
    assert (configured.reviewer.format, configured.reviewer.family) == ('vertex', 'gemma')
    assert configured.summarizer.model == 'gemini-3.5-flash'
    assert configured.guard is None and configured.same_family_policy == 'wait'
    assert configured.independence() == 'cross_family'


def test_from_env_role_overrides():
    configured = ModelRoles.from_env({
        'REASONING_MODEL': 'gemini-3.5-flash', 'REVIEWER_MODEL': 'gemma-x',
        'RZ_REVIEWER_FORMAT': 'openai_chat', 'RZ_REVIEWER_ENDPOINT': URL, 'RZ_REVIEWER_MODEL': 'llama3.1'})
    assert (configured.reviewer.format, configured.reviewer.family) == ('openai_chat', 'llama')


@pytest.mark.parametrize('model,family', [('llama3.1:8b', 'llama'), ('claude-sonnet-x', 'claude'),
                                          ('qwen2.5-coder', 'qwen'), ('my-model', 'other')])
def test_suggest_family(model, family):
    assert suggest_family(model) == family


def test_fingerprint_changes_with_policy_family_endpoint_model():
    base = roles()
    value = inference_fingerprint('x', base)
    assert value == inference_fingerprint('x', roles())
    assert inference_fingerprint('x', replace(base, same_family_policy='proceed')) != value
    assert inference_fingerprint('x', replace(base, reviewer=replace(base.reviewer, family='gpt'))) != value
    assert inference_fingerprint('x', replace(
        base, reviewer=replace(base.reviewer, endpoint='http://127.0.0.1:9/v1'))) != value
    assert inference_fingerprint('x', replace(base, reviewer=replace(base.reviewer, model='r2'))) != value


def test_changed_roles_mid_cycle_requires_human_review(tmp_path):
    store = SQLiteStore(tmp_path / 'db.sqlite3')
    InferenceJournal(store, 'A', 1, context=inference_fingerprint('x', roles()))._ensure_context()
    changed = InferenceJournal(store, 'A', 1, context=inference_fingerprint('x', roles('gemini', 'gpt')))
    with pytest.raises(ValueError, match='changed within this cycle'):
        changed._ensure_context()


def test_module_is_standard_library_only():
    subprocess.run([sys.executable, '-S', '-c', 'import tools.model_roles'], cwd=REPO_ROOT, check=True)


# --- from_settings: what RZ_MODEL / RZ_MODEL_ENDPOINT override ---------------

OTHER = 'https://models.example.invalid/v1/chat/completions'


def saved(model='llama3.1', family='llama', endpoint=URL):
    return {'roles': {'proposer': {'format': 'openai_chat', 'endpoint': endpoint,
                                   'model': model, 'family': family},
                      'reviewer': None, 'summarizer': None, 'guard': None},
            'same_family_policy': 'wait'}


def test_from_settings_without_overrides_is_the_saved_proposer():
    built = ModelRoles.from_settings(saved(), {})
    assert built.proposer == role('proposer', 'llama3.1', 'llama')


def test_rz_model_overrides_the_saved_model_and_resuggests_the_family():
    built = ModelRoles.from_settings(saved(), {'RZ_MODEL': 'qwen2.5-coder'})
    assert (built.proposer.model, built.proposer.family) == ('qwen2.5-coder', 'qwen')
    assert built.proposer.endpoint == URL and built.proposer.format == 'openai_chat'


def test_rz_model_equal_to_the_saved_model_keeps_the_chosen_family():
    # The person chose "other" for a llama-named model; the same name keeps it.
    built = ModelRoles.from_settings(saved(family='other'), {'RZ_MODEL': 'llama3.1'})
    assert built.proposer.family == 'other'


def test_rz_model_endpoint_overrides_only_the_endpoint():
    built = ModelRoles.from_settings(saved(family='other'), {'RZ_MODEL_ENDPOINT': OTHER})
    assert built.proposer == role('proposer', 'llama3.1', 'other', endpoint=OTHER)


def test_both_overrides_apply_together():
    built = ModelRoles.from_settings(saved(), {'RZ_MODEL_ENDPOINT': OTHER, 'RZ_MODEL': 'gpt-4o'})
    assert built.proposer == role('proposer', 'gpt-4o', 'gpt', endpoint=OTHER)


def test_rz_model_with_nothing_saved_needs_an_endpoint():
    empty = dict(saved(), roles={'proposer': None, 'reviewer': None, 'summarizer': None, 'guard': None})
    with pytest.raises(ValueError):
        ModelRoles.from_settings(empty, {'RZ_MODEL': 'gpt-4o'})
    built = ModelRoles.from_settings(empty, {'RZ_MODEL': 'gpt-4o', 'RZ_MODEL_ENDPOINT': OTHER})
    assert built.proposer == role('proposer', 'gpt-4o', 'gpt', endpoint=OTHER)


def test_overrides_touch_only_the_proposer():
    settings = saved()
    settings['roles']['reviewer'] = {'format': 'openai_chat', 'endpoint': URL,
                                     'model': 'claude-x', 'family': 'claude'}
    built = ModelRoles.from_settings(settings, {'RZ_MODEL': 'gpt-4o'})
    assert built.reviewer == role('reviewer', 'claude-x', 'claude')


# --- the adapter reads keys from the environ it was built with ---------------


def test_adapter_uses_the_environ_from_settings_not_the_process(monkeypatch):
    import tools.model_roles as model_roles
    seen = []
    monkeypatch.setattr(model_roles, 'build_adapter',
                        lambda fmt, url, model, key: seen.append(key) or object())
    monkeypatch.setenv('RZ_PROPOSER_API_KEY', 'process-key')
    monkeypatch.delenv('RZ_MODEL_API_KEY', raising=False)
    built = ModelRoles.from_settings(saved(), {'RZ_PROPOSER_API_KEY': 'passed-key'})
    built.adapter('proposer')
    assert seen == ['passed-key']
    ModelRoles.from_settings(saved(), {}).adapter('proposer')
    assert seen == ['passed-key', None]
    # Never shown: the environ is not part of the roles' repr or equality.
    assert 'passed-key' not in repr(built)
    assert built == ModelRoles.from_settings(saved(), {})


def test_adapter_without_an_environ_reads_the_process(monkeypatch):
    import tools.model_roles as model_roles
    seen = []
    monkeypatch.setattr(model_roles, 'build_adapter',
                        lambda fmt, url, model, key: seen.append(key) or object())
    monkeypatch.setenv('RZ_PROPOSER_API_KEY', 'process-key')
    ModelRoles(proposer=role('proposer', 'p', 'gpt')).adapter('proposer')
    assert seen == ['process-key']


def test_run_local_cycle_builds_adapters_from_its_environ(tmp_path, monkeypatch):
    import tools.model_roles as model_roles
    from scripts import local
    from tools import local_settings
    from tools.local_layout import Workspace
    ws = Workspace(tmp_path / 'workspace')
    local_settings.save(local_settings.settings_path(ws.root), dict(local_settings.DEFAULTS, **saved()))
    seen = []

    def stop(fmt, url, model, key):
        seen.append(key)
        raise RuntimeError('stop before any model call')

    monkeypatch.setattr(model_roles, 'build_adapter', stop)
    monkeypatch.setenv('RZ_PROPOSER_API_KEY', 'process-key')
    with pytest.raises(RuntimeError, match='stop before'):
        local.run_local_cycle(ws, 1, environ={'RZ_PROPOSER_API_KEY': 'passed-key'})
    assert seen == ['passed-key']
