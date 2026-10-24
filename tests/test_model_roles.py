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
