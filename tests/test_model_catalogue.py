# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
import json

import pytest
from tools import model_catalogue as mc
from tools.model_roles import FAMILIES


def _model(provider='openai', pattern='gpt-*', tier='large', **over):
    entry = {'provider': provider, 'pattern': pattern, 'family': 'gpt', 'tier': tier,
             'strengths': 'A short line.', 'cost': 'higher'}
    entry.update(over)
    return entry


def _write(tmp_path, models, version=1):
    path = tmp_path / 'c.json'
    path.write_text(json.dumps({'version': version, 'providers': [], 'models': models}))
    return path


def test_presets_in_order_with_their_values():
    got = [(p.id, p.name, p.letter, p.colour, p.format, p.base_url, p.needs_key, p.key_page) for p in mc.presets()]
    assert got == [
        ('anthropic', 'Anthropic', 'A', '#c96442', 'anthropic_messages', 'https://api.anthropic.com/v1', True,
         'https://console.anthropic.com/settings/keys'),
        ('openai', 'OpenAI', 'O', '#111111', 'openai_chat', 'https://api.openai.com/v1', True,
         'https://platform.openai.com/api-keys'),
        ('gemini', 'Google Gemini', 'G', '#4f7df3', 'gemini_api',
         'https://generativelanguage.googleapis.com/v1beta', True, 'https://aistudio.google.com/apikey'),
        ('openrouter', 'OpenRouter', 'R', '#6d5bd0', 'openai_chat', 'https://openrouter.ai/api/v1', True,
         'https://openrouter.ai/keys'),
        ('ollama', 'Ollama', 'Ol', '#52525b', 'openai_chat', 'http://127.0.0.1:11434/v1', False, ''),
        ('other', 'Other', '+', '#a1a1aa', '', '', False, ''),
    ]


def test_preset_lookup_and_preset_for():
    assert mc.preset('gemini').name == 'Google Gemini'
    with pytest.raises(KeyError):
        mc.preset('nope')
    assert mc.preset_for('openai_chat', 'http://127.0.0.1:11434/v1').id == 'ollama'
    assert mc.preset_for('openai_chat', 'https://api.openai.com/v1').id == 'openai'
    assert mc.preset_for('openai_chat', 'https://x.example.invalid/v1').id == 'other'
    assert mc.preset_for('anthropic_messages', 'https://api.openai.com/v1').id == 'other'


def test_job_names():
    assert mc.JOB_ORDER == ('proposer', 'reviewer', 'guard', 'summarizer')
    assert mc.JOB_NAMES == {'proposer': 'Triage', 'reviewer': 'Review', 'guard': 'Screening',
                            'summarizer': 'Summaries'}


def test_match_is_case_insensitive():
    entry = mc.match('anthropic', 'Claude-Sonnet-Whatever')
    assert entry is not None and entry.provider == 'anthropic' and entry.family == 'claude'


def test_first_match_wins(tmp_path):
    loaded = mc.load_catalogue(_write(tmp_path, [_model(pattern='gpt-*mini*', tier='small'), _model()]))
    assert [e.tier for e in loaded] == ['small', 'large']
    # In the shipped file the more specific small patterns come before the broad gpt-* one.
    assert mc.match('openai', 'gpt-5-mini').tier == 'small'
    assert mc.match('openai', 'gpt-5').tier == 'large'


def test_unmatched_cloud_model_is_none_and_ollama_is_local():
    assert mc.match('anthropic', 'totally-unknown') is None
    entry = mc.match('ollama', 'qwen3:8b-custom')
    assert (entry.tier, entry.cost, entry.family) == ('local', 'free', 'qwen')
    assert entry.strengths == 'Runs on your own server'


def test_each_cloud_provider_has_large_and_small():
    for provider in ('anthropic', 'openai', 'gemini'):
        tiers = {e.tier for e in mc.entries() if e.provider == provider}
        assert {'large', 'small'} <= tiers


def test_every_entry_family_is_known_and_family_for():
    assert all(e.family in FAMILIES for e in mc.entries())
    assert mc.family_for('anthropic', 'claude-3-haiku') == 'claude'
    assert mc.family_for('openrouter', 'mistral-small') == 'mistral'


@pytest.mark.parametrize('over', [{'tier': 'huge'}, {'cost': 'cheap'}, {'family': 'martian'}, {'pattern': ''},
                                  {'strengths': ''}, {'provider': 5}])
def test_malformed_entry_raises(tmp_path, over):
    with pytest.raises(ValueError):
        mc.load_catalogue(_write(tmp_path, [_model(**over)]))


def test_malformed_file_raises(tmp_path):
    bad = tmp_path / 'bad.json'
    bad.write_text('{')
    with pytest.raises(ValueError):
        mc.load_catalogue(bad)
    with pytest.raises(ValueError):
        mc.load_catalogue(_write(tmp_path, [], version=2))
