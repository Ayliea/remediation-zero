# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Job recommendations for a newly chosen model."""
import copy
import dataclasses
import itertools

import pytest

from tools import connection_advice as ca
from tools.connection_advice import recommend
from tools.local_settings import DEFAULTS, validate
from tools.model_catalogue import JOB_ORDER

OA = 'conn-aaaaaaaaaaaa'
OL = 'conn-bbbbbbbbbbbb'
AN = 'conn-cccccccccccc'


def conn(name, provider, fmt, base, source):
    return {'name': name, 'provider': provider, 'format': fmt, 'base_url': base, 'endpoint_style': 'base',
            'ca_file': '', 'key_source': source, 'last_test': None}


def job(cid, model, family):
    return {'connection': cid, 'model': model, 'family': family, 'timeout_seconds': 60}


def settings(policy='wait', **roles):
    value = copy.deepcopy(DEFAULTS)
    value['connections'] = {
        OA: conn('OpenAI', 'openai', 'openai_chat', 'https://api.openai.com/v1', 'stored'),
        OL: conn('Local', 'ollama', 'openai_chat', 'http://127.0.0.1:11434/v1', 'none'),
        AN: conn('Anthropic', 'anthropic', 'anthropic_messages', 'https://api.anthropic.com/v1', 'stored'),
    }
    value['roles'].update(roles)
    value['same_family_policy'] = policy
    return validate(value)


def by_role(cards):
    return {c.role: c for c in cards}


def test_one_card_per_job_in_order_with_fixed_descriptions():
    cards = recommend(settings(), provider='openai', model='gpt-test', family='gpt')
    assert [c.role for c in cards] == list(JOB_ORDER)
    assert [c.job for c in cards] == ['Triage', 'Review', 'Screening', 'Summaries']
    assert cards[0].description == 'Proposes severity, deadline and fix, citing evidence.'
    assert cards[3].description == 'Writes the plain-English report of each cycle.'


def test_mockup_openai_triage_ollama_screening_adding_large_anthropic():
    s = settings(proposer=job(OA, 'gpt-test', 'gpt'), guard=job(OL, 'llama3', 'llama'))
    cards = by_role(recommend(s, provider='anthropic', model='claude-test', family='claude'))
    assert (cards['reviewer'].badge, cards['reviewer'].on) == ('recommended', True)
    assert 'claude' in cards['reviewer'].reason and 'gpt' in cards['reviewer'].reason
    assert (cards['summarizer'].badge, cards['summarizer'].on) == ('recommended', True)
    assert (cards['proposer'].badge, cards['proposer'].on) == ('covered', False)
    assert cards['proposer'].reason == ('OpenAI already does this. Switching on replaces it, and then Review would be '
                                        'the same family, which the record would say.')
    assert (cards['guard'].badge, cards['guard'].on) == ('not_suggested', False)
    assert 'Local' in cards['guard'].reason


@pytest.mark.parametrize('policy,note', [
    ('wait', "With 'wait', triage waits for a person before anything is assigned."),
    ('proceed', "With 'proceed', it is assigned without waiting.")])
def test_first_connection_ever_cannot_review_itself(policy, note):
    cards = by_role(recommend(settings(policy), provider='openai', model='gpt-test', family='gpt'))
    assert cards['proposer'].reason == 'Without triage no cycle runs.'
    for role in ('proposer', 'guard', 'summarizer'):
        assert (cards[role].badge, cards[role].on) == ('recommended', True)
    review = cards['reviewer']
    assert (review.badge, review.on, review.same_family) == ('not_suggested', False, True)
    assert review.reason == ('Same family as your triage model, so the record would read '
                             '"reviewed by the same model family".')
    assert review.policy_note == note


def test_family_other_counts_as_same_family():
    s = settings(proposer=job(OA, 'gpt-test', 'gpt'))
    cards = by_role(recommend(s, provider='openai', model='mystery', family='other'))
    assert (cards['reviewer'].badge, cards['reviewer'].on, cards['reviewer'].same_family) == (
        'not_suggested', False, True)
    s = settings(proposer=job(OA, 'mystery', 'other'))
    cards = by_role(recommend(s, provider='anthropic', model='claude-test', family='claude'))
    assert cards['reviewer'].badge == 'not_suggested'


@pytest.mark.parametrize('covered', [set(c) for n in range(5) for c in itertools.combinations(JOB_ORDER, n)])
def test_a_covered_job_never_starts_on(covered):
    models = {'proposer': ('gpt-test', 'gpt'), 'reviewer': ('claude-test', 'claude'),
              'guard': ('llama3', 'llama'), 'summarizer': ('llama3', 'llama')}
    roles = {r: job(OA if r in ('proposer', 'reviewer') else OL, *models[r]) for r in covered}
    for provider, model, family in (('gemini', 'gemini-test', 'gemini'), ('openai', 'gpt-test', 'gpt'),
                                    ('x', 'm', 'other')):
        cards = by_role(recommend(settings(**roles), provider=provider, model=model, family=family))
        for role in covered:
            assert cards[role].on is False
            assert cards[role].badge in ('covered', 'not_suggested')
        for card in cards.values():
            assert card.on == (card.badge == 'recommended')


def test_cost_changes_the_sentence_never_the_badge(monkeypatch):
    s = settings(proposer=job(OA, 'gpt-test', 'gpt'), guard=job(OL, 'llama3', 'llama'))
    seen = {}
    real = ca.match
    for cost, sentence in (('higher', 'Costs more per finding.'), ('lower', 'Costs less per finding.'),
                           ('free', 'Free, runs on your own server.')):
        monkeypatch.setattr(ca, 'match', lambda p, m, cost=cost: dataclasses.replace(real(p, m), cost=cost)
                            if p == 'anthropic' else real(p, m))
        cards = recommend(s, provider='anthropic', model='claude-test', family='claude')
        seen[cost] = [(c.badge, c.on) for c in cards]
        assert {c.cost for c in cards} == {sentence}
    assert seen['higher'] == seen['lower'] == seen['free']


def test_unknown_model_uses_family_only_and_says_so():
    cards = recommend(settings(proposer=job(OA, 'gpt-test', 'gpt')), provider='other', model='zz-9', family='zz')
    by = by_role(cards)
    assert by['reviewer'].badge == 'recommended'
    assert by['proposer'].badge == 'covered'
    for card in cards:
        assert card.cost is None
        assert card.reason.endswith("We don't know this model's strengths.")


def test_editing_a_connection_treats_its_own_jobs_as_its_own():
    s = settings(proposer=job(OA, 'gpt-test', 'gpt'), summarizer=job(OL, 'llama3', 'llama'))
    plain = by_role(recommend(s, provider='openai', model='gpt-test-mini', family='gpt'))
    assert plain['proposer'].badge == 'covered'
    own = by_role(recommend(s, provider='openai', model='gpt-test-mini', family='gpt', editing=OA))
    assert (own['proposer'].badge, own['proposer'].on) == ('recommended', True)
    assert 'replaces' not in own['proposer'].reason
    assert own['summarizer'].badge == 'covered'
    assert 'Local already does this' in own['summarizer'].reason


def test_triage_without_knock_on_has_no_extra_sentence():
    s = settings(proposer=job(OA, 'gpt-test', 'gpt'), reviewer=job(AN, 'claude-test', 'claude'))
    cards = by_role(recommend(s, provider='gemini', model='gemini-test', family='gemini'))
    assert cards['proposer'].reason == 'OpenAI already does this. Switching on replaces it.'


def test_weak_tiers_keep_the_badge_and_add_the_suffix():
    cards = by_role(recommend(settings(), provider='ollama', model='llama3', family='llama'))
    assert (cards['proposer'].badge, cards['proposer'].on) == ('recommended', True)
    assert cards['proposer'].reason.endswith('A stronger model would do this better.')
    assert 'stronger' not in cards['summarizer'].reason


def test_large_model_uncovered_for_cheap_jobs_works_but_costs_more():
    cards = by_role(recommend(settings(), provider='anthropic', model='claude-test', family='claude'))
    assert cards['guard'].badge == 'recommended'
    assert cards['guard'].reason.endswith('A smaller model would be cheaper here, but this one works.')
