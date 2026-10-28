# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Which jobs a newly chosen model should take: a pure function over the settings dict.

Standard library only. Rules follow the design spec, "Recommendations": gaps first,
independent review, never silently replace, match the job to the tier, cost as a sentence.
It reads no environment and no key file, and never changes a badge because of cost.
"""
from dataclasses import dataclass

from tools.model_catalogue import JOB_NAMES, JOB_ORDER, match

DESCRIPTIONS = {
    'proposer': 'Proposes severity, deadline and fix, citing evidence.',
    'reviewer': 'Double-checks every triage proposal before anything happens.',
    'guard': 'Checks scanner text for tricks before any model reads it.',
    'summarizer': 'Writes the plain-English report of each cycle.',
}
COSTS = {'higher': 'Costs more per finding.', 'lower': 'Costs less per finding.',
         'free': 'Free, runs on your own server.'}
SAME_FAMILY_REASON = 'Same family as your triage model, so the record would read "reviewed by the same model family".'
REVIEW_SAME_FAMILY = 'Review (%s) is the same family, so the record would read "reviewed by the same model family".'
POLICY_NOTES = {'wait': "With 'wait', triage waits for a person before anything is assigned.",
                'proceed': "With 'proceed', it is assigned without waiting."}
UNKNOWN = "We don't know this model's strengths."


@dataclass(frozen=True)
class Card:
    role: str
    job: str
    description: str
    badge: str  # 'recommended' | 'covered' | 'not_suggested'
    on: bool
    reason: str
    cost: str | None
    same_family: bool
    policy_note: str | None


def _same(a, b):
    """The rule ModelRoles.independence() applies: equal, or either 'other'."""
    return a == b or 'other' in (a, b)


def recommend(settings, *, provider, model, family, editing=None):
    roles = settings.get('roles') or {}
    connections = settings.get('connections') or {}
    entry = match(provider, model)
    policy = POLICY_NOTES.get(settings.get('same_family_policy', 'wait'), POLICY_NOTES['wait'])

    def covering(role):
        """The connection record already doing the job (not the one being edited), else None."""
        raw = roles.get(role)
        if not raw or raw['connection'] == editing:
            return None
        return connections.get(raw['connection']) or {'name': 'Another connection', 'provider': ''}

    def current_family(role):
        raw = roles.get(role)
        return raw['family'] if raw else None

    covered = {role: covering(role) for role in JOB_ORDER}
    triage_on = covered['proposer'] is None
    triage_family = family if triage_on else current_family('proposer')

    # Review is decided first: Triage's knock-on sentence depends on it.
    review_on = False
    review_same = False
    if covered['reviewer'] is None:
        review_same = _same(triage_family, family)
        review_on = not review_same
    if review_on:
        review_family = family
    else:
        review_family = current_family('reviewer') if covered['reviewer'] is not None else None

    def knock_on(role):
        """Would switching this covered job on be what makes Review the same family as Triage?"""
        if role == 'proposer':
            return review_family is not None and _same(family, review_family)
        # Already the same family with Review left as it is: switching on causes nothing new.
        return _same(triage_family, family) and not _same(triage_family, current_family('reviewer'))

    weak = entry is not None and entry.tier in ('small', 'local')
    large = entry is not None and entry.tier == 'large'
    cards = []
    for role in JOB_ORDER:
        conn = covered[role]
        badge, on, same_family, note = 'recommended', True, False, None
        if conn is not None:
            badge, on = 'covered', False
            reason = '%s already does this. Switching on replaces it' % conn['name']
            if role in ('proposer', 'reviewer') and knock_on(role):
                reason += (', and then Review would be the same family, which the record would say.'
                           if role == 'proposer' else
                           ', and then it would be the same family as Triage, which the record would say.')
                same_family, note = True, policy
            else:
                reason += '.'
            if role in ('guard', 'summarizer') and large:
                held = match(conn['provider'], roles[role]['model'])
                if held is not None and held.tier in ('local', 'small'):
                    badge = 'not_suggested'
                    reason = '%s already does this at lower cost. A large model is not needed here.' % conn['name']
        elif role == 'proposer':
            reason = 'Without triage no cycle runs.'
            # Review stays on another connection: this model's triage would be reviewed by its own family.
            if covered['reviewer'] is not None and _same(family, current_family('reviewer')):
                reason += ' ' + REVIEW_SAME_FAMILY % current_family('reviewer')
                same_family, note = True, policy
        elif role == 'reviewer':
            if review_same:
                badge, on, same_family, note = 'not_suggested', False, True, policy
                reason = SAME_FAMILY_REASON
            else:
                reason = ('Nothing double-checks triage yet, and %s is a different family from your triage model (%s).'
                          % (family, triage_family))
        elif role == 'guard':
            reason = 'Nothing screens scanner text yet.'
        else:
            reason = 'Nothing writes the cycle report yet.'
        if badge == 'recommended':
            if role in ('proposer', 'reviewer') and weak:
                reason += ' A stronger model would do this better.'
            elif role in ('guard', 'summarizer') and large:
                reason += ' A smaller model would be cheaper here, but this one works.'
        if entry is None:
            reason += ' ' + UNKNOWN
        cards.append(Card(role=role, job=JOB_NAMES[role], description=DESCRIPTIONS[role], badge=badge, on=on,
                          reason=reason, cost=COSTS[entry.cost] if entry else None,
                          same_family=same_family, policy_note=note))
    return cards
