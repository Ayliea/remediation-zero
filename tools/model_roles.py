# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Per-role model configuration: proposer, reviewer, summarizer, guard.

Standard library only. The Vertex adapter is imported lazily, so the local
edition never needs a cloud SDK. Provenance carries no endpoint and no key.
"""
import os
from collections.abc import Mapping
from dataclasses import dataclass, field, replace

from tools.model_transport import validate_endpoint
from tools.models import FORMATS, build_adapter

ROLES = ('proposer', 'reviewer', 'summarizer', 'guard')
FAMILIES = ('gemini', 'gemma', 'llama', 'claude', 'gpt', 'qwen', 'mistral', 'deepseek', 'phi', 'other')
POLICIES = ('wait', 'proceed')
_PREFIXES = (('gemini', 'gemini'), ('gemma', 'gemma'), ('llama', 'llama'), ('claude', 'claude'),
             ('gpt', 'gpt'), ('o1', 'gpt'), ('o3', 'gpt'), ('o4', 'gpt'), ('qwen', 'qwen'),
             ('mistral', 'mistral'), ('mixtral', 'mistral'), ('deepseek', 'deepseek'), ('phi', 'phi'))


def suggest_family(model):
    name = model.lower() if isinstance(model, str) else ''
    for prefix, family in _PREFIXES:
        if name.startswith(prefix):
            return family
    return 'other'


@dataclass(frozen=True)
class RoleConfig:
    role: str
    format: str
    endpoint: str
    model: str
    family: str

    def __post_init__(self):
        if self.role not in ROLES:
            raise ValueError('Unknown model role')
        if self.format != 'vertex' and self.format not in FORMATS:
            raise ValueError('Unknown model format')
        if self.family not in FAMILIES:
            raise ValueError('Unknown model family')
        if not isinstance(self.model, str) or not self.model.strip() or len(self.model) > 200:
            raise ValueError('A model name is required (at most 200 characters)')
        if self.format != 'vertex':
            if not isinstance(self.endpoint, str) or len(self.endpoint) > 2048:
                raise ValueError('Invalid endpoint URL')
            validate_endpoint(self.endpoint)

    def as_settings(self):
        return {'format': self.format, 'endpoint': self.endpoint, 'model': self.model, 'family': self.family}


def _key_names(role):
    names = ['RZ_%s_API_KEY' % role.upper()]
    return names + ['RZ_MODEL_API_KEY'] if role == 'proposer' else names


def key_present(role, environ):
    """Whether an API key is set for the role. Reports presence only, never the value."""
    return any(bool(environ.get(n)) for n in _key_names(role))


@dataclass(frozen=True)
class ModelRoles:
    proposer: RoleConfig | None = None
    reviewer: RoleConfig | None = None
    summarizer: RoleConfig | None = None
    guard: RoleConfig | None = None
    same_family_policy: str = 'wait'
    #: Where adapter() reads API keys; None means the process environment.
    #: Never shown (repr=False) and not part of equality or the fingerprint.
    environ: Mapping[str, str] | None = field(default=None, repr=False, compare=False)

    def __post_init__(self):
        if self.same_family_policy not in POLICIES:
            raise ValueError('Unknown same-family policy')

    def configured(self):
        return [(role, getattr(self, role)) for role in ROLES if getattr(self, role) is not None]

    def independence(self):
        if self.reviewer is None:
            return 'unreviewed'
        families = (self.proposer.family if self.proposer else 'other', self.reviewer.family)
        if families[0] == families[1] or 'other' in families:
            return 'same_family'
        return 'cross_family'

    def provenance(self):
        return {role: {'format': c.format, 'model': c.model, 'family': c.family}
                for role, c in self.configured()}

    def adapter(self, role, *, vertex_client=None):
        config = getattr(self, role, None) if role in ROLES else None
        if config is None:
            raise ValueError('Model role is not configured: %s' % role)
        if config.format == 'vertex':
            from tools.vertex_models import VertexAdapter
            return VertexAdapter(vertex_client, config.model)
        environ = os.environ if self.environ is None else self.environ
        key = next((environ[n] for n in _key_names(role) if environ.get(n)), None)
        if key and ('\n' in key or '\r' in key):
            raise ValueError('Invalid API key')
        return build_adapter(config.format, config.endpoint, config.model, key)

    @classmethod
    def from_env(cls, environ):
        def build(role, base):
            prefix = 'RZ_%s_' % role.upper()
            model = environ.get(prefix + 'MODEL') or (base.model if base else '')
            if not model:
                return None
            fmt = environ.get(prefix + 'FORMAT') or (base.format if base else 'openai_chat')
            endpoint = environ.get(prefix + 'ENDPOINT', base.endpoint if base else '')
            family = environ.get(prefix + 'FAMILY') or (
                base.family if base and model == base.model else suggest_family(model))
            return RoleConfig(role, fmt, endpoint, model, family)

        def vertex(role, name):
            model = environ.get(name)
            return RoleConfig(role, 'vertex', '', model, suggest_family(model)) if model else None

        proposer = build('proposer', vertex('proposer', 'REASONING_MODEL'))
        reviewer = build('reviewer', vertex('reviewer', 'REVIEWER_MODEL'))
        summarizer = build('summarizer', replace(proposer, role='summarizer') if proposer else None)
        return cls(proposer, reviewer, summarizer, build('guard', None), 'wait')

    @classmethod
    def from_settings(cls, settings, environ):
        """Roles from local settings; `environ` overrides the proposer connection."""
        roles = settings.get('roles') or {}
        built = {role: RoleConfig(role, **roles[role]) if roles.get(role) else None for role in ROLES}
        endpoint, model = environ.get('RZ_MODEL_ENDPOINT'), environ.get('RZ_MODEL')
        if endpoint or model:
            saved = built['proposer']
            use_model = model or (saved.model if saved else '')
            same = saved is not None and use_model == saved.model
            built['proposer'] = RoleConfig(
                'proposer', saved.format if saved else 'openai_chat',
                endpoint or (saved.endpoint if saved else ''), use_model,
                saved.family if same else suggest_family(use_model))
        return cls(**built, same_family_policy=settings.get('same_family_policy', 'wait'),
                   environ=environ)
