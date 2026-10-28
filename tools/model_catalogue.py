# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Provider presets and the small model catalogue behind Settings -> Models.

Standard library only. The data lives in model_catalogue.json beside this file,
is versioned and reviewed like a prompt, and is validated at import: a bad edit
fails the suite. It will go stale, so entries claim nothing beyond tier, speed
and relative cost, and an unmatched model is simply unknown. No network lookup.
"""
import fnmatch
import json
import re
from dataclasses import dataclass
from pathlib import Path

from tools.model_roles import FAMILIES, suggest_family

JOB_NAMES = {'proposer': 'Triage', 'reviewer': 'Review', 'guard': 'Screening', 'summarizer': 'Summaries'}
JOB_ORDER = ('proposer', 'reviewer', 'guard', 'summarizer')
TIERS = ('large', 'small', 'local')
COSTS = ('higher', 'lower', 'free')
_PATH = Path(__file__).with_name('model_catalogue.json')
#: A tile's colour reaches a style attribute, and its key page a link: both are held to these.
_COLOUR = re.compile(r'#[0-9a-f]{6}')
_KEY_PAGE = re.compile(r'https://[a-z0-9.-]+(/[A-Za-z0-9._~/-]*)?')


@dataclass(frozen=True)
class Preset:
    id: str
    name: str
    letter: str
    colour: str
    format: str
    base_url: str
    needs_key: bool
    key_page: str


@dataclass(frozen=True)
class Entry:
    provider: str
    pattern: str
    family: str
    tier: str
    strengths: str
    cost: str


def _text(item, field, required=True):
    value = item.get(field) if isinstance(item, dict) else None
    if not isinstance(value, str) or len(value) > 2048 or (required and not value.strip()):
        raise ValueError('Model catalogue: bad %r' % field)
    return value


def _load(path):
    try:
        data = json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        raise ValueError('Model catalogue cannot be read (%s)' % type(exc).__name__) from None
    if not isinstance(data, dict) or data.get('version') != 1:
        raise ValueError('Model catalogue: unsupported version')
    if not isinstance(data.get('providers'), list) or not isinstance(data.get('models'), list):
        raise ValueError('Model catalogue: providers and models must be lists')
    return data


def load_presets(path=_PATH):
    out = []
    for item in _load(path)['providers']:
        if not isinstance(item, dict) or not isinstance(item.get('needs_key'), bool):
            raise ValueError('Model catalogue: bad provider')
        out.append(Preset(id=_text(item, 'id'), name=_text(item, 'name'), letter=_text(item, 'letter'),
                          colour=_text(item, 'colour'), format=_text(item, 'format', False),
                          base_url=_text(item, 'base_url', False), needs_key=item['needs_key'],
                          key_page=_text(item, 'key_page', False)))
        if not _COLOUR.fullmatch(out[-1].colour) or not (out[-1].key_page == '' or _KEY_PAGE.fullmatch(out[-1].key_page)):
            raise ValueError('Model catalogue: a colour is #rrggbb and a key page an https:// address')
    return tuple(out)


def load_catalogue(path=_PATH):
    out = []
    for item in _load(path)['models']:
        entry = Entry(provider=_text(item, 'provider'), pattern=_text(item, 'pattern').lower(),
                      family=_text(item, 'family'), tier=_text(item, 'tier'),
                      strengths=_text(item, 'strengths'), cost=_text(item, 'cost'))
        if entry.family not in FAMILIES or entry.tier not in TIERS or entry.cost not in COSTS:
            raise ValueError('Model catalogue: unknown family, tier or cost')
        out.append(entry)
    return tuple(out)


_PRESETS = load_presets()
_ENTRIES = load_catalogue()


def presets():
    return _PRESETS


def entries():
    return _ENTRIES


def preset(id):
    for item in _PRESETS:
        if item.id == id:
            return item
    raise KeyError(id)


def preset_for(format, base_url):
    """The preset whose format and base URL match, else Other."""
    wanted = (base_url or '').rstrip('/').lower()
    for item in _PRESETS:
        if item.base_url and item.format == format and item.base_url.rstrip('/').lower() == wanted:
            return item
    return preset('other')


def match(provider, model):
    """The first catalogue entry for the model, a generic local entry for Ollama, else None."""
    name = model.lower() if isinstance(model, str) else ''
    for entry in _ENTRIES:
        if entry.provider == provider and fnmatch.fnmatchcase(name, entry.pattern):
            return entry
    if provider == 'ollama':
        return Entry('ollama', '*', suggest_family(model), 'local', 'Runs on your own server', 'free')
    return None


def family_for(provider, model):
    entry = match(provider, model)
    return entry.family if entry else suggest_family(model)
