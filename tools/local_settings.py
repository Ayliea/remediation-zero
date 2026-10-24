# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Non-secret local preferences, validated before atomic persistence."""
import copy
import json
import os
from pathlib import Path
import tempfile
from tools.model_roles import POLICIES, ROLES, RoleConfig, suggest_family

DEFAULTS = {'version': 2, 'roles': {role: None for role in ROLES}, 'same_family_policy': 'wait',
            'mode': 'demo', 'open_browser': True, 'port': 8081, 'cycle_interval_minutes': 0}
_V1_FIELDS = {'endpoint', 'model', 'mode', 'open_browser', 'port'}
_ROLE_FIELDS = {'format', 'endpoint', 'model', 'family'}


def settings_path(database):
    return Path(database).resolve().with_suffix('.settings.json')


def validate(value):
    if not isinstance(value, dict) or set(value) != set(DEFAULTS) or value['version'] != 2:
        raise ValueError('Unexpected settings fields')
    roles = value['roles']
    if not isinstance(roles, dict) or set(roles) != set(ROLES):
        raise ValueError('Unexpected settings fields')
    for role, raw in roles.items():
        if raw is None:
            continue
        if not isinstance(raw, dict) or set(raw) != _ROLE_FIELDS:
            raise ValueError('Unexpected settings fields')
        if raw['format'] == 'vertex':
            raise ValueError('The local edition has no cloud model format')
        RoleConfig(role, **raw)
    if value['same_family_policy'] not in POLICIES:
        raise ValueError('Invalid same-family policy')
    if not isinstance(value['mode'], str) or value['mode'] not in {'demo', 'saved'} or type(value['open_browser']) is not bool:
        raise ValueError('Invalid startup preferences')
    if type(value['port']) is not int or not 1024 <= value['port'] <= 65535:
        raise ValueError('Choose a port from 1024 to 65535')
    if type(value['cycle_interval_minutes']) is not int or not 0 <= value['cycle_interval_minutes'] <= 1440:
        raise ValueError('Choose a cycle interval from 0 to 1440 minutes')
    return copy.deepcopy(value)


def _upgrade_v1(value):
    if not isinstance(value, dict) or set(value) != _V1_FIELDS:
        raise ValueError('Unexpected settings fields')
    if not all(isinstance(value[k], str) for k in ('endpoint', 'model', 'mode')):
        raise ValueError('Invalid text settings')
    upgraded = copy.deepcopy(DEFAULTS)
    upgraded.update(mode=value['mode'], open_browser=value['open_browser'], port=value['port'])
    if value['endpoint'] or value['model']:
        upgraded['roles']['proposer'] = {'format': 'openai_chat', 'endpoint': value['endpoint'],
                                         'model': value['model'], 'family': suggest_family(value['model'])}
    return upgraded


def load(path):
    try:
        raw = json.loads(Path(path).read_text())
    except FileNotFoundError:
        return copy.deepcopy(DEFAULTS)
    if isinstance(raw, dict) and 'version' not in raw:
        raw = _upgrade_v1(raw)
    return validate(raw)


def save(path, value):
    value = validate(value)
    path = Path(path)
    fd, name = tempfile.mkstemp(prefix='.rz-settings-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)
