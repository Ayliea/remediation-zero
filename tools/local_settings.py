# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Non-secret local preferences, validated before atomic persistence."""
import copy
import ipaddress
import json
import os
from pathlib import Path
import re
import tempfile
from tools.gmp import GmpTarget
from tools.model_transport import CertificateFileUnreadable, tls_context
from tools.model_roles import POLICIES, ROLES, RoleConfig, suggest_family

SCANNER_DEFAULTS = {'transport': 'unix', 'socket_path': '', 'host': '', 'port': 9390, 'ca_file': '',
                    'task_ids': [], 'qod_floor': 70, 'auto_enrichment': False}
DEFAULTS = {'version': 4, 'roles': {role: None for role in ROLES}, 'same_family_policy': 'wait',
            'mode': 'demo', 'open_browser': True, 'port': 8081, 'cycle_interval_minutes': 0,
            'scanner': SCANNER_DEFAULTS}
_V2_FIELDS = set(DEFAULTS) - {'scanner'}
TASK_ID_RE = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
_HOSTNAME_RE = re.compile(r'[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?')
_V1_FIELDS = {'endpoint', 'model', 'mode', 'open_browser', 'port'}
_ROLE_FIELDS = {'format', 'endpoint', 'model', 'family', 'ca_file'}
_V3_ROLE_FIELDS = _ROLE_FIELDS - {'ca_file'}


def settings_path(database):
    return Path(database).resolve().with_suffix('.settings.json')


def validate(value):
    if not isinstance(value, dict) or set(value) != set(DEFAULTS) or value['version'] != 4:
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
    _validate_scanner(value['scanner'])
    return copy.deepcopy(value)


def _absolute_path(value, what):
    if not isinstance(value, str) or '\n' in value or '\r' in value or '\0' in value:
        raise ValueError(f'Invalid {what}')
    if value and not os.path.isabs(value):
        raise ValueError(f'The {what} must be an absolute path')


def _validate_scanner(scanner):
    # Exactly these fields: a credential (username, password, token) has no place to live.
    if not isinstance(scanner, dict) or set(scanner) != set(SCANNER_DEFAULTS):
        raise ValueError('Unexpected settings fields')
    if not isinstance(scanner['transport'], str) or scanner['transport'] not in {'unix', 'tls'}:
        raise ValueError('The Greenbone transport must be unix or tls')
    _absolute_path(scanner['socket_path'], 'socket path')
    _absolute_path(scanner['ca_file'], 'CA file')
    host = scanner['host']
    if not isinstance(host, str):
        raise ValueError('Invalid Greenbone host')
    if host:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not _HOSTNAME_RE.fullmatch(host):
                raise ValueError('The Greenbone host must be a hostname or IP address') from None
    if scanner['transport'] == 'tls' and not host:
        raise ValueError('A TLS connection needs a host')
    if type(scanner['port']) is not int or not 1 <= scanner['port'] <= 65535:
        raise ValueError('Choose a Greenbone port from 1 to 65535')
    if type(scanner['qod_floor']) is not int or not 0 <= scanner['qod_floor'] <= 100:
        raise ValueError('Choose a quality-of-detection floor from 0 to 100')
    if type(scanner['auto_enrichment']) is not bool:
        raise ValueError('Invalid auto-enrichment setting')
    ids = scanner['task_ids']
    if not isinstance(ids, list) or not all(isinstance(i, str) and TASK_ID_RE.fullmatch(i) for i in ids):
        raise ValueError('Task IDs must be lowercase UUIDs')
    if len(set(ids)) != len(ids):
        raise ValueError('Task IDs must not repeat')


def gmp_target(settings, *, timeout=30.0):
    """The GMP endpoint the saved settings name. Raises ValueError if it is not yet configured."""
    scanner = validate(settings)['scanner']
    if scanner['transport'] == 'unix' and not scanner['socket_path']:
        raise ValueError('No Greenbone socket path is set')
    return GmpTarget(transport=scanner['transport'], socket_path=scanner['socket_path'] or None,
                     host=scanner['host'] or None, port=scanner['port'],
                     ca_file=scanner['ca_file'] or None, timeout=timeout)


def check_ca_file(path):
    """Refuse a CA certificate file that cannot be used, when it is saved. Not part of
    validate(): settings must still load if the file later moves; the model call then
    reports CertificateFileUnreadable."""
    try:
        tls_context(path)
    except CertificateFileUnreadable:
        raise ValueError('The CA certificate file could not be read as a PEM certificate') from None


def _upgrade_v3(value):
    """v3 had no per-role CA file: each configured role gains an empty one."""
    if not isinstance(value, dict) or set(value) != set(DEFAULTS) or not isinstance(value.get('roles'), dict):
        raise ValueError('Unexpected settings fields')
    upgraded = dict(copy.deepcopy(value), version=4)
    for role, raw in upgraded['roles'].items():
        if raw is not None:
            if not isinstance(raw, dict) or set(raw) != _V3_ROLE_FIELDS:
                raise ValueError('Unexpected settings fields')
            raw['ca_file'] = ''
    return validate(upgraded)


def _upgrade_v2(value):
    if not isinstance(value, dict) or set(value) != _V2_FIELDS:
        raise ValueError('Unexpected settings fields')
    upgraded = dict(copy.deepcopy(value), version=3, scanner=copy.deepcopy(SCANNER_DEFAULTS))
    return _upgrade_v3(upgraded)


def _upgrade_v1(value):
    if not isinstance(value, dict) or set(value) != _V1_FIELDS:
        raise ValueError('Unexpected settings fields')
    if not all(isinstance(value[k], str) for k in ('endpoint', 'model', 'mode')):
        raise ValueError('Invalid text settings')
    upgraded = copy.deepcopy(DEFAULTS)
    upgraded.update(mode=value['mode'], open_browser=value['open_browser'], port=value['port'])
    if value['endpoint'] or value['model']:
        upgraded['roles']['proposer'] = {'format': 'openai_chat', 'endpoint': value['endpoint'],
                                         'model': value['model'], 'family': suggest_family(value['model']),
                                         'ca_file': ''}
    return upgraded


def load(path):
    try:
        raw = json.loads(Path(path).read_text())
    except FileNotFoundError:
        return copy.deepcopy(DEFAULTS)
    if isinstance(raw, dict) and 'version' not in raw:
        raw = _upgrade_v1(raw)
    elif isinstance(raw, dict) and raw.get('version') == 2:
        return _upgrade_v2(raw)  # in memory only; the next save writes v4, as for v1
    elif isinstance(raw, dict) and raw.get('version') == 3:
        return _upgrade_v3(raw)
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
