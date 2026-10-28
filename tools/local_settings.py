# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Non-secret local preferences, validated before atomic persistence."""
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import tempfile
from tools.gmp import GmpTarget
from tools.model_catalogue import JOB_NAMES, preset_for, presets
from tools.model_endpoints import call_endpoint, split_endpoint
from tools.model_transport import CertificateFileUnreadable, tls_context, validate_endpoint
from tools.model_roles import POLICIES, ROLES, RoleConfig, suggest_family
from tools.models import FORMATS

SCANNER_DEFAULTS = {'transport': 'unix', 'socket_path': '', 'host': '', 'port': 9390, 'ca_file': '',
                    'task_ids': [], 'qod_floor': 70, 'auto_enrichment': False}
CERTIFICATE_DEFAULTS = {'mode': 'self-signed', 'cert_file': '', 'key_file': ''}
DEFAULTS = {'version': 6, 'connections': {}, 'roles': {role: None for role in ROLES},
            'same_family_policy': 'wait', 'mode': 'demo', 'open_browser': True, 'port': 8081,
            'cycle_interval_minutes': 0, 'scanner': SCANNER_DEFAULTS, 'listen_address': '127.0.0.1',
            'server_names': [], 'certificate': CERTIFICATE_DEFAULTS}
_V5_FIELDS = set(DEFAULTS) - {'connections'}
_V4_ADDED = {'listen_address', 'server_names', 'certificate'}
_V3_FIELDS = _V5_FIELDS - _V4_ADDED
_V2_FIELDS = _V3_FIELDS - {'scanner'}
MAX_SERVER_NAMES = 20
#: The one rule for a host name people type or a proxy forwards (lower case). scripts/local.py's
#: public_origin uses it too.
PUBLIC_HOST_RE = re.compile(r'[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?')
TASK_ID_RE = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
_HOSTNAME_RE = re.compile(r'[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?')
_V1_FIELDS = {'endpoint', 'model', 'mode', 'open_browser', 'port'}
#: A v5 role carried its whole call; a v6 role points at a connection for format, address and CA file.
_V5_ROLE_FIELDS = {'format', 'endpoint', 'model', 'family', 'ca_file', 'timeout_seconds'}
_V3_ROLE_FIELDS = _V5_ROLE_FIELDS - {'ca_file', 'timeout_seconds'}
_ROLE_FIELDS = {'connection', 'model', 'family', 'timeout_seconds'}
#: Exactly these fields: a key has no place to live in a connection (it is in the key file or
#: the environment).
CONNECTION_FIELDS = {'name', 'provider', 'format', 'base_url', 'endpoint_style', 'ca_file', 'key_source',
                     'last_test'}
LAST_TEST_FIELDS = {'ok', 'error', 'seconds', 'jobs', 'real_ts', 'sim_ts'}
KEY_SOURCES = ('stored', 'environment', 'none')
CONNECTION_ID_RE = re.compile(r'conn-[0-9a-f]{12}')
MAX_CONNECTION_NAME = 60
#: A test's error is an exception class name, never its message (which could carry anything).
_ERROR_CLASS_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_.]{0,99}')


def settings_path(database):
    return Path(database).resolve().with_suffix('.settings.json')


def new_connection_id():
    return 'conn-' + secrets.token_hex(6)


def migrated_connection_id(role):
    """The id of the connection a v5 role becomes: derived from the role, the v5 grouping (one
    connection per configured role), so every load of one v5 file gives the same settings, and no
    two roles' ids collide."""
    return 'conn-' + hashlib.sha256(f'v5-{role}'.encode()).hexdigest()[:12]


def validate(value):
    if not isinstance(value, dict) or set(value) != set(DEFAULTS) or value['version'] != 6:
        raise ValueError('Unexpected settings fields')
    connections = value['connections']
    if not isinstance(connections, dict):
        raise ValueError('Unexpected settings fields')
    names = set()
    for cid, conn in connections.items():
        if not isinstance(cid, str) or not CONNECTION_ID_RE.fullmatch(cid):
            raise ValueError('Unexpected settings fields')
        _validate_connection(conn)
        if conn['name'].casefold() in names:
            raise ValueError('Each connection needs its own name')
        names.add(conn['name'].casefold())
    roles = value['roles']
    if not isinstance(roles, dict) or set(roles) != set(ROLES):
        raise ValueError('Unexpected settings fields')
    for role, raw in roles.items():
        if raw is None:
            continue
        if not isinstance(raw, dict) or set(raw) != _ROLE_FIELDS:
            raise ValueError('Unexpected settings fields')
        if not isinstance(raw['connection'], str) or raw['connection'] not in connections:
            raise ValueError('A job points at a connection that does not exist')
        if not isinstance(raw['model'], str):
            raise ValueError('A model name is required (at most 200 characters)')
        conn = connections[raw['connection']]
        # The call each job makes must pass the endpoint rules, as a v5 role's did.
        RoleConfig(role, conn['format'], call_endpoint(conn['format'], conn['base_url'], raw['model'],
                                                       conn['endpoint_style']),
                   raw['model'], raw['family'], conn['ca_file'], raw['timeout_seconds'], raw['connection'])
    return _validate_rest(value)


def _validate_connection(conn):
    if not isinstance(conn, dict) or set(conn) != CONNECTION_FIELDS:
        raise ValueError('Unexpected settings fields')
    name = conn['name']
    if (not isinstance(name, str) or not 1 <= len(name) <= MAX_CONNECTION_NAME or not name.strip()
            or any(ord(c) < 32 or 127 <= ord(c) < 160 for c in name)):
        raise ValueError(f'A connection name is 1 to {MAX_CONNECTION_NAME} characters on one line')
    if conn['provider'] not in {p.id for p in presets()}:
        raise ValueError('Unknown provider')
    if conn['format'] == 'vertex':
        raise ValueError('The local edition has no cloud model format')
    if conn['format'] not in FORMATS:
        raise ValueError('Unknown model format')
    if not isinstance(conn['base_url'], str) or len(conn['base_url']) > 2048:
        raise ValueError('Invalid endpoint URL')
    validate_endpoint(conn['base_url'])
    if conn['endpoint_style'] not in {'base', 'exact'}:
        raise ValueError('Unexpected settings fields')
    ca_file = conn['ca_file']
    if not isinstance(ca_file, str) or len(ca_file) > 4096 or any(c in ca_file for c in '\n\r\0'):
        raise ValueError('Invalid CA certificate file')
    if ca_file:
        if not os.path.isabs(ca_file):
            raise ValueError('The CA certificate file must be an absolute path')
        if not conn['base_url'].lower().startswith('https://'):
            raise ValueError('A CA certificate file applies only to an HTTPS endpoint')
    if conn['key_source'] not in KEY_SOURCES:
        raise ValueError('Unexpected settings fields')
    test = conn['last_test']
    if test is None:
        return
    number = lambda v: type(v) in (int, float) and v >= 0
    if (not isinstance(test, dict) or set(test) != LAST_TEST_FIELDS or type(test['ok']) is not bool
            or not isinstance(test['error'], str)
            or (test['error'] and not _ERROR_CLASS_RE.fullmatch(test['error']))
            or not all(number(test[k]) for k in ('seconds', 'real_ts', 'sim_ts'))
            or not isinstance(test['jobs'], list) or not all(j in ROLES for j in test['jobs'])
            or len(set(test['jobs'])) != len(test['jobs'])):
        raise ValueError('Unexpected settings fields')


def _validate_v5(value):
    """A version 5 file as it was saved: each role carries its whole call."""
    if not isinstance(value, dict) or set(value) != _V5_FIELDS or value['version'] != 5:
        raise ValueError('Unexpected settings fields')
    roles = value['roles']
    if not isinstance(roles, dict) or set(roles) != set(ROLES):
        raise ValueError('Unexpected settings fields')
    for role, raw in roles.items():
        if raw is None:
            continue
        if not isinstance(raw, dict) or set(raw) != _V5_ROLE_FIELDS:
            raise ValueError('Unexpected settings fields')
        if raw['format'] == 'vertex':
            raise ValueError('The local edition has no cloud model format')
        RoleConfig(role, **raw)
    return _validate_rest(value)


def _validate_rest(value):
    """Everything but the models, the same in v5 and v6."""
    if value['same_family_policy'] not in POLICIES:
        raise ValueError('Invalid same-family policy')
    if not isinstance(value['mode'], str) or value['mode'] not in {'demo', 'saved'} or type(value['open_browser']) is not bool:
        raise ValueError('Invalid startup preferences')
    if type(value['port']) is not int or not 1024 <= value['port'] <= 65535:
        raise ValueError('Choose a port from 1024 to 65535')
    if type(value['cycle_interval_minutes']) is not int or not 0 <= value['cycle_interval_minutes'] <= 1440:
        raise ValueError('Choose a cycle interval from 0 to 1440 minutes')
    _validate_scanner(value['scanner'])
    _validate_listening(value)
    return copy.deepcopy(value)


def normalize_server_name(name):
    """A host name (lower-cased) or an IP literal as people type it; ValueError otherwise."""
    if not isinstance(name, str):
        raise ValueError('A server name must be text')
    name = name.strip().lower()
    if '%' in name:
        raise ValueError('An IPv6 scope ID is not allowed')
    try:
        return str(ipaddress.ip_address(name))
    except ValueError:
        pass
    if not PUBLIC_HOST_RE.fullmatch(name):
        raise ValueError('A server name must be a host name or an IP address')
    return name


def parse_server_names(text):
    """Names from a comma- or space-separated list, validated, lower-cased, de-duplicated in order."""
    names = []
    for raw in re.split(r'[,\s]+', text):
        if raw:
            name = normalize_server_name(raw)
            if name not in names:
                names.append(name)
    if len(names) > MAX_SERVER_NAMES:
        raise ValueError(f'At most {MAX_SERVER_NAMES} server names')
    return names


def _validate_listening(value):
    address = value['listen_address']
    if not isinstance(address, str):
        raise ValueError('The listen address must be an IP address')
    try:
        if '%' in address:
            raise ValueError()  # an IPv6 scope ID is free text, not part of the address
        ipaddress.ip_address(address)
    except ValueError:
        raise ValueError('The listen address must be an IP address, such as 127.0.0.1 or 0.0.0.0') from None
    names = value['server_names']
    if (not isinstance(names, list) or len(names) > MAX_SERVER_NAMES
            or [normalize_server_name(n) for n in names] != names or len(set(names)) != len(names)):
        raise ValueError('Server names must be up to 20 distinct, lower-case host names or IP addresses')
    cert = value['certificate']
    if not isinstance(cert, dict) or set(cert) != set(CERTIFICATE_DEFAULTS):
        raise ValueError('Unexpected settings fields')
    if not isinstance(cert['mode'], str) or cert['mode'] not in {'self-signed', 'own'}:
        raise ValueError('The certificate must be self-signed or your own')
    _absolute_path(cert['cert_file'], 'certificate file')
    _absolute_path(cert['key_file'], 'key file')
    if cert['mode'] == 'own' and not (cert['cert_file'] and cert['key_file']):
        raise ValueError('Your own certificate needs two absolute paths: the certificate and its key')


def exposed(settings):
    """True when the server would listen beyond this machine."""
    return not ipaddress.ip_address(settings['listen_address']).is_loopback


def check_certificate(cert_file, key_file):
    """Save-time only: the pair must load, and match, as a server certificate."""
    try:
        ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(cert_file, key_file)
    except (ssl.SSLError, OSError, ValueError):
        raise ValueError('The certificate and key could not be loaded as a matching PEM pair') from None


def check_bindable(address, port):
    """Bind and close, to refuse an address this machine does not have. Leaves nothing open."""
    family = socket.AF_INET6 if ipaddress.ip_address(address).version == 6 else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as probe:
        try:
            probe.bind((address, port))
        except OSError:
            # port 0 checks the address alone, so the sentence names the address alone
            raise ValueError(f'This machine cannot listen on {address}' + (f':{port}' if port else '')) from None


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


def connection_name(format, base_url, role):
    """The name of a connection made for one job: '<Provider> (<Job>)'."""
    return f'{preset_for(format, base_url).name} ({JOB_NAMES[role]})'


def new_connection(format, endpoint, model, ca_file, role):
    """A connection for one job's call, named for the job. Its key comes from the environment, as
    before connections, except Ollama's, which needs none."""
    base_url, style = split_endpoint(format, endpoint, model)
    provider = preset_for(format, base_url)
    return {'name': connection_name(format, base_url, role), 'provider': provider.id, 'format': format,
            'base_url': base_url, 'endpoint_style': style, 'ca_file': ca_file,
            'key_source': 'none' if provider.id == 'ollama' else 'environment', 'last_test': None}


def role_settings(value, role):
    """A v6 role resolved to its whole call (format, endpoint, model, family, ca_file,
    timeout_seconds), as a v5 role was saved; None when the role is not configured."""
    raw = value['roles'][role]
    if raw is None:
        return None
    conn = value['connections'][raw['connection']]
    return {'format': conn['format'],
            'endpoint': call_endpoint(conn['format'], conn['base_url'], raw['model'], conn['endpoint_style']),
            'model': raw['model'], 'family': raw['family'], 'ca_file': conn['ca_file'],
            'timeout_seconds': raw['timeout_seconds']}


def _upgrade_v5(value):
    """Each configured v5 role becomes its own connection, so no job's format, call address,
    model, family, CA file, timeout or key changes."""
    value = _validate_v5(value)
    upgraded = dict(value, version=6, connections={}, roles={})
    for role in ROLES:
        raw = value['roles'][role]
        if raw is None:
            upgraded['roles'][role] = None
            continue
        cid = migrated_connection_id(role)
        upgraded['connections'][cid] = new_connection(raw['format'], raw['endpoint'], raw['model'],
                                                      raw['ca_file'], role)
        upgraded['roles'][role] = {'connection': cid, 'model': raw['model'], 'family': raw['family'],
                                   'timeout_seconds': raw['timeout_seconds']}
    return validate(upgraded)


def _upgrade_v4(value):
    """v4 listened on loopback only, with no names and no certificate choice."""
    if not isinstance(value, dict) or set(value) != _V3_FIELDS:
        raise ValueError('Unexpected settings fields')
    upgraded = dict(copy.deepcopy(value), version=5, listen_address=DEFAULTS['listen_address'],
                    server_names=[], certificate=dict(CERTIFICATE_DEFAULTS))
    return _upgrade_v5(upgraded)


def _upgrade_v3(value):
    """v3 had no per-role CA file or timeout: each configured role gains none and 60 s."""
    if not isinstance(value, dict) or set(value) != _V3_FIELDS or not isinstance(value.get('roles'), dict):
        raise ValueError('Unexpected settings fields')
    upgraded = dict(copy.deepcopy(value), version=4)
    for role, raw in upgraded['roles'].items():
        if raw is not None:
            if not isinstance(raw, dict) or set(raw) != _V3_ROLE_FIELDS:
                raise ValueError('Unexpected settings fields')
            raw['ca_file'] = ''
            raw['timeout_seconds'] = 60
    return _upgrade_v4(upgraded)


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
    upgraded = {k: copy.deepcopy(v) for k, v in DEFAULTS.items() if k in _V5_FIELDS}
    upgraded.update(version=5, mode=value['mode'], open_browser=value['open_browser'], port=value['port'])
    if value['endpoint'] or value['model']:
        upgraded['roles']['proposer'] = {'format': 'openai_chat', 'endpoint': value['endpoint'],
                                         'model': value['model'], 'family': suggest_family(value['model']),
                                         'ca_file': '', 'timeout_seconds': 60}
    return _upgrade_v5(upgraded)


def load(path):
    try:
        raw = json.loads(Path(path).read_text())
    except FileNotFoundError:
        return copy.deepcopy(DEFAULTS)
    # An earlier version is upgraded in memory only; the next save writes v6.
    if isinstance(raw, dict) and 'version' not in raw:
        return _upgrade_v1(raw)
    elif isinstance(raw, dict) and raw.get('version') == 2:
        return _upgrade_v2(raw)
    elif isinstance(raw, dict) and raw.get('version') == 3:
        return _upgrade_v3(raw)
    elif isinstance(raw, dict) and raw.get('version') == 4:
        return _upgrade_v4(raw)
    elif isinstance(raw, dict) and raw.get('version') == 5:
        return _upgrade_v5(raw)
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
