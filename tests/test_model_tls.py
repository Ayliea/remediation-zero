# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""A model on another machine behind HTTPS with its own certificate (a role's CA file).

Real TLS over loopback: certificates are made for each run with the openssl command
(no key, even a test one, lives in the repository), and a stdlib HTTPS server answers
like an OpenAI-compatible endpoint."""
import http.client
import json
import re
import shutil
import socket
import ssl
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from urllib.parse import urlencode

import pytest

from scripts import local
from tools import inference, local_settings, model_check
from tools.adjudication import CapacityError
from tools.model_roles import ModelRoles, RoleConfig
from tools import model_transport
from tools.model_transport import (CertificateExpired, CertificateFileUnreadable, CertificateNameMismatch,
                                   CertificateNotTrusted, CertificateProblem, ModelTimedOut, TLSRefused)
from tools.models import build_adapter

pytestmark = pytest.mark.skipif(shutil.which('openssl') is None, reason='needs the openssl command')


def _openssl(*args, cwd):
    subprocess.run(['openssl', *args], cwd=cwd, check=True, capture_output=True)


@pytest.fixture(scope='module')
def certs(tmp_path_factory):
    """ca.pem signs good.pem (localhost, valid) and expired.pem; self.pem is self-signed for
    localhost; other_ca.pem is an unrelated CA."""
    d = tmp_path_factory.mktemp('tls')
    key = ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes']
    for name in ('ca', 'other_ca'):
        _openssl('req', '-x509', *key, '-keyout', f'{name}.key', '-out', f'{name}.pem', '-days', '2',
                 '-subj', f'/CN=synthetic {name}', '-addext', 'basicConstraints=critical,CA:TRUE',
                 '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-addext', 'subjectKeyIdentifier=hash', cwd=d)
    # Python 3.13 verifies strictly by default (VERIFY_X509_STRICT): a CA needs key usage, and
    # older openssl builds add no key identifiers unless asked.
    (d / 'san').write_text('subjectAltName=DNS:localhost\nsubjectKeyIdentifier=hash\n'
                           'authorityKeyIdentifier=keyid\n')
    for name, days in (('good', '2'), ('expired', '-1')):
        _openssl('req', *key, '-keyout', f'{name}.key', '-out', f'{name}.csr', '-subj', '/CN=localhost', cwd=d)
        _openssl('x509', '-req', '-in', f'{name}.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial',
                 '-out', f'{name}.pem', '-days', days, '-extfile', 'san', cwd=d)
    _openssl('req', '-x509', *key, '-keyout', 'self.key', '-out', 'self.pem', '-days', '2', '-subj', '/CN=localhost',
             '-addext', 'subjectAltName=DNS:localhost', '-addext', 'subjectKeyIdentifier=hash', cwd=d)
    (d / 'not-a-cert.pem').write_text('this is not a certificate\n')
    return d


class _Chat(BaseHTTPRequestHandler):
    delay = 0.0  # seconds before answering, for the timeout tests

    def log_message(self, *args):
        pass

    def do_POST(self):
        self.rfile.read(int(self.headers.get('Content-Length', '0')))
        time.sleep(self.delay)
        body = json.dumps({'choices': [{'message': {'content': 'ok'}, 'finish_reason': 'stop'}]}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture(autouse=True)
def no_reverse_lookup(monkeypatch):
    monkeypatch.setattr(socket, 'getfqdn', lambda name='': name)


@pytest.fixture
def https_model(certs, fake_endpoints):
    """Start an HTTPS model server presenting `<name>.pem`; returns its port."""
    servers = []

    def start(name, *, delay=0.0, refuse_unknown_names=False):
        httpd = ThreadingHTTPServer(('127.0.0.1', 0), type('Chat', (_Chat,), {'delay': delay}))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certs / f'{name}.pem', certs / f'{name}.key')
        if refuse_unknown_names:
            # As Caddy does: no certificate for the requested name, so the handshake is refused.
            context.sni_callback = lambda sock, server_name, ctx: (
                None if server_name == 'localhost' else ssl.ALERT_DESCRIPTION_INTERNAL_ERROR)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        fake_endpoints.tcp(httpd.socket)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        servers.append(httpd)
        return httpd.server_port

    yield start
    for httpd in servers:
        httpd.shutdown()
        httpd.server_close()


def ask(port, ca_file, host='localhost'):
    adapter = build_adapter('openai_chat', f'https://{host}:{port}/v1/chat/completions', 'm', None, ca_file=ca_file)
    return adapter.complete('system', 'user', json_output=False)


def test_a_model_with_its_own_ca_is_trusted_through_the_ca_file(https_model, certs):
    assert ask(https_model('good'), str(certs / 'ca.pem')) == 'ok'


def test_a_self_signed_certificate_can_be_its_own_ca_file(https_model, certs):
    assert ask(https_model('self'), str(certs / 'self.pem')) == 'ok'


@pytest.mark.parametrize('ca', [None, 'other_ca.pem'])
def test_without_the_right_ca_file_the_certificate_is_not_trusted(https_model, certs, ca):
    with pytest.raises(CertificateNotTrusted):
        ask(https_model('good'), str(certs / ca) if ca else None)


def test_the_ca_file_does_not_switch_off_the_name_check(https_model, certs):
    # The certificate names localhost; the endpoint says 127.0.0.1.
    with pytest.raises(CertificateNameMismatch):
        ask(https_model('good'), str(certs / 'ca.pem'), host='127.0.0.1')


def test_an_expired_certificate_is_refused_even_with_its_ca(https_model, certs):
    with pytest.raises(CertificateExpired):
        ask(https_model('expired'), str(certs / 'ca.pem'))


def test_a_ca_file_that_disappeared_is_reported_as_such(https_model, certs):
    with pytest.raises(CertificateFileUnreadable):
        ask(https_model('good'), str(certs / 'gone.pem'))


def test_a_certificate_problem_is_an_outage_never_a_verdict_and_is_not_retried(monkeypatch):
    # A CapacityError: the reviewer loop records "unavailable", never a rejection.
    assert issubclass(CertificateProblem, CapacityError)
    monkeypatch.setattr(inference.time, 'sleep', lambda s: pytest.fail('backed off on a certificate problem'))
    calls = []

    def call():
        calls.append(1)
        raise CertificateNotTrusted('not trusted')
    with pytest.raises(CertificateNotTrusted):
        inference._with_backoff(call, what='reviewer model')
    assert calls == [1]


def test_the_model_check_says_what_to_do_about_a_certificate(https_model, certs):
    port = https_model('good')
    roles = ModelRoles(proposer=RoleConfig('proposer', 'openai_chat', f'https://localhost:{port}/v1/chat/completions',
                                           'm', 'qwen'), environ={})
    lines = []
    assert model_check.check_models(roles, only='proposer', out=lines.append) == 1
    assert lines == ["proposer: failed (CertificateNotTrusted: set this role's CA certificate file to the model "
                     "server's certificate or the CA that signed it)"]


# -- settings ------------------------------------------------------------------------------

def role(endpoint='https://models.example.test/v1/chat/completions', ca_file=''):
    return {'format': 'openai_chat', 'endpoint': endpoint, 'model': 'qwen2.5:3b', 'family': 'qwen', 'ca_file': ca_file,
            'timeout_seconds': 60}


def test_version_3_settings_upgrade_with_an_empty_ca_file_and_the_default_timeout(tmp_path):
    path = tmp_path / 'db.settings.json'
    old = {k: v for k, v in local_settings.DEFAULTS.items()
           if k not in {'connections', 'listen_address', 'server_names', 'certificate'}}
    old['version'] = 3
    old['roles'] = dict(old['roles'], proposer={k: v for k, v in role().items()
                                                if k not in ('ca_file', 'timeout_seconds')})
    path.write_text(json.dumps(old))
    loaded = local_settings.load(path)
    assert loaded['version'] == 6
    assert local_settings.role_settings(loaded, 'proposer')['ca_file'] == ''
    assert loaded['roles']['proposer']['timeout_seconds'] == 60
    assert loaded['roles']['reviewer'] is None


@pytest.mark.parametrize('bad', [
    role(ca_file='relative/ca.pem'),                                  # must be absolute
    role(endpoint='http://127.0.0.1:11434/v1/chat/completions', ca_file='/etc/ca.pem'),  # http has no certificate
    role(ca_file='/etc/ca.pem\n'),
])
def test_a_ca_file_setting_that_cannot_apply_is_refused(bad):
    connection = {'name': 'Test', 'provider': 'other', 'format': bad['format'], 'base_url': bad['endpoint'],
                  'endpoint_style': 'exact', 'ca_file': bad['ca_file'], 'key_source': 'environment', 'last_test': None}
    proposer = {'connection': 'conn-000000000001', 'model': bad['model'], 'family': bad['family'],
                'timeout_seconds': bad['timeout_seconds']}
    value = dict(local_settings.DEFAULTS, connections={'conn-000000000001': connection},
                 roles=dict(local_settings.DEFAULTS['roles'], proposer=proposer))
    with pytest.raises(ValueError):
        local_settings.validate(value)
    local_settings.validate(dict(value, connections={'conn-000000000001': dict(connection, ca_file='')}))


def test_the_ca_file_is_checked_when_saved(certs):
    local_settings.check_ca_file(str(certs / 'ca.pem'))
    for bad in ('gone.pem', 'not-a-cert.pem'):
        with pytest.raises(ValueError):
            local_settings.check_ca_file(str(certs / bad))


def test_the_ca_file_reaches_the_adapter():
    roles = ModelRoles.from_settings({'roles': {'proposer': role(ca_file='/etc/rz/model-ca.pem')}}, {})
    assert roles.proposer.ca_file == '/etc/rz/model-ca.pem'
    assert roles.adapter('proposer').ca_file == '/etc/rz/model-ca.pem'
    # An environment endpoint override is another server: the saved CA file does not follow it.
    moved = ModelRoles.from_settings({'roles': {'proposer': role(ca_file='/etc/rz/model-ca.pem')}},
                                     {'RZ_MODEL_ENDPOINT': 'https://other.example.test/v1/chat/completions'})
    assert moved.proposer.ca_file == ''


SESSION_COOKIES = {}
SETTINGS_PATHS = {}


@pytest.fixture
def settings_server(tmp_path, fake_endpoints, signed_in):
    config_path = tmp_path / 'db.settings.json'
    httpd = local.DashboardServer(('127.0.0.1', 0), local.handler(SimpleNamespace(snapshot=lambda: {}), False,
                                                                  config_path, accounts=signed_in.accounts))
    SESSION_COOKIES[httpd.server_port] = signed_in.cookie()  # every page needs a session
    SETTINGS_PATHS[httpd.server_port] = config_path
    fake_endpoints.tcp(httpd.socket)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield httpd.server_port, config_path
    httpd.shutdown()
    httpd.server_close()


def save_model(port, ca_file, timeout='60'):
    """Set Triage's whole call as `settings set` does on the server, with the Settings page's own
    validation (apply_settings_form). The page itself posts only the same-family policy now; that
    it refuses these fields is checked first, so a refusal below is the validation's own."""
    config_path = SETTINGS_PATHS[port]
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
    conn.request('GET', '/?view=settings&section=model', headers={'Host': f'127.0.0.1:{port}',
                                                                   'Cookie': SESSION_COOKIES[port]})
    page = conn.getresponse().read().decode()
    token = re.search(r'name="token" value="([^"]+)"', page).group(1)
    assert 'name="proposer_ca_file"' not in page and 'name="proposer_timeout_seconds"' not in page
    fields = {'token': token, 'section': 'model', 'same_family_policy': 'wait',
              'proposer_endpoint': 'https://models.example.test/v1/chat/completions', 'proposer_model': 'qwen2.5:3b',
              'proposer_ca_file': ca_file, 'proposer_timeout_seconds': timeout}
    conn.request('POST', '/settings', body=urlencode(fields), headers={
        'Host': f'127.0.0.1:{port}', 'Origin': f'http://127.0.0.1:{port}', 'Sec-Fetch-Site': 'same-origin',
        'Content-Type': 'application/x-www-form-urlencoded', 'Cookie': SESSION_COOKIES[port]})
    response = conn.getresponse()
    response.read()
    conn.close()
    assert response.status == 400
    try:
        message = local.settings_set(config_path, 'model', [
            'proposer.endpoint=https://models.example.test/v1/chat/completions', 'proposer.model=qwen2.5:3b',
            f'proposer.ca_file={ca_file}', f'proposer.timeout_seconds={timeout}'])
    except local.SettingsCommandRefused as refusal:
        return 400, str(refusal)
    return 303, message


def test_a_model_ca_file_is_saved_from_the_settings_command(settings_server, certs):
    port, config_path = settings_server
    assert save_model(port, str(certs / 'ca.pem'))[0] == 303
    assert local_settings.role_settings(local_settings.load(config_path), 'proposer')['ca_file'] == str(certs / 'ca.pem')


def test_an_unreadable_ca_file_is_refused_and_nothing_is_saved(settings_server, certs):
    port, config_path = settings_server
    status, text = save_model(port, str(certs / 'not-a-cert.pem'))
    assert status == 400
    assert 'CA certificate file' in text
    assert local_settings.load(config_path)['roles']['proposer'] is None


# -- timeouts and a refused handshake ------------------------------------------------------

def test_a_slow_model_times_out_with_its_own_message(https_model, certs):
    port = https_model('good', delay=2.0)
    adapter = build_adapter('openai_chat', f'https://localhost:{port}/v1/chat/completions', 'm', None,
                            ca_file=str(certs / 'ca.pem'), timeout_seconds=0.5)
    with pytest.raises(ModelTimedOut, match='0.5'):
        adapter.complete('system', 'user', json_output=False)
    assert issubclass(ModelTimedOut, CapacityError) and not issubclass(ModelTimedOut, CertificateProblem)


def test_a_role_timeout_gives_a_slow_model_time_to_answer(https_model, certs):
    port = https_model('good', delay=1.0)
    adapter = build_adapter('openai_chat', f'https://localhost:{port}/v1/chat/completions', 'm', None,
                            ca_file=str(certs / 'ca.pem'), timeout_seconds=5)
    assert adapter.complete('system', 'user', json_output=False) == 'ok'


def test_the_default_timeout_is_unchanged():
    assert model_transport.TIMEOUT_SECONDS == 60
    assert RoleConfig('proposer', 'openai_chat', 'https://m.example.test/v1', 'm', 'qwen').timeout_seconds == 60


def test_a_refused_handshake_is_named_and_not_retried(https_model, certs):
    port = https_model('good', refuse_unknown_names=True)
    assert ask(port, str(certs / 'ca.pem')) == 'ok'          # the name it serves
    with pytest.raises(TLSRefused):
        ask(port, str(certs / 'ca.pem'), host='127.0.0.1')   # a name it does not serve
    assert issubclass(TLSRefused, CertificateProblem)


@pytest.mark.parametrize('problem, hint', [
    ('ModelTimedOut', "raise this role's timeout"),
    ('TLSRefused', 'check the host name and port'),
])
def test_the_model_check_explains_timeouts_and_refusals(problem, hint):
    assert hint in model_check.PROBLEM_HINTS[problem]


@pytest.mark.parametrize('bad', [0, 4, 601, True, '60', 60.5])
def test_a_timeout_outside_5_to_600_seconds_is_refused(bad):
    with pytest.raises(ValueError):
        RoleConfig('proposer', 'openai_chat', 'https://m.example.test/v1', 'm', 'qwen', timeout_seconds=bad)


def test_the_timeout_is_saved_from_the_settings_command_and_reaches_the_adapter(settings_server):
    port, config_path = settings_server
    assert save_model(port, '', timeout='300')[0] == 303
    saved = local_settings.load(config_path)
    assert saved['roles']['proposer']['timeout_seconds'] == 300
    assert ModelRoles.from_settings(saved, {}).adapter('proposer').timeout_seconds == 300


@pytest.mark.parametrize('bad', ['4', '601', 'abc', '60.5', '٣٠٠'])
def test_a_bad_timeout_from_the_settings_command_saves_nothing(settings_server, bad):
    port, config_path = settings_server
    assert save_model(port, '', timeout=bad)[0] == 400
    assert local_settings.load(config_path)['roles']['proposer'] is None


def test_a_blank_timeout_means_the_default(settings_server):
    port, config_path = settings_server
    assert save_model(port, '', timeout='')[0] == 303
    assert local_settings.load(config_path)['roles']['proposer']['timeout_seconds'] == 60
