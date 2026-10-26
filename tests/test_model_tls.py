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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from urllib.parse import urlencode

import pytest

from scripts import local
from tools import inference, local_settings, model_check
from tools.adjudication import CapacityError
from tools.model_roles import ModelRoles, RoleConfig
from tools.model_transport import (CertificateExpired, CertificateFileUnreadable, CertificateNameMismatch,
                                   CertificateNotTrusted, CertificateProblem)
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
                 '-subj', f'/CN=synthetic {name}', '-addext', 'basicConstraints=critical,CA:TRUE', cwd=d)
    (d / 'san').write_text('subjectAltName=DNS:localhost\n')
    for name, days in (('good', '2'), ('expired', '-1')):
        _openssl('req', *key, '-keyout', f'{name}.key', '-out', f'{name}.csr', '-subj', '/CN=localhost', cwd=d)
        _openssl('x509', '-req', '-in', f'{name}.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial',
                 '-out', f'{name}.pem', '-days', days, '-extfile', 'san', cwd=d)
    _openssl('req', '-x509', *key, '-keyout', 'self.key', '-out', 'self.pem', '-days', '2', '-subj', '/CN=localhost',
             '-addext', 'subjectAltName=DNS:localhost', cwd=d)
    (d / 'not-a-cert.pem').write_text('this is not a certificate\n')
    return d


class _Chat(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        self.rfile.read(int(self.headers.get('Content-Length', '0')))
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

    def start(name):
        httpd = ThreadingHTTPServer(('127.0.0.1', 0), _Chat)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certs / f'{name}.pem', certs / f'{name}.key')
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
    return {'format': 'openai_chat', 'endpoint': endpoint, 'model': 'qwen2.5:3b', 'family': 'qwen', 'ca_file': ca_file}


def test_version_3_settings_upgrade_with_an_empty_ca_file(tmp_path):
    path = tmp_path / 'db.settings.json'
    old = dict(local_settings.DEFAULTS, version=3)
    old['roles'] = dict(old['roles'], proposer={k: v for k, v in role().items() if k != 'ca_file'})
    path.write_text(json.dumps(old))
    loaded = local_settings.load(path)
    assert loaded['version'] == 4
    assert loaded['roles']['proposer']['ca_file'] == ''
    assert loaded['roles']['reviewer'] is None


@pytest.mark.parametrize('bad', [
    role(ca_file='relative/ca.pem'),                                  # must be absolute
    role(endpoint='http://127.0.0.1:11434/v1/chat/completions', ca_file='/etc/ca.pem'),  # http has no certificate
    role(ca_file='/etc/ca.pem\n'),
])
def test_a_ca_file_setting_that_cannot_apply_is_refused(bad):
    value = dict(local_settings.DEFAULTS, roles=dict(local_settings.DEFAULTS['roles'], proposer=bad))
    with pytest.raises(ValueError):
        local_settings.validate(value)


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


@pytest.fixture
def settings_server(tmp_path, fake_endpoints):
    config_path = tmp_path / 'db.settings.json'
    httpd = local.DashboardServer(('127.0.0.1', 0), local.handler(SimpleNamespace(snapshot=lambda: {}), False,
                                                                  config_path))
    fake_endpoints.tcp(httpd.socket)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield httpd.server_port, config_path
    httpd.shutdown()
    httpd.server_close()


def save_model(port, ca_file):
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
    conn.request('GET', '/?view=settings&section=model', headers={'Host': f'127.0.0.1:{port}'})
    page = conn.getresponse().read().decode()
    token = re.search(r'name="token" value="([^"]+)"', page).group(1)
    assert 'name="proposer_ca_file"' in page
    fields = {'token': token, 'section': 'model', 'same_family_policy': 'wait'}
    for name in local.ROLES:
        fields.update({f'{name}_format': 'openai_chat', f'{name}_endpoint': '', f'{name}_model': '',
                       f'{name}_family': '', f'{name}_ca_file': ''})
    fields.update(proposer_endpoint='https://models.example.test/v1/chat/completions', proposer_model='qwen2.5:3b',
                  proposer_ca_file=ca_file)
    conn.request('POST', '/settings', body=urlencode(fields), headers={
        'Host': f'127.0.0.1:{port}', 'Origin': f'http://127.0.0.1:{port}', 'Sec-Fetch-Site': 'same-origin',
        'Content-Type': 'application/x-www-form-urlencoded'})
    response = conn.getresponse()
    text = response.read().decode()
    conn.close()
    return response.status, text


def test_a_model_ca_file_is_saved_from_the_settings_page(settings_server, certs):
    port, config_path = settings_server
    assert save_model(port, str(certs / 'ca.pem'))[0] == 303
    assert local_settings.load(config_path)['roles']['proposer']['ca_file'] == str(certs / 'ca.pem')


def test_an_unreadable_ca_file_is_refused_and_nothing_is_saved(settings_server, certs):
    port, config_path = settings_server
    status, text = save_model(port, str(certs / 'not-a-cert.pem'))
    assert status == 400
    assert 'CA certificate file' in text
    assert local_settings.load(config_path)['roles']['proposer'] is None
