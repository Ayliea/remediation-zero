# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""The dashboard's own HTTPS listener: what `serve` binds, certifies and prints.

The offline guard lets a test reach only 127.0.0.1, so the exposed cases keep the listen
address on 127.0.0.1 and declare it exposed (local_settings.exposed patched): everything
else, the certificate, the TLS listener and the request kinds, is what a network address gets.
"""
import errno
import http.client
import io
import logging
import shlex
import shutil
import socket
import ssl
import threading
import time
from types import SimpleNamespace

import pytest

from scripts import local, local_launcher
from tools import local_settings, server_tls

NAME = 'rz.example.test'
needs_openssl = pytest.mark.skipif(shutil.which('openssl') is None, reason='openssl is not installed')


@pytest.fixture(autouse=True)
def no_reverse_lookup(monkeypatch):
    monkeypatch.setattr(socket, 'getfqdn', lambda name='': name)


@pytest.fixture
def served(tmp_path, fake_endpoints, monkeypatch):
    """build_server on a fresh workspace; returns (server, lines, ws). Shut down on teardown."""
    running = []

    def run(*, exposed=True, demo=False, **settings):
        monkeypatch.setattr(local.local_settings, 'exposed', lambda value: exposed)
        ws = local.open_workspace(tmp_path / 'ws')
        config_path = local_settings.settings_path(ws.root)
        preferences = dict(local_settings.DEFAULTS, mode='saved', **settings)
        server, lines = local.build_server(ws, preferences, config_path, demo=demo, port=0)
        fake_endpoints.tcp(server.socket)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        running.append(server)
        return server, lines, ws

    yield run
    for server in running:
        server.shutdown()
        server.server_close()


def client_context(ws, *, tls11=False):
    context = ssl.create_default_context(cafile=str(ws.root / server_tls.CERT_NAME))
    context.check_hostname = False  # the test connects to 127.0.0.1; the SAN is the server name
    if tls11:
        context.set_ciphers('DEFAULT:@SECLEVEL=0')
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_1
    return context


def https_get(server, ws, path='/signin', host=NAME, timeout=10):
    conn = http.client.HTTPSConnection('127.0.0.1', server.server_port, timeout=timeout, context=client_context(ws))
    conn.request('GET', path, headers={'Host': f'{host}:{server.server_port}'})
    response = conn.getresponse()
    response.read()
    conn.close()
    return response


@needs_openssl
def test_exposed_settings_serve_https_with_tls12_minimum(served):
    server, lines, ws = served(server_names=[NAME])
    assert isinstance(server.tls_context, ssl.SSLContext)
    assert server.tls_context.minimum_version == ssl.TLSVersion.TLSv1_2
    assert https_get(server, ws).status == 200
    # Direct requests answer only to the configured name, over TLS.
    assert https_get(server, ws, host='other.example.test').status == 403
    with socket.create_connection(('127.0.0.1', server.server_port), timeout=5) as raw:
        # The client offers TLS 1.1 (it can: SECLEVEL=0); the server's protocol-version alert refuses it.
        with pytest.raises(ssl.SSLError, match='PROTOCOL_VERSION'):
            client_context(ws, tls11=True).wrap_socket(raw, server_hostname=NAME)
    # The certificate is in the workspace, 0600, and names the server.
    cert, key = ws.root / server_tls.CERT_NAME, ws.root / server_tls.KEY_NAME
    assert cert.stat().st_mode & 0o777 == 0o600 and key.stat().st_mode & 0o777 == 0o600
    assert ('DNS', NAME) in server_tls._sans(cert)


@needs_openssl
def test_a_stalled_handshake_does_not_block_other_clients(served):
    server, _, ws = served(server_names=[NAME])
    stalled = socket.create_connection(('127.0.0.1', server.server_port), timeout=5)
    try:
        time.sleep(0.2)  # the stalled connection has been accepted and sends nothing
        started = time.monotonic()
        assert https_get(server, ws, timeout=5).status == 200
        assert time.monotonic() - started < 5
    finally:
        stalled.close()


@needs_openssl
def test_plain_http_is_refused_on_the_tls_listener(served, capfd, caplog):
    server, _, _ = served(server_names=[NAME])
    caplog.set_level(logging.INFO, logger='remediation_zero.local')
    with socket.create_connection(('127.0.0.1', server.server_port), timeout=5) as raw:
        raw.sendall(f'GET /signin HTTP/1.1\r\nHost: {NAME}:{server.server_port}\r\n\r\n'.encode())
        try:
            answer = raw.recv(4096)
        except ConnectionResetError:
            answer = b''
    assert b'HTTP/1.' not in answer and b'signin' not in answer.lower()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and not [r for r in caplog.records if 'tls_handshake_failed' in r.getMessage()]:
        time.sleep(0.05)
    failed = [r.getMessage() for r in caplog.records if 'tls_handshake_failed' in r.getMessage()]
    assert len(failed) == 1 and '"error":' in failed[0]
    assert '127.0.0.1' not in failed[0] and 'GET' not in failed[0]
    assert 'Traceback' not in capfd.readouterr().err


@needs_openssl
def test_banner_prints_the_fingerprint_and_the_setup_command(served):
    server, lines, ws = served(server_names=[NAME, '192.0.2.10'])
    port = server.server_port
    assert lines == [
        f'Local dashboard: https://{NAME}:{port}/',
        f'Certificate fingerprint (SHA-256): {server_tls.fingerprint(ws.root / server_tls.CERT_NAME)}',
        'No accounts yet. Create the first one on this server: python3 -S -m scripts.local --database '
        f'{shlex.quote(str(ws.root.resolve()))} account setup',
    ]
    assert local_launcher.is_ready_line(lines[0])


@needs_openssl
def test_exposed_without_names_uses_the_host_name(served, monkeypatch):
    monkeypatch.setattr(local.socket, 'gethostname', lambda: 'RZ-Box.example.test')
    assert local.default_server_names(dict(local_settings.DEFAULTS, listen_address='0.0.0.0')) == ['rz-box.example.test']
    assert local.default_server_names(dict(local_settings.DEFAULTS, listen_address='::')) == ['rz-box.example.test']
    assert local.default_server_names(dict(local_settings.DEFAULTS, listen_address='192.0.2.10')) == [
        'rz-box.example.test', '192.0.2.10']
    assert local.default_server_names(dict(local_settings.DEFAULTS, listen_address='0.0.0.0',
                                           server_names=[NAME])) == [NAME]
    server, lines, ws = served()  # listening on 127.0.0.1, declared exposed: the address is a name too
    assert lines[0] == f'Local dashboard: https://rz-box.example.test:{server.server_port}/'
    assert server_tls._sans(ws.root / server_tls.CERT_NAME) == {('DNS', 'rz-box.example.test'),
                                                                 ('IP Address', '127.0.0.1')}
    # The Host allowlist is the certificate's names.
    assert https_get(server, ws, host='rz-box.example.test').status == 200
    assert https_get(server, ws, host='127.0.0.1').status == 200
    assert https_get(server, ws, host=NAME).status == 403


def test_exposed_with_no_usable_name_refuses_to_start(tmp_path, monkeypatch):
    monkeypatch.setattr(local.socket, 'gethostname', lambda: 'not a host name!')
    ws = local.open_workspace(tmp_path / 'ws')
    preferences = dict(local_settings.DEFAULTS, listen_address='0.0.0.0')
    with pytest.raises(local.ServeRefused) as refusal:
        local.build_server(ws, preferences, local_settings.settings_path(ws.root), port=0)
    assert str(refusal.value) == ('No server name is set, so a certificate cannot be made. Set the names people '
                                  'use to reach this server: settings set application server_names=NAME')
    assert not (ws.root / server_tls.CERT_NAME).exists()


def test_no_openssl_says_what_to_do(tmp_path, monkeypatch):
    monkeypatch.setattr(server_tls.shutil, 'which', lambda name: None)
    monkeypatch.setattr(local.local_settings, 'exposed', lambda value: True)
    ws = local.open_workspace(tmp_path / 'ws')
    preferences = dict(local_settings.DEFAULTS, server_names=[NAME])
    with pytest.raises(local.ServeRefused) as refusal:
        local.build_server(ws, preferences, local_settings.settings_path(ws.root), port=0)
    assert str(refusal.value) == ('No openssl command was found, so a certificate cannot be made. Set your own '
                                  'certificate (settings set application certificate.mode=own …) or use a proxy.')


@needs_openssl
def test_own_certificate_is_served(served, tmp_path):
    (tmp_path / 'own').mkdir()
    cert, key = server_tls.ensure_self_signed(tmp_path / 'own', [NAME])
    server, lines, ws = served(server_names=[NAME], certificate={'mode': 'own', 'cert_file': str(cert),
                                                                  'key_file': str(key)})
    assert lines[1] == f'Certificate fingerprint (SHA-256): {server_tls.fingerprint(cert)}'
    assert not (ws.root / server_tls.CERT_NAME).exists()  # no self-signed one is made
    context = ssl.create_default_context(cafile=str(cert))
    context.check_hostname = False
    conn = http.client.HTTPSConnection('127.0.0.1', server.server_port, timeout=10, context=context)
    conn.request('GET', '/signin', headers={'Host': f'{NAME}:{server.server_port}'})
    assert conn.getresponse().status == 200
    conn.close()


@needs_openssl
def test_an_unloadable_own_certificate_names_the_file(tmp_path, monkeypatch):
    monkeypatch.setattr(local.local_settings, 'exposed', lambda value: True)
    (tmp_path / 'own').mkdir()
    cert, key = server_tls.ensure_self_signed(tmp_path / 'own', [NAME])
    secret = key.read_text()
    ws = local.open_workspace(tmp_path / 'ws')
    for cert_file, key_file, named in ((str(tmp_path / 'missing.pem'), str(key), str(tmp_path / 'missing.pem')),
                                       (str(cert), str(cert), str(cert))):
        preferences = dict(local_settings.DEFAULTS, server_names=[NAME],
                           certificate={'mode': 'own', 'cert_file': cert_file, 'key_file': key_file})
        with pytest.raises(local.ServeRefused) as refusal:
            local.build_server(ws, preferences, local_settings.settings_path(ws.root), port=0)
        assert named in str(refusal.value) and 'BEGIN' not in str(refusal.value)
        assert secret not in str(refusal.value)


def test_a_busy_port_exits_with_a_sentence(tmp_path):
    ws = local.open_workspace(tmp_path / 'ws')
    with socket.socket() as taken:
        taken.bind(('127.0.0.1', 0))
        taken.listen()
        port = taken.getsockname()[1]
        with pytest.raises(local.ServeRefused) as refusal:
            local.build_server(ws, dict(local_settings.DEFAULTS), local_settings.settings_path(ws.root), port=port)
    assert str(refusal.value) == f'This machine cannot listen on 127.0.0.1:{port}: the port is already in use.'
    assert local.bind_refusal('192.0.2.10', 8443, OSError(errno.EADDRNOTAVAIL, 'x')) == (
        'This machine cannot listen on 192.0.2.10:8443: that address is not one of this machine\'s.')


def test_loopback_default_is_unchanged(served):
    server, lines, ws = served(exposed=False)
    assert lines == [local.serve_banner(False, server.server_port)]
    assert lines[0] == f'Local dashboard: http://127.0.0.1:{server.server_port}'
    assert server.tls_context is None and not isinstance(server.socket, ssl.SSLSocket)
    assert server.server_address[0] == '127.0.0.1'
    conn = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=10)
    conn.request('GET', '/')
    response = conn.getresponse()
    response.read()
    conn.close()
    assert (response.status, response.getheader('Location')) == (303, '/setup')  # local, plain HTTP
    assert not (ws.root / server_tls.CERT_NAME).exists()


def test_launcher_does_not_open_a_browser_when_exposed(tmp_path, monkeypatch, capsys):
    database = tmp_path / 'ws'
    local_settings.save(local_settings.settings_path(database), dict(local_settings.DEFAULTS,
        mode='saved', open_browser=True, listen_address='0.0.0.0', server_names=[NAME], port=8443))
    banner = (f'Local dashboard: https://{NAME}:8443/\n'
              'Certificate fingerprint (SHA-256): AB:CD\n'
              'No accounts yet. Create the first one on this server: python3 -S -m scripts.local '
              f'--database {database} account setup\n')
    monkeypatch.setattr('sys.argv', ['start', '--database', str(database)])
    monkeypatch.setattr(local_launcher.subprocess, 'Popen', lambda command, **kw: SimpleNamespace(
        stdout=io.StringIO(banner), wait=lambda **k: 0, poll=lambda: 0))
    monkeypatch.setattr(local_launcher.webbrowser, 'open', lambda *a: pytest.fail('No browser when exposed'))
    local_launcher.main()
    out = capsys.readouterr().out
    for line in banner.splitlines():
        assert line in out.splitlines()


@needs_openssl
def test_settings_fingerprint_reads_the_workspace_certificate(served):
    server, lines, ws = served(server_names=[NAME])
    values = dict(local_settings.DEFAULTS, server_names=[NAME])
    assert lines[1] == local.FINGERPRINT_LINE + local._certificate_fingerprint(values, ws.root)
    assert local._certificate_fingerprint(values, None) is None


# --- final round: a total deadline and a connection cap (I1) -----------------------


def _client_hello(ws):
    """The bytes of a real TLS ClientHello, made in memory: nothing is sent."""
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = client_context(ws).wrap_bio(incoming, outgoing, server_hostname=NAME)
    with pytest.raises(ssl.SSLWantReadError):
        tls.do_handshake()
    return outgoing.read()


def _seconds_until_closed(sock, data, limit):
    """Send `data` a byte a second until the server closes the connection; the seconds that took,
    or None if it was still open after `limit` seconds."""
    started = time.monotonic()
    sock.settimeout(0.05)
    for byte in data:
        if time.monotonic() - started > limit:
            return None
        try:
            sock.sendall(bytes([byte]))
        except OSError:
            return time.monotonic() - started
        pause = time.monotonic() + 1
        while time.monotonic() < pause:
            try:
                if sock.recv(4096) == b'':
                    return time.monotonic() - started
            except TimeoutError:
                pass
            except OSError:
                return time.monotonic() - started
    return None


@needs_openssl
def test_a_trickled_handshake_is_cut_off_by_the_deadline(served, monkeypatch):
    monkeypatch.setattr(local, 'HEADER_SECONDS', 3, raising=False)
    server, _, ws = served(server_names=[NAME])
    hello = _client_hello(ws)
    assert len(hello) > 20
    with socket.create_connection(('127.0.0.1', server.server_port), timeout=5) as sock:
        took = _seconds_until_closed(sock, hello, limit=12)
    assert took is not None and took < 8, 'a byte a second kept the handshake open past the deadline'


@needs_openssl
def test_trickled_headers_over_tls_are_cut_off_by_the_deadline(served, monkeypatch):
    monkeypatch.setattr(local, 'HEADER_SECONDS', 3, raising=False)
    server, _, ws = served(server_names=[NAME])
    raw = socket.create_connection(('127.0.0.1', server.server_port), timeout=5)
    with client_context(ws).wrap_socket(raw, server_hostname=NAME) as sock:
        headers = f'GET /signin HTTP/1.1\r\nHost: {NAME}:{server.server_port}\r\nX-Slow: {"a" * 40}\r\n\r\n'
        took = _seconds_until_closed(sock, headers.encode(), limit=12)
    assert took is not None and took < 8


def test_trickled_headers_on_loopback_are_cut_off_by_the_deadline(served, monkeypatch):
    monkeypatch.setattr(local, 'HEADER_SECONDS', 3, raising=False)
    server, _, _ = served(exposed=False)
    with socket.create_connection(('127.0.0.1', server.server_port), timeout=5) as sock:
        headers = f'GET / HTTP/1.1\r\nHost: 127.0.0.1:{server.server_port}\r\nX-Slow: {"a" * 40}\r\n\r\n'
        took = _seconds_until_closed(sock, headers.encode(), limit=12)
    assert took is not None and took < 8


def _plain_get(port, timeout=5):
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=timeout)
    conn.request('GET', '/')
    response = conn.getresponse()
    response.read()
    conn.close()
    return response


def test_connections_over_the_cap_are_closed_and_a_freed_slot_serves_again(served, monkeypatch):
    monkeypatch.setattr(local, 'MAX_CONNECTIONS', 2, raising=False)
    server, _, _ = served(exposed=False)
    port = server.server_port
    held = [socket.create_connection(('127.0.0.1', port), timeout=5) for _ in range(2)]
    try:
        time.sleep(0.3)  # both are accepted and hold a slot each, sending nothing
        with socket.create_connection(('127.0.0.1', port), timeout=5) as extra:
            started = time.monotonic()
            try:
                answer = extra.recv(1)
            except ConnectionResetError:
                answer = b''
            assert answer == b'' and time.monotonic() - started < 3   # closed at once
        held.pop().close()
        deadline = time.monotonic() + 5
        while True:
            try:
                assert _plain_get(port, timeout=2).status == 303
                break
            except (OSError, http.client.HTTPException):
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.1)
    finally:
        for sock in held:
            sock.close()
