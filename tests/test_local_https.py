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


def machine_addresses(monkeypatch, host, entries):
    """getaddrinfo for this machine's (patched) host name answers `entries`; every other
    lookup, the test client's own included, goes to the real one."""
    real = socket.getaddrinfo

    def lookup(name, port, *args, **kwargs):
        if name == host:
            if isinstance(entries, BaseException):
                raise entries
            return entries
        return real(name, port, *args, **kwargs)

    monkeypatch.setattr(local.socket, 'getaddrinfo', lookup)


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
        f'Answers to: {NAME}, 192.0.2.10',
        f'Certificate fingerprint (SHA-256): {server_tls.fingerprint(ws.root / server_tls.CERT_NAME)}',
        'No accounts yet. Create the first one on this server: python3 -S -m scripts.local --database '
        f'{shlex.quote(str(ws.root.resolve()))} account setup',
    ]
    assert local_launcher.is_ready_line(lines[0])


@needs_openssl
def test_exposed_without_names_uses_the_host_name(served, monkeypatch):
    monkeypatch.setattr(local.socket, 'gethostname', lambda: 'RZ-Box.example.test')
    machine_addresses(monkeypatch, 'RZ-Box.example.test', [])
    assert local.default_server_names(dict(local_settings.DEFAULTS, listen_address='0.0.0.0')) == ['rz-box.example.test']
    assert local.default_server_names(dict(local_settings.DEFAULTS, listen_address='::')) == ['rz-box.example.test']
    assert local.default_server_names(dict(local_settings.DEFAULTS, listen_address='192.0.2.10')) == [
        'rz-box.example.test', '192.0.2.10']
    assert local.default_server_names(dict(local_settings.DEFAULTS, listen_address='0.0.0.0',
                                           server_names=[NAME])) == [NAME]
    server, lines, ws = served()  # listening on 127.0.0.1, declared exposed: the address is a name too
    assert lines[0] == f'Local dashboard: https://rz-box.example.test:{server.server_port}/'
    assert lines[1] == 'Answers to: rz-box.example.test, 127.0.0.1'
    assert server_tls._sans(ws.root / server_tls.CERT_NAME) == {('DNS', 'rz-box.example.test'),
                                                                 ('IP Address', '127.0.0.1')}
    # The Host allowlist is the certificate's names.
    assert https_get(server, ws, host='rz-box.example.test').status == 200
    assert https_get(server, ws, host='127.0.0.1').status == 200
    assert https_get(server, ws, host=NAME).status == 403


def test_exposed_with_no_usable_name_refuses_to_start(tmp_path, monkeypatch):
    monkeypatch.setattr(local.socket, 'gethostname', lambda: 'not a host name!')
    machine_addresses(monkeypatch, 'not a host name!', [])
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
    assert lines[2] == f'Certificate fingerprint (SHA-256): {server_tls.fingerprint(cert)}'
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
    assert lines[2] == local.FINGERPRINT_LINE + local._certificate_fingerprint(values, ws.root)
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



# --- final round: the self-signed pair is ours to remake (I2) ----------------------------


@needs_openssl
def test_a_corrupt_self_signed_key_is_made_again(served, tmp_path):
    first, _, ws = served(server_names=[NAME])
    old = server_tls.fingerprint(ws.root / server_tls.CERT_NAME)
    first.shutdown()
    first.server_close()
    (ws.root / server_tls.KEY_NAME).write_text('-----BEGIN PRIVATE KEY-----\nnot a key\n-----END PRIVATE KEY-----\n')
    server, lines, ws = served(server_names=[NAME])
    assert lines[2] == local.FINGERPRINT_LINE + server_tls.fingerprint(ws.root / server_tls.CERT_NAME)
    assert server_tls.fingerprint(ws.root / server_tls.CERT_NAME) != old
    assert https_get(server, ws).status == 200


@needs_openssl
def test_a_key_that_does_not_match_its_certificate_is_made_again(tmp_path):
    (tmp_path / 'a').mkdir()
    (tmp_path / 'b').mkdir()
    cert, key = server_tls.ensure_self_signed(tmp_path / 'a', [NAME])
    _, other = server_tls.ensure_self_signed(tmp_path / 'b', [NAME])
    key.write_bytes(other.read_bytes())    # a valid key, but not this certificate's
    cert, key = server_tls.ensure_self_signed(tmp_path / 'a', [NAME])
    server_tls.server_context(cert, key)   # loads: the pair was made again


@needs_openssl
def test_a_self_signed_pair_that_will_not_load_is_refused_naming_both_files(tmp_path, monkeypatch):
    monkeypatch.setattr(local.local_settings, 'exposed', lambda value: True)
    calls = []

    def refuse(cert, key):
        calls.append((cert, key))
        raise ssl.SSLError('synthetic')

    ws = local.open_workspace(tmp_path / 'ws')
    monkeypatch.setattr(local.server_tls, 'server_context', refuse)
    preferences = dict(local_settings.DEFAULTS, server_names=[NAME])
    with pytest.raises(local.ServeRefused) as refusal:
        local.build_server(ws, preferences, local_settings.settings_path(ws.root), port=0)
    message = str(refusal.value)
    assert str(ws.root / server_tls.CERT_NAME) in message and str(ws.root / server_tls.KEY_NAME) in message
    assert len(calls) == 2 and 'BEGIN' not in message      # made again once, then refused


@needs_openssl
def test_a_self_signed_pair_that_fails_once_is_made_again(served, monkeypatch):
    real, failed = server_tls.server_context, []

    def once(cert, key):
        if not failed:
            failed.append(True)
            raise ssl.SSLError('synthetic')
        return real(cert, key)

    monkeypatch.setattr(local.server_tls, 'server_context', once)
    server, _, ws = served(server_names=[NAME])
    assert failed and https_get(server, ws).status == 200


def test_nothing_listens_when_the_accounts_file_cannot_be_opened(tmp_path, monkeypatch):
    ws = local.open_workspace(tmp_path / 'ws')
    bound = []
    monkeypatch.setattr(local, 'DashboardServer', lambda *a, **k: bound.append(a) or pytest.fail('bound'))

    def broken(path):
        raise PermissionError(13, 'synthetic')

    monkeypatch.setattr(local, 'AccountStore', broken)
    with pytest.raises(local.ServeRefused) as refusal:
        local.build_server(ws, dict(local_settings.DEFAULTS), local_settings.settings_path(ws.root), port=0)
    assert str(refusal.value) == local.ACCOUNTS_UNREADABLE and not bound


# --- final round: the setup command whenever the browser cannot offer setup (M5) -----------


def test_a_proxied_loopback_install_with_no_accounts_prints_the_setup_command(tmp_path, fake_endpoints):
    ws = local.open_workspace(tmp_path / 'ws')
    preferences = dict(local_settings.DEFAULTS, mode='saved')
    server, lines = local.build_server(ws, preferences, local_settings.settings_path(ws.root), port=0,
                                       public_url='https://dashboard.example.test')
    server.server_close()
    assert lines == [local.serve_banner(False, server.server_port),
                     'No accounts yet. Create the first one on this server: python3 -S -m scripts.local '
                     f'--database {shlex.quote(str(ws.root.resolve()))} account setup']
    # Plain loopback with no proxy offers setup in the browser: no extra line.
    server, lines = local.build_server(ws, preferences, local_settings.settings_path(ws.root), port=0)
    server.server_close()
    assert lines == [local.serve_banner(False, server.server_port)]



# --- final round: an unspecified listen address answers to this machine's addresses (I7) ---


def test_an_unspecified_address_answers_to_the_host_name_and_the_machine_addresses(monkeypatch):
    monkeypatch.setattr(local.socket, 'gethostname', lambda: 'rz-box.example.test')
    asked = []

    def addresses(host, port, *args, **kwargs):
        asked.append((host, port))
        v4 = lambda a: (socket.AF_INET, socket.SOCK_STREAM, 6, '', (a, 0))
        v6 = lambda a, scope=0: (socket.AF_INET6, socket.SOCK_STREAM, 6, '', (a, 0, 0, scope))
        return [v4('192.0.2.10'), v4('192.0.2.10'), v4('127.0.1.1'), v4('0.0.0.0'), v6('::1'),
                v6('fe80::1%eth0', 2), v6('2001:db8::5'), v6('2001:DB8::5'), v4('198.51.100.3')]

    monkeypatch.setattr(local.socket, 'getaddrinfo', addresses)
    for unspecified in ('0.0.0.0', '::'):
        names = local.default_server_names(dict(local_settings.DEFAULTS, listen_address=unspecified))
        assert names == ['rz-box.example.test', '192.0.2.10', '2001:db8::5', '198.51.100.3']
    assert asked[0] == ('rz-box.example.test', None)
    # A host name that is not a valid one is left out; the addresses still count.
    monkeypatch.setattr(local.socket, 'gethostname', lambda: 'not a host name!')
    assert local.default_server_names(dict(local_settings.DEFAULTS, listen_address='0.0.0.0')) == [
        '192.0.2.10', '2001:db8::5', '198.51.100.3']
    # A lookup that fails leaves the host name alone.
    monkeypatch.setattr(local.socket, 'gethostname', lambda: 'rz-box.example.test')
    machine_addresses(monkeypatch, 'rz-box.example.test', socket.gaierror())
    assert local.default_server_names(dict(local_settings.DEFAULTS, listen_address='0.0.0.0')) == [
        'rz-box.example.test']


@needs_openssl
def test_the_machine_addresses_are_in_the_certificate_the_allowlist_and_the_banner(served, monkeypatch):
    monkeypatch.setattr(local.socket, 'gethostname', lambda: 'rz-box.example.test')
    machine_addresses(monkeypatch, 'rz-box.example.test',
                      [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.0.2.10', 0))])
    real = local.default_server_names
    # The test listens on 127.0.0.1 (the offline guard); the names are what 0.0.0.0 would get.
    monkeypatch.setattr(local, 'default_server_names',
                        lambda settings: real(dict(settings, listen_address='0.0.0.0')))
    server, lines, ws = served()
    assert lines[1] == 'Answers to: rz-box.example.test, 192.0.2.10'
    assert server_tls._sans(ws.root / server_tls.CERT_NAME) == {('DNS', 'rz-box.example.test'),
                                                                 ('IP Address', '192.0.2.10')}
    assert https_get(server, ws, host='192.0.2.10').status == 200


# --- final round: HSTS with your own certificate only (M2) ---------------------------------


@needs_openssl
def test_hsts_is_sent_with_your_own_certificate_only(served, tmp_path):
    (tmp_path / 'own').mkdir()
    cert, key = server_tls.ensure_self_signed(tmp_path / 'own', [NAME])
    server, _, _ = served(server_names=[NAME], certificate={'mode': 'own', 'cert_file': str(cert),
                                                             'key_file': str(key)})
    context = ssl.create_default_context(cafile=str(cert))
    context.check_hostname = False
    for path in ('/signin', '/', '/nope'):
        conn = http.client.HTTPSConnection('127.0.0.1', server.server_port, timeout=10, context=context)
        conn.request('GET', path, headers={'Host': f'{NAME}:{server.server_port}'})
        response = conn.getresponse()
        response.read()
        conn.close()
        assert response.getheader('Strict-Transport-Security') == 'max-age=31536000', path


@needs_openssl
def test_no_hsts_with_the_self_signed_certificate_or_on_loopback(served):
    server, _, ws = served(server_names=[NAME])
    assert https_get(server, ws).getheader('Strict-Transport-Security') is None
    plain, _, _ = served(exposed=False)
    assert _plain_get(plain.server_port).getheader('Strict-Transport-Security') is None
