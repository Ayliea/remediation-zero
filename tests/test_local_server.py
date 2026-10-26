# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""The local dashboard server over a real loopback socket, the way a browser reaches it.

The handler tests elsewhere build requests by hand, so they set whatever headers they
like. These tests cover what only a real connection shows: the headers a browser
actually sends back, and an idle connection held open the way browsers do."""
import http.client
import io
import re
import socket
import threading
from types import SimpleNamespace
from urllib.parse import urlencode

import pytest

from scripts import local, local_launcher
from tools import local_settings


def browser_form_origin(referrer_policy, origin):
    """The Origin header a browser sends on a same-origin form POST (Fetch, "append a
    request Origin header"): "null" under no-referrer, the page's origin otherwise."""
    return 'null' if referrer_policy.strip().lower() == 'no-referrer' else origin


@pytest.fixture(autouse=True)
def no_reverse_lookup(monkeypatch):
    # HTTPServer.server_bind names itself with socket.getfqdn, a lookup the offline guard refuses.
    monkeypatch.setattr(socket, 'getfqdn', lambda name='': name)


@pytest.fixture
def server(tmp_path, fake_endpoints):
    config_path = tmp_path / 'db.settings.json'
    cls = local.handler(SimpleNamespace(snapshot=lambda: {}), False, config_path)
    httpd = local.DashboardServer(('127.0.0.1', 0), cls)
    fake_endpoints.tcp(httpd.socket)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd, config_path
    httpd.shutdown()
    httpd.server_close()


def get(port, path, timeout=5):
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=timeout)
    conn.request('GET', path, headers={'Host': f'127.0.0.1:{port}'})
    response = conn.getresponse()
    body = response.read().decode()
    conn.close()
    return response, body


def test_a_settings_save_from_a_browser_is_accepted(server):
    httpd, config_path = server
    port = httpd.server_port
    page, body = get(port, '/?view=settings&section=scanner')
    token = re.search(r'name="token" value="([^"]+)"', body).group(1)
    origin = browser_form_origin(page.getheader('Referrer-Policy', ''), f'http://127.0.0.1:{port}')
    fields = dict(token=token, section='scanner', transport='unix', socket_path='/run/gvmd/gvmd.sock',
                  host='', port='9390', ca_file='', task_ids='', qod_floor='70')
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
    conn.request('POST', '/settings', body=urlencode(fields), headers={
        'Host': f'127.0.0.1:{port}', 'Origin': origin, 'Sec-Fetch-Site': 'same-origin',
        'Content-Type': 'application/x-www-form-urlencoded'})
    response = conn.getresponse()
    response.read()
    conn.close()
    assert response.status == 303
    assert local_settings.load(config_path)['scanner']['socket_path'] == '/run/gvmd/gvmd.sock'


def test_a_post_with_a_null_origin_is_still_refused(server):
    # The fix is the page's policy, not trusting "null": sandboxed frames send it too.
    httpd, _ = server
    port = httpd.server_port
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
    conn.request('POST', '/settings', body='token=x&section=scanner', headers={
        'Host': f'127.0.0.1:{port}', 'Origin': 'null', 'Sec-Fetch-Site': 'same-origin',
        'Content-Type': 'application/x-www-form-urlencoded'})
    response = conn.getresponse()
    response.read()
    conn.close()
    assert response.status == 403


def test_an_idle_connection_does_not_block_other_visitors(server):
    httpd, _ = server
    idle = socket.create_connection(('127.0.0.1', httpd.server_port), timeout=5)
    try:
        response, _ = get(httpd.server_port, '/', timeout=3)
        assert response.status == 200
    finally:
        idle.close()


def test_an_idle_connection_is_closed_after_the_idle_timeout(tmp_path, fake_endpoints, monkeypatch):
    assert 0 < local.IDLE_TIMEOUT <= 30
    monkeypatch.setattr(local, 'IDLE_TIMEOUT', 1)  # read when the handler class is built
    cls = local.handler(SimpleNamespace(snapshot=lambda: {}), False, tmp_path / 'db.settings.json')
    httpd = local.DashboardServer(('127.0.0.1', 0), cls)
    fake_endpoints.tcp(httpd.socket)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    idle = socket.create_connection(('127.0.0.1', httpd.server_port), timeout=5)
    try:
        assert idle.recv(1) == b''  # the server closed it; it did not hold a thread forever
    finally:
        idle.close()
        httpd.shutdown()
        httpd.server_close()


def test_requests_are_still_handled_one_at_a_time(tmp_path, fake_endpoints):
    # The scanner probe's deadline and the settings read-modify-write both rely on it.
    inside, release, overlap = threading.Event(), threading.Event(), []
    active = []

    def snapshot():
        active.append(1)
        if len(active) > 1:
            overlap.append(True)
        inside.set()
        release.wait(5)
        active.pop()
        return {}

    cls = local.handler(SimpleNamespace(snapshot=snapshot), False, tmp_path / 'db.settings.json')
    httpd = local.DashboardServer(('127.0.0.1', 0), cls)
    fake_endpoints.tcp(httpd.socket)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        first = threading.Thread(target=get, args=(httpd.server_port, '/'))
        first.start()
        assert inside.wait(5)
        second = threading.Thread(target=get, args=(httpd.server_port, '/'))
        second.start()
        second.join(0.5)
        release.set()
        first.join(5)
        second.join(5)
        assert overlap == []
    finally:
        release.set()
        httpd.shutdown()
        httpd.server_close()


@pytest.mark.parametrize('records, notice, footer', [
    ('saved', 'Your saved records', 'Read-only · Infrastructure changes disabled'),
    ('synthetic', 'Synthetic environment', 'Synthetic preview'),
])
def test_the_page_banner_says_what_the_records_are(tmp_path, records, notice, footer):
    cls = local.handler(SimpleNamespace(snapshot=lambda: {}), False, tmp_path / 'db.settings.json',
                        records=lambda: records)
    obj = object.__new__(cls)
    obj.server = SimpleNamespace(server_port=8081)
    obj.path = '/'
    obj.headers = {'Host': '127.0.0.1:8081'}
    obj.wfile = io.BytesIO()
    obj.send_response = obj.send_header = lambda *a: None
    obj.end_headers = lambda: None
    obj.do_GET()
    page = obj.wfile.getvalue().decode()
    assert notice in page
    assert footer in page
    if records == 'saved':
        assert 'Synthetic' not in page


def test_records_kind_follows_where_the_findings_came_from():
    def docs(*sources):
        rows = [SimpleNamespace(to_dict=lambda s=s: {'source': s} if s else {}) for s in sources]
        return SimpleNamespace(collection=lambda name: SimpleNamespace(stream=lambda: iter(rows)))
    assert local.records_kind(docs()) == 'saved'               # empty: waiting for its first import
    assert local.records_kind(docs('greenbone')) == 'saved'
    assert local.records_kind(docs(None, None)) == 'synthetic'  # seeded demo corpus


@pytest.mark.parametrize('flags, says_synthetic', [(['--saved'], False), (['--demo'], True)])
def test_the_launcher_only_calls_a_saved_workspace_synthetic_when_it_is(tmp_path, monkeypatch, capsys,
                                                                       flags, says_synthetic):
    database = tmp_path / 'db'
    local_settings.save(local_settings.settings_path(database), dict(local_settings.DEFAULTS, open_browser=False))
    monkeypatch.setattr('sys.argv', ['start', '--database', str(database), *flags])
    monkeypatch.setattr(local_launcher.subprocess, 'Popen', lambda *a, **kw: SimpleNamespace(
        stdout=io.StringIO('Local dashboard: http://127.0.0.1:8081\n'), wait=lambda **kw: 0, poll=lambda: 0))
    local_launcher.main()
    assert ('Synthetic' in capsys.readouterr().out) is says_synthetic


# -- reaching the dashboard through an HTTPS proxy (--public-url) ------------------------

PUBLIC = 'https://dashboard.example.test:8443'


@pytest.mark.parametrize('url, origin', [
    ('https://dashboard.example.test:8443', 'https://dashboard.example.test:8443'),
    ('https://Dashboard.Example.TEST:8443/', 'https://dashboard.example.test:8443'),
    ('https://dashboard.example.test:443', 'https://dashboard.example.test'),  # browsers omit :443
    ('https://dashboard.example.test', 'https://dashboard.example.test'),
])
def test_a_public_url_is_reduced_to_its_origin(url, origin):
    assert local.public_origin(url) == origin


@pytest.mark.parametrize('url', [
    'http://dashboard.example.test:8443',          # the proxy must supply HTTPS
    'https://dashboard.example.test:8443/rz',      # no path: every page is served from /
    'https://dashboard.example.test/?a=1',
    'https://dashboard.example.test/#x',
    'https://user@dashboard.example.test',
    'https://:8443', 'https://', 'dashboard.example.test',
    'https://dashboard.example.test:0', 'https://dashboard.example.test:70000',
    'https://dashboard.example.test:port', 'https://dash board.example.test',
])
def test_a_public_url_that_is_not_a_plain_https_origin_is_refused(url):
    with pytest.raises(ValueError):
        local.public_origin(url)


@pytest.fixture
def proxied(tmp_path, fake_endpoints):
    config_path = tmp_path / 'db.settings.json'
    cls = local.handler(SimpleNamespace(snapshot=lambda: {}), False, config_path, public_origin=PUBLIC)
    httpd = local.DashboardServer(('127.0.0.1', 0), cls)
    fake_endpoints.tcp(httpd.socket)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield httpd
    httpd.shutdown()
    httpd.server_close()


def request(port, method, path, host, origin=None, body=''):
    """A request as the proxy forwards it: the browser's Host and Origin, passed through."""
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
    headers = {'Host': host, 'Sec-Fetch-Site': 'same-origin',
               'Content-Type': 'application/x-www-form-urlencoded'}
    if origin:
        headers['Origin'] = origin
    conn.request(method, path, body=body or None, headers=headers)
    response = conn.getresponse()
    text = response.read().decode()
    conn.close()
    return response, text


def scanner_save(token):
    return urlencode(dict(token=token, section='scanner', transport='unix', socket_path='/run/gvmd/gvmd.sock',
                          host='', port='9390', ca_file='', task_ids='', qod_floor='70'))


def test_the_configured_public_name_is_served_and_others_are_refused(proxied):
    port = proxied.server_port
    assert request(port, 'GET', '/', 'dashboard.example.test:8443')[0].status == 200
    assert request(port, 'GET', '/', f'127.0.0.1:{port}')[0].status == 200       # loopback still works
    for host in ('evil.example.test:8443', 'dashboard.example.test', 'dashboard.example.test:9999'):
        assert request(port, 'GET', '/', host)[0].status == 403


def test_a_save_through_the_proxy_needs_the_exact_https_origin(proxied):
    port = proxied.server_port
    page, body = request(port, 'GET', '/?view=settings&section=scanner', 'dashboard.example.test:8443')
    token = re.search(r'name="token" value="([^"]+)"', body).group(1)
    host = 'dashboard.example.test:8443'
    for wrong in ('http://dashboard.example.test:8443', f'http://127.0.0.1:{port}', 'null',
                  'https://evil.example.test:8443'):
        assert request(port, 'POST', '/settings', host, wrong, scanner_save(token))[0].status == 403
    origin = browser_form_origin(page.getheader('Referrer-Policy', ''), PUBLIC)
    assert request(port, 'POST', '/settings', host, origin, scanner_save(token))[0].status == 303


def test_a_loopback_save_still_needs_the_loopback_origin(proxied):
    port = proxied.server_port
    _, body = request(port, 'GET', '/?view=settings&section=scanner', f'127.0.0.1:{port}')
    token = re.search(r'name="token" value="([^"]+)"', body).group(1)
    assert request(port, 'POST', '/settings', f'127.0.0.1:{port}', PUBLIC, scanner_save(token))[0].status == 403
    assert request(port, 'POST', '/settings', f'127.0.0.1:{port}', f'http://127.0.0.1:{port}',
                   scanner_save(token))[0].status == 303


def test_without_a_public_url_a_proxied_name_is_refused(server):
    httpd, _ = server
    assert request(httpd.server_port, 'GET', '/', 'dashboard.example.test:8443')[0].status == 403


def test_the_launcher_passes_the_public_url_on_and_warns(tmp_path, monkeypatch, capsys):
    database = tmp_path / 'db'
    local_settings.save(local_settings.settings_path(database), dict(local_settings.DEFAULTS, open_browser=False))
    monkeypatch.setattr('sys.argv', ['start', '--saved', '--database', str(database), '--public-url', PUBLIC])
    calls = []
    def start(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(stdout=io.StringIO('Local dashboard: http://127.0.0.1:8081\n'),
                               wait=lambda **kw: 0, poll=lambda: 0)
    monkeypatch.setattr(local_launcher.subprocess, 'Popen', start)
    local_launcher.main()
    command = calls[-1]
    assert command[command.index('--public-url') + 1] == PUBLIC
    out = capsys.readouterr().out
    assert f'Also at {PUBLIC} through your HTTPS proxy' in out
    assert 'No sign-in yet' in out


def test_the_launcher_refuses_a_bad_public_url_before_starting(tmp_path, monkeypatch):
    database = tmp_path / 'db'
    local_settings.save(local_settings.settings_path(database), dict(local_settings.DEFAULTS, open_browser=False))
    monkeypatch.setattr('sys.argv', ['start', '--database', str(database), '--public-url', 'http://x.test'])
    monkeypatch.setattr(local_launcher.subprocess, 'Popen', lambda *a, **kw: pytest.fail('Unexpected process'))
    with pytest.raises(SystemExit):
        local_launcher.main()
