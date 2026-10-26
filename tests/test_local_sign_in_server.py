# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Signed-in requests to the local dashboard server, over real sockets.

Every page and form needs a session; the role decides what each request may
do; setup is offered only to a local visit with no accounts; the Origin a POST
must carry is the way the request came in. Synthetic data only."""
import http.client
import re
import select
import shutil
import socket
import ssl
import threading
from types import SimpleNamespace
from urllib.parse import quote, urlencode

import pytest

from scripts import local
from tests.signed_in import OWNER, TECH, empty
from tests.test_accounts import PW_OWNER, PW_TECH, code_for, wrong_code
from tools import access, local_settings, totp
from tools.account_store import AccountStore
from tools.accounts import Accounts, RateLimiter

PUBLIC = 'https://dashboard.example.test:8443'
PUBLIC_HOST = 'dashboard.example.test:8443'
SERVER_NAME = 'rz.example.test'


@pytest.fixture(autouse=True)
def no_reverse_lookup(monkeypatch):
    monkeypatch.setattr(socket, 'getfqdn', lambda name='': name)


class Running:
    def __init__(self, httpd, config_path, accounts, scheme, cafile=None):
        self.httpd, self.config_path, self.accounts, self.scheme = httpd, config_path, accounts, scheme
        self.cafile = cafile
        self.port = httpd.server_port

    @property
    def local_host(self):
        return f'127.0.0.1:{self.port}'

    def request(self, method, path, *, host=None, origin=None, cookie=None, body=None, headers=None,
                content_type='application/x-www-form-urlencoded'):
        if self.scheme == 'https':
            # Verified against the test's own self-signed certificate; its SAN is the server
            # name, not the 127.0.0.1 the test connects to, so only the host name check is off.
            context = ssl.create_default_context(cafile=self.cafile)
            context.check_hostname = False
            conn = http.client.HTTPSConnection('127.0.0.1', self.port, timeout=10, context=context)
        else:
            conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=10)
        sent = {'Host': host or self.local_host}
        if method == 'POST':
            sent.update({'Sec-Fetch-Site': 'same-origin', 'Content-Type': content_type})
            sent['Origin'] = origin if origin is not None else f'http://{sent["Host"]}'
        if cookie:
            sent['Cookie'] = cookie
        sent.update(headers or {})
        sent = {k: v for k, v in sent.items() if v is not None}
        conn.request(method, path, body=body, headers=sent)
        response = conn.getresponse()
        text = response.read().decode()
        conn.close()
        return response, text


@pytest.fixture
def start(tmp_path, fake_endpoints):
    servers = []

    def run(accounts, *, snapshot=None, public_origin=None, settings_exposed=False, server_names=(),
            tls=None, limiter=None, upload=None):
        config_path = tmp_path / 'db.settings.json'
        store = SimpleNamespace(snapshot=snapshot or (lambda: {'scanner_state': []}))
        cls = local.handler(store, False, config_path, 'python3 -S -m scripts.local --database /srv/rz', upload,
                            public_origin=public_origin, accounts=accounts, settings_exposed=settings_exposed,
                            server_names=tuple(server_names), scheme='https' if tls else 'http', limiter=limiter)
        httpd = local.DashboardServer(('127.0.0.1', 0), cls)
        fake_endpoints.tcp(httpd.socket)
        if tls:
            httpd.socket = tls[0].wrap_socket(httpd.socket, server_side=True)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        servers.append(httpd)
        return Running(httpd, config_path, accounts, 'https' if tls else 'http', tls[1] if tls else None)

    yield run
    for httpd in servers:
        httpd.shutdown()
        httpd.server_close()


def form_value(body, name):
    found = re.search(rf'name="{name}" value="([^"]*)"', body)
    return found.group(1) if found else None


def pre_cookie(response):
    for value in response.headers.get_all('Set-Cookie') or ():
        if value.startswith('rz_pre='):
            return value.split(';', 1)[0]
    return None


def session_cookie(response):
    for value in response.headers.get_all('Set-Cookie') or ():
        if value.startswith('rz_session='):
            return value
    return None


def open_form(server, path, *, host=None, cookie=None):
    """GET a pre-session form: (rz_pre cookie, the form's pre value, body)."""
    response, body = server.request('GET', path, host=host, cookie=cookie)
    assert response.status == 200, body
    pre = pre_cookie(response)
    return pre, form_value(body, 'pre'), body


def sign_in(server, email, password, code, *, host=None, origin=None, headers=None):
    pre, value, _ = open_form(server, '/signin', host=host)
    fields = urlencode({'pre': value, 'email': email, 'password': password, 'code': code})
    return server.request('POST', '/signin', host=host, origin=origin, cookie=pre, body=fields, headers=headers)


def scanner_save(token):
    return urlencode(dict(token=token, section='scanner', transport='unix', socket_path='/run/gvmd/gvmd.sock',
                          host='', port='9390', ca_file='', task_ids='', qod_floor='70'))


def page_token(server, cookie, host=None, path='/?view=settings&section=scanner'):
    response, body = server.request('GET', path, host=host, cookie=cookie)
    assert response.status == 200, body
    return form_value(body, 'token')


def events(accounts, name):
    return [dict(r) for r in accounts.store.events(1000) if r['event'] == name]


# --- every page needs a session ------------------------------------------------

PAGES = [('GET', f'/?view={view}') for view in ('overview', 'infrastructure', 'actions', 'activity')] + [
    ('GET', '/'), ('GET', '/?view=settings&section=model'), ('GET', '/?view=settings&section=scanner'),
    ('POST', '/settings'), ('POST', '/upload')]


@pytest.mark.parametrize('method, path', PAGES)
def test_every_page_needs_a_session(start, signed_in, method, path):
    server = start(signed_in.accounts, snapshot=lambda: pytest.fail('records read without a session'),
                   upload=lambda data, add_task: pytest.fail('imported without a session'))
    for cookie in (None, 'rz_session=not-a-session', 'rz_session='):
        body = scanner_save('x') if method == 'POST' else None
        response, _ = server.request(method, path, cookie=cookie, body=body)
        if method == 'GET':
            assert response.status == 303
            assert response.getheader('Location') == '/signin'
        else:
            assert response.status == 403
    assert not server.config_path.exists()


def test_unknown_paths_are_404_with_or_without_a_session(start, signed_in):
    server = start(signed_in.accounts)
    for cookie in (None, signed_in.cookie()):
        for path in ('/nope', '/?view=nope', '/index.html', '/invite/', '/invite/x/y'):
            assert server.request('GET', path, cookie=cookie)[0].status == 404, (path, cookie)


# --- setup ---------------------------------------------------------------------

def test_setup_only_local_and_only_without_accounts(start, tmp_path, signed_in):
    (tmp_path / 'fresh').mkdir()
    accounts, now = empty(tmp_path / 'fresh')
    server = start(accounts)
    response, _ = server.request('GET', '/')
    assert response.status == 303 and response.getheader('Location') == '/setup'
    assert server.request('GET', '/signin')[0].status == 303      # nobody to sign in as yet
    pre, value, body = open_form(server, '/setup')
    secret = form_value(body, 'secret')
    assert '<svg' in body and secret in body and 'otpauth://totp/' in body.replace('&amp;', '&')
    fields = {'pre': value, 'secret': secret, 'email': OWNER, 'role': 'owner', 'password': PW_OWNER,
              'code': code_for(secret, now)}
    response, body = server.request('POST', '/setup', cookie=pre, body=urlencode(fields))
    assert response.status == 200, body
    assert accounts.store.count_accounts() == 1
    codes = re.findall(r'<li><code>([a-z2-7]{5}-[a-z2-7]{5})</code></li>', body)
    assert len(codes) == 10
    # Once an account exists, setup is gone and pages ask for sign-in.
    assert server.request('GET', '/setup')[0].status == 404
    assert server.request('POST', '/setup', cookie=pre, body=urlencode(fields))[0].status == 404
    response, _ = server.request('GET', '/')
    assert response.status == 303 and response.getheader('Location') == '/signin'
    # A workspace that already had accounts never offers it.
    assert start(signed_in.accounts).request('GET', '/setup')[0].status == 404


def test_setup_refuses_a_forged_or_missing_pre_session_token(start, tmp_path):
    accounts, now = empty(tmp_path)
    server = start(accounts)
    pre, value, body = open_form(server, '/setup')
    secret = form_value(body, 'secret')
    fields = {'secret': secret, 'email': OWNER, 'role': 'owner', 'password': PW_OWNER,
              'code': code_for(secret, now)}
    for cookie, given in ((None, value), (pre, 'forged'), ('rz_pre=forged', 'forged'), (pre, None)):
        sent = dict(fields, **({'pre': given} if given else {}))
        assert server.request('POST', '/setup', cookie=cookie, body=urlencode(sent))[0].status == 403
    assert accounts.store.count_accounts() == 0


@pytest.mark.parametrize('how', ['proxy', 'exposed'])
def test_a_loopback_host_through_a_configured_proxy_is_not_local(start, tmp_path, signed_in, how):
    # Tailscale Serve and curl through the tailnet both connect from 127.0.0.1, and curl can send
    # Host: 127.0.0.1:PORT. With a proxy (or a network listen address) configured, that is not local.
    (tmp_path / 'fresh').mkdir()
    accounts, _ = empty(tmp_path / 'fresh')
    options = {'public_origin': PUBLIC} if how == 'proxy' else {'settings_exposed': True}
    server = start(accounts, **options)
    assert server.request('GET', '/setup')[0].status == 404
    response, body = server.request('GET', '/')
    assert response.status == 200
    assert 'account setup' in body and '<form' not in body
    # With accounts, a sign-in on that loopback Host still gets a Secure cookie, and the
    # forwarded address is not trusted for it.
    server = start(signed_in.accounts, **options)
    signed_in.now.tick()
    response, _ = sign_in(server, OWNER, PW_OWNER, code_for(signed_in.owner_secret, signed_in.now),
                          headers={'X-Forwarded-For': '198.51.100.7'})
    assert response.status == 303
    assert '; Secure' in session_cookie(response)
    assert events(signed_in.accounts, 'sign_in')[0]['source'] == '127.0.0.1'


def test_no_accounts_through_the_proxy_shows_only_the_setup_command(start, tmp_path):
    accounts, _ = empty(tmp_path)
    server = start(accounts, public_origin=PUBLIC)
    for path in ('/', '/?view=settings&section=scanner', '/?view=infrastructure', '/signin'):
        response, body = server.request('GET', path, host=PUBLIC_HOST)
        assert response.status == 200, path
        assert 'account setup' in body
        assert '<form' not in body and 'name="token"' not in body
    assert server.request('GET', '/setup', host=PUBLIC_HOST)[0].status == 404
    assert server.request('POST', '/setup', host=PUBLIC_HOST, origin=PUBLIC, body='x=1')[0].status in (403, 404)
    assert server.request('POST', '/settings', host=PUBLIC_HOST, origin=PUBLIC, body=scanner_save('x'))[0].status == 403
    assert accounts.store.count_accounts() == 0


# --- sign-in -------------------------------------------------------------------

def test_sign_in_sets_a_strict_httponly_cookie_and_secure_when_not_local(start, signed_in):
    for options, host, origin, secure in (({}, None, None, False),
                                          ({'public_origin': PUBLIC}, PUBLIC_HOST, PUBLIC, True)):
        server = start(signed_in.accounts, **options)
        signed_in.now.tick()
        response, _ = sign_in(server, OWNER, PW_OWNER, code_for(signed_in.owner_secret, signed_in.now),
                              host=host, origin=origin)
        assert response.status == 303
        assert response.getheader('Location') == '/'
        cookie = session_cookie(response)
        parts = [p.strip() for p in cookie.split(';')]
        assert re.fullmatch(r'rz_session=[A-Za-z0-9_-]{43}', parts[0])
        assert {'HttpOnly', 'SameSite=Strict', 'Path=/'} <= set(parts[1:])
        assert ('Secure' in parts) is secure
        assert server.request('GET', '/', host=host, cookie=parts[0])[0].status == 200


def test_sign_in_redirects_only_to_a_fixed_path(start, signed_in):
    server = start(signed_in.accounts)
    pre, value, _ = open_form(server, '/signin?next=https://evil.example.test/')
    signed_in.now.tick()
    fields = urlencode({'pre': value, 'email': OWNER, 'password': PW_OWNER,
                        'code': code_for(signed_in.owner_secret, signed_in.now)})
    response, _ = server.request('POST', '/signin?next=//evil.example.test', cookie=pre, body=fields)
    assert response.status == 303 and response.getheader('Location') == '/'


def test_sign_in_with_a_recovery_code_spends_it(start, signed_in):
    server = start(signed_in.accounts)
    code = signed_in.owner_codes[0]
    assert sign_in(server, OWNER, PW_OWNER, code)[0].status == 303
    assert sign_in(server, OWNER, PW_OWNER, code)[0].status == 400


def test_sign_out_ends_the_session(start, signed_in):
    server = start(signed_in.accounts)
    cookie = signed_in.cookie()
    token = page_token(server, cookie, path='/')
    assert server.request('POST', '/signout', cookie=cookie, body=urlencode({'token': 'wrong'}))[0].status == 403
    response, _ = server.request('POST', '/signout', cookie=cookie, body=urlencode({'token': token}))
    assert response.status == 303 and response.getheader('Location') == '/signin'
    assert 'rz_session=;' in response.getheader('Set-Cookie') and 'Max-Age=0' in response.getheader('Set-Cookie')
    assert server.request('GET', '/', cookie=cookie)[0].status == 303


def test_unknown_email_and_wrong_password_return_identical_responses(start, signed_in):
    server = start(signed_in.accounts)
    pre, value, _ = open_form(server, '/signin')
    signed_in.now.tick()
    code = code_for(signed_in.owner_secret, signed_in.now)
    answers = []
    for email, password in (('nobody@client.example', PW_OWNER), (OWNER, 'wrong password here'),
                            (OWNER, 'x' * 5000), ('not an email', PW_OWNER)):
        fields = urlencode({'pre': value, 'email': email, 'password': password, 'code': code})
        response, body = server.request('POST', '/signin', cookie=pre, body=fields)
        headers = sorted((k, v) for k, v in response.getheaders() if k.lower() != 'date')
        answers.append((response.status, headers, body))
    assert answers[0][0] == 400
    assert all(answer == answers[0] for answer in answers)
    assert not any(k.lower() == 'set-cookie' and v.startswith('rz_session') for k, v in answers[0][1])
    assert email not in answers[0][2]


def test_sign_in_rate_limit_returns_429_with_retry_after(start, signed_in):
    server = start(signed_in.accounts, limiter=RateLimiter(per_minute=2))
    before = events(signed_in.accounts, 'sign_in')
    for _ in range(2):
        assert sign_in(server, 'nobody@client.example', PW_OWNER, '000000')[0].status == 400
    signed_in.now.tick()
    response, body = sign_in(server, OWNER, PW_OWNER, code_for(signed_in.owner_secret, signed_in.now))
    assert response.status == 429
    assert response.getheader('Retry-After').isdigit() and int(response.getheader('Retry-After')) >= 1
    assert session_cookie(response) is None
    assert events(signed_in.accounts, 'sign_in') == before


def test_oversize_sign_in_forms_are_refused(start, signed_in):
    server = start(signed_in.accounts)
    pre, value, _ = open_form(server, '/signin')
    big = urlencode({'pre': value, 'email': OWNER, 'password': 'x' * 9000, 'code': '000000'})
    assert server.request('POST', '/signin', cookie=pre, body=big)[0].status == 400
    many = urlencode([('pre', value)] + [(f'f{i}', '1') for i in range(50)])
    assert server.request('POST', '/signin', cookie=pre, body=many)[0].status == 400
    assert events(signed_in.accounts, 'sign_in_failed') == []


def test_forwarded_for_is_used_only_through_the_proxy(start, signed_in):
    server = start(signed_in.accounts, public_origin=PUBLIC)
    for host, origin, forwarded, expected in (
            (PUBLIC_HOST, PUBLIC, '198.51.100.7, 203.0.113.9', '203.0.113.9'),
            (PUBLIC_HOST, PUBLIC, 'not-an-address', '127.0.0.1'),
            (None, None, '203.0.113.50', '127.0.0.1')):
        before = len(events(signed_in.accounts, 'sign_in_failed'))
        response, _ = sign_in(server, 'nobody@client.example', PW_OWNER, '000000', host=host, origin=origin,
                              headers={'X-Forwarded-For': forwarded})
        assert response.status == 400
        failed = events(signed_in.accounts, 'sign_in_failed')
        assert len(failed) == before + 1
        assert failed[0]['source'] == expected


# --- roles, re-confirm, origin, csrf -------------------------------------------

def test_a_tech_cannot_reach_owner_actions(start, signed_in):
    server = start(signed_in.accounts)
    tech = signed_in.cookie('tech')
    token = page_token(server, tech, path='/')
    assert server.request('GET', '/?view=accounts', cookie=tech)[0].status == 403
    response, _ = server.request('POST', '/accounts/invite', cookie=tech,
                                 body=urlencode({'token': token, 'email': 'new@client.example', 'role': 'tech'}))
    assert response.status == 403
    tech_id = signed_in.accounts.store.account_by_email(TECH)['id']
    assert all(e['actor_id'] != tech_id for e in events(signed_in.accounts, 'invite_created'))
    assert server.request('GET', '/?view=accounts', cookie=signed_in.cookie())[0].status != 403
    # The same table the handler asks.
    assert not access.allowed('tech', 'manage_accounts') and access.allowed('owner', 'manage_accounts')


def test_settings_save_requires_reconfirm(start, signed_in):
    server = start(signed_in.accounts)
    cookie = signed_in.cookie('unconfirmed')
    token = page_token(server, cookie)
    response, _ = server.request('POST', '/settings', cookie=cookie, body=scanner_save(token))
    assert response.status == 303
    nxt = '/?view=settings&section=scanner'
    assert response.getheader('Location') == '/confirm?next=' + quote(nxt, safe='')
    assert not server.config_path.exists()
    pre, value, body = open_form(server, response.getheader('Location'), cookie=cookie)
    assert 'name="password"' in body
    wrong = urlencode({'pre': value, 'password': 'not the password', 'code': ''})
    both = cookie + '; ' + pre
    assert server.request('POST', '/confirm?next=' + quote(nxt, safe=''), cookie=both, body=wrong)[0].status == 400
    right = urlencode({'pre': value, 'password': PW_OWNER, 'code': ''})
    response, _ = server.request('POST', '/confirm?next=' + quote(nxt, safe=''), cookie=both, body=right)
    assert response.status == 303 and response.getheader('Location') == nxt
    response, _ = server.request('POST', '/settings', cookie=cookie, body=scanner_save(token))
    assert response.status == 303 and 'saved=1' in response.getheader('Location')
    assert local_settings.load(server.config_path)['scanner']['socket_path'] == '/run/gvmd/gvmd.sock'


def test_an_upload_requires_reconfirm(start, signed_in):
    server = start(signed_in.accounts, upload=lambda data, add_task: pytest.fail('imported before re-confirm'))
    cookie = signed_in.cookie('unconfirmed')
    token = page_token(server, cookie, path='/?view=infrastructure')
    boundary = 'rzboundary'
    body = (f'--{boundary}\r\nContent-Disposition: form-data; name="token"\r\n\r\n{token}\r\n'
            f'--{boundary}\r\nContent-Disposition: form-data; name="report"; filename="r.xml"\r\n'
            'Content-Type: application/xml\r\n\r\n<report/>\r\n'
            f'--{boundary}--\r\n')
    response, _ = server.request('POST', '/upload', cookie=cookie, body=body,
                                 content_type=f'multipart/form-data; boundary={boundary}')
    assert response.status == 303
    assert response.getheader('Location') == '/confirm?next=' + quote('/?view=infrastructure', safe='')


@pytest.mark.parametrize('nxt, expected', [
    ('/?view=settings&section=model', '/?view=settings&section=model'),
    ('/?view=infrastructure', '/?view=infrastructure'),
    ('https://evil.example.test/', '/'), ('//evil.example.test', '/'), ('/\\evil.example.test', '/'),
    ('/?view=settings&section=model&x=1', '/'), ('', '/'),
])
def test_confirm_next_is_from_a_closed_set(start, signed_in, nxt, expected):
    server = start(signed_in.accounts)
    cookie = signed_in.cookie('unconfirmed')
    path = '/confirm?next=' + quote(nxt, safe='')
    pre, value, _ = open_form(server, path, cookie=cookie)
    signed_in.now.tick()
    fields = urlencode({'pre': value, 'password': '', 'code': code_for(signed_in.owner_secret, signed_in.now)})
    response, _ = server.request('POST', path, cookie=cookie + '; ' + pre, body=fields)
    assert response.status == 303 and response.getheader('Location') == expected


def test_confirm_without_a_session_goes_to_sign_in(start, signed_in):
    server = start(signed_in.accounts)
    response, _ = server.request('GET', '/confirm')
    assert response.status == 303 and response.getheader('Location') == '/signin'


@pytest.fixture
def tls(tmp_path):
    if shutil.which('openssl') is None:
        pytest.skip('openssl is not installed')
    from tools import server_tls
    (tmp_path / 'tls').mkdir()
    cert, key = server_tls.ensure_self_signed(tmp_path / 'tls', [SERVER_NAME])
    return server_tls.server_context(cert, key), str(cert)


def test_post_origin_must_match_the_way_in(start, signed_in, tls):
    cookie = signed_in.cookie()
    # Local: the loopback origin only.
    server = start(signed_in.accounts)
    token = page_token(server, cookie)
    for origin in (PUBLIC, f'https://{server.local_host}', 'null', f'http://localhost:{server.port}'):
        assert server.request('POST', '/settings', origin=origin, cookie=cookie, body=scanner_save(token))[0].status == 403
    assert server.request('POST', '/settings', cookie=cookie, body=scanner_save(token))[0].status == 303
    # Proxied: the public origin only, on the public Host.
    server = start(signed_in.accounts, public_origin=PUBLIC)
    for origin in (f'http://{server.local_host}', 'http://dashboard.example.test:8443', 'https://dashboard.example.test'):
        assert server.request('POST', '/settings', host=PUBLIC_HOST, origin=origin, cookie=cookie,
                              body=scanner_save(token))[0].status == 403
    assert server.request('POST', '/settings', host=PUBLIC_HOST, origin=PUBLIC, cookie=cookie,
                          body=scanner_save(token))[0].status == 303
    # Direct over TLS: https and the server name the request came in on.
    server = start(signed_in.accounts, settings_exposed=True, server_names=(SERVER_NAME,), tls=tls)
    host = f'{SERVER_NAME}:{server.port}'
    assert server.request('GET', '/', host=f'other.example.test:{server.port}', cookie=cookie)[0].status == 403
    assert server.request('GET', '/', host=SERVER_NAME, cookie=cookie)[0].status == 403   # wrong port
    for origin in (f'http://{host}', PUBLIC, f'https://{server.local_host}'):
        assert server.request('POST', '/settings', host=host, origin=origin, cookie=cookie,
                              body=scanner_save(token))[0].status == 403
    assert server.request('POST', '/settings', host=host, origin=f'https://{host}', cookie=cookie,
                          body=scanner_save(token))[0].status == 303


def test_direct_sign_in_over_tls_sets_a_secure_cookie(start, signed_in, tls):
    server = start(signed_in.accounts, settings_exposed=True, server_names=(SERVER_NAME,), tls=tls)
    host = f'{SERVER_NAME}:{server.port}'
    assert server.request('GET', '/setup', host=host)[0].status == 404
    signed_in.now.tick()
    response, _ = sign_in(server, OWNER, PW_OWNER, code_for(signed_in.owner_secret, signed_in.now),
                          host=host, origin=f'https://{host}', headers={'X-Forwarded-For': '203.0.113.9'})
    assert response.status == 303
    assert '; Secure' in session_cookie(response)
    assert events(signed_in.accounts, 'sign_in')[0]['source'] == '127.0.0.1'


def test_server_names_are_not_served_over_plain_http(start, signed_in):
    server = start(signed_in.accounts, server_names=(SERVER_NAME,))
    assert server.request('GET', '/', host=f'{SERVER_NAME}:{server.port}', cookie=signed_in.cookie())[0].status == 403


def test_csrf_token_is_per_session(start, signed_in):
    server = start(signed_in.accounts)
    owner, tech = signed_in.cookie(), signed_in.cookie('tech')
    owner_token, tech_token = page_token(server, owner), page_token(server, tech)
    assert owner_token and tech_token and owner_token != tech_token
    assert page_token(server, owner) == owner_token
    assert server.request('POST', '/settings', cookie=owner, body=scanner_save(tech_token))[0].status == 403
    assert server.request('POST', '/settings', cookie=tech, body=scanner_save(owner_token))[0].status == 403
    assert not server.config_path.exists()
    assert server.request('POST', '/settings', cookie=owner, body=scanner_save(owner_token))[0].status == 303


def test_a_cli_removal_ends_a_live_session_on_the_next_request(start, signed_in):
    server = start(signed_in.accounts)
    tech = signed_in.cookie('tech')
    assert server.request('GET', '/', cookie=tech)[0].status == 200
    # The command line opens the same file with its own Accounts while the server runs.
    cli = Accounts(AccountStore(signed_in.accounts.store.path), signed_in.accounts.clock, now=signed_in.now)
    owner_id = cli.store.account_by_email(OWNER)['id']
    cli.remove(owner_id, cli.store.account_by_email(TECH)['id'], via='command_line')
    response, _ = server.request('GET', '/', cookie=tech)
    assert response.status == 303 and response.getheader('Location') == '/signin'


def test_a_role_change_applies_on_the_next_request(start, signed_in):
    server = start(signed_in.accounts)
    accounts = signed_in.accounts
    owner_id = accounts.store.account_by_email(OWNER)['id']
    tech_id = accounts.store.account_by_email(TECH)['id']
    cli = Accounts(AccountStore(accounts.store.path), accounts.clock, now=signed_in.now)
    cli.set_role(owner_id, tech_id, 'owner', via='command_line')
    # The role change ended the tech's sessions; a fresh sign-in now carries the owner role.
    assert server.request('GET', '/', cookie=signed_in.cookie('tech'))[0].status == 303
    signed_in.now.tick()
    response, _ = sign_in(server, TECH, PW_TECH, code_for(signed_in.tech_secret, signed_in.now))
    cookie = session_cookie(response).split(';', 1)[0]
    assert server.request('GET', '/?view=accounts', cookie=cookie)[0].status != 403


def test_signed_in_proxy_gets_settings_back(start, signed_in, monkeypatch):
    monkeypatch.setattr(local, 'scanner_probe', lambda *a, **kw: {})
    imported = []
    server = start(signed_in.accounts, public_origin=PUBLIC, upload=lambda data, add_task: imported.append(data) or 'imported')
    cookie = signed_in.cookie()
    response, body = server.request('GET', '/?view=settings&section=scanner', host=PUBLIC_HOST, cookie=cookie)
    assert response.status == 200 and 'action="/settings"' in body
    token = form_value(body, 'token')
    response, _ = server.request('POST', '/settings', host=PUBLIC_HOST, origin=PUBLIC, cookie=cookie,
                                 body=scanner_save(token))
    assert response.status == 303
    assert local_settings.load(server.config_path)['scanner']['socket_path'] == '/run/gvmd/gvmd.sock'
    _, body = server.request('GET', '/?view=infrastructure', host=PUBLIC_HOST, cookie=cookie)
    assert 'action="/upload"' in body


# --- the header ----------------------------------------------------------------

def test_the_header_names_the_account_and_offers_sign_out(start, signed_in):
    server = start(signed_in.accounts)
    _, body = server.request('GET', '/', cookie=signed_in.cookie('tech'))
    assert TECH in body and 'action="/signout"' in body
    assert 'No owner has joined yet' not in body


def test_no_owner_notice_while_only_techs_have_joined(start, tmp_path):
    accounts, now = empty(tmp_path)
    secret = totp.new_secret()
    accounts.setup_first(TECH, 'tech', PW_TECH, secret, code_for(secret, now))
    now.tick()
    token = accounts.sign_in(TECH, PW_TECH, code_for(secret, now), '192.0.2.10')
    server = start(accounts)
    _, body = server.request('GET', '/', cookie=f'rz_session={token}')
    assert 'No owner has joined yet, so risks cannot be accepted.' in body


# --- invites -------------------------------------------------------------------

def test_an_invite_link_sets_a_password_and_mfa_once(start, signed_in):
    accounts = signed_in.accounts
    owner_id = accounts.store.account_by_email(OWNER)['id']
    link = accounts.invite(owner_id, 'new@client.example', 'tech')
    server = start(accounts)
    assert server.request('GET', '/invite/' + 'A' * 43)[0].status == 404
    pre, value, body = open_form(server, f'/invite/{link}')
    assert '<svg' in body and 'new@client.example' in body
    secret = re.search(r'<code class="totp-key">([A-Z2-7]+)</code>', body).group(1)
    signed_in.now.tick()
    fields = {'pre': value, 'password': 'amber pelican lighthouse', 'code': wrong_code(secret, signed_in.now)}
    assert server.request('POST', f'/invite/{link}', cookie=pre, body=urlencode(fields))[0].status == 400
    fields['code'] = code_for(secret, signed_in.now)
    response, body = server.request('POST', f'/invite/{link}', cookie=pre, body=urlencode(fields))
    assert response.status == 200
    assert len(re.findall(r'<li><code>[a-z2-7]{5}-[a-z2-7]{5}</code></li>', body)) == 10
    assert server.request('GET', f'/invite/{link}')[0].status == 404           # single use
    assert server.request('POST', f'/invite/{link}', cookie=pre, body=urlencode(fields))[0].status == 404
    signed_in.now.tick()
    assert sign_in(server, 'new@client.example', 'amber pelican lighthouse', code_for(secret, signed_in.now))[0].status == 303


# --- fix round 1 ---------------------------------------------------------------

def test_a_slow_post_body_does_not_block_other_requests(start, signed_in, monkeypatch):
    # The body deadline is longer than the window watched here, and the client trickles a byte
    # a second so no per-recv timeout ends it: only reading outside the lock lets the GET through.
    monkeypatch.setattr(local, 'BODY_SECONDS', 8)
    server = start(signed_in.accounts)
    slow = socket.create_connection(('127.0.0.1', server.port), timeout=20)
    stop = threading.Event()

    def trickle():
        try:
            while not stop.wait(1.0):
                slow.sendall(b'x')
        except OSError:
            pass
    try:
        slow.sendall((f'POST /signin HTTP/1.1\r\nHost: {server.local_host}\r\n'
                      f'Origin: http://{server.local_host}\r\nContent-Type: application/x-www-form-urlencoded\r\n'
                      'Content-Length: 8192\r\n\r\npre=').encode())
        threading.Thread(target=trickle, daemon=True).start()
        threading.Event().wait(1.5)
        done = []

        def visit():
            done.append(server.request('GET', '/', cookie=signed_in.cookie())[0].status)
        other = threading.Thread(target=visit)
        other.start()
        other.join(4)
        assert done == [200]
        # ...while the slow body is still being read: no answer to it yet.
        assert select.select([slow], [], [], 0)[0] == []
        # It is then cut off at the overall deadline.
        assert slow.recv(64).startswith(b'HTTP/1.0 408')
    finally:
        stop.set()
        slow.close()


def raw_headers(server, path, length, cookie=None, extra=''):
    sock = socket.create_connection(('127.0.0.1', server.port), timeout=10)
    sock.sendall((f'POST {path} HTTP/1.1\r\nHost: {server.local_host}\r\nOrigin: http://{server.local_host}\r\n'
                  f'Content-Type: multipart/form-data; boundary=b\r\nContent-Length: {length}\r\n'
                  + (f'Cookie: {cookie}\r\n' if cookie else '') + extra + '\r\n').encode())
    return sock


def test_an_anonymous_upload_is_refused_before_its_body_is_read(start, signed_in):
    server = start(signed_in.accounts, upload=lambda data, add_task: pytest.fail('imported without a session'))
    for path, cookie in (('/upload', None), ('/upload', 'rz_session=forged'), ('/settings', None),
                         ('/nowhere', None)):
        sock = raw_headers(server, path, 60 * 1024 * 1024, cookie)
        try:
            # Not one body byte was sent: the answer comes from the headers alone.
            assert sock.recv(64).split(b' ')[1] in (b'403', b'404'), path
        finally:
            sock.close()
    # A tech may upload, but no role may post to an owner-only route without the right.
    sock = raw_headers(server, '/accounts/invite', 60 * 1024 * 1024, signed_in.cookie('tech'))
    try:
        assert sock.recv(64).split(b' ')[1] == b'403'
    finally:
        sock.close()


def status_of(sock):
    return sock.recv(256).split(b' ')[1]


def test_inflight_body_bytes_are_capped(start, signed_in, monkeypatch):
    monkeypatch.setattr(local, 'FORM_BUDGET_LIMIT', 10000)     # read when the handler is built
    monkeypatch.setattr(local, 'BODY_SECONDS', 8)
    server = start(signed_in.accounts)
    holding = raw_headers(server, '/signin', 8192)              # 8192 of the 10000 bytes, held
    try:
        threading.Event().wait(0.5)
        refused = raw_headers(server, '/signin', 8192)
        try:
            answer = refused.recv(256)
            assert answer.split(b' ')[1] == b'503'
            assert b'Retry-After: 5' in answer
        finally:
            refused.close()
    finally:
        holding.close()                                         # the read ends; its bytes come back
    threading.Event().wait(0.5)
    assert sign_in(server, 'nobody@client.example', PW_OWNER, '000000')[0].status == 400
    # The released bytes are all back: another full-size body is read (and refused as a bad form).
    full = raw_headers(server, '/signin', 8192)
    try:
        full.sendall(b'x' * 8192)
        assert status_of(full) == b'400'
    finally:
        full.close()


def test_uploads_cannot_block_sign_in(start, signed_in, monkeypatch):
    monkeypatch.setattr(local, 'INFLIGHT_BODY_LIMIT', 100000)
    monkeypatch.setattr(local, 'BODY_SECONDS', 8)
    server = start(signed_in.accounts, upload=lambda data, add_task: 'imported')
    held = [raw_headers(server, '/upload', 50000, signed_in.cookie(who)) for who in ('owner', 'tech')]
    try:
        threading.Event().wait(0.5)
        # The authorised budget is full: a settings save waits its turn...
        token = page_token(server, signed_in.cookie())
        assert server.request('POST', '/settings', cookie=signed_in.cookie(),
                              body=scanner_save(token))[0].status == 503
        # ...but sign-in does not: it has its own budget.
        assert sign_in(server, 'nobody@client.example', PW_OWNER, '000000')[0].status == 400
    finally:
        for sock in held:
            sock.close()


def test_anonymous_sign_in_bodies_cannot_block_a_settings_save(start, signed_in, monkeypatch):
    monkeypatch.setattr(local, 'FORM_BUDGET_LIMIT', 2 * 8192)
    monkeypatch.setattr(local, 'BODY_SECONDS', 8)
    server = start(signed_in.accounts)
    held = [raw_headers(server, '/signin', 8192) for _ in range(2)]
    try:
        threading.Event().wait(0.5)
        extra = raw_headers(server, '/signin', 8192)
        try:
            assert status_of(extra) == b'503'                    # the sign-in budget is full
        finally:
            extra.close()
        token = page_token(server, signed_in.cookie())
        assert server.request('POST', '/settings', cookie=signed_in.cookie(),
                              body=scanner_save(token))[0].status == 303
    finally:
        for sock in held:
            sock.close()


def test_one_upload_per_session(start, signed_in, monkeypatch):
    monkeypatch.setattr(local, 'BODY_SECONDS', 8)
    imported = []
    server = start(signed_in.accounts, upload=lambda data, add_task: imported.append(data) or 'imported')
    first = raw_headers(server, '/upload', 50000, signed_in.cookie())
    try:
        threading.Event().wait(0.5)
        second = raw_headers(server, '/upload', 50000, signed_in.cookie())
        try:
            answer = second.recv(256)
            assert answer.split(b' ')[1] == b'409' and b'Retry-After: 5' in answer
        finally:
            second.close()
        # Another session's upload is not held up.
        other = raw_headers(server, '/upload', 10, signed_in.cookie('tech'))
        try:
            other.sendall(b'x' * 10)
            assert status_of(other) == b'400'                    # read, then refused as a bad form
        finally:
            other.close()
    finally:
        first.close()
    threading.Event().wait(0.5)
    again = raw_headers(server, '/upload', 10, signed_in.cookie())   # the slot came back
    try:
        again.sendall(b'x' * 10)
        assert status_of(again) == b'400'
    finally:
        again.close()
    assert imported == []


def test_setup_ends_signed_in(start, tmp_path):
    accounts, now = empty(tmp_path)
    server = start(accounts)
    pre, value, body = open_form(server, '/setup')
    secret = form_value(body, 'secret')
    fields = {'pre': value, 'secret': secret, 'email': OWNER, 'role': 'owner', 'password': PW_OWNER,
              'code': code_for(secret, now)}
    response, body = server.request('POST', '/setup', cookie=pre, body=urlencode(fields))
    assert response.status == 200
    assert 'href="/"' in body and len(re.findall(r'<li><code>[a-z2-7]{5}-[a-z2-7]{5}</code></li>', body)) == 10
    cookie = session_cookie(response)
    assert cookie and 'HttpOnly' in cookie and 'SameSite=Strict' in cookie and 'Secure' not in cookie
    response, body = server.request('GET', '/', cookie=cookie.split(';', 1)[0])
    assert response.status == 200 and OWNER in body
    assert [e['event'] for e in reversed(accounts.store.events(10))] == ['setup', 'sign_in']


def test_accepting_an_invite_ends_signed_in(start, signed_in):
    accounts = signed_in.accounts
    owner_id = accounts.store.account_by_email(OWNER)['id']
    link = accounts.invite(owner_id, 'new@client.example', 'tech')
    server = start(accounts)
    pre, value, body = open_form(server, f'/invite/{link}')
    secret = re.search(r'<code class="totp-key">([A-Z2-7]+)</code>', body).group(1)
    signed_in.now.tick()
    fields = {'pre': value, 'password': 'amber pelican lighthouse', 'code': code_for(secret, signed_in.now)}
    response, body = server.request('POST', f'/invite/{link}', cookie=pre, body=urlencode(fields))
    assert response.status == 200 and 'href="/"' in body
    cookie = session_cookie(response).split(';', 1)[0]
    response, body = server.request('GET', '/', cookie=cookie)
    assert response.status == 200 and 'new@client.example' in body


def test_first_account_page_hides_the_workspace_path_off_the_server(start, tmp_path):
    accounts, _ = empty(tmp_path)
    server = start(accounts, public_origin=PUBLIC)   # start() passes --database /srv/rz
    for host in (PUBLIC_HOST, None):
        response, body = server.request('GET', '/', host=host)
        assert response.status == 200
        assert '/srv/rz' not in body
        assert '--database DIR account setup' in body


def test_an_unreadable_accounts_file_gives_503_on_every_route(start, signed_in):
    server = start(signed_in.accounts)
    cookie = signed_in.cookie()
    token = page_token(server, cookie)
    signed_in.accounts.store.path.write_bytes(b'not a database ' * 512)
    for method, path, sent_cookie, body in (('GET', '/', None, None), ('GET', '/', cookie, None),
                                            ('GET', '/signin', None, None),
                                            ('POST', '/signin', None, 'pre=x&email=a&password=b&code=c'),
                                            ('POST', '/settings', cookie, scanner_save(token))):
        response, _ = server.request(method, path, cookie=sent_cookie, body=body)
        assert response.status == 503, (method, path, sent_cookie)
