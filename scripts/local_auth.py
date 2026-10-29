# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Who is asking, and how they came in: the dashboard server's sign-in layer.

Standard library only. `scripts.local.handler` asks this module three things
for every request, before it reads a record or a setting:

- `classify`: the way in. `local` is a loopback peer, a loopback Host, no
  `--public-url` and settings not exposed: only then is setup offered and the
  cookie sent without Secure. `proxied` is a loopback peer whose Host is the
  configured `--public-url` name; its client address is the last
  X-Forwarded-For entry. `direct` is everything else that is still allowed:
  a configured server name over the TLS listener, or a loopback Host that
  cannot be told apart from a proxied one (a proxy is configured, or the
  listen address is a network one). Anything else is refused, as before.
- the session, from the `rz_session` cookie, re-read from the accounts file
  on every request so a change made by the command line applies at once;
- the Origin a POST must carry: the scheme and Host the request came in on.

`AuthRoutes` serves the pages that work without a session: sign-in, setup
(local only, and only while no account exists), invite links and re-confirm
(which needs a session but is a pre-session form). Their forms carry a
double-submit token: a random, server-signed value in the SameSite=Strict
cookie `rz_pre` that must equal the form's hidden `pre` field. Every one of
those POSTs is rate limited per client address, capped at FORM_LIMIT bytes and
a handful of fields, and caps each password at PASSWORD_LIMIT characters
before it can reach scrypt.

**Cookie, not bearer token (deviation from the web baseline's API rule):** a
server-rendered page needs a cookie. It is HttpOnly, SameSite=Strict, Path=/,
and Secure except on a `local` request (plain http://127.0.0.1, where a
browser would drop a Secure cookie on some versions and nothing crosses a
network); it is kept together with the Origin and Sec-Fetch-Site checks and a
per-session form token.

**A link's new TOTP secret is never stored** (join, MFA reset, recovery): every
GET of the page makes a new one and puts it in the form beside a MAC,
HMAC-SHA256 under a per-process key over the link's token hash and the
secret. The POST is refused as an invalid form unless the MAC verifies
(`hmac.compare_digest`), and only then is that secret enrolled. Whatever fetched
the link before the person did (a mail scanner, a chat unfurler) saw a secret
that is never enrolled, and a secret chosen by anyone else is refused. A server
restart only means the page is opened again.

**Invite tokens are in the path** (`/invite/<token>`): the link is what the
inviter copies. It is single use, expires after 7 days, is stored only as a
SHA-256, and pages are served with `Referrer-Policy: same-origin`. The server
logs no request line, so a token in a path never reaches a log.
"""
import hashlib
import hmac
import ipaddress
import secrets
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import parse_qs, quote

from tools import totp
from tools.accounts import AccountRefused
from tools.qr_svg import qr_svg
from ui import account_views
from ui.dashboard_view import VIEWS
from ui.settings_view import SECTIONS

SESSION_COOKIE = 'rz_session'
PRE_COOKIE = 'rz_pre'
FORM_LIMIT = 8192            # bytes in one sign-in, setup, invite or confirm form
FORM_FIELDS = 12             # fields in one such form
PASSWORD_LIMIT = 1024        # characters; longer is a failure before scrypt runs
PRE_SECONDS = 30 * 60        # a pre-session form token's life
COOKIE_LIMIT = 4096
#: The command the first-account page shows. Only a visitor who has not signed in sees that
#: page, so it names no workspace path: DIR stands for the --database the server was started with.
SETUP_COMMAND = 'python3 -S -m scripts.local --database DIR account setup'
_SECRET_CHARS = frozenset('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567')
_HEX_CHARS = frozenset('0123456789abcdef')
_TOKEN_CHARS = frozenset('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_')

#: Where re-confirm may send someone back to: a closed set, never a client-supplied URL.
NEXT_PATHS = frozenset({'/', '/?view=accounts'} | {f'/?view={view}' for view in VIEWS}
                       | {f'/?view=settings&section={section}' for section in SECTIONS})

SIGN_IN_FAILED = 'That did not work. Check your email, password and code, and try again.'
CONFIRM_FAILED = 'That did not match. Enter your password and a new code from your authenticator app.'
_REFUSALS = {
    'too_short': 'Use a password of at least 12 characters.',
    'too_long': 'Use a password of at most 128 characters.',
    'breached': 'That password is on a list of breached passwords. Choose another.',
    'missing': 'Enter a password.',
    'incorrect': 'Your current password did not match.',
    'bad_code': "That code did not match. Use the newest code in your authenticator app, and check this device's clock.",
    'locked': 'This account is locked for a while after too many failed attempts. Try again later.',
    'email': 'Enter one email address and choose a role.',
}


def is_loopback(address) -> bool:
    try:
        return ipaddress.ip_address(address).is_loopback
    except (TypeError, ValueError):
        return False


def server_hosts(names, port) -> frozenset:
    """The Host values a browser sends for each configured name on `port`."""
    hosts = set()
    for name in names:
        shown = f'[{name}]' if ':' in name else name      # an IPv6 address
        hosts.add(f'{shown}:{port}')
        if port == 443:
            hosts.add(shown)
    return frozenset(hosts)


def classify(peer, host, *, port, public_host, exposed, server_names, scheme):
    """(kind, expected Origin) for a request, or None to refuse it."""
    host = host.lower() if isinstance(host, str) else ''
    peer_loopback = is_loopback(peer)
    if public_host is not None and host == public_host and peer_loopback:
        return 'proxied', f'https://{public_host}'
    if host in (f'127.0.0.1:{port}', f'localhost:{port}'):
        if peer_loopback and public_host is None and not exposed and scheme == 'http':
            return 'local', f'http://{host}'
        # A proxy also connects from 127.0.0.1 and may pass this Host through: not local.
        return 'direct', f'{scheme}://{host}'
    if scheme == 'https' and host in server_hosts(server_names, port):
        return 'direct', f'https://{host}'
    return None


def client_address(kind, peer, forwarded) -> str:
    """The address for the rate limit and the audit trail. Only a proxied request's
    X-Forwarded-For is read, and only its last entry: the one the proxy itself added."""
    if kind == 'proxied' and forwarded:
        last = ','.join(forwarded).split(',')[-1].strip()
        try:
            return str(ipaddress.ip_address(last))
        except ValueError:
            pass
    return str(peer)


def read_cookies(header) -> dict:
    """name -> value; the first of a repeated name wins. Nothing is unquoted or decoded."""
    found = {}
    if not isinstance(header, str) or len(header) > COOKIE_LIMIT:
        return found
    for part in header.split(';'):
        name, eq, value = part.strip().partition('=')
        if eq and name and name not in found:
            found[name] = value.strip()
    return found


def _cookie(name, value, secure, max_age=None):
    # SameSite=Strict, HttpOnly, Path=/; Secure unless the request is local (see the module docstring).
    parts = [f'{name}={value}', 'HttpOnly', 'SameSite=Strict', 'Path=/']
    if max_age is not None:
        parts.append(f'Max-Age={max_age}')
    if secure:
        parts.append('Secure')
    return '; '.join(parts)


def session_cookie(token, secure):
    return _cookie(SESSION_COOKIE, token, secure)


def cleared_session_cookie(secure):
    return _cookie(SESSION_COOKIE, '', secure, max_age=0)


class SecretSeals:
    """The MAC that ties a link page's TOTP secret to that link, so the POST can carry the
    secret without its being stored or chosen by the client. Per-process key; runtime only."""

    def __init__(self):
        self._key = secrets.token_bytes(32)

    def seal(self, token, secret):
        body = hashlib.sha256(token.encode()).hexdigest() + secret   # token hash || secret
        return hmac.new(self._key, body.encode(), hashlib.sha256).hexdigest()

    @staticmethod
    def well_formed(secret, mac):
        """A secret as totp.new_secret makes them and a MAC of 64 lower-case hex digits."""
        return (isinstance(secret, str) and len(secret) == 32 and set(secret) <= _SECRET_CHARS
                and isinstance(mac, str) and len(mac) == 64 and set(mac) <= _HEX_CHARS)

    def valid(self, token, secret, mac):
        if not self.well_formed(secret, mac):
            return False
        return hmac.compare_digest(mac, self.seal(token, secret))


class PreTokens:
    """Short-lived double-submit values, signed with a per-process key so a value
    planted in the cookie by anyone else is not accepted. Runtime-only: the age is
    measured on the monotonic clock and nothing is persisted."""

    def __init__(self, now=time.monotonic):
        self._key = secrets.token_bytes(32)
        self._now = now

    def _mac(self, body):
        return hmac.new(self._key, body.encode(), hashlib.sha256).hexdigest()[:32]

    def new(self):
        body = f'{int(self._now())}.{secrets.token_urlsafe(16)}'
        return f'{body}.{self._mac(body)}'

    def valid(self, value):
        if not isinstance(value, str) or len(value) > 128 or not value.isascii():
            return False
        body, _, mac = value.rpartition('.')
        issued = body.partition('.')[0]
        if not (mac and issued.isdigit() and hmac.compare_digest(mac, self._mac(body))):
            return False
        return 0 <= self._now() - int(issued) <= PRE_SECONDS


def read_form(headers, rfile, names):
    """A small urlencoded form: each field at most once, only `names`. ValueError otherwise."""
    length = headers.get('Content-Length')
    if (length is None or not (length.isascii() and length.isdigit()) or headers.get('Transfer-Encoding')
            or headers.get('Content-Type') != 'application/x-www-form-urlencoded'):
        raise ValueError('form')
    length = int(length)
    if not 0 < length <= FORM_LIMIT:
        raise ValueError('size')
    raw = rfile.read(length)
    if len(raw) != length:
        raise ValueError('short')
    fields = parse_qs(raw.decode('utf-8'), keep_blank_values=True, strict_parsing=True,
                      max_num_fields=FORM_FIELDS)
    if any(len(v) != 1 for v in fields.values()) or not set(fields) <= set(names):
        raise ValueError('fields')
    return {k: v[0] for k, v in fields.items()}


def safe_next(query) -> str:
    values = parse_qs(query, keep_blank_values=True).get('next', [])
    return values[0] if len(values) == 1 and values[0] in NEXT_PATHS else '/'


def confirm_location(next_path) -> str:
    return '/confirm?next=' + quote(next_path if next_path in NEXT_PATHS else '/', safe='')


def invite_token(path) -> Optional[str]:
    """The token of a well-formed /invite/<token> path, else None (and the path is a 404)."""
    if not path.startswith('/invite/'):
        return None
    token = path[len('/invite/'):]
    return token if 20 <= len(token) <= 128 and set(token) <= _TOKEN_CHARS else None


@dataclass(frozen=True)
class Request:
    kind: str           # 'local' | 'proxied' | 'direct'
    origin: str         # the Origin a POST must carry
    client: str         # for the rate limit and the audit trail
    token: Optional[str]
    session: object     # tools.accounts.Session or None
    cookies: dict

    @property
    def secure(self):
        return self.kind != 'local'


class AuthRoutes:
    """GET and POST for /signin, /signout, /setup, /invite/<token> and /confirm.

    `h` is the request handler: it supplies `send_page(body, status, headers=())`,
    `redirect(location, headers=())`, `send_error`, `headers` and `body_file` (the body, already read)."""

    def __init__(self, accounts, limiter):
        self.accounts = accounts
        self.limiter = limiter
        self.pre = PreTokens()
        self.seals = SecretSeals()

    def handles(self, path):
        return path in ('/signin', '/signout', '/setup', '/confirm') or path.startswith('/invite/')

    def no_accounts(self):
        return self.accounts.store.count_accounts() == 0

    # --- the pre-session token -----------------------------------------------

    def _pre_for(self, req):
        """(value, Set-Cookie headers): the visitor's valid rz_pre, or a new one."""
        value = req.cookies.get(PRE_COOKIE)
        if self.pre.valid(value):
            return value, ()
        value = self.pre.new()
        return value, (('Set-Cookie', _cookie(PRE_COOKIE, value, req.secure, max_age=PRE_SECONDS)),)

    def _pre_ok(self, req, fields):
        cookie, given = req.cookies.get(PRE_COOKIE), fields.get('pre')
        return (self.pre.valid(cookie) and isinstance(given, str)
                and hmac.compare_digest(cookie.encode(), given.encode()))

    # --- GET -----------------------------------------------------------------

    def get(self, h, req, path, query):
        if path == '/signout':
            h.send_error(404)
            return
        token = invite_token(path) if path.startswith('/invite/') else None
        if path.startswith('/invite/') and token is None:
            h.send_error(404)
            return
        if self.no_accounts() and path != '/setup':
            if req.kind == 'local':
                h.redirect('/setup')
            elif token is not None:
                h.send_error(404)
            else:
                h.send_page(account_views.first_account_page(SETUP_COMMAND), 200)
            return
        if path == '/setup':
            if req.kind != 'local' or not self.no_accounts():
                h.send_error(404)
                return
            secret = totp.new_secret()
            pre, headers = self._pre_for(req)
            h.send_page(self._setup_page(pre, secret), 200, headers)
        elif path == '/signin':
            if req.session is not None:
                h.redirect('/')
                return
            pre, headers = self._pre_for(req)
            h.send_page(account_views.sign_in_page(pre), 200, headers)
        elif path == '/confirm':
            if req.session is None:
                h.redirect('/signin')
                return
            pre, headers = self._pre_for(req)
            h.send_page(account_views.confirm_page(pre, safe_next(query)), 200, headers)
        else:
            view = self.accounts.invite_view(token)
            if view is None:
                h.send_page(account_views.invalid_link_page(), 404)
                return
            pre, headers = self._pre_for(req)
            h.send_page(self._invite_page(pre, token, view, view.totp_secret), 200, headers)

    def _setup_page(self, pre, secret, *, email='', role='owner', message=''):
        uri = totp.otpauth_uri(secret, email or 'first account')
        return account_views.setup_page(pre, secret, uri, qr_svg(uri), email=email, role=role, message=message)

    def _invite_page(self, pre, token, view, secret, message=''):
        """The link's page. `secret` is the new TOTP secret it shows (None for a password reset),
        sealed into the form for this link: a fresh one on a GET, the submitted one on a retry."""
        uri = totp.otpauth_uri(secret, view.email) if secret else None
        return account_views.invite_page(pre, view.kind, view.email, view.role, secret, uri,
                                         qr_svg(uri) if uri else None, message=message,
                                         secret_mac=self.seals.seal(token, secret) if secret else None)

    # --- POST ----------------------------------------------------------------

    def post(self, h, req, path, query):
        token = invite_token(path) if path.startswith('/invite/') else None
        if path == '/signout':
            self._sign_out(h, req)
            return
        if (path.startswith('/invite/') and token is None) or (path == '/setup' and (
                req.kind != 'local' or not self.no_accounts())):
            h.send_error(404)
            return
        if path == '/confirm' and req.session is None:
            h.send_error(403)
            return
        if self.no_accounts() and path != '/setup':
            h.send_error(403)
            return
        names = {'/signin': ('pre', 'email', 'password', 'code'),
                 '/setup': ('pre', 'secret', 'email', 'role', 'password', 'code'),
                 '/confirm': ('pre', 'password', 'code')}.get(
                     path, ('pre', 'password', 'current_password', 'code', 'secret', 'secret_mac'))
        try:
            fields = read_form(h.headers, h.body_file, names)
        except (ValueError, UnicodeError):
            h.send_error(400, 'Invalid form.')
            return
        if not self._pre_ok(req, fields):
            h.send_error(403)
            return
        pre = fields['pre']
        wait = self.limiter.hit(req.client)
        if wait is not None:
            h.send_page(account_views.too_many_page(wait), 429, (('Retry-After', str(wait)),))
            return
        if path == '/signin':
            self._sign_in(h, req, fields, pre)
        elif path == '/setup':
            self._setup(h, req, fields, pre)
        elif path == '/confirm':
            self._confirm(h, req, fields, pre, query)
        else:
            self._accept(h, req, token, fields, pre)

    @staticmethod
    def _capped(value):
        """A password field, or None when it is missing or longer than PASSWORD_LIMIT."""
        return value if isinstance(value, str) and len(value) <= PASSWORD_LIMIT else None

    def _sign_in(self, h, req, fields, pre):
        # Every failure, a too-long password included, takes the same path through
        # Accounts.sign_in (one scrypt, one event) and gets the same response.
        password = self._capped(fields.get('password', '')) or ''
        session = self.accounts.sign_in(fields.get('email', ''), password, fields.get('code', ''), req.client)
        if session is None:
            h.send_page(account_views.sign_in_page(pre, message=SIGN_IN_FAILED), 400)
            return
        h.redirect('/', (('Set-Cookie', session_cookie(session, req.secure)),))  # never a client-supplied URL

    def _setup(self, h, req, fields, pre):
        secret = fields.get('secret', '')
        if not (len(secret) == 32 and set(secret) <= _SECRET_CHARS):
            h.send_error(400, 'Invalid form.')
            return
        email, role = fields.get('email', ''), fields.get('role', '')
        password = self._capped(fields.get('password'))
        try:
            if password is None:
                raise AccountRefused('password', 'too_long' if fields.get('password') else 'missing')
            codes, session = self.accounts.setup_first(email, role, password, secret, fields.get('code', ''),
                                                       via='dashboard', source=req.client, start_session=True)
        except AccountRefused as refusal:
            if refusal.code == 'accounts_exist':
                h.send_error(404)
                return
            h.send_page(self._setup_page(pre, secret, email=email, role=role, message=_message(refusal)), 400)
            return
        except ValueError:
            h.send_page(self._setup_page(pre, secret, email=email, role=role, message=_REFUSALS['email']), 400)
            return
        # A new password and a code from the new secret were just verified: setup ends signed in.
        h.send_page(account_views.recovery_codes_page(codes, 'Your account is ready'), 200,
                    (('Set-Cookie', session_cookie(session, req.secure)),))

    def _confirm(self, h, req, fields, pre, query):
        nxt = safe_next(query)
        password, code = fields.get('password') or None, fields.get('code') or None
        ok = False
        if password is not None and self._capped(password) is not None:
            ok = self.accounts.confirm(req.token, password=password, code=code, source=req.client)
        if not ok:
            h.send_page(account_views.confirm_page(pre, nxt, message=CONFIRM_FAILED), 400)
            return
        h.redirect(nxt)

    def _accept(self, h, req, token, fields, pre):
        view = self.accounts.invite_view(token)
        if view is None:
            h.send_page(account_views.invalid_link_page(), 404)
            return
        secret = None
        if view.kind != 'reset_password':
            # The secret this page showed, sealed for this link; nothing else is ever enrolled.
            secret, mac = fields.get('secret'), fields.get('secret_mac')
            if not self.seals.well_formed(secret, mac):
                h.send_error(400, 'Invalid form.')
                return
            if not self.seals.valid(token, secret, mac):
                # Most often the server restarted since the page was opened (a new key). The
                # same answer for a changed secret: nothing says which.
                h.send_page(account_views.expired_page(), 400)
                return
        password = self._capped(fields.get('password'))
        current = self._capped(fields.get('current_password'))
        code = fields.get('code', '')
        try:
            if view.kind == 'reset_mfa':
                if current is None:
                    raise AccountRefused('password', 'incorrect')
                args, kwargs = (None, code), {'current_password': current, 'secret': secret}
            else:
                if password is None:
                    raise AccountRefused('password', 'too_long' if fields.get('password') else 'missing')
                if view.kind == 'reset_password':
                    args, kwargs = (password, None), {'current_code': code}
                else:
                    args, kwargs = (password, code), {'secret': secret}
            # The link's checks passed in this request, so it ends signed in (a new session).
            _, codes, session = self.accounts.accept_invite(token, *args, via='dashboard', source=req.client,
                                                            start_session=True, **kwargs)
        except AccountRefused as refusal:
            if refusal.code == 'invalid_link':
                h.send_page(account_views.invalid_link_page(), 404)
                return
            h.send_page(self._invite_page(pre, token, view, secret, _message(refusal)), 400)
            return
        signed_in = (('Set-Cookie', session_cookie(session, req.secure)),)
        if codes:
            h.send_page(account_views.recovery_codes_page(codes, 'You are set up'), 200, signed_in)
        else:
            h.send_page(account_views.done_page(), 200, signed_in)

    def _sign_out(self, h, req):
        clear = (('Set-Cookie', cleared_session_cookie(req.secure)),)
        if req.session is None:
            h.redirect('/signin', clear)
            return
        try:
            fields = read_form(h.headers, h.body_file, ("token",))
        except (ValueError, UnicodeError):
            h.send_error(400, 'Invalid form.')
            return
        if not hmac.compare_digest(fields.get('token', '').encode(), req.session.csrf.encode()):
            h.send_error(403)
            return
        self.accounts.sign_out(req.token, source=req.client)
        h.redirect('/signin', clear)


def _message(refusal):
    if refusal.code == 'password':
        return _REFUSALS.get(refusal.reason, _REFUSALS['missing'])
    return _REFUSALS.get(refusal.code, SIGN_IN_FAILED)
