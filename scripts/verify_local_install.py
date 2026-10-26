# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Offline, standard-library-only installation/HTTP check; no model calls."""
from email.utils import parsedate_to_datetime
import http.client
import json
from pathlib import Path
import queue
import re
import subprocess
import sys
import tempfile
import threading
from urllib.parse import urlencode, urlsplit

from scripts.build_local_installer import build
from tools import totp

EMAIL = 'owner@client.example'
PASSWORD = 'quiet orchard sundial lantern'  # synthetic


class Browser:
    """Just enough of a browser for the check: it keeps cookies and sends the Origin a form would."""

    def __init__(self, base):
        self.base = base
        self.host = urlsplit(base).netloc
        self.cookies = {}

    def request(self, method, path, body=None, *, origin=None):
        conn = http.client.HTTPConnection(self.host, timeout=10)
        headers = {'Host': self.host}
        if self.cookies:
            headers['Cookie'] = '; '.join(f'{k}={v}' for k, v in self.cookies.items())
        if method == 'POST':
            headers.update({'Origin': origin or self.base, 'Content-Type': 'application/x-www-form-urlencoded'})
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        text = response.read().decode()
        for value in response.headers.get_all('Set-Cookie') or ():
            name, _, rest = value.partition('=')
            self.cookies[name] = rest.split(';', 1)[0]
        found = {k.lower(): v for k, v in response.getheaders()}
        conn.close()
        return response.status, found, text

    def page(self, path):
        status, _, text = self.request('GET', path)
        assert status == 200, f'{path} answered {status}'
        return text

    def form(self, path):
        """(pre, body, the server's wall time) for a pre-session form."""
        status, headers, text = self.request('GET', path)
        assert status == 200, f'{path} answered {status}'
        return re.search('name="pre" value="([^"]+)"', text)[1], text, parsedate_to_datetime(headers['date']).timestamp()

    def set_up(self, email, password):
        pre, text, now = self.form('/setup')
        secret = re.search('name="secret" value="([A-Z2-7]+)"', text)[1]
        # The server's own Date header is the time its TOTP check uses, so no clock is read here.
        code = totp.code_at(secret, totp.step_for(now))
        status, _, text = self.request('POST', '/setup', urlencode(dict(
            pre=pre, secret=secret, email=email, role='owner', password=password, code=code)))
        assert status == 200, f'Setup answered {status}'
        codes = re.findall(r'<li><code>([a-z2-7]{5}-[a-z2-7]{5})</code></li>', text)
        assert len(codes) == 10, 'No recovery codes shown'
        return codes

    def sign_in(self, email, password, code):
        pre, _, _ = self.form('/signin')
        status, headers, _ = self.request('POST', '/signin', urlencode(dict(pre=pre, email=email, password=password,
                                                                              code=code)))
        assert status == 303 and headers['location'] == '/' and 'rz_session' in self.cookies, 'Sign-in failed'

    def confirm(self, location, password):
        pre, _, _ = self.form(location)
        status, _, _ = self.request('POST', location, urlencode(dict(pre=pre, password=password, code='')))
        assert status == 303, 'Re-confirm failed'


def verify():
    with tempfile.TemporaryDirectory(prefix='rz-install-check-') as temp:
        root = Path(temp)
        installer = build(root / 'install.py')
        app = root / 'installed preview'
        subprocess.run([sys.executable, '-S', str(installer), '--directory', str(app),
                        '--yes', '--no-start'], check=True, capture_output=True, timeout=30)
        # Use an unrelated cwd to verify the root launcher imports its own code.
        subprocess.run([sys.executable, '-S', str(app / 'start-remediation-zero.py'),
                        '--help'], cwd=root, check=True, capture_output=True, timeout=10)
        process = subprocess.Popen([sys.executable, '-S', '-m', 'scripts.local',
            'serve', '--port', '0'], cwd=app, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True)
        try:
            ready = queue.Queue()
            threading.Thread(target=lambda: ready.put(process.stdout.readline()), daemon=True).start()
            line = ready.get(timeout=10).strip()
            # Saved records (no --demo): the banner does not claim a synthetic preview.
            assert line.startswith('Local dashboard: http://127.0.0.1:'), 'Server did not start'
            base = line.split()[-1]
            assert urlsplit(base).hostname == '127.0.0.1'
            browser = Browser(base)
            # No account yet, on the server itself: every page leads to setup.
            status, headers, _ = browser.request('GET', '/')
            assert status == 303 and headers['location'] == '/setup', 'Setup was not offered'
            codes = browser.set_up(EMAIL, PASSWORD)
            browser.sign_in(EMAIL, PASSWORD, codes[0])
            for view in ('overview', 'infrastructure', 'actions', 'activity'):
                browser.page('/?view=' + view)
            for section in ('model', 'application', 'storage', 'safety', 'updates'):
                browser.page('/?view=settings&section=' + section)
            html = browser.page('/?view=settings')
            token = re.search('name="token" value="([^"]+)"', html)[1]
            data = urlencode(dict(token=token, section='application', mode='saved', port='8082'))
            # A save asks for re-confirmation first, then goes through.
            status, headers, _ = browser.request('POST', '/settings', data)
            assert status == 303 and headers['location'].startswith('/confirm?next='), 'Save without re-confirm'
            browser.confirm(headers['location'], PASSWORD)
            status, headers, _ = browser.request('POST', '/settings', data)
            assert status == 303, 'Save refused'
            assert 'Preferences saved' in browser.page(headers['location'])
            prefs = app / 'remediation-zero.settings.json'
            saved = prefs.read_bytes()
            assert json.loads(saved)['port'] == 8082
            status, _, _ = browser.request('POST', '/settings', data, origin='https://example.invalid')
            assert status == 403, 'Cross-origin request accepted'
            status, _, _ = Browser(base).request('POST', '/settings', data)
            assert status == 403, 'Save without a session accepted'
            assert prefs.read_bytes() == saved
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            process.stdout.close()
        # Re-running the installer must not replace the existing workspace.
        result = subprocess.run([sys.executable, '-S', str(installer), '--directory',
            str(app), '--yes', '--no-start'], capture_output=True, timeout=30)
        assert result.returncode != 0
        assert prefs.read_bytes() == saved
    print('PASS: offline install, launcher imports, first-account setup, sign-in, all dashboard/Settings pages, '
          're-confirm, persistence, Origin and no-session rejection, overwrite refusal. No model calls.')


if __name__ == '__main__':
    verify()
