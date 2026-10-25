# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Offline, standard-library-only installation/HTTP check; no model calls."""
import json
from pathlib import Path
import queue
import re
import subprocess
import sys
import tempfile
import threading
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, build_opener, ProxyHandler

from scripts.build_local_installer import build


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
            opener = build_opener(ProxyHandler({}))
            def get(path):
                with opener.open(base + path, timeout=5) as response:
                    assert response.status == 200
                    return response.read().decode()
            for view in ('overview', 'infrastructure', 'actions', 'activity'):
                get('/?view=' + view)
            for section in ('model', 'application', 'storage', 'safety', 'updates'):
                get('/?view=settings&section=' + section)
            html = get('/?view=settings')
            token = re.search('name="token" value="([^"]+)"', html)[1]
            data = urlencode(dict(token=token, section='application', mode='saved', port='8082')).encode()
            with opener.open(Request(base + '/settings', data=data, headers={'Origin':base}), timeout=5) as response:
                assert 'Preferences saved' in response.read().decode()
            prefs = app / 'remediation-zero.settings.json'
            saved = prefs.read_bytes()
            assert json.loads(saved)['port'] == 8082
            try:
                opener.open(Request(base + '/settings', data=data, headers={'Origin':'https://example.invalid'}), timeout=5)
                raise AssertionError('Cross-origin request accepted')
            except HTTPError as exc:
                assert exc.code == 403
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
    print('PASS: offline install, launcher imports, all dashboard/Settings pages, persistence, Origin rejection, overwrite refusal. No model calls.')


if __name__ == '__main__':
    verify()
