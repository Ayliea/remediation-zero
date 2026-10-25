# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Caught guard denials remain observable without any network operation."""
import subprocess
import sys
from pathlib import Path


def test_guard_denials_remain_observable_when_caught():
    guard = Path(__file__).with_name("offline_guard.py")
    script = f"guard = __import__('runpy').run_path({str(guard)!r})\n" + """
import sys
import google.auth
import requests
import httpx
from google.auth.compute_engine import _metadata
from google.genai.models import Models, AsyncModels
operations = [
    lambda: sys.audit('socket.connect', None, None),
    lambda: sys.audit('socket.getaddrinfo', None, None, None, None, None),
    google.auth.default, _metadata.get, _metadata.ping,
    requests.sessions.Session.request, httpx.HTTPTransport.handle_request,
    httpx.AsyncHTTPTransport.handle_async_request,
    Models.generate_content, AsyncModels.generate_content,
]
for operation in operations:
    try:
        operation()
    except AssertionError as exc:
        assert 'Offline tests forbid' in str(exc)
    else:
        raise AssertionError('offline guard allowed an operation')
assert len(guard['violations']) == len(operations)
"""
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr


def _guard_script(body):
    guard = Path(__file__).with_name("offline_guard.py")
    return f"guard = __import__('runpy').run_path({str(guard)!r})\nimport os, socket, sys, tempfile\n" + body


def _run(body):
    result = subprocess.run([sys.executable, "-c", _guard_script(body)], capture_output=True,
                            text=True, timeout=30)
    assert result.returncode == 0, result.stderr


def test_unregistered_loopback_port_is_refused():
    _run("""
srv = socket.socket(); srv.bind(('127.0.0.1', 0)); srv.listen(1)
port = srv.getsockname()[1]
c = socket.socket()
try:
    c.connect(('127.0.0.1', port))
except AssertionError:
    pass
else:
    raise SystemExit('unregistered loopback port was reachable')
try:
    socket.getaddrinfo('localhost', port)
except AssertionError:
    pass
else:
    raise SystemExit('lookup for an unregistered port was allowed')
assert len(guard['violations']) == 2
""")


def test_unix_path_outside_basetemp_is_refused(tmp_path):
    _run(f"""
base = {str(tmp_path / 'base')!r}
os.makedirs(base)
outside = tempfile.mkdtemp()
path = os.path.join(outside, 's.sock')
srv = socket.socket(socket.AF_UNIX); srv.bind(path); srv.listen(1)
try:
    guard['register_unix'](path, base)
except ValueError:
    pass
else:
    raise SystemExit('registered a socket outside the base temp dir')
c = socket.socket(socket.AF_UNIX)
try:
    c.connect(path)
except AssertionError:
    pass
else:
    raise SystemExit('unregistered unix socket was reachable')
try:
    c.connect(b'\\0abstract')
except AssertionError:
    pass
else:
    raise SystemExit('abstract socket was reachable')
""")


def test_registered_fake_server_is_allowed(tmp_path):
    _run(f"""
base = {str(tmp_path)!r}
path = os.path.join(base, 's.sock')
srv = socket.socket(socket.AF_UNIX); srv.bind(path); srv.listen(1)
entry = guard['register_unix'](path, base)
socket.socket(socket.AF_UNIX).connect(path)
guard['deregister'](entry)
try:
    socket.socket(socket.AF_UNIX).connect(path)
except AssertionError:
    pass
else:
    raise SystemExit('still reachable after deregistration')
tcp = socket.socket(); tcp.bind(('127.0.0.1', 0)); tcp.listen(1)
host, port = tcp.getsockname()[:2]
entry = guard['register_tcp'](host, port)
socket.create_connection(('localhost', port)).close()
guard['deregister'](entry)
""")
