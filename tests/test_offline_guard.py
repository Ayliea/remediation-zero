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
