# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Shared transport rules for every explicitly configured model endpoint.

HTTPS unless the host is loopback; no redirects; no inherited proxies; no URL
credentials, query or fragment; bounded response; fixed socket timeout.
Standard library only.
"""
import ipaddress
import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from tools.adjudication import CapacityError

MAX_INPUT_BYTES = 32768
MAX_RESPONSE_BYTES = 65536
MAX_OUTPUT_TOKENS = 2048
TIMEOUT_SECONDS = 60
_CAPACITY_CODES = {408, 429, 500, 502, 503, 504}


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def validate_endpoint(url):
    if not isinstance(url, str) or any(ord(c) < 33 or ord(c) == 127 for c in url):
        raise ValueError('Invalid endpoint URL')
    parsed = urlsplit(url)
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError('Invalid endpoint port')
    try:
        local = ipaddress.ip_address(parsed.hostname or '').is_loopback
    except ValueError:
        local = parsed.hostname == 'localhost'
    if (parsed.scheme not in {'http', 'https'} or not parsed.hostname or
            (parsed.scheme == 'http' and not local) or parsed.username or
            parsed.password or parsed.query or parsed.fragment):
        raise ValueError('Use an HTTPS endpoint, or HTTP on loopback; no URL credentials, query or fragment')
    return url.rstrip('/')


def _build_opener():
    # Avoid forwarding credentials via redirects or inherited proxy settings.
    return build_opener(ProxyHandler({}), NoRedirects())


def _open(request, timeout):
    return _build_opener().open(request, timeout=timeout)


def post_json(url, body, headers):
    data = json.dumps(body).encode()
    try:
        with _open(Request(url, data=data, headers=headers), timeout=TIMEOUT_SECONDS) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except HTTPError as exc:
        if exc.code in _CAPACITY_CODES:
            raise CapacityError('Model endpoint temporarily unavailable') from None
        raise ValueError('Model endpoint rejected request') from None
    except (URLError, TimeoutError):
        raise CapacityError('Model endpoint could not be reached') from None
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError('Model response exceeds limit')
    try:
        return json.loads(raw)
    except ValueError:
        raise ValueError('Model returned an invalid proposal') from None
