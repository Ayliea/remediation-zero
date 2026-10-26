# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
import io
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler

import pytest

from tools import model_transport
from tools.adjudication import CapacityError
from tools.model_transport import NoRedirects, post_json, validate_endpoint


class _Response:
    def __init__(self, raw):
        self._raw = raw

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, n=-1):
        return self._raw if n < 0 else self._raw[:n]


def _stub(monkeypatch, result):
    def fake(request, timeout, ca_file=None):
        assert timeout == 60
        if isinstance(result, Exception):
            raise result
        return _Response(result)
    monkeypatch.setattr(model_transport, '_open', fake)


def _http_error(code):
    return HTTPError('https://m.test/v1', code, 'x', {}, io.BytesIO(b''))


def test_rejects_plain_http_off_loopback():
    with pytest.raises(ValueError):
        validate_endpoint('http://example.test/v1')


@pytest.mark.parametrize('url', ['http://127.0.0.1:11434/v1/chat/completions', 'http://localhost:8080/x'])
def test_allows_http_on_loopback(url):
    assert validate_endpoint(url) == url


def test_strips_trailing_slash():
    assert validate_endpoint('https://m.test/v1/') == 'https://m.test/v1'


@pytest.mark.parametrize('url', ['https://u:p@m.test/v1', 'https://m.test/v1?a=1', 'https://m.test/v1#f'])
def test_rejects_credentials_query_fragment(url):
    with pytest.raises(ValueError, match='no URL credentials, query or fragment'):
        validate_endpoint(url)


@pytest.mark.parametrize('code', [408, 429, 500, 502, 503, 504, 529])
def test_overload_is_capacity(monkeypatch, code):
    _stub(monkeypatch, _http_error(code))
    with pytest.raises(CapacityError):
        post_json('https://m.test/v1', {}, {})


@pytest.mark.parametrize('exc', [URLError('down'), TimeoutError()])
def test_unreachable_and_timeout_are_capacity(monkeypatch, exc):
    _stub(monkeypatch, exc)
    with pytest.raises(CapacityError):
        post_json('https://m.test/v1', {}, {})


@pytest.mark.parametrize('code', [501, 505, 520, 599])
def test_every_server_error_is_capacity(monkeypatch, code):
    _stub(monkeypatch, _http_error(code))
    with pytest.raises(CapacityError):
        post_json('https://m.test/v1', {}, {})


@pytest.mark.parametrize('code', [400, 404, 499, 600])
def test_client_errors_outside_408_429_are_rejection(monkeypatch, code):
    _stub(monkeypatch, _http_error(code))
    with pytest.raises(ValueError, match='rejected request') as info:
        post_json('https://m.test/v1', {}, {})
    assert not isinstance(info.value, CapacityError)


def test_other_http_error_is_rejection(monkeypatch):
    _stub(monkeypatch, _http_error(401))
    with pytest.raises(ValueError, match='rejected request') as info:
        post_json('https://m.test/v1', {}, {})
    assert not isinstance(info.value, CapacityError)


def test_oversized_response_rejected(monkeypatch):
    _stub(monkeypatch, b'x' * 65537)
    with pytest.raises(ValueError):
        post_json('https://m.test/v1', {}, {})


def test_non_json_response_rejected(monkeypatch):
    _stub(monkeypatch, b'not json')
    with pytest.raises(ValueError):
        post_json('https://m.test/v1', {}, {})


def test_returns_parsed_json(monkeypatch):
    _stub(monkeypatch, b'{"a": 1}')
    assert post_json('https://m.test/v1', {'q': 1}, {'X': 'y'}) == {'a': 1}


def test_redirect_not_followed():
    assert NoRedirects().redirect_request(None, None, 302, 'Found', {}, 'https://evil.test/') is None


def test_proxy_env_ignored(monkeypatch):
    monkeypatch.setenv('HTTPS_PROXY', 'http://proxy.test:3128')
    opener = model_transport._build_opener()
    proxies = [h for h in opener.handlers if isinstance(h, ProxyHandler)]
    # An empty ProxyHandler registers no handlers; the default env-driven one must be absent.
    assert all(h.proxies == {} for h in proxies)
    assert any(isinstance(h, NoRedirects) for h in opener.handlers)
