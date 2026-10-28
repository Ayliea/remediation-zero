# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
import io
import json
from urllib.error import HTTPError

import pytest

from tools import model_transport
from tools.adjudication import CapacityError
from tools.model_endpoints import MODEL_LIST_LIMIT, call_endpoint, list_models, split_endpoint
from tools.model_transport import get_json, validate_endpoint


class _Response:
    def __init__(self, raw):
        self._raw = raw

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, n=-1):
        return self._raw if n < 0 else self._raw[:n]


class _Stub:
    def __init__(self):
        self.calls = []
        self.result = b'{}'

    def __call__(self, request, timeout, ca_file=None):
        self.calls.append((request, timeout, ca_file))
        if isinstance(self.result, Exception):
            raise self.result
        return _Response(self.result)


@pytest.fixture
def stub_open(monkeypatch):
    stub = _Stub()
    monkeypatch.setattr(model_transport, '_open', stub)
    return stub


def _headers(stub):
    return {k.lower(): v for k, v in stub.calls[0][0].header_items()}


def test_call_endpoint_per_format():
    assert call_endpoint('openai_chat', 'https://api.openai.com/v1', 'gpt-x') == 'https://api.openai.com/v1/chat/completions'
    assert call_endpoint('anthropic_messages', 'https://api.anthropic.com/v1', 'c') == 'https://api.anthropic.com/v1/messages'
    assert call_endpoint('gemini_api', 'https://generativelanguage.googleapis.com/v1beta', 'gemini-x') == \
        'https://generativelanguage.googleapis.com/v1beta/models/gemini-x:generateContent'
    assert call_endpoint('openai_chat', 'http://127.0.0.1:8080/v1/chat/completions', 'm', 'exact') == \
        'http://127.0.0.1:8080/v1/chat/completions'


def test_call_endpoint_quotes_the_model_and_result_validates():
    url = call_endpoint('gemini_api', 'https://g.example.invalid/v1beta', 'a/b?c#d')
    assert url == 'https://g.example.invalid/v1beta/models/a%2Fb%3Fc%23d:generateContent'
    assert validate_endpoint(url) == url
    assert validate_endpoint(call_endpoint('openai_chat', 'https://h.example.invalid/v1/', 'm'))


def test_split_endpoint_round_trips_and_keeps_unknown_shapes_exact():
    assert split_endpoint('openai_chat', 'http://localhost:11434/v1/chat/completions', 'q') == ('http://localhost:11434/v1', 'base')
    assert split_endpoint('gemini_api', 'https://g.example.invalid/v1beta/models/gemini-x:generateContent', 'gemini-x') == \
        ('https://g.example.invalid/v1beta', 'base')
    assert split_endpoint('gemini_api', 'https://g.example.invalid/v1beta/models/other:generateContent', 'gemini-x')[1] == 'exact'
    assert split_endpoint('openai_chat', 'https://h.example.invalid/complete', 'm') == ('https://h.example.invalid/complete', 'exact')


def test_list_models_sends_the_format_header_and_parses(stub_open):
    stub_open.result = json.dumps({'data': [{'id': 'b'}, {'id': 'a'}]}).encode()
    assert list_models('openai_chat', 'https://api.openai.com/v1', 'sk-test-1') == ['a', 'b']
    request, timeout, _ = stub_open.calls[0]
    assert request.full_url == 'https://api.openai.com/v1/models'
    assert request.get_method() == 'GET'
    assert _headers(stub_open)['authorization'] == 'Bearer sk-test-1'
    assert timeout == 15

    stub_open.calls.clear()
    stub_open.result = json.dumps({'data': [{'id': 'claude-x'}]}).encode()
    assert list_models('anthropic_messages', 'https://api.anthropic.com/v1', 'sk-test-2') == ['claude-x']
    headers = _headers(stub_open)
    assert headers['x-api-key'] == 'sk-test-2' and headers['anthropic-version'] == '2023-06-01'

    stub_open.calls.clear()
    stub_open.result = json.dumps({'models': [
        {'name': 'models/gemini-x', 'supportedGenerationMethods': ['generateContent', 'countTokens']},
        {'name': 'models/embed-x', 'supportedGenerationMethods': ['embedContent']},
        {'name': 'models/nomethods'},
    ]}).encode()
    assert list_models('gemini_api', 'https://g.example.invalid/v1beta', 'k-test-3') == ['gemini-x']
    assert _headers(stub_open)['x-goog-api-key'] == 'k-test-3'


def test_list_models_without_a_key_sends_no_auth_header(stub_open):
    stub_open.result = b'{"data": []}'
    assert list_models('openai_chat', 'http://127.0.0.1:8080/v1', None) == []
    assert 'authorization' not in _headers(stub_open)


def test_list_models_caps_drops_bad_ids_and_sorts(stub_open, monkeypatch):
    ids = [{'id': f'm{n:05d}'} for n in range(5000, 0, -1)]
    ids += [{'id': None}, {'id': 7}, {'id': 'x' * 300}, {'id': 'm00001'}, {}]
    stub_open.result = json.dumps({'data': ids}).encode()
    monkeypatch.setattr(model_transport, 'MAX_RESPONSE_BYTES', 10_000_000)  # the stub returns the whole body
    out = list_models('openai_chat', 'https://api.openai.com/v1', 'sk-test-1')
    assert len(out) == MODEL_LIST_LIMIT == 200
    assert out == sorted(out) and all(isinstance(i, str) and len(i) <= 200 for i in out)
    assert out[0] == 'm00001'


def test_list_models_unexpected_shapes(stub_open):
    for body in (b'[]', b'{"data": 3}', b'{"models": "x"}', b'{"other": []}', b'null'):
        stub_open.result = body
        with pytest.raises(ValueError, match='Model list could not be read'):
            list_models('openai_chat', 'https://api.openai.com/v1', 'sk-test-1')


def test_list_models_refuses_a_bad_key_before_any_request(stub_open):
    for bad in ('a\nb', 'a b\r', 'kéy'):
        with pytest.raises(ValueError, match='Invalid API key'):
            list_models('openai_chat', 'https://api.openai.com/v1', bad)
    assert stub_open.calls == []


def test_get_json_maps_errors_like_post_json(stub_open):
    stub_open.result = HTTPError('https://m.test/v1', 429, 'x', {}, io.BytesIO(b''))
    with pytest.raises(CapacityError):
        get_json('https://m.test/v1/models', {})
    stub_open.result = HTTPError('https://m.test/v1', 401, 'x', {}, io.BytesIO(b''))
    with pytest.raises(ValueError, match='Model endpoint rejected request'):
        get_json('https://m.test/v1/models', {})
    stub_open.result = b'x' * (model_transport.MAX_RESPONSE_BYTES + 1)
    with pytest.raises(ValueError, match='Model response exceeds limit'):
        get_json('https://m.test/v1/models', {})
    stub_open.result = b'{"a": 1}'
    assert get_json('https://m.test/v1/models', {}) == {'a': 1}
    assert stub_open.calls[-1][1] == 60


def test_get_json_refuses_ca_file_on_plain_http(stub_open):
    with pytest.raises(ValueError, match='CA file'):
        get_json('http://127.0.0.1/v1/models', {}, ca_file='/x.pem')


def test_get_json_never_puts_the_key_in_an_exception_message(stub_open):
    key = 'sk-test-SECRET'
    for result in (HTTPError('https://m.test/v1', 401, key, {}, io.BytesIO(key.encode())),
                   HTTPError('https://m.test/v1', 503, key, {}, io.BytesIO(b'')),
                   b'not json ' + key.encode()):
        stub_open.result = result
        with pytest.raises((ValueError, CapacityError)) as info:
            list_models('openai_chat', 'https://api.openai.com/v1', key)
        assert key not in str(info.value) and key not in repr(info.value)
