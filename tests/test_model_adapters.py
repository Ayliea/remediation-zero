# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
import json
from pathlib import Path

import pytest

from tools.adjudication import CapacityError
from tools.models import FORMATS, build_adapter

FIXTURES = Path(__file__).parent / 'fixtures' / 'model_responses'
URL = 'https://m.test/v1/chat'
GEMINI_URL = 'https://m.test/v1beta/models/g:generateContent'
MODULES = {'openai_chat': 'tools.models.openai_chat', 'anthropic_messages': 'tools.models.anthropic_messages',
           'gemini_api': 'tools.models.gemini_api'}
ENDPOINTS = {'openai_chat': URL, 'anthropic_messages': URL, 'gemini_api': GEMINI_URL}
KEY_HEADERS = {'openai_chat': ('Authorization', 'Bearer k'), 'anthropic_messages': ('x-api-key', 'k'),
               'gemini_api': ('x-goog-api-key', 'k')}
BODIES = {
    'openai_chat': lambda j: {'model': 'm', 'messages': [{'role': 'system', 'content': 'S'}, {'role': 'user', 'content': 'U'}],
                              'stream': False, 'max_tokens': 2048, **({'response_format': {'type': 'json_object'}} if j else {})},
    'anthropic_messages': lambda j: {'model': 'm', 'system': 'S', 'messages': [{'role': 'user', 'content': 'U'}], 'max_tokens': 2048},
    'gemini_api': lambda j: {'systemInstruction': {'parts': [{'text': 'S'}]},
                             'contents': [{'role': 'user', 'parts': [{'text': 'U'}]}],
                             'generationConfig': {'maxOutputTokens': 2048, **({'responseMimeType': 'application/json'} if j else {})}},
}


def fixture(fmt, name):
    return json.loads((FIXTURES / f'{fmt}_{name}.json').read_text())


@pytest.fixture
def capture(monkeypatch):
    calls = []

    def install(fmt, reply=None, error=None):
        def fake(url, body, headers, ca_file=None, timeout=None):
            calls.append((url, body, headers))
            if error:
                raise error
            return reply
        monkeypatch.setattr(MODULES[fmt] + '.post_json', fake)
        return calls
    return install


@pytest.mark.parametrize('fmt', FORMATS)
class TestAdapters:
    def adapter(self, fmt, key='k'):
        return build_adapter(fmt, ENDPOINTS[fmt], 'm', key)

    @pytest.mark.parametrize('json_output', [True, False])
    def test_request_body_matches_contract(self, fmt, json_output, capture):
        calls = capture(fmt, fixture(fmt, 'success'))
        self.adapter(fmt).complete('S', 'U', json_output=json_output)
        url, body, headers = calls[0]
        assert url == ENDPOINTS[fmt]
        assert body == BODIES[fmt](json_output)
        name, value = KEY_HEADERS[fmt]
        assert headers[name] == value
        if fmt == 'anthropic_messages':
            assert headers['anthropic-version'] == '2023-06-01'

    def test_returns_text_on_success(self, fmt, capture):
        capture(fmt, fixture(fmt, 'success'))
        assert self.adapter(fmt).complete('S', 'U', json_output=True) == '{"ok": true}'

    def test_incomplete_response_rejected(self, fmt, capture):
        capture(fmt, fixture(fmt, 'incomplete'))
        with pytest.raises(ValueError):
            self.adapter(fmt).complete('S', 'U', json_output=True)

    def test_malformed_response_rejected(self, fmt, capture):
        capture(fmt, fixture(fmt, 'malformed'))
        with pytest.raises(ValueError):
            self.adapter(fmt).complete('S', 'U', json_output=True)

    def test_capacity_passes_through(self, fmt, capture):
        err = CapacityError('busy')
        capture(fmt, error=err)
        with pytest.raises(CapacityError) as caught:
            self.adapter(fmt).complete('S', 'U', json_output=True)
        assert caught.value is err

    @pytest.mark.parametrize('key', [None, ''])
    def test_no_key_header_when_key_absent(self, fmt, key, capture):
        calls = capture(fmt, fixture(fmt, 'success'))
        self.adapter(fmt, key).complete('S', 'U', json_output=True)
        assert KEY_HEADERS[fmt][0] not in calls[0][2]

    def test_oversize_input_rejected_before_request(self, fmt, capture):
        calls = capture(fmt, fixture(fmt, 'success'))
        with pytest.raises(ValueError, match='input exceeds 32768 bytes'):
            self.adapter(fmt).complete('S' * 32768, 'U', json_output=True)
        assert calls == []

    def test_insecure_endpoint_rejected(self, fmt):
        with pytest.raises(ValueError):
            build_adapter(fmt, 'http://example.com/v1', 'm', None)


def test_openai_tool_calls_rejected(capture):
    reply = fixture('openai_chat', 'success')
    reply['choices'][0]['message']['tool_calls'] = [{'id': 'x'}]
    capture('openai_chat', reply)
    with pytest.raises(ValueError):
        build_adapter('openai_chat', URL, 'm', None).complete('S', 'U', json_output=False)


def test_build_adapter_unknown_format_rejected():
    with pytest.raises(ValueError):
        build_adapter('cohere', URL, 'm', None)
