# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Call URLs from a base URL, and a provider's model list. Standard library only."""
from urllib.parse import quote

from tools.model_transport import get_json, validate_endpoint

SUFFIXES = {'openai_chat': '/chat/completions', 'anthropic_messages': '/messages',
            'gemini_api': '/models/{model}:generateContent'}
MODEL_LIST_LIMIT = 200
MODEL_LIST_TIMEOUT = 15
_MAX_ID_CHARS = 200


def call_endpoint(format, base_url, model, style='base'):
    """The URL a model call is sent to. 'exact' uses `base_url` as it is, character for character
    once it passes the endpoint rules: the stored string feeds the inference fingerprint."""
    if style == 'exact':
        validate_endpoint(base_url)
        return base_url
    suffix = SUFFIXES[format].replace('{model}', quote(model, safe=''))
    return validate_endpoint(base_url.rstrip('/') + suffix)


def split_endpoint(format, endpoint, model):
    """(base_url, 'base') if `endpoint` is exactly what call_endpoint builds from a base URL for
    this model, else (endpoint, 'exact'): any other address (a trailing or doubled slash, another
    path) is kept as typed, so the call string never changes."""
    suffix = SUFFIXES[format].replace('{model}', quote(model, safe=''))
    if endpoint.endswith(suffix) and len(endpoint) > len(suffix):
        base = endpoint[:-len(suffix)]
        try:
            if call_endpoint(format, base, model, 'base') == endpoint:
                return base, 'base'
        except ValueError:
            pass
    return endpoint, 'exact'


def _auth_headers(format, key):
    if format == 'anthropic_messages':
        headers = {'anthropic-version': '2023-06-01'}
        name = 'x-api-key'
    elif format == 'gemini_api':
        headers, name = {}, 'x-goog-api-key'
    else:
        headers, name = {}, 'Authorization'
    if key:
        headers[name] = f'Bearer {key}' if name == 'Authorization' else key
    return headers


def _ids(format, reply):
    if format == 'gemini_api':
        items = reply.get('models') if isinstance(reply, dict) else None
        if not isinstance(items, list):
            raise ValueError('Model list could not be read')
        for item in items:
            if (isinstance(item, dict) and isinstance(item.get('name'), str)
                    and isinstance(item.get('supportedGenerationMethods'), list)
                    and 'generateContent' in item['supportedGenerationMethods']):
                yield item['name'].removeprefix('models/')
        return
    items = reply.get('data') if isinstance(reply, dict) else None
    if not isinstance(items, list):
        raise ValueError('Model list could not be read')
    for item in items:
        if isinstance(item, dict):
            yield item.get('id')


def list_models(format, base_url, key, ca_file=None):
    """The model names the provider lists, sorted and bounded. The key goes only in a header."""
    if key is not None and (not isinstance(key, str) or any(not 32 <= ord(c) <= 126 for c in key)):
        raise ValueError('Invalid API key')
    url = validate_endpoint(base_url) + '/models'
    reply = get_json(url, _auth_headers(format, key), ca_file=ca_file, timeout=MODEL_LIST_TIMEOUT)
    names = {i for i in _ids(format, reply) if isinstance(i, str) and 0 < len(i) <= _MAX_ID_CHARS}
    return sorted(names)[:MODEL_LIST_LIMIT]
