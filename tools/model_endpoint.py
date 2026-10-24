# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Explicitly configured chat-completions transport; no automatic discovery."""
import json
import ipaddress
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler, ProxyHandler
from urllib.error import HTTPError, URLError
from tools.adjudication import CapacityError, Proposal


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class ModelEndpoint:
    def __init__(self, url, model, api_key=None):
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
        if not isinstance(model, str) or not model.strip() or len(model) > 200:
            raise ValueError('A model name is required (at most 200 characters)')
        if api_key and ('\n' in api_key or '\r' in api_key):
            raise ValueError('Invalid API key')
        self.url, self.model, self.api_key = url.rstrip('/'), model, api_key

    def propose(self, prompt, finding_id):
        if len(prompt.encode()) > 32768:
            raise ValueError('Input exceeds 32768 bytes')
        body = json.dumps({'model': self.model, 'messages': [{'role': 'user', 'content': prompt}],
                           'stream': False, 'max_tokens': 2048}).encode()
        headers = {'Content-Type': 'application/json'}
        if self.api_key:
            headers['Authorization'] = 'Bearer ' + self.api_key
        # Avoid forwarding credentials via redirects or inherited proxy settings.
        opener = build_opener(ProxyHandler({}), NoRedirects())
        try:
            with opener.open(Request(self.url, data=body, headers=headers), timeout=60) as response:
                raw = response.read(65537)
        except HTTPError as exc:
            if exc.code in {408, 429, 500, 502, 503, 504}:
                raise CapacityError('Model endpoint temporarily unavailable') from None
            raise ValueError('Model endpoint rejected request') from None
        except (URLError, TimeoutError):
            raise CapacityError('Model endpoint could not be reached') from None
        if len(raw) > 65536:
            raise ValueError('Model response exceeds limit')
        try:
            envelope = json.loads(raw)
            choice = envelope['choices'][0]
            if choice.get('finish_reason') != 'stop' or choice['message'].get('tool_calls'):
                raise ValueError('Incomplete or tool-call response')
            value = json.loads(choice['message']['content'])
            if set(value) != {'finding_id', 'severity', 'sla_days', 'remediation', 'evidence', 'rationale'}:
                raise ValueError('Invalid fields')
            if not isinstance(value['evidence'], list):
                raise ValueError('Invalid evidence')
            value['evidence'] = tuple(value['evidence'])
            result = Proposal(**value)
            if result.finding_id != finding_id:
                raise ValueError('Identity mismatch')
            return result
        except (ValueError, TypeError, KeyError, IndexError, AttributeError):
            raise ValueError('Model returned an invalid proposal') from None
