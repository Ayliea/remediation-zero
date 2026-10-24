# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Explicitly configured chat-completions transport; no automatic discovery."""
import json
from tools.adjudication import Proposal
from tools.model_transport import MAX_INPUT_BYTES, MAX_OUTPUT_TOKENS, post_json, validate_endpoint


class ModelEndpoint:
    def __init__(self, url, model, api_key=None):
        url = validate_endpoint(url)
        if not isinstance(model, str) or not model.strip() or len(model) > 200:
            raise ValueError('A model name is required (at most 200 characters)')
        if api_key and ('\n' in api_key or '\r' in api_key):
            raise ValueError('Invalid API key')
        self.url, self.model, self.api_key = url, model, api_key

    def propose(self, prompt, finding_id):
        if len(prompt.encode()) > MAX_INPUT_BYTES:
            raise ValueError('Input exceeds 32768 bytes')
        body = {'model': self.model, 'messages': [{'role': 'user', 'content': prompt}],
                'stream': False, 'max_tokens': MAX_OUTPUT_TOKENS}
        headers = {'Content-Type': 'application/json'}
        if self.api_key:
            headers['Authorization'] = 'Bearer ' + self.api_key
        raw = post_json(self.url, body, headers)
        try:
            choice = raw['choices'][0]
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
