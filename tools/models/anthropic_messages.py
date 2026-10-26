# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Anthropic Messages adapter. json_output is ignored: the prompt asks for JSON."""
from tools.model_transport import MAX_OUTPUT_TOKENS, post_json, validate_endpoint
from tools.models._common import check_input


class AnthropicMessagesAdapter:
    def __init__(self, endpoint, model, api_key, ca_file=None, timeout_seconds=None):
        self.endpoint = validate_endpoint(endpoint)
        self.ca_file = ca_file or None
        self.timeout_seconds = timeout_seconds
        self.model = model
        self.api_key = api_key

    def complete(self, system, user, *, json_output):
        check_input(system, user)
        body = {'model': self.model, 'system': system, 'messages': [{'role': 'user', 'content': user}],
                'max_tokens': MAX_OUTPUT_TOKENS}
        headers = {'Content-Type': 'application/json', 'anthropic-version': '2023-06-01'}
        if self.api_key:
            headers['x-api-key'] = self.api_key
        reply = post_json(self.endpoint, body, headers, ca_file=self.ca_file, timeout=self.timeout_seconds)
        try:
            complete = reply['stop_reason'] == 'end_turn'
            text = ''.join(block['text'] for block in reply['content'] if block.get('type') == 'text')
        except (KeyError, TypeError, AttributeError):
            raise ValueError('Model returned an invalid response') from None
        if not complete:
            raise ValueError('Model response incomplete')
        return text
