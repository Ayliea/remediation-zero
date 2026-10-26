# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""OpenAI-compatible chat completions adapter."""
from tools.model_transport import MAX_OUTPUT_TOKENS, post_json, validate_endpoint
from tools.models._common import check_input


class OpenAIChatAdapter:
    def __init__(self, endpoint, model, api_key, ca_file=None, timeout_seconds=None):
        self.endpoint = validate_endpoint(endpoint)
        self.ca_file = ca_file or None
        self.timeout_seconds = timeout_seconds
        self.model = model
        self.api_key = api_key

    def complete(self, system, user, *, json_output):
        check_input(system, user)
        body = {'model': self.model, 'messages': [{'role': 'system', 'content': system}, {'role': 'user', 'content': user}],
                'stream': False, 'max_tokens': MAX_OUTPUT_TOKENS}
        if json_output:
            body['response_format'] = {'type': 'json_object'}
        headers = {'Content-Type': 'application/json'}
        if self.api_key:
            headers['Authorization'] = f'Bearer {self.api_key}'
        reply = post_json(self.endpoint, body, headers, ca_file=self.ca_file, timeout=self.timeout_seconds)
        try:
            choice = reply['choices'][0]
            message = choice['message']
            text = message['content']
            complete = choice['finish_reason'] == 'stop' and not message.get('tool_calls')
        except (KeyError, IndexError, TypeError, AttributeError):
            raise ValueError('Model returned an invalid response') from None
        if not complete or not isinstance(text, str):
            raise ValueError('Model response incomplete')
        return text
