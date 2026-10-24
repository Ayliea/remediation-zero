# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Gemini generateContent adapter. The endpoint is the full .../models/<model>:generateContent URL."""
from tools.model_transport import MAX_OUTPUT_TOKENS, post_json, validate_endpoint
from tools.models._common import check_input


class GeminiApiAdapter:
    def __init__(self, endpoint, model, api_key):
        self.endpoint = validate_endpoint(endpoint)
        self.model = model
        self.api_key = api_key

    def complete(self, system, user, *, json_output):
        check_input(system, user)
        config = {'maxOutputTokens': MAX_OUTPUT_TOKENS}
        if json_output:
            config['responseMimeType'] = 'application/json'
        body = {'systemInstruction': {'parts': [{'text': system}]},
                'contents': [{'role': 'user', 'parts': [{'text': user}]}], 'generationConfig': config}
        headers = {'Content-Type': 'application/json'}
        if self.api_key:
            headers['x-goog-api-key'] = self.api_key
        reply = post_json(self.endpoint, body, headers)
        try:
            candidate = reply['candidates'][0]
            complete = candidate['finishReason'] == 'STOP'
            text = ''.join(part['text'] for part in candidate['content']['parts'])
        except (KeyError, IndexError, TypeError):
            raise ValueError('Model returned an invalid response') from None
        if not complete:
            raise ValueError('Model response incomplete')
        return text
