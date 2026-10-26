# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Request-format adapters: one small class per wire format. Standard library only."""
from typing import Protocol

FORMATS = ('openai_chat', 'anthropic_messages', 'gemini_api')


class ChatAdapter(Protocol):
    def complete(self, system: str, user: str, *, json_output: bool) -> str: ...


def build_adapter(format, endpoint, model, api_key, ca_file=None):
    if format == 'openai_chat':
        from tools.models.openai_chat import OpenAIChatAdapter as adapter
    elif format == 'anthropic_messages':
        from tools.models.anthropic_messages import AnthropicMessagesAdapter as adapter
    elif format == 'gemini_api':
        from tools.models.gemini_api import GeminiApiAdapter as adapter
    else:
        raise ValueError('Unknown model format')
    return adapter(endpoint, model, api_key, ca_file)
