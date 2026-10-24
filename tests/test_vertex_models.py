# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""VertexAdapter builds the same real google.genai config the old code did."""
from types import SimpleNamespace

from tools.vertex_models import VertexAdapter


def make(text="ok"):
    seen = []

    def generate(**kwargs):
        seen.append(kwargs)
        return SimpleNamespace(text=text)

    client = SimpleNamespace(models=SimpleNamespace(generate_content=generate))
    return VertexAdapter(client, "m-1"), seen


def test_json_output_uses_temperature_02_and_json_mime():
    adapter, seen = make()
    adapter.complete("sys", "hi", json_output=True)
    assert seen[0]["model"] == "m-1" and seen[0]["contents"] == "hi"
    assert seen[0]["config"].temperature == 0.2
    assert seen[0]["config"].response_mime_type == "application/json"


def test_text_output_uses_temperature_01_and_no_mime():
    adapter, seen = make()
    adapter.complete("", "hi", json_output=False)
    assert seen[0]["config"].temperature == 0.1
    assert seen[0]["config"].response_mime_type is None


def test_empty_system_sends_no_system_instruction():
    adapter, seen = make()
    adapter.complete("", "hi", json_output=False)
    assert seen[0]["config"].system_instruction is None


def test_nonempty_system_sends_system_instruction():
    adapter, seen = make()
    adapter.complete("be brief", "hi", json_output=True)
    assert seen[0]["config"].system_instruction == "be brief"


def test_max_output_tokens_and_http_options_preserved():
    adapter, seen = make()
    adapter.complete("", "hi", json_output=False)
    config = seen[0]["config"]
    assert config.max_output_tokens == 2048
    assert config.http_options.timeout == 60000
    assert config.http_options.retry_options.attempts == 1


def test_none_text_returns_empty_string():
    adapter, _ = make(text=None)
    assert adapter.complete("", "hi", json_output=False) == ""
