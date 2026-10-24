# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Shared inference runs over any ChatAdapter."""
import subprocess
import sys
from pathlib import Path

import pytest

from tools import inference

REPO_ROOT = Path(__file__).resolve().parents[1]
PAYLOAD = ('{"severity": "High", "sla_days": 7, "remediation": "patch", '
           '"evidence": ["KEV"], "rationale": "because"}')
REVIEW = "INJECTION: none\nVERDICT: RATIFY\nREASON: fine"


class FakeAdapter:
    def __init__(self, reply):
        self.reply = reply
        self.calls = []

    def complete(self, system, user, *, json_output):
        self.calls.append((system, user, json_output))
        return self.reply


def test_propose_uses_triage_prompt_as_system_and_json():
    adapter = FakeAdapter(PAYLOAD)
    proposal = inference.propose("finding text", adapter, finding_id="RZ-1")
    assert adapter.calls == [(inference._load("triage.md"), "finding text", True)]
    assert proposal.finding_id == "RZ-1" and proposal.severity == "high"


def test_review_prepends_instruction_with_empty_system():
    adapter = FakeAdapter(REVIEW)
    verdict = inference.review("the proposal", adapter)
    assert adapter.calls == [("", inference._load("reviewer.md") + "\n\n---\n\nthe proposal", False)]
    assert verdict.ratified


def test_extract_json_object_strips_fence():
    assert inference.extract_json_object('```json\n{"a":1}\n```') == {"a": 1}


def test_extract_json_object_from_prose():
    assert inference.extract_json_object('Here is the result: {"a": 1} Thanks.') == {"a": 1}


def test_extract_json_object_rejects_two_objects():
    with pytest.raises(ValueError):
        inference.extract_json_object('{"a":1} {"b":2}')


def test_extract_json_object_rejects_array():
    with pytest.raises(ValueError):
        inference.extract_json_object('[{"a":1}]')


def test_extract_json_object_rejects_truncated_outer_with_inner_object():
    with pytest.raises(ValueError):
        inference.extract_json_object('{"a": {"b":1}, "c": ')


def test_extract_json_object_rejects_garbage_then_object():
    with pytest.raises(ValueError):
        inference.extract_json_object('{oops} {"a":1}')


def test_extract_json_object_rejects_array_in_prose():
    with pytest.raises(ValueError):
        inference.extract_json_object('Result: [{"a":1}]')


def test_extract_json_object_rejects_trailing_object_after_prose():
    with pytest.raises(ValueError):
        inference.extract_json_object('Here: {"a":1} and also {"b":2}')


def test_extract_json_object_keeps_nested_object_whole():
    assert inference.extract_json_object('Result: {"a": {"b": 1}} done.') == {"a": {"b": 1}}


def test_inference_module_is_stdlib_only():
    subprocess.run([sys.executable, "-S", "-c", "import tools.inference"], cwd=REPO_ROOT, check=True)
