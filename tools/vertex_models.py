# Copyright 2026 Daviyon Daniels
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Vertex / Agent Platform as one ChatAdapter. Cloud edition only."""

import os

from google import genai
from google.genai import types

from tools.inference import MAX_OUTPUT_TOKENS, REQUEST_TIMEOUT_MS


def vertex_client() -> genai.Client:
    """A Vertex client. Both models are served from `global`."""
    return genai.Client(
        vertexai=True,
        project=os.environ["GOOGLE_CLOUD_PROJECT"],
        location=os.environ.get("GOOGLE_CLOUD_LOCATION", "global"),
    )


def _http_options():
    return types.HttpOptions(timeout=REQUEST_TIMEOUT_MS, retry_options=types.HttpRetryOptions(attempts=1))


class VertexAdapter:
    """`ChatAdapter` over `client.models.generate_content`."""

    def __init__(self, client, model: str):
        self.client = client
        self.model = model

    def complete(self, system: str, user: str, *, json_output: bool) -> str:
        options = {
            "max_output_tokens": MAX_OUTPUT_TOKENS,
            "http_options": _http_options(),
            "temperature": 0.2 if json_output else 0.1,
        }
        # Gemma MaaS has no system role, so an empty system sends none.
        if system:
            options["system_instruction"] = system
        if json_output:
            options["response_mime_type"] = "application/json"
        response = self.client.models.generate_content(
            model=self.model, contents=user, config=types.GenerateContentConfig(**options))
        return response.text or ""
