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

"""Compatibility surface for the Vertex-backed callers.

The shared logic lives in `tools.inference`; this module re-exports it and keeps
the original `propose` / `review` signatures, which take a model name and a
`google-genai` client, by wrapping that client in a `VertexAdapter`.
"""

from tools.inference import *  # noqa: F401,F403
from tools.inference import (  # noqa: F401  (underscore names are not covered by *)
    _defang_fence, _invoke, _is_capacity, _load, _strip_fences, _with_backoff,
)
from tools import inference as _inference
from tools.vertex_models import VertexAdapter, vertex_client as _client  # noqa: F401


def propose(prompt_text, model, client, *, finding_id, retry=True):
    """Ask Gemini for a triage proposal."""
    return _inference.propose(
        prompt_text, VertexAdapter(client, model), finding_id=finding_id, retry=retry)


def review(prompt_text, model, client, *, retry=True):
    """Ask Gemma to adjudicate."""
    return _inference.review(prompt_text, VertexAdapter(client, model), retry=retry)
