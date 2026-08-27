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

"""Orchestrator package.

The import is relative because this package is loaded under two different
names. Locally it is `agents.orchestrator`; in Agent Engine the agent is staged
at /app/agents/orchestrator and loaded as `orchestrator`, with no
/app/agents/__init__.py to make the absolute form resolve. An absolute import
therefore works in every local test and fails in the deployed image, where it
surfaces as a 400 from stream_query with the cause buried in the engine's logs.
"""

from .agent import root_agent

__all__ = ["root_agent"]
