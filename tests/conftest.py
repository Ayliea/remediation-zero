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

"""Test configuration.

The orchestrator module builds `root_agent` at import time, because that is
the symbol ADK's loader looks for. That makes importing it a configuration
read, so the suite supplies configuration rather than the module inventing a
default. The production code still refuses to start unconfigured, which is the
behaviour that matters, and there is a test asserting exactly that.
"""

import os
import runpy
from pathlib import Path

_OFFLINE = runpy.run_path(str(Path(__file__).with_name("offline_guard.py")))

import pytest

# Set before collection so that importing agents.orchestrator.agent succeeds.
# The orchestrator wraps both sub-agents in AgentTool at module scope, so it
# needs the reviewer's model named as well as its own -- which is why
# REVIEWER_MODEL belongs here and not only in .env.
#
# All three have to be seeded rather than left to load_dotenv. A developer
# machine has a .env and never notices the difference; a clean checkout does
# not, and CI is a clean checkout. Omitting REVIEWER_MODEL broke collection on
# the first run of the workflow while the same suite passed locally.
os.environ.setdefault("REASONING_MODEL", "gemini-3.5-flash")
os.environ.setdefault("REVIEWER_MODEL", "gemma-4-26b-a4b-it-maas")
os.environ.setdefault("SIM_CLOCK_MODE", "real")


class FakeEndpoints:
    """Lets a fixture register exactly the socket its fake server bound; removed on teardown."""

    def __init__(self, basetemp):
        self._basetemp = basetemp
        self.entries = []

    def unix(self, path):
        self.entries.append(_OFFLINE["register_unix"](path, self._basetemp))

    def tcp(self, sock):
        host, port = sock.getsockname()[:2]
        self.entries.append(_OFFLINE["register_tcp"](host, port))


@pytest.fixture
def fake_endpoints(tmp_path_factory):
    registry = FakeEndpoints(tmp_path_factory.getbasetemp())
    yield registry
    for entry in registry.entries:
        _OFFLINE["deregister"](entry)


@pytest.fixture
def unconfigured_env(monkeypatch):
    """Strip configuration, for tests asserting that startup refuses."""
    monkeypatch.delenv("REASONING_MODEL", raising=False)
    return monkeypatch


def pytest_sessionfinish(session, exitstatus):
    if _OFFLINE["violations"]:
        reporter = session.config.pluginmanager.get_plugin("terminalreporter")
        if reporter:
            reporter.write_sep("=", "Forbidden offline-test operations")
            for stack in _OFFLINE["violations"]:
                reporter.write(stack)
        session.exitstatus = pytest.ExitCode.TESTS_FAILED
