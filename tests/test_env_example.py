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

"""Every setting the code reads is documented in .env.example.

The repository is public and the setup instructions claim to be reproducible.
A variable the code reads and the example never mentions makes that claim false
in the most annoying possible way: the reader configures everything they were
told about and something still fails, with no indication which knob is missing.

This drifted once already — four settings, including the model-versus-engine
location split that is one of the loudest constraints in the project.
"""

import glob
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = (REPO_ROOT / ".env.example").read_text()

#: Set by the deployment rather than by a person, and documented as such.
NOT_USER_SET = {"WORKER_AGENT"}

#: Supplied by the runtime, never by this file.
AMBIENT = {"GOOGLE_APPLICATION_CREDENTIALS", "PORT", "K_SERVICE", "HOME"}


def _settings_the_code_reads() -> set:
    found = set()
    patterns = [
        glob.glob(str(REPO_ROOT / "tools" / "*.py")),
        glob.glob(str(REPO_ROOT / "scripts" / "*.py")),
        glob.glob(str(REPO_ROOT / "ui" / "*.py")),
        glob.glob(str(REPO_ROOT / "worker" / "*.py")),
        glob.glob(str(REPO_ROOT / "agents" / "**" / "*.py"), recursive=True),
    ]
    for group in patterns:
        for path in group:
            text = Path(path).read_text()
            found |= set(re.findall(
                r'environ(?:\.get)?\(?\[?["\']([A-Z][A-Z0-9_]+)["\']', text))
    return found - AMBIENT


def test_every_setting_the_code_reads_is_documented():
    undocumented = sorted(
        name for name in _settings_the_code_reads()
        if f"{name}=" not in EXAMPLE and name not in NOT_USER_SET
    )
    assert undocumented == [], (
        f"read by the code and absent from .env.example: {undocumented}"
    )


def test_deployment_set_variables_are_explained_rather_than_listed():
    """WORKER_AGENT has no line to fill in, so it gets a paragraph instead."""
    for name in NOT_USER_SET:
        assert name in EXAMPLE
        assert f"\n{name}=" not in EXAMPLE


def test_the_example_carries_no_real_values():
    """It is committed. The real one is not."""
    for leaked in ("gho_", "ghp_", "AIza", "-----BEGIN"):
        assert leaked not in EXAMPLE
    # The engine id is a live resource; the example must not pin it.
    assert "3119663582942330880" not in EXAMPLE


def test_the_two_locations_are_documented_as_different():
    """The single most expensive confusion in this build."""
    assert "GOOGLE_CLOUD_LOCATION=" in EXAMPLE
    assert "AGENT_ENGINE_LOCATION=" in EXAMPLE
    assert "global" in EXAMPLE
