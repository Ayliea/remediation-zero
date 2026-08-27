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

"""The agent has to import the way the deployment imports it.

Agent Engine stages the agent at /app/agents/orchestrator, puts /app on
PYTHONPATH, and loads the module as `orchestrator` rather than as
`agents.orchestrator`. An absolute `from agents.orchestrator...` import
therefore resolves locally and fails in the deployed image, where the failure
surfaces as a 400 from stream_query with the real cause buried in the engine's
own logs.

That is exactly what happened: the deployed engine answered every query with
"Reasoning Engine Execution failed" while the same code imported cleanly in
every local test. These tests reproduce the deployed import path so the next
occurrence is a red test rather than a broken demo.
"""

import importlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
AGENT_DIR = REPO_ROOT / "agents" / "orchestrator"


def test_the_package_imports_under_its_deployed_module_name(tmp_path):
    """Reproduce the deployed layout exactly, then import the way ADK does.

    Agent Engine stages the agent at /app/agents/orchestrator and the
    --extra_packages entries at /app/tools and /app/prompts, with /app and the
    agent's parent on the path. Critically there is no /app/agents/__init__.py,
    so `agents` is not an importable package — which is what made the absolute
    import fail there while passing everywhere else.

    Building the tree rather than pointing at the repo is the whole point: with
    the repo root on sys.path the broken import resolves and the test passes
    while the deployment stays broken.
    """
    app = tmp_path / "app"
    shutil.copytree(AGENT_DIR, app / "agents" / "orchestrator")
    shutil.copytree(REPO_ROOT / "tools", app / "tools")
    shutil.copytree(REPO_ROOT / "prompts", app / "prompts")
    assert not (app / "agents" / "__init__.py").exists()

    script = (
        "import sys; "
        f"sys.path[:] = [{str(app)!r}, {str(app / 'agents')!r}] + "
        "[p for p in sys.path if 'site-packages' in p or 'python3' in p]; "
        "import orchestrator; "
        "assert orchestrator.root_agent is not None; "
        "print('ok')"
    )
    result = subprocess.run([sys.executable, "-c", script],
                            capture_output=True, text=True, cwd=str(tmp_path),
                            env={**os.environ, "PYTHONPATH": ""})
    assert "ok" in result.stdout, (
        "the agent does not import in the deployed layout. This is the failure "
        "that shows up as a 400 from stream_query.\n"
        f"{result.stderr[-1500:]}"
    )


def test_the_package_init_uses_a_relative_import():
    """An absolute import of `agents` is what broke the deployment.

    Asserted against the source because the failure only appears in an
    environment the test suite does not otherwise run in.
    """
    source = (AGENT_DIR / "__init__.py").read_text()
    assert "from agents." not in source, (
        "__init__.py imports the `agents` package absolutely. The deployed "
        "image has no such top-level package: the agent is staged at "
        "/app/agents/orchestrator and loaded as `orchestrator`."
    )
    assert "from .agent import" in source


def test_root_agent_still_resolves_the_normal_way():
    """The repo-relative import path has to keep working too."""
    module = importlib.import_module("agents.orchestrator")
    assert module.root_agent is not None
    assert module.root_agent.name == "orchestrator"


def test_the_prompt_resolves_from_the_deployed_layout():
    """PROMPT_PATH is parents[2]/prompts, which is /app/prompts once staged.

    This passes locally for the same reason it passes deployed, but only if
    prompts/ is actually staged alongside the agent — which is what
    --extra_packages in deploy-agent.sh is for.
    """
    from agents.orchestrator.agent import PROMPT_PATH

    assert PROMPT_PATH.is_file()
    assert PROMPT_PATH.parent.name == "prompts"
    assert PROMPT_PATH.parent.parent == REPO_ROOT


def test_the_deploy_stages_everything_the_agent_imports():
    """tools/ and prompts/ are not inside the agent directory.

    Without --extra_packages they are simply absent from the image, and the
    agent raises on import for a second reason after the first is fixed.
    """
    deploy = (REPO_ROOT / "scripts" / "deploy-agent.sh").read_text()
    for needed in ("tools", "prompts"):
        assert f"--extra_packages" in deploy and needed in deploy, (
            f"deploy-agent.sh does not stage {needed}/, which the agent imports"
        )
