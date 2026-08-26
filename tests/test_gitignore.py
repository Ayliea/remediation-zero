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

"""The .gitignore secret boundary is a control, so it is tested like one.

This repository is public. A committed credential is compromised the moment it
is pushed and rewriting history does not un-leak it, so the only useful place
to catch the mistake is before it is staged.

These cases are asserted against `git check-ignore`, which is the same matcher
git itself uses when staging, rather than against a reimplementation of the
pattern rules.
"""

import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

# Paths that must never reach the index. These are hypothetical: the test asks
# git how it *would* treat the path, so the files need not exist.
MUST_BE_IGNORED = [
    # Environment files
    ".env",
    ".env.local",
    ".env.production",
    "prod.env",
    # A service-account key downloaded from the Cloud console keeps its
    # generated name. This is the most likely real-world accident.
    "remediation-zero-1a2b3c4d5e6f.json",
    "sa-key.json",
    "keyfile.json",
    "my-credentials.json",
    "gcp-service-account.json",
    "application_default_credentials.json",
    # Credential material anywhere in the tree, not just at the root
    "infra/prod-key.json",
    "agents/triage/api_secret.json",
    "secrets/anything.yaml",
    ".secrets/x",
    "private/notes.md",
    # Key and certificate material
    "server.pem",
    "tls.key",
    "bundle.p12",
    "id_ed25519",
    ".netrc",
    # Terraform state records resource identities and can hold plaintext secrets
    "infra/terraform.tfstate",
    "infra/terraform.tfvars",
    "infra/.terraform/x",
]

# Paths the ignore rules must not swallow. Over-broad patterns are a real
# failure mode: a rule that hides a source file is discovered late and by
# accident.
MUST_STAY_TRACKED = [
    ".env.example",
    ".env.template",
    "README.md",
    "CLAUDE.md",
    "LICENSE",
    "NOTICE",
    "requirements.txt",
    ".gitignore",
    "agents/triage/__init__.py",
    "tools/idempotency.py",
    "tests/test_clock.py",
    "scripts/deploy-agent.sh",
    "scripts/seed.py",
    "data/README.md",
    # The enrichment cache is committed on purpose: a demo must not depend on
    # a third-party API being reachable at that moment.
    "data/cache/kev.json",
    "data/cache/epss.json",
    "data/findings.json",
    "docs/architecture.png",
    "infra/main.tf",
    "infra/terraform.tfvars.example",
    "prompts/triage.v1.md",
    "ui/index.html",
]


def _is_ignored(path: str) -> bool:
    """Ask git whether it would ignore `path`. Exit code 0 means ignored."""
    result = subprocess.run(
        ["git", "check-ignore", "-q", "--no-index", path],
        cwd=REPO_ROOT,
        capture_output=True,
    )
    if result.returncode not in (0, 1):
        raise RuntimeError(
            f"git check-ignore failed for {path!r}: "
            f"{result.stderr.decode(errors='replace')}"
        )
    return result.returncode == 0


@pytest.mark.parametrize("path", MUST_BE_IGNORED)
def test_credential_paths_are_ignored(path):
    assert _is_ignored(path), (
        f"{path!r} is NOT ignored. This repository is public: add a rule to "
        f".gitignore before committing anything."
    )


@pytest.mark.parametrize("path", MUST_STAY_TRACKED)
def test_source_paths_are_not_ignored(path):
    assert not _is_ignored(path), (
        f"{path!r} IS ignored, but it is source or committed data. An ignore "
        f"rule is too broad. Narrow it, or add a ! exception."
    )


def test_no_ignored_file_is_currently_tracked():
    """A rule added after a file was already committed does not untrack it."""
    tracked = subprocess.run(
        ["git", "ls-files"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
    ).stdout.split()
    offenders = [p for p in tracked if _is_ignored(p)]
    assert not offenders, (
        f"These files are tracked despite matching an ignore rule: {offenders}. "
        f"Adding the rule was not enough; run `git rm --cached` on each."
    )
