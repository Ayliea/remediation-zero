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

"""Prove the four security claims. Every one of them, by doing it.

    ./scripts/verify-controls.sh

Nothing here asserts a control. Each check performs the action the control is
supposed to stop and reports what actually happened, so a reader who did not
write this system can watch it fail in the right way.
"""

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(REPO_ROOT / ".env")

import os  # noqa: E402  (after load_dotenv so .env is present)

from google.cloud import firestore  # noqa: E402

from tools.idempotency import derive_key  # noqa: E402
from tools.model_armor import ModelArmor  # noqa: E402

PROJECT = os.environ["GOOGLE_CLOUD_PROJECT"]
PLANTED = "RZ-0216"

GREEN, RED, DIM, RESET = "\033[32m", "\033[31m", "\033[2m", "\033[0m"
results: list[tuple[str, bool, str]] = []


def record(name: str, passed: bool, detail: str) -> None:
    mark = f"{GREEN}PASS{RESET}" if passed else f"{RED}FAIL{RESET}"
    print(f"  [{mark}] {name}")
    print(f"         {DIM}{detail}{RESET}")
    results.append((name, passed, detail))


def _token() -> str:
    return subprocess.run(
        ["gcloud", "auth", "application-default", "print-access-token"],
        capture_output=True, text=True, check=False,
    ).stdout.strip()


# --- 1 ----------------------------------------------------------------------

def check_model_armor_blocks_the_payload() -> None:
    """The boundary catches the planted injection, and lets a benign comment
    through. A filter that blocks everything is not a filter."""
    findings = json.loads((REPO_ROOT / "data" / "findings.json").read_text())
    planted = next(f for f in findings if f["injection_planted"])

    armor = ModelArmor(enabled=True)
    token = _token()
    bad = armor.screen(planted["scanner_comment"], token)
    good = armor.screen("Detected during authenticated credentialed scan.", token)

    passed = bad.blocked and bad.screened and not good.blocked
    record(
        "Model Armor blocks the planted injection",
        passed,
        f"planted: blocked={bad.blocked} confidence={bad.confidence} "
        f"reasons={list(bad.reasons)} | benign: blocked={good.blocked}",
    )


# --- 2 ----------------------------------------------------------------------

def check_reviewer_catches_it_independently() -> None:
    """With the boundary disabled, the second layer has to hold on its own."""
    env = dict(os.environ, MODEL_ARMOR_ENABLED="false")
    cycle = 900
    subprocess.run(
        [".venv/bin/python", "scripts/cycle.py", "--cycle", str(cycle),
         "--limit", "1", "--start", "216"],
        cwd=REPO_ROOT, env=env, capture_output=True, text=True, check=False,
    )
    client = firestore.Client()
    doc = client.collection("decisions").document(f"{PLANTED}-c{cycle:03d}").get()
    data = doc.to_dict() or {}
    reasons = " ".join(v.get("reason", "") for v in data.get("verdicts", []))

    passed = "untrusted text:" in reasons
    record(
        "Reviewer catches it with Model Armor disabled",
        passed,
        (reasons[:200] if reasons else "no verdict recorded"),
    )


# --- 3 ----------------------------------------------------------------------

def check_reporting_cannot_write_tickets() -> None:
    """Impersonate the reporting identity and try to write a ticket.

    A denial here is the pass condition. This is the claim that would be
    easiest to assert and hardest to believe, so it is performed.
    """
    script = (
        "import sys;"
        "from google.cloud import firestore;"
        "from google.auth import impersonated_credentials, default;"
        "src,_=default();"
        "c=impersonated_credentials.Credentials("
        f"  source_credentials=src,"
        f"  target_principal='rz-reporting@{PROJECT}.iam.gserviceaccount.com',"
        "  target_scopes=['https://www.googleapis.com/auth/cloud-platform']);"
        f"db=firestore.Client(project='{PROJECT}', credentials=c);"
        "db.collection('tickets').document('__control_probe__')"
        "  .set({'written_by':'rz-reporting'});"
        "print('WROTE')"
    )
    proc = subprocess.run(
        [".venv/bin/python", "-c", script],
        cwd=REPO_ROOT, capture_output=True, text=True, check=False,
    )
    combined = (proc.stdout + proc.stderr)
    denied = "PermissionDenied" in combined or "403" in combined or "denied" in combined.lower()
    wrote = "WROTE" in proc.stdout

    record(
        "Reporting identity is denied a ticket write",
        denied and not wrote,
        ("write succeeded, which it must not"
         if wrote else
         next((ln.strip() for ln in combined.splitlines()
               if "403" in ln or "denied" in ln.lower()), combined.strip()[-180:])
         or "no denial observed"),
    )


# --- 4 ----------------------------------------------------------------------

def check_resume_produces_no_duplicates() -> None:
    """Re-run a cycle that already ran and confirm nothing new is written."""
    client = firestore.Client()

    def counts():
        return {
            name: client.collection(name).count().get()[0][0].value
            for name in ("decisions", "tickets", "human_queue", "idempotency")
        }

    before = counts()
    subprocess.run(
        [".venv/bin/python", "scripts/cycle.py", "--cycle", "1",
         "--limit", "4", "--start", "300"],
        cwd=REPO_ROOT, capture_output=True, text=True, check=False,
    )
    after = counts()

    passed = before == after
    record(
        "A resumed cycle writes nothing a second time",
        passed,
        f"before={before} after={after}",
    )


def main() -> int:
    print("\nRemediation Zero — control verification")
    print("Each check performs the action the control is meant to stop.\n")

    check_model_armor_blocks_the_payload()
    check_reviewer_catches_it_independently()
    check_reporting_cannot_write_tickets()
    check_resume_produces_no_duplicates()

    failed = [n for n, ok, _ in results if not ok]
    print()
    if failed:
        print(f"{RED}{len(failed)} of {len(results)} controls did not hold:{RESET}")
        for name in failed:
            print(f"  - {name}")
        return 1
    print(f"{GREEN}All {len(results)} controls hold.{RESET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
