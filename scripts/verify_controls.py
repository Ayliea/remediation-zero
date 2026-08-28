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

"""Prove the five security claims. Every one of them, by doing it.

    ./scripts/verify-controls.sh

Nothing here asserts a control. Each check performs the action the control is
supposed to stop and reports what actually happened, so a reader who did not
write this system can watch it fail in the right way.
"""

import argparse
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

from tools.clock import SimClock  # noqa: E402
from tools.idempotency import derive_key  # noqa: E402
from tools.model_armor import ModelArmor  # noqa: E402

PROJECT = os.environ["GOOGLE_CLOUD_PROJECT"]
PLANTED = "RZ-0216"

GREEN, RED, DIM, RESET = "\033[32m", "\033[31m", "\033[2m", "\033[0m"
results: list[tuple[str, bool, str]] = []
inconclusive_checks: list[str] = []


AMBER = "\033[33m"


def record(name: str, passed: bool, detail: str, inconclusive: bool = False) -> None:
    """Three outcomes, not two.

    A check that could not run is not a check that passed. Collapsing those
    two into one green mark is how a control ends up believed on the strength
    of a test that never exercised it.
    """
    if inconclusive:
        mark = f"{AMBER}????{RESET}"
    else:
        mark = f"{GREEN}PASS{RESET}" if passed else f"{RED}FAIL{RESET}"
    print(f"  [{mark}] {name}")
    print(f"         {DIM}{detail}{RESET}")
    results.append((name, passed and not inconclusive, detail))
    if inconclusive:
        inconclusive_checks.append(name)


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
    """With the boundary disabled, the second layer has to hold on its own.

    The probe cycle is a fixed number so the record it writes is identifiable.
    That is also what made this check stop testing anything: the idempotency
    record from the previous run survives, `cycle.py` skips triage and review
    before either model is called, and the check then passes by re-reading a
    decision made days earlier. It reported PASS in 0.3s for 37 hours.

    So the prior artefacts are cleared before the run, and the verdict is
    accepted only if it was written *during* this invocation. The freshness
    test is the load-bearing half: clearing can fail, but a stale record can
    then no longer be mistaken for a result.
    """
    env = dict(os.environ, MODEL_ARMOR_ENABLED="false")
    cycle = 900
    client = firestore.Client()
    decision_ref = client.collection("decisions").document(f"{PLANTED}-c{cycle:03d}")

    decision_ref.delete()
    client.collection("idempotency").document(
        derive_key(finding_id=PLANTED, action="decision", cycle=cycle)
    ).delete()

    # real_ts, from the one clock in the system. Never falsified, so it is
    # sound to compare a stored stamp against it.
    started = SimClock.from_env(os.environ).now().real_ts

    subprocess.run(
        [".venv/bin/python", "scripts/cycle.py", "--cycle", str(cycle),
         "--limit", "1", "--start", "216"],
        cwd=REPO_ROOT, env=env, capture_output=True, text=True, check=False,
    )

    data = decision_ref.get().to_dict() or {}
    reasons = " ".join(v.get("reason", "") for v in data.get("verdicts", []))
    written_at = data.get("real_ts", 0.0)
    fresh = written_at >= started

    passed = fresh and "untrusted text:" in reasons
    if not data:
        detail = "no verdict recorded"
    elif not fresh:
        detail = (f"STALE: decision predates this run by "
                  f"{(started - written_at) / 3600:.1f}h. The models were not "
                  f"called, so this control proved nothing.")
    else:
        detail = reasons[:200]
    record("Reviewer catches it with Model Armor disabled", passed, detail)


# --- 3 ----------------------------------------------------------------------

def _run_probe_job(job: str, name: str) -> None:
    """Execute one probe job and score it from its own output."""
    execute = subprocess.run(
        ["gcloud", "run", "jobs", "execute", job,
         "--project", PROJECT, "--region", "us-central1", "--wait"],
        capture_output=True, text=True, check=False,
    )
    if execute.returncode != 0 and job in execute.stderr:
        record(name, False,
               f"INCONCLUSIVE: the {job} job is not deployed. See the README.",
               inconclusive=True)
        return

    execution = subprocess.run(
        ["gcloud", "run", "jobs", "executions", "list", "--job", job,
         "--project", PROJECT, "--region", "us-central1",
         "--limit", "1", "--format", "value(name)"],
        capture_output=True, text=True, check=False,
    ).stdout.strip()

    logs = subprocess.run(
        ["gcloud", "logging", "read",
         f'resource.type=cloud_run_job AND labels."run.googleapis.com/execution_name"="{execution}"',
         "--project", PROJECT, "--limit", "30",
         "--format", "value(textPayload)", "--order", "asc"],
        capture_output=True, text=True, check=False,
    ).stdout

    held = "CONTROL HOLDS" in logs
    lines = [ln.strip() for ln in logs.splitlines() if "expect" in ln]
    record(name, held,
           " | ".join(ln.split("|")[-1].strip() + ": " + ln.split("|")[1].strip()
                      for ln in lines) or logs.strip()[:200])


def check_reporting_cannot_write_tickets() -> None:
    """Run the probe as the reporting identity and read what happened.

    A Cloud Run job rather than impersonation. The job's service account IS
    rz-reporting, so this is the identity the agent actually runs under
    attempting the action the architecture says it cannot perform. Nothing is
    simulated and nothing is granted to the operator to make it work.
    """
    execute = subprocess.run(
        ["gcloud", "run", "jobs", "execute", "reporting-write-probe",
         "--project", PROJECT, "--region", "us-central1", "--wait"],
        capture_output=True, text=True, check=False,
    )
    if execute.returncode != 0 and "reporting-write-probe" in execute.stderr:
        record(
            "Reporting identity is denied a ticket write",
            False,
            "INCONCLUSIVE: the probe job is not deployed. See scripts/grant-iam.sh.",
            inconclusive=True,
        )
        return

    name = subprocess.run(
        ["gcloud", "run", "jobs", "executions", "list", "--job",
         "reporting-write-probe", "--project", PROJECT, "--region", "us-central1",
         "--limit", "1", "--format", "value(name)"],
        capture_output=True, text=True, check=False,
    ).stdout.strip()

    logs = subprocess.run(
        ["gcloud", "logging", "read",
         f'resource.type=cloud_run_job AND labels."run.googleapis.com/execution_name"="{name}"',
         "--project", PROJECT, "--limit", "30",
         "--format", "value(textPayload)", "--order", "asc"],
        capture_output=True, text=True, check=False,
    ).stdout

    held = "CONTROL HOLDS" in logs
    lines = [ln.strip() for ln in logs.splitlines() if "expect" in ln]
    record(
        "Reporting identity is denied a ticket write",
        held,
        " | ".join(ln.split("|")[-1].strip() + ": " + ln.split("|")[1].strip()
                   for ln in lines) or logs.strip()[:200],
    )


# --- 4 ----------------------------------------------------------------------

def check_exception_cannot_read_the_token() -> None:
    """Run the probe as the exception identity and read what happened.

    A Cloud Run job whose service account IS rz-exception, attempting to read
    the credential only rz-chase is granted. Not impersonation: the first
    attempt at this check ran `--impersonate-service-account` from a laptop and
    both identities returned PERMISSION_DENIED on getAccessToken — a refusal to
    impersonate, which says nothing about the secret. It reads as proof of the
    control and is proof that the operator cannot impersonate anyone.
    """
    _run_probe_job(
        job="exception-secret-probe",
        name="Exception identity is denied the tracker token",
    )


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


#: The checks, in the order they run. The probe is named separately because it
#: costs a Cloud Run job execution and roughly three and a half minutes, while
#: the other three together take under twenty seconds. A demonstration that has
#: to run all four in sequence spends its whole budget waiting for one of them,
#: so the set is selectable. The default is still all four: a partial run has
#: to be asked for explicitly, because a control suite that quietly skips the
#: slow check is how the slow check stops being run at all.
CHECKS = {
    "armor": ("Model Armor blocks the planted injection",
              lambda: check_model_armor_blocks_the_payload()),
    "reviewer": ("Reviewer catches it with Model Armor disabled",
                 lambda: check_reviewer_catches_it_independently()),
    "probe": ("Reporting identity is denied a ticket write",
              lambda: check_reporting_cannot_write_tickets()),
    "secret": ("Exception identity is denied the tracker token",
               lambda: check_exception_cannot_read_the_token()),
    "resume": ("A resumed cycle writes nothing a second time",
               lambda: check_resume_produces_no_duplicates()),
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--only", default="", metavar="NAME[,NAME...]",
        help=("run a subset: " + ", ".join(CHECKS) +
              ". 'probe' executes a Cloud Run job and takes about 3m30s; the "
              "other three together take under 20s."),
    )
    args = parser.parse_args()

    selected = [n.strip() for n in args.only.split(",") if n.strip()] or list(CHECKS)
    unknown = [n for n in selected if n not in CHECKS]
    if unknown:
        parser.error(f"unknown check(s): {', '.join(unknown)}. "
                     f"Choose from: {', '.join(CHECKS)}")

    print("\nRemediation Zero — control verification")
    print("Each check performs the action the control is meant to stop.\n")
    if len(selected) < len(CHECKS):
        skipped = [CHECKS[n][0] for n in CHECKS if n not in selected]
        print(f"{AMBER}Partial run. Not exercised in this run:{RESET}")
        for name in skipped:
            print(f"  - {name}")
        print()

    for name in selected:
        CHECKS[name][1]()

    failed = [n for n, ok, _ in results if not ok and n not in inconclusive_checks]
    print()
    if inconclusive_checks:
        print(f"{AMBER}{len(inconclusive_checks)} check(s) could not run:{RESET}")
        for name in inconclusive_checks:
            print(f"  - {name}")
    if failed:
        print(f"{RED}{len(failed)} of {len(results)} controls did not hold:{RESET}")
        for name in failed:
            print(f"  - {name}")
    if failed or inconclusive_checks:
        # An unrun check is not a pass, so it is not a zero exit either.
        return 1
    print(f"{GREEN}All {len(results)} controls hold.{RESET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
