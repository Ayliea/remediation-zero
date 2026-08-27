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

"""Control probe: attempt, as the exception identity, to read the tracker token.

Runs as a Cloud Run job whose service account is rz-exception. Nothing is
impersonated and nothing is simulated: this is the identity the exception agent
actually runs under, attempting to read a credential only the chase agent is
granted.

    read the tracker token           must be DENIED
    read a finding                   must SUCCEED

The second is not filler. An identity that can read nothing proves only that it
is broken, and a probe that reports one denial and stops cannot tell the two
apart. The control is that the boundary falls in a specific place: chase
delivers to the tracker, the exception sweep does not, and the difference is
enforced on the secret rather than by the exception agent choosing not to ask.

Why this exists at all: the first attempt to check this was run from a laptop
with --impersonate-service-account, and both identities came back
PERMISSION_DENIED on `iam.serviceAccounts.getAccessToken` — a refusal to
impersonate, which says nothing about the secret. Read one way it looked like
proof of the control. It was proof that the operator cannot impersonate anyone.
"""

import sys

import google.auth
import google.auth.transport.requests
from google.cloud import firestore

PROJECT = "remediation-zero"
SECRET = "rz-github-token"
SECRET_URL = (
    f"https://secretmanager.googleapis.com/v1/projects/{PROJECT}"
    f"/secrets/{SECRET}/versions/latest:access"
)


def attempt(label: str, expect_denied: bool, fn) -> bool:
    expectation = "DENIED" if expect_denied else "ALLOWED"
    message = ""
    try:
        fn()
        outcome, denied = "ALLOWED", False
    except Exception as exc:
        name = type(exc).__name__
        message = str(exc)
        denied = (
            "PermissionDenied" in name
            or "403" in message
            or "PERMISSION_DENIED" in message
        )
        # A denial on impersonation is not a denial on the action. That
        # confusion is the reason this probe runs as the identity rather than
        # borrowing it, and it is worth refusing to score even here.
        if "getAccessToken" in message or "Failed to impersonate" in message:
            denied = False
            outcome = f"IMPERSONATION FAILURE ({name})"
        elif "InvalidArgument" in name or "400" in message[:8]:
            denied = False
            outcome = f"INVALID REQUEST ({name})"
        else:
            outcome = f"DENIED ({name})" if denied else f"ERROR ({name})"

    ok = denied == expect_denied
    print(f"  expect {expectation:8} | got {outcome:34} | "
          f"{'ok' if ok else 'MISMATCH'}  {label}")
    if not ok:
        print(f"           why: {message[:400]}")
    return ok


def read_secret() -> None:
    """Fetch the token with this job's own credentials.

    Uses the ambient service account rather than a Secret Manager client, so
    the probe adds no dependency to the image it shares with the console. The
    value is never printed: a probe that leaks the credential it is proving is
    protected would be a strange kind of control.
    """
    credentials, _ = google.auth.default(
        scopes=["https://www.googleapis.com/auth/cloud-platform"])
    session = google.auth.transport.requests.AuthorizedSession(credentials)
    response = session.get(SECRET_URL, timeout=20)
    if response.status_code == 403:
        raise PermissionError(f"403 PERMISSION_DENIED on {SECRET}")
    response.raise_for_status()


def main() -> int:
    print(f"Running as the exception identity against project {PROJECT}.\n")

    operational = firestore.Client(project=PROJECT)

    results = [
        attempt("read the tracker token", True, read_secret),
        attempt(
            "read a finding",
            False,
            lambda: operational.collection("findings").document("RZ-0001").get(),
        ),
    ]

    print()
    if all(results):
        print("CONTROL HOLDS: the exception identity cannot reach the tracker "
              "credential, and is not merely broken.")
        return 0
    print("CONTROL DID NOT HOLD.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
