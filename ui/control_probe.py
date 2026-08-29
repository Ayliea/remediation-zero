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

"""Control probe: attempt, as the reporting identity, the writes it must not do.

Runs as a Cloud Run job whose service account is rz-reporting. There is no
impersonation here and nothing is simulated: this is the identity the reporting
agent actually runs under, attempting the action the architecture says it
cannot perform.

Four attempts, and the expected result of each is printed before it runs so
that a reader can check the outcome against the claim rather than trusting a
summary:

    write a ticket                   must be DENIED
    write to the human queue         must be DENIED
    read a finding                   must SUCCEED
    write a report                   must SUCCEED

The last two matter as much as the first two. An identity that cannot do
anything proves nothing about scoping; it only proves it is broken. The control
is that the boundary falls in a specific place.
"""

import sys
import traceback

from google.cloud import firestore

PROJECT = "remediation-zero"
REPORTS_DATABASE = "reports"
#: Not double-underscored. Firestore reserves ids matching __.*__, and an
#: earlier version of this probe used one: every attempt failed with
#: InvalidArgument on the document name, which the probe reported as a denial.
#: The control looked like it was holding when it had never been tested.
PROBE_ID = "control-probe"


def attempt(label: str, expect_denied: bool, fn) -> bool:
    expectation = "DENIED" if expect_denied else "ALLOWED"
    message = ""
    try:
        fn()
        outcome, denied = "ALLOWED", False
    except Exception as exc:
        name = type(exc).__name__
        message = str(exc)
        denied = "PermissionDenied" in name or "403" in message
        # An invalid request is not a denial. Reporting it as one is how the
        # earlier version of this probe passed without exercising anything.
        # One branch, not three: the previous shape classified correctly and
        # then overwrote the label unconditionally, so a 400 that was not an
        # InvalidArgument scored right and printed ERROR. The score is what
        # gates the control, but the label is what a person reads.
        if "InvalidArgument" in name or "400" in message[:8]:
            denied = False
            outcome = f"INVALID REQUEST ({name})"
        else:
            outcome = f"DENIED ({name})" if denied else f"ERROR ({name})"

    ok = denied == expect_denied
    print(f"  expect {expectation:8} | got {outcome:34} | {'ok' if ok else 'MISMATCH'}  {label}")
    if not ok:
        # Print what actually happened. A mismatch that does not say why is
        # a dead end for whoever reads this next.
        print(f"           why: {message[:400]}")
    return ok


def main() -> int:
    print(f"Running as the reporting identity against project {PROJECT}.\n")

    operational = firestore.Client(project=PROJECT)
    reports = firestore.Client(project=PROJECT, database=REPORTS_DATABASE)

    results = [
        attempt(
            "write a ticket",
            True,
            lambda: operational.collection("tickets").document(PROBE_ID).set(
                {"written_by": "rz-reporting"}
            ),
        ),
        attempt(
            "write to the human queue",
            True,
            lambda: operational.collection("human_queue").document(PROBE_ID).set(
                {"written_by": "rz-reporting"}
            ),
        ),
        attempt(
            "read a finding",
            False,
            lambda: operational.collection("findings").document("RZ-0001").get(),
        ),
        attempt(
            "write a report",
            False,
            lambda: reports.collection("reports").document(PROBE_ID).set(
                {"written_by": "rz-reporting"}
            ),
        ),
    ]

    print()
    if all(results):
        print("CONTROL HOLDS: the reporting identity can read the record and write "
              "reports, and cannot write tickets or the human queue.")
        return 0
    print("CONTROL DID NOT HOLD")
    return 1


if __name__ == "__main__":
    sys.exit(main())
