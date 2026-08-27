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

"""Create the long-running orchestrator session and the Memory Bank scope.

Run once. Every later run refuses.

The session created here is the single most valuable artefact in the build. Its
value is entirely in how long it has been alive, which means it can only be
earned by waiting and can never be regenerated. Losing it on the 30th cannot be
fixed by the 31st.

So this script has exactly one destructive-adjacent behaviour, which is that it
could create a second session and leave the first unreferenced. It refuses to
do that: if a session already exists it prints the existing session's ID and
age and exits non-zero, without touching anything.
"""

import asyncio
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# The filename is hyphenated, so this runs as a script rather than as a module
# and does not get the repository root on sys.path for free.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dotenv import load_dotenv

from google.adk.memory import VertexAiMemoryBankService
from google.adk.sessions import VertexAiSessionService

from tools.clock import SimClock

#: Stable identity for the long-running session. These are deliberately fixed
#: rather than generated, so that "does a session already exist" is a question
#: with an answer rather than a guess.
APP_NAME = "remediation-zero"
USER_ID = "orchestrator"


def _require(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        print(
            f"ERROR: {name} is not set. Copy .env.example to .env and fill it in.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    return value


def _format_age(seconds: float) -> str:
    days, rem = divmod(int(seconds), 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    return f"{days}d {hours}h {minutes}m"


async def main() -> int:
    load_dotenv()

    project = _require("GOOGLE_CLOUD_PROJECT")
    location = _require("GOOGLE_CLOUD_LOCATION")
    engine_id = _require("AGENT_ENGINE_ID")

    clock = SimClock.from_env()

    sessions = VertexAiSessionService(
        project=project, location=location, agent_engine_id=engine_id
    )

    # ---------------------------------------------------------------------
    # Refuse if one already exists. This is the whole point of the script.
    # ---------------------------------------------------------------------
    existing = await sessions.list_sessions(app_name=APP_NAME, user_id=USER_ID)
    if existing.sessions:
        print("REFUSING TO CREATE A SECOND SESSION.\n", file=sys.stderr)
        print(
            "A long-running session already exists. Its elapsed time is the "
            "demo's strongest proof point and cannot be regenerated, so this "
            "script will not create another one alongside it.\n",
            file=sys.stderr,
        )
        now = time.time()
        for session in existing.sessions:
            age = now - (session.last_update_time or now)
            print(f"  session id     : {session.id}", file=sys.stderr)
            print(f"  app / user     : {session.app_name} / {session.user_id}", file=sys.stderr)
            print(f"  last update    : {_iso(session.last_update_time)}", file=sys.stderr)
            print(f"  age            : {_format_age(age)}", file=sys.stderr)
        print(
            "\nNothing was changed. To use this session, put its ID in .env as "
            "ORCHESTRATOR_SESSION_ID.",
            file=sys.stderr,
        )
        return 1

    # ---------------------------------------------------------------------
    # Create. Both stamps are recorded from SimClock, never from a server
    # timestamp or a direct wall-clock read.
    # ---------------------------------------------------------------------
    stamp = clock.now()
    session = await sessions.create_session(
        app_name=APP_NAME,
        user_id=USER_ID,
        state={
            "created_real_ts": stamp.real_ts,
            "created_sim_ts": stamp.sim_ts,
            "clock_mode": clock.mode.value,
            "cycle_id": "cycle-0",
        },
    )

    # One real memory into the Memory Bank scope, so the scope exists and is
    # demonstrably non-empty rather than merely provisioned.
    memory = VertexAiMemoryBankService(
        project=project, location=location, agent_engine_id=engine_id
    )
    await memory.add_memory(
        fact=(
            "The orchestrator session for remediation-zero was created at "
            f"{_iso(stamp.real_ts)} UTC with clock mode "
            f"'{clock.mode.value}'. This session is updated in place for the "
            "duration of the build and is never recreated."
        ),
        scope={"app_name": APP_NAME, "user_id": USER_ID},
    )

    print("=" * 58)
    print(f"session id       : {session.id}")
    print(f"app / user       : {APP_NAME} / {USER_ID}")
    print(f"agent engine     : projects/{project}/locations/{location}"
          f"/reasoningEngines/{engine_id}")
    print(f"created real_ts  : {stamp.real_ts:.3f}  ({_iso(stamp.real_ts)} UTC)")
    print(f"created sim_ts   : {stamp.sim_ts:.3f}  ({_iso(stamp.sim_ts)} UTC)")
    print(f"clock mode       : {clock.mode.value}")
    print("=" * 58)
    print()
    print("Record this in .env as ORCHESTRATOR_SESSION_ID.")
    print("Screenshot the created real_ts line for the demo video.")
    return 0


def _iso(epoch: float) -> str:
    if not epoch:
        return "unknown"
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
