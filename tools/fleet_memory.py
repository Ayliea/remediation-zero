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

"""What the fleet remembers after the process that learned it has exited.

A remediation programme runs for weeks; a cycle runs for a minute. Firestore
keeps every row those cycles wrote, but rows are not context. Nothing in
`decisions` tells an agent three weeks later that the reviewer has been
rejecting the same class of remediation the whole time, or that the human queue
has been growing while the ticket count has not. That is the gap Memory Bank
fills: recollection that outlives the session which formed it.

Two rules make it safe to act on.

Every memory records both clocks. A recollection read weeks later is useless if
it cannot say which time it refers to, and dangerous if the reader assumes the
wrong one. `real_ts` is wall clock and is never adjusted; `sim_ts` is the
scenario.

Nothing here computes. The memory describes figures it was handed, in the same
way and for the same reason the reporting agent does. A recollection assembled
from numbers nobody calculated is worse than no recollection, because a future
agent will act on it without any way to check it.
"""

import json
import logging
from typing import Any, Callable, Mapping, Optional

logger = logging.getLogger("remediation_zero.memory")

#: The Memory Bank scope, matching the one session-init.py creates.
APP_NAME = "remediation-zero"
USER_ID = "orchestrator"


class MemoryUnavailable(RuntimeError):
    """Recollection could not be reached.

    Raised rather than returning an empty result. An empty recall and a fleet
    that has done nothing are the same answer, and only one of them is true;
    guessing which costs a reader their trust in every other memory.
    """


def _iso(epoch: float) -> str:
    from datetime import datetime, timezone

    if not epoch:
        return "unknown"
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


#: Each key is reported only when supplied. A cycle that tracked no SLAs must
#: not produce a memory asserting anything about SLAs.
#:
#: The keys are the ones the drivers actually emit. An earlier version listed
#: plausible names instead, so a real cycle filed a recollection that silently
#: dropped its human-queue count — a memory that omits the finding a person now
#: owns is precisely the memory that misleads.
_PHRASES = (
    ("decisions_total", "{v} decisions were adjudicated"),
    ("ratified", "{v} findings were ratified"),
    ("human_queue", "{v} went to the human queue for a person to decide"),
    ("routed_to_human", "{v} went to the human queue"),
    ("unavailable", "{v} could not be adjudicated because the reviewer was unavailable"),
    ("rejections", "the reviewer issued {v} rejections"),
    ("required_retry", "{v} needed a second proposal"),
    ("open_ticket", "{v} tickets were opened"),
    ("nudge", "{v} owners were nudged"),
    ("escalate", "{v} findings were escalated"),
    ("tickets_open", "{v} tickets were open"),
    ("sla_breached", "{v} SLAs had breached"),
    ("exceptions_active", "{v} risk acceptances were active"),
)


def render_cycle_memory(
    cycle_id: str, counts: Mapping[str, Any], real_ts: float, sim_ts: float
) -> str:
    """One cycle, as a sentence a later agent can act on."""
    drift = (sim_ts - real_ts) / 86400 if sim_ts and real_ts else 0
    head = (
        f"In {cycle_id}, at real time {_iso(real_ts)} "
        f"(simulated {_iso(sim_ts)}"
        + (f", running {drift:.0f} days ahead" if abs(drift) >= 1 else "")
        + ")"
    )

    clauses = [
        phrase.format(v=counts[key])
        for key, phrase in _PHRASES
        if counts.get(key) is not None
    ]
    if not clauses:
        return head + ", the fleet ran and recorded no adjudications."
    return head + ", " + "; ".join(clauses) + "."


class FleetMemory:
    """Read and write the fleet's cross-session recollection.

    Args:
        service_factory: builds the Memory Bank service. Injected so the
            failure paths can be tested without reaching Google Cloud.
    """

    def __init__(self, service_factory: Optional[Callable[..., Any]] = None) -> None:
        self._factory = service_factory or _default_service

    def remember_cycle(
        self, cycle_id: str, counts: Mapping[str, Any], real_ts: float, sim_ts: float
    ) -> bool:
        """File one recollection. Returns whether it was filed.

        Never raises. Memory is context and Firestore is the record, so a cycle
        whose work completed must not be reported as failed because its
        recollection could not be written. The failure is logged, loudly enough
        to notice and quietly enough not to stop the fleet.
        """
        text = render_cycle_memory(cycle_id, counts, real_ts, sim_ts)
        try:
            self._add(text)
            return True
        except Exception as exc:  # noqa: BLE001 - deliberately broad
            logger.warning(json.dumps({
                "event": "memory_write_failed", "cycle_id": cycle_id,
                "finding_id": "-", "error": type(exc).__name__,
                "detail": str(exc)[:200],
            }, sort_keys=True))
            return False

    async def recall_async(self, query: str) -> list[str]:
        """Search the fleet's recollection, from inside a running event loop.

        The agent form. ADK runs tools inside its own loop, where asyncio.run
        raises RuntimeError outright — which is how the first version of this
        failed in the deployed engine while working from every command line.

        Raises:
            MemoryUnavailable: rather than returning nothing. See the class
                docstring: an empty answer is a claim about the fleet.
        """
        try:
            service = self._factory()
            response = await service.search_memory(
                app_name=APP_NAME, user_id=USER_ID, query=query)
            return _texts(response)
        except Exception as exc:  # noqa: BLE001 - deliberately broad
            raise MemoryUnavailable(
                f"Memory Bank could not be reached: {type(exc).__name__}: "
                f"{str(exc)[:200]}. This is not the same as the fleet having "
                f"no history."
            ) from exc

    def recall(self, query: str) -> list[str]:
        """The command-line form. Safe only where no loop is already running.

        Raises:
            MemoryUnavailable: rather than returning nothing.
        """
        import asyncio

        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass  # no loop, which is what this form needs
        else:
            raise MemoryUnavailable(
                "recall() was called from inside a running event loop. Use "
                "recall_async(); asyncio.run() cannot nest."
            )
        try:
            return asyncio.run(self._search_coro(query))
        except MemoryUnavailable:
            raise
        except Exception as exc:  # noqa: BLE001 - deliberately broad
            raise MemoryUnavailable(
                f"Memory Bank could not be reached: {type(exc).__name__}: "
                f"{str(exc)[:200]}. This is not the same as the fleet having "
                f"no history."
            ) from exc

    # -- the async service, called from synchronous drivers ------------------

    def _add(self, text: str) -> None:
        import asyncio

        from google.adk.memory.memory_entry import MemoryEntry
        from google.genai import types

        service = self._factory()

        async def go():
            await service.add_memory(
                app_name=APP_NAME, user_id=USER_ID,
                memories=[MemoryEntry(
                    author=USER_ID,
                    content=types.Content(
                        role="model", parts=[types.Part(text=text)]),
                )],
            )

        asyncio.run(go())

    async def _search_coro(self, query: str) -> list[str]:
        service = self._factory()
        response = await service.search_memory(
            app_name=APP_NAME, user_id=USER_ID, query=query)
        return _texts(response)


def _texts(response: Any) -> list[str]:
    """Pull the memory text out of a search response."""
    out: list[str] = []
    for entry in getattr(response, "memories", []) or []:
        content = getattr(entry, "content", None)
        for part in getattr(content, "parts", []) or []:
            if getattr(part, "text", None):
                out.append(part.text)
    return out


def _default_service() -> Any:
    import os

    from google.adk.memory import VertexAiMemoryBankService

    # RZ_ first, matching RZ_FIRESTORE_PROJECT: Agent Engine reserves some
    # standard names outright and refuses to deploy when they appear in the
    # environment config, so the deployed engine is told its own identifiers
    # under names that are certain to be accepted.
    engine_id = (os.environ.get("RZ_AGENT_ENGINE_ID")
                 or os.environ.get("AGENT_ENGINE_ID") or "").strip()
    if not engine_id:
        raise RuntimeError(
            "AGENT_ENGINE_ID is not set, so there is no Memory Bank scope to "
            "address. Memory lives on the Agent Engine resource."
        )
    return VertexAiMemoryBankService(
        project=os.environ.get("RZ_FIRESTORE_PROJECT")
        or os.environ.get("GOOGLE_CLOUD_PROJECT"),
        location=(os.environ.get("RZ_AGENT_ENGINE_LOCATION")
                  or os.environ.get("AGENT_ENGINE_LOCATION") or "us-central1"),
        agent_engine_id=engine_id,
    )
