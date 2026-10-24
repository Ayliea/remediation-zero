# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""The parts each edition supplies to the engine.

Firestore and Model Armor in the cloud, SQLite and a guard model locally. The
engine speaks only these names. Standard library only: nothing here imports
`tools.telemetry`, `tools.delivery` or `tools.fleet_memory`.
"""
import json
import logging
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, ContextManager, Iterator, Mapping, Optional, Protocol, runtime_checkable

from tools.clock import SimClock
from tools.docstore import DocStore
from tools.guardrail import Guardrail
from tools.model_roles import ModelRoles

logger = logging.getLogger("remediation_zero.delivery")


@runtime_checkable
class Memory(Protocol):
    def remember_cycle(self, cycle_id: str, counts: Mapping[str, Any],
                       real_ts: float, sim_ts: float) -> bool: ...

    def recall(self, query: str) -> list[str]: ...


@runtime_checkable
class Telemetry(Protocol):
    def finding_span(self, finding_id: str, cycle_id: str,
                     name: str = "remediation.finding") -> ContextManager: ...

    def set_outcome(self, span: Any, outcome: str) -> None: ...

    def flush(self) -> None: ...


class NoTelemetry:
    """Local edition: no tracing backend. All three calls do nothing."""

    @contextmanager
    def finding_span(self, finding_id: str, cycle_id: str,
                     name: str = "remediation.finding") -> Iterator[None]:
        yield None

    def set_outcome(self, span: Any, outcome: str) -> None:
        return None

    def flush(self) -> None:
        return None


@runtime_checkable
class TicketDelivery(Protocol):
    def deliver(self, event: str, finding_id: str, owner: Any, cycle: int,
                now_sim_ts: float, state: Any,
                delivery_id: Optional[str] = None) -> Optional[int]: ...


class NoDelivery:
    """Local edition: no tracker. The dashboard is the delivery."""

    def deliver(self, event: str, finding_id: str, owner: Any, cycle: int,
                now_sim_ts: float, state: Any,
                delivery_id: Optional[str] = None) -> Optional[int]:
        # Same cycle rendering as tools.telemetry.cycle_id, which is cloud-only.
        cycle_label = "-" if cycle is None else f"cycle-{int(cycle):03d}"
        logger.info(json.dumps({
            "event": "delivery_skipped", "reason": "dashboard-only",
            "finding_id": finding_id, "cycle_id": cycle_label}, sort_keys=True))
        return None


@dataclass(frozen=True)
class Ports:
    docs: DocStore
    journal: Any
    clock: SimClock
    roles: Optional[ModelRoles]
    guard: Guardrail
    delivery: TicketDelivery
    memory: Memory
    telemetry: Telemetry
    #: Local wiring sets this; the engine checks it rather than the store type.
    record_failed_runs: bool = False
