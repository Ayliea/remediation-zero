# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Local-edition cross-cycle memory, kept in the `memories` collection.

One document per cycle, id = cycle_id, written with `set()` so a resumed cycle
overwrites rather than duplicates. Both clocks are stored exactly as passed;
this module never reads a clock. Neither method raises.
"""
import json
import logging
from typing import Any, Mapping

from tools.docstore import DocStore
from tools.fleet_memory import render_cycle_memory

logger = logging.getLogger("remediation_zero.memory")

COLLECTION = "memories"
MAX_RECALL = 5
MIN_TERM = 3


class LocalMemory:
    def __init__(self, docs: DocStore) -> None:
        self._docs = docs

    def remember_cycle(self, cycle_id: str, counts: Mapping[str, Any],
                       real_ts: float, sim_ts: float) -> bool:
        try:
            self._docs.collection(COLLECTION).document(cycle_id).set({
                "cycle_id": cycle_id,
                "text": render_cycle_memory(cycle_id, counts, real_ts, sim_ts),
                "counts": dict(counts),
                "real_ts": real_ts,
                "sim_ts": sim_ts,
            })
            return True
        except Exception as exc:  # noqa: BLE001 - memory must never fail a cycle
            self._log("memory_write_failed", exc, cycle_id)
            return False

    def recall(self, query: str) -> list[str]:
        try:
            terms = [t for t in str(query).lower().split() if len(t) >= MIN_TERM]
            rows = [s.to_dict() for s in self._docs.collection(COLLECTION).stream()]
            hits = [r for r in rows if r and all(t in r["text"].lower() for t in terms)]
            hits.sort(key=lambda r: r["sim_ts"], reverse=True)
            return [r["text"] for r in hits[:MAX_RECALL]]
        except Exception as exc:  # noqa: BLE001
            self._log("memory_recall_failed", exc, "-")
            return []

    @staticmethod
    def _log(event: str, exc: Exception, cycle_id: str) -> None:
        # Class name only: a store error message can carry paths.
        logger.warning(json.dumps({
            "event": event, "cycle_id": cycle_id, "finding_id": "-",
            "error": type(exc).__name__}, sort_keys=True))
