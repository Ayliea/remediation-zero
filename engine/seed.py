# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""The seed stage: load the committed corpus into the reference collections.

Reads `findings.json`, `assets.json` and `owners.json` from the corpus
directory (the synthetic corpus in `data/`), strips test-only fields, stamps
both clocks from `ports.clock`, and writes each record under its natural key.
`scripts/ingest.py` calls this in the cloud; the local edition calls it too.

Safe to re-run. Documents are written under their natural keys, so a second run
overwrites in place rather than producing a second copy of every finding.
Writes `findings`, `assets` and `owners` only; no agent writes these.

Refused, before any write, in a workspace that holds Greenbone findings:
seeded synthetic data and a client's real scanner data never share one.

Standard library only: nothing here imports a cloud SDK.
"""
import json
from pathlib import Path
from typing import Callable, Iterable, Optional

from engine.ports import Ports
from tools.docstore import FieldFilter
from tools.ingest import REFERENCE_COLLECTIONS, to_document

#: Firestore caps a batched write at 500 operations.
BATCH_LIMIT = 450


class SeedRefused(ValueError):
    """Seeding was refused before anything was written."""


def seed(ports: Ports, corpus_dir: Path, *,
         kinds: Iterable[str] = REFERENCE_COLLECTIONS,
         progress: Optional[Callable[[str, int], None]] = None) -> dict[str, int]:
    """Write every corpus record and return the count written per collection.

    `progress(kind, written)` is called as each collection finishes.
    """
    db = ports.docs
    real = db.collection("findings").where(
        filter=FieldFilter("source", "==", "greenbone")).limit(1).stream()
    if any(True for _ in real):
        raise SeedRefused("this workspace holds Greenbone findings; seeding demo data is "
                          "refused so demo and real data never mix. Nothing was loaded.")
    counts: dict[str, int] = {}

    for kind in kinds:
        path = Path(corpus_dir) / f"{kind}.json"
        records = json.loads(path.read_text(encoding="utf-8"))
        collection = db.collection(kind)

        written = 0
        batch = db.batch()
        pending = 0

        for record in records:
            document = to_document(record, clock=ports.clock, kind=kind)
            document_id = document.pop("_document_id")
            batch.set(collection.document(document_id), document)
            pending += 1
            written += 1

            if pending >= BATCH_LIMIT:
                batch.commit()
                batch = db.batch()
                pending = 0

        if pending:
            batch.commit()

        counts[kind] = written
        if progress is not None:
            progress(kind, written)

    return counts
