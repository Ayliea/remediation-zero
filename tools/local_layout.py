# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""The local workspace: one SQLite file per agent, and a per-stage write boundary.

The cloud gives each agent a service account with IAM on its own collections.
Here the same boundary is a set of files plus the stage that opens them:
`docs_for(stage)` opens every collection for reading, and only the collections
in `STAGE_WRITES[stage]` for writing. A collection outside that set is refused
by `PermissionError` and, when its file holds only read-only collections (the
reporting stage and `chase.sqlite3`, for example), by SQLite's `mode=ro` again.

`shared.sqlite3` holds `SHARED` and the idempotency journal. The journal is
written through `SQLiteStore` on its own connection, so a stage whose docstore
has the shared file read-only can still record an idempotency key.

Permissions: the workspace directory is 0700 and every database file 0600,
including files recreated after deletion. Files are created with an explicit
`os.open(..., 0o600)` before SQLite opens them (no process-wide umask change),
and SQLite's journal files inherit the database file's mode.

No clock is read here. Standard library only.
"""

import os
import sqlite3
from pathlib import Path

from tools.sqlite_docstore import DOCS_SCHEMA, SQLiteDocStore
from tools.sqlite_store import SQLiteStore

AGENT_FILES = {
    "orchestrator": ("cycles", "memories", "failed_runs"),
    "decisions": ("decisions",),
    "ownership": ("assignments",),
    "chase": ("tickets",),
    "exception": ("exceptions",),
    "reporting": ("reports",),
    "references": ("findings", "assets", "owners", "scans", "approvals"),
}
SHARED = ("human_queue", "sla_clocks")
# The triage cycle writes `assignments` because scripts/cycle.py runs the
# assignment step today; the ownership agent's own file still holds it.
STAGE_WRITES = {
    "triage_cycle": {"decisions", "assignments", "cycles", "memories", "failed_runs"} | set(SHARED),
    "chase": {"tickets"} | set(SHARED),
    "sweep": {"exceptions"} | set(SHARED),
    "report": {"reports"},
    "rescan": {"findings", "scans"},
    "seed": {"findings", "assets", "owners"},
    "approve": {"approvals"},
    "exception_accept": {"exceptions"} | set(SHARED),
}
SHARED_FILE = "shared"


def _private_file(path: Path) -> None:
    """Create `path` with mode 0600 if absent; tighten it if it exists."""
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    os.close(fd)
    os.chmod(path, 0o600)


class Workspace:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self._file_of = {name: agent for agent, names in AGENT_FILES.items() for name in names}
        self._file_of.update({name: SHARED_FILE for name in SHARED})

    def _path(self, stem: str) -> Path:
        return self.root / f"{stem}.sqlite3"

    def file_for(self, collection: str) -> Path:
        try:
            return self._path(self._file_of[collection])
        except KeyError:
            raise KeyError(f"unknown collection: {collection}") from None

    def init(self) -> None:
        """Create the directory, every file and its tables. Safe to repeat."""
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        for stem in (*AGENT_FILES, SHARED_FILE):
            path = self._path(stem)
            _private_file(path)
            conn = sqlite3.connect(path)
            try:
                conn.execute(DOCS_SCHEMA.format(alias="main"))
                conn.commit()
            finally:
                conn.close()
        SQLiteStore(self._path(SHARED_FILE))  # creates the journal tables

    def docs_for(self, stage: str) -> SQLiteDocStore:
        writable = STAGE_WRITES[stage]  # KeyError for an unknown stage
        self.init()
        files = {name: self.file_for(name) for name in self._file_of}
        return SQLiteDocStore(files, writable=frozenset(writable))

    def journal(self) -> SQLiteStore:
        self.init()
        return SQLiteStore(self._path(SHARED_FILE))
