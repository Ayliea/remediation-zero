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
and SQLite's journal files inherit the database file's mode. Every `init()`
tightens an existing file back to 0600: that is the intended default for
customer data, not an accident. A root is adopted only if it is new, empty, or
already holds `shared.sqlite3`; any other directory is refused untouched.

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
    "references": ("findings", "assets", "owners", "scans"),
    # Its own file, so the approve command reaches findings only read-only.
    # Workspaces made before this kept approvals in references; init moves them.
    "approvals": ("approvals",),
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
    # The served dashboard reads everything and writes nothing (Ruling 43).
    "dashboard": set(),
}
SHARED_FILE = "shared"


def _private_file(path: Path) -> None:
    """Create `path` with mode 0600 if absent; tighten it if it exists."""
    # O_NOFOLLOW: a symlinked database file fails (ELOOP) rather than having
    # its target chmodded. fchmod acts on the descriptor, not the path.
    fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        # Windows (before Python 3.13) has no fchmod; there chmod only toggles
        # the read-only bit, and privacy comes from the user profile's ACLs,
        # not POSIX modes.
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        else:
            os.chmod(path, 0o600)
    finally:
        os.close(fd)


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
        self._init()

    def _init(self) -> SQLiteStore:
        """`init()`, returning the journal store it built."""
        # Ruling 20: adopt a root only if it is new, empty, or already a
        # workspace (shared.sqlite3 is the marker). Never chmod a foreign dir.
        if self.root.exists():
            names = os.listdir(self.root)
            if names and f"{SHARED_FILE}.sqlite3" not in names:
                raise ValueError(f"{self.root} is not empty and is not a Remediation Zero "
                                 "workspace; choose an empty or new directory")
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
        self._move_old_layout_approvals()
        return SQLiteStore(self._path(SHARED_FILE))  # creates the journal tables

    def _move_old_layout_approvals(self) -> None:
        """Move approvals out of references.sqlite3, where they used to live.

        One transaction across both files (journal_mode=DELETE makes that
        commit atomic), so an approval is never in neither file. INSERT OR
        IGNORE keeps a copy already in approvals.sqlite3, which is what an
        interrupted earlier move would leave, and then the stale one goes.
        """
        old = self._path("references")
        conn = sqlite3.connect(self._path("approvals"), isolation_level=None)
        try:
            conn.execute("PRAGMA busy_timeout=10000")
            conn.execute("ATTACH DATABASE ? AS old", (str(old),))
            if conn.execute("SELECT 1 FROM old.docs WHERE collection = 'approvals' "
                            "LIMIT 1").fetchone() is None:
                return
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute("INSERT OR IGNORE INTO main.docs (collection, id, data, revision) "
                             "SELECT collection, id, data, revision FROM old.docs "
                             "WHERE collection = 'approvals'")
                conn.execute("DELETE FROM old.docs WHERE collection = 'approvals'")
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        finally:
            conn.close()

    def docs_for(self, stage: str) -> SQLiteDocStore:
        writable = STAGE_WRITES[stage]  # KeyError for an unknown stage
        self.init()
        files = {name: self.file_for(name) for name in self._file_of}
        return SQLiteDocStore(files, writable=frozenset(writable))

    def journal(self) -> SQLiteStore:
        return self._init()
