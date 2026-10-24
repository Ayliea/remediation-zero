# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""The neutral document store on SQLite, for the local edition.

Up to two connections per store: a write connection over the files holding a
writable collection, and a read connection over the rest; a store with no
files of one kind opens no connection for it. Each distinct
database file is attached to one of them under a generated schema alias
(`main`, `f1`, `f2`, ...; never a collection name), and each file holds one
table:

    docs(collection TEXT, id TEXT, data TEXT NOT NULL, revision INTEGER NOT NULL,
         PRIMARY KEY(collection, id))

`data` is the document as JSON. Filtering, ordering and limits run in Python
after `json.loads`; there are no indexes beyond the primary key and no filter
operator beyond `==`, because the writers use nothing more.

Atomicity: every write, single or batched, runs inside `BEGIN IMMEDIATE ...
COMMIT` on the write connection, so a batch spanning several attached files
commits in all of them or none. Files use the rollback journal
(`journal_mode=DELETE`); SQLite only makes a multi-file commit atomic across a
crash with a rollback journal and a real file as `main`, so `main` is the first
writable file. `busy_timeout=10000` lets a second writer wait for the first
instead of failing with `database is locked`.

Scoping (CLAUDE.md hard constraint 4): a write addressed to any collection
outside `writable` raises `PermissionError` before any SQL runs. A collection
in a file that holds only read-only collections is refused twice: by that
`PermissionError`, and by SQLite itself, because the file is attached
`mode=ro` to the read connection. A read-only collection that shares a file
with a writable one is guarded by the `PermissionError` alone, because that
file is attached read-write. In the local layout that happens only in the
references file (findings, assets, owners, scans, approvals), which is written
by the seed, rescan and approve scripts and never by an agent. Agent files are
never mixed (Ruling 18).

`revision` counts writes to one document: 1 when a create, or a set that
creates the document, first writes it, then the previous value + 1 on every set
or update, computed inside the write transaction. A delete removes the row, so a
later create starts at 1 again. It is surfaced as `Snapshot.update_time`, the
name the protocol mirrors from Firestore, but here it is an opaque concurrency
token, not a time. It is never shown and never used for a lifecycle decision;
those read `real_ts` and `sim_ts` from `SimClock`. No clock is read here.

Standard library only.
"""

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Iterator, Mapping, Optional
from urllib.parse import quote

from tools.docstore import (
    ASCENDING,
    DELETE_FIELD,
    DESCENDING,
    Aggregation,
    AlreadyExists,
    ArrayUnion,
    DocStoreBase,
    FieldFilter,
    Increment,
    NotFound,
    Snapshot,
)

BUSY_TIMEOUT_MS = 10000
DOCS_SCHEMA = ("CREATE TABLE IF NOT EXISTS {alias}.docs(collection TEXT, id TEXT, "
           "data TEXT NOT NULL, revision INTEGER NOT NULL, "
           "PRIMARY KEY(collection, id))")
_ABSENT = object()


def _uri(path: Path, mode: str) -> str:
    return f"file:{quote(str(path))}?mode={mode}"


class SQLiteDocStore(DocStoreBase):
    """Collections stored in SQLite files, behind the neutral API."""

    def __init__(self, files: Mapping[str, Path], *,
                 writable: Optional[frozenset] = None) -> None:
        self.files = {name: Path(path) for name, path in files.items()}
        self._writable = frozenset(self.files if writable is None else writable)

        unknown = self._writable - set(self.files)
        if unknown:
            raise ValueError(f"writable collection(s) {', '.join(sorted(unknown))} "
                             "have no database file")

        # One entry per database file. An existing file is keyed by device and
        # inode, so a hardlink or a second spelling of a path is attached once.
        by_file: dict = {}
        for name, path in self.files.items():
            if path.exists():
                st = path.stat()
                key: tuple = (st.st_dev, st.st_ino)
            else:
                key = ("path", str(path.resolve()))
            by_file.setdefault(key, (path.resolve(), []))[1].append(name)
        rw = [entry for entry in by_file.values()
              if any(name in self._writable for name in entry[1])]
        ro = [entry for entry in by_file.values() if entry not in rw]
        for path, names in ro:
            if not path.exists():
                raise FileNotFoundError(
                    f"{path} does not exist; the read-only collection(s) "
                    f"{', '.join(sorted(names))} need their database file "
                    f"created before a store can open it read-only")

        # Two connections (Ruling 17). The write connection attaches only files
        # holding a writable collection, so BEGIN IMMEDIATE never opens a read
        # transaction on a file this store cannot write; that read lock would
        # block another store's commit to that file until this one finished.
        # The read connection attaches the rest `mode=ro` and reads in
        # autocommit, holding a lock only for the statement. Within a store,
        # write locks are taken in the sorted order of its writable files.
        self._lock = threading.RLock()
        self._conn_for: dict = {}
        self._write_conn = self._open(sorted(rw, key=lambda e: str(e[0])), "rwc")
        self._read_conn = None
        try:
            self._read_conn = self._open(sorted(ro, key=lambda e: str(e[0])), "ro")
        except BaseException:
            if self._write_conn is not None:
                self._write_conn.close()
            raise

    def _open(self, entries: list, mode: str) -> Optional[sqlite3.Connection]:
        """One connection over `entries`, aliased `main`, `f1`, `f2`, ..."""
        if not entries:
            return None
        aliases = ["main"] + [f"f{i}" for i in range(1, len(entries))]
        conn = sqlite3.connect(_uri(entries[0][0], mode), uri=True,
                               timeout=BUSY_TIMEOUT_MS / 1000,
                               isolation_level=None, check_same_thread=False)
        try:
            conn.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
            for (path, _), alias in zip(entries[1:], aliases[1:]):
                conn.execute(f"ATTACH DATABASE ? AS {alias}", (_uri(path, mode),))
            for (path, names), alias in zip(entries, aliases):
                if mode == "rwc":
                    got = conn.execute(f"PRAGMA {alias}.journal_mode=DELETE").fetchone()[0]
                    if got.lower() != "delete":
                        raise RuntimeError(f"{path} stayed in journal mode {got}")
                    conn.execute(DOCS_SCHEMA.format(alias=alias))
                for name in names:
                    self._conn_for[name] = (conn, alias)
        except BaseException:
            conn.close()
            raise
        return conn

    # --- the neutral API ---------------------------------------------------

    def collection(self, name: str) -> "_Query":
        self._conn_of(name)
        return _Query(self, name)

    def batch(self) -> "_Batch":
        return _Batch(self)

    def close(self) -> None:
        with self._lock:
            for conn in (self._write_conn, self._read_conn):
                if conn is not None:
                    conn.close()

    # --- internals ---------------------------------------------------------

    def _conn_of(self, collection: str) -> tuple:
        """The connection holding `collection`'s file, and its schema alias."""
        try:
            return self._conn_for[collection]
        except KeyError:
            raise KeyError(f"{collection} has no database file in this store") from None

    def _require_writable(self, collection: str) -> None:
        self._conn_of(collection)
        if collection not in self._writable:
            raise PermissionError(f"{collection} is read-only for this agent")

    def _read(self, collection: str, doc_id: str) -> Optional[tuple]:
        conn, alias = self._conn_of(collection)
        with self._lock:
            return conn.execute(
                f"SELECT data, revision FROM {alias}.docs "
                "WHERE collection = ? AND id = ?", (collection, doc_id)).fetchone()

    def _rows(self, collection: str) -> list:
        conn, alias = self._conn_of(collection)
        with self._lock:
            return conn.execute(
                f"SELECT id, data, revision FROM {alias}.docs WHERE collection = ?",
                (collection,)).fetchall()

    def _commit(self, ops: list) -> None:
        if not ops:
            return
        conn = self._write_conn  # every op passed _require_writable
        with self._lock:
            try:
                conn.execute("BEGIN IMMEDIATE")
                for op in ops:
                    self._apply(*op)
                conn.execute("COMMIT")
            except BaseException:
                if conn.in_transaction:
                    try:
                        conn.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass  # the original error is the one worth raising
                raise

    def _apply(self, kind: str, collection: str, doc_id: str,
               data: Optional[dict], merge: bool) -> None:
        conn, alias = self._conn_of(collection)
        if kind == "delete":
            conn.execute(f"DELETE FROM {alias}.docs WHERE collection = ? AND id = ?",
                               (collection, doc_id))
            return
        row = self._read(collection, doc_id)
        current = json.loads(row[0]) if row else None
        if kind == "create":
            if current is not None:
                raise AlreadyExists(f"{collection}/{doc_id} already exists")
            new = _materialize(data)
        elif kind == "set":
            new = _merge(current or {}, data) if merge else _materialize(data)
        elif kind == "update":
            if current is None:
                raise NotFound(f"{collection}/{doc_id} does not exist")
            new = current
            for key, value in data.items():
                _assign(new, key.split("."), value)
        else:
            raise ValueError(f"unknown write: {kind}")
        conn.execute(
            f"INSERT OR REPLACE INTO {alias}.docs (collection, id, data, revision) "
            "VALUES (?, ?, ?, ?)",
            (collection, doc_id, json.dumps(new, sort_keys=True),
             row[1] + 1 if row else 1))


def _op(store: SQLiteDocStore, kind: str, ref: "_Document",
        data: Optional[dict] = None, merge: bool = False) -> tuple:
    """Check a write before any SQL runs, and return it ready to apply."""
    store._require_writable(ref._collection)
    if kind in ("create", "set") and not merge and _contains_delete(data):
        raise ValueError("DELETE_FIELD is only allowed in update or set(merge=True)")
    if kind == "update" and not data:
        raise ValueError("update needs at least one field")
    if kind == "update" and any(_contains_delete(v) for v in data.values()
                                if v is not DELETE_FIELD):
        raise ValueError("DELETE_FIELD must be a field's whole value in update")
    return (kind, ref._collection, ref.id, data, merge)


# --- value semantics, mirroring Firestore ------------------------------------


def _contains_delete(value: Any) -> bool:
    if value is DELETE_FIELD:
        return True
    return isinstance(value, dict) and any(_contains_delete(v) for v in value.values())


def _materialize(value: Any) -> Any:
    """`value` written over nothing: transforms resolve against an absent field."""
    if isinstance(value, dict):
        return {k: _materialize(v) for k, v in value.items()}
    return _resolve(_ABSENT, value)


def _resolve(old: Any, value: Any) -> Any:
    """The value a field takes when `value` is written over `old`."""
    if isinstance(value, ArrayUnion):
        out = list(old) if isinstance(old, list) else []
        for item in value.values:
            if not any(_same(item, have) for have in out):
                out.append(item)
        return out
    if isinstance(value, Increment):
        base = old if _rank(old) == 2 else 0
        return base + value.value
    if isinstance(value, dict):
        return _materialize(value)
    return value


def _merge(base: dict, patch: dict) -> dict:
    """`set(merge=True)`: nested maps merge, every other value replaces."""
    out = dict(base)
    for key, value in patch.items():
        if value is DELETE_FIELD:
            out.pop(key, None)
        elif isinstance(value, dict) and value:
            old = out.get(key)
            out[key] = _merge(old if isinstance(old, dict) else {}, value)
        else:
            out[key] = _resolve(out.get(key, _ABSENT), value)
    return out


def _assign(doc: dict, path: list, value: Any) -> None:
    """`update`: the field at `path` is replaced, never merged."""
    for part in path[:-1]:
        child = doc.get(part)
        if not isinstance(child, dict):
            if value is DELETE_FIELD:
                return
            child = doc[part] = {}
        doc = child
    if value is DELETE_FIELD:
        doc.pop(path[-1], None)
    else:
        doc[path[-1]] = _resolve(doc.get(path[-1], _ABSENT), value)


def _rank(value: Any) -> int:
    """Firestore's cross-type order: null, bool, number, string, array, map."""
    if value is None:
        return 0
    if isinstance(value, bool):
        return 1
    if isinstance(value, (int, float)):
        return 2
    if isinstance(value, str):
        return 3
    if isinstance(value, list):
        return 5
    if isinstance(value, dict):
        return 6
    return 7


def _same(a: Any, b: Any) -> bool:
    """JSON equality: `True` is not `1`, but `1` is `1.0`."""
    if _rank(a) != _rank(b):
        return False
    if isinstance(a, list):
        return len(a) == len(b) and all(_same(x, y) for x, y in zip(a, b))
    if isinstance(a, dict):
        return a.keys() == b.keys() and all(_same(a[k], b[k]) for k in a)
    return a == b


def _sort_key(value: Any) -> tuple:
    rank = _rank(value)
    if rank == 0:
        return (rank, 0)
    if rank == 5:
        return (rank, tuple(_sort_key(v) for v in value))
    if rank == 6:
        return (rank, tuple((k, _sort_key(value[k])) for k in sorted(value)))
    return (rank, value)


def _lookup(data: dict, field: str) -> Any:
    value: Any = data
    for part in field.split("."):
        if not isinstance(value, dict) or part not in value:
            return _ABSENT
        value = value[part]
    return value


# --- references, queries and batches -----------------------------------------


class _Document:
    def __init__(self, store: SQLiteDocStore, collection: str, doc_id: str) -> None:
        self._store, self._collection, self.id = store, collection, doc_id

    def get(self) -> Snapshot:
        row = self._store._read(self._collection, self.id)
        if row is None:
            return Snapshot(self.id, False, None)
        return Snapshot(self.id, True, json.loads(row[0]), row[1])

    def create(self, data: dict) -> None:
        self._store._commit([_op(self._store, "create", self, data)])

    def set(self, data: dict, merge: bool = False) -> None:
        self._store._commit([_op(self._store, "set", self, data, merge)])

    def update(self, data: dict) -> None:
        self._store._commit([_op(self._store, "update", self, data)])

    def delete(self) -> None:
        self._store._commit([_op(self._store, "delete", self)])


class _Query:
    def __init__(self, store: SQLiteDocStore, collection: str, filters: tuple = (),
                 orders: tuple = (), limit: Optional[int] = None) -> None:
        self._store, self._collection = store, collection
        self._filters, self._orders, self._limit = filters, orders, limit

    def _with(self, **changes: Any) -> "_Query":
        state = {"filters": self._filters, "orders": self._orders,
                 "limit": self._limit, **changes}
        return _Query(self._store, self._collection, **state)

    def document(self, doc_id: str) -> _Document:
        return _Document(self._store, self._collection, doc_id)

    def where(self, *, filter: FieldFilter) -> "_Query":
        return self._with(filters=self._filters + (filter,))

    def order_by(self, field: str, direction: str = ASCENDING) -> "_Query":
        if direction not in (ASCENDING, DESCENDING):
            raise ValueError(f"unknown direction: {direction!r}")
        return self._with(orders=self._orders + ((field, direction),))

    def limit(self, n: int) -> "_Query":
        return self._with(limit=n)

    def stream(self) -> Iterator[Snapshot]:
        docs = [(doc_id, json.loads(data), revision)
                for doc_id, data, revision in self._store._rows(self._collection)]
        docs = [d for d in docs
                if all(_same(_lookup(d[1], f.field_path), f.value) for f in self._filters)
                and all(_lookup(d[1], field) is not _ABSENT for field, _ in self._orders)]
        # Ties break by document id, in the direction of the last ordering.
        last_desc = bool(self._orders) and self._orders[-1][1] == DESCENDING
        docs.sort(key=lambda d: d[0], reverse=last_desc)
        for field, direction in reversed(self._orders):
            docs.sort(key=lambda d: _sort_key(_lookup(d[1], field)),
                      reverse=direction == DESCENDING)
        if self._limit is not None:
            docs = docs[:self._limit]
        for doc_id, data, revision in docs:
            yield Snapshot(doc_id, True, data, revision)

    def count(self) -> "_Count":
        return _Count(self)


class _Count:
    def __init__(self, query: _Query) -> None:
        self._query = query

    def get(self) -> list:
        return [[Aggregation(sum(1 for _ in self._query.stream()))]]


class _Batch:
    """Writes are checked as they are added and applied in order at `commit()`."""

    def __init__(self, store: SQLiteDocStore) -> None:
        self._store, self._ops, self._committed = store, [], False

    def _ref(self, ref: Any) -> _Document:
        if self._committed:
            raise ValueError("batch already committed")
        if not isinstance(ref, _Document) or ref._store is not self._store:
            raise TypeError("a batch takes references from the same store")
        return ref

    def create(self, ref: _Document, data: dict) -> None:
        self._ops.append(_op(self._store, "create", self._ref(ref), data))

    def set(self, ref: _Document, data: dict, merge: bool = False) -> None:
        self._ops.append(_op(self._store, "set", self._ref(ref), data, merge))

    def update(self, ref: _Document, data: dict) -> None:
        self._ops.append(_op(self._store, "update", self._ref(ref), data))

    def delete(self, ref: _Document) -> None:
        self._ops.append(_op(self._store, "delete", self._ref(ref)))

    def commit(self) -> None:
        """Apply every write or none. A failed commit may be retried; a
        successful one may not be repeated."""
        if self._committed:
            raise ValueError("batch already committed")
        self._store._commit(self._ops)
        self._committed = True
