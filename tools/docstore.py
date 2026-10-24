# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""A neutral document-store API, and the adapter that puts Firestore behind it.

The writers in `tools/` speak only the names defined here, so that the same
writer runs on Firestore in the cloud edition and on SQLite in the local one.
The API mirrors the slice of Firestore the writers actually use and nothing
more: documents, single-field equality filters, ordering, limits, counts, and
atomic write batches. No transactions and no preconditions.

Everything above `FirestoreDocStore` is standard library only. The adapter
imports `google.cloud.firestore` when it is constructed, never at import time.

`as_docstore` is the one entry point the writers use. The scripts still hand
writers a raw `firestore.Client`; `as_docstore` wraps it, so that Firestore's
`AlreadyExists` reaches a writer as the neutral `AlreadyExists` it catches.
Without that, an idempotent create that lost a race would escape uncaught.
"""

from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator, Optional, Protocol


class AlreadyExists(Exception):
    """A create found the document already there."""


class FailedPrecondition(Exception):
    """The store refused a write whose precondition did not hold."""


class NotFound(Exception):
    """An update or delete addressed a document that does not exist."""


class _DeleteField:
    def __repr__(self) -> str:
        return "DELETE_FIELD"


#: Removes the field it is assigned to, in `update` or a merging `set`.
DELETE_FIELD = _DeleteField()


class ArrayUnion:
    """Appends each value not already present in the array field."""

    def __init__(self, values: list) -> None:
        self.values = list(values)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, ArrayUnion) and other.values == self.values

    def __repr__(self) -> str:
        return f"ArrayUnion({self.values!r})"


class Increment:
    """Adds `value` to the numeric field, treating a missing field as zero."""

    def __init__(self, value: "int | float") -> None:
        self.value = value

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Increment) and other.value == self.value

    def __repr__(self) -> str:
        return f"Increment({self.value!r})"


@dataclass(frozen=True)
class FieldFilter:
    """One field compared to one value. Only equality is supported."""

    field_path: str
    op_string: str
    value: Any

    def __post_init__(self) -> None:
        if self.op_string != "==":
            raise ValueError(f"unsupported filter operator: {self.op_string!r}")


ASCENDING = "ASCENDING"
DESCENDING = "DESCENDING"


@dataclass(frozen=True)
class Aggregation:
    value: int


@dataclass(frozen=True)
class Snapshot:
    """One document as read. `to_dict()` is None when it does not exist."""

    id: Optional[str]
    exists: bool
    data: Optional[dict]
    update_time: Any = None

    def to_dict(self) -> Optional[dict]:
        return dict(self.data) if self.data is not None else None


class DocumentRef(Protocol):
    def get(self) -> Snapshot: ...
    def create(self, data: dict) -> None: ...
    def set(self, data: dict, merge: bool = False) -> None: ...
    def update(self, data: dict) -> None: ...
    def delete(self) -> None: ...


class Query(Protocol):
    def where(self, *, filter: FieldFilter) -> "Query": ...
    def order_by(self, field: str, direction: str = ASCENDING) -> "Query": ...
    def limit(self, n: int) -> "Query": ...
    def stream(self) -> Iterator[Snapshot]: ...
    def count(self) -> Any: ...


class CollectionRef(Query, Protocol):
    def document(self, doc_id: str) -> DocumentRef: ...


class WriteBatch(Protocol):
    """Every write is applied at `commit()`, all of them or none."""

    def create(self, ref: DocumentRef, data: dict) -> None: ...
    def set(self, ref: DocumentRef, data: dict, merge: bool = False) -> None: ...
    def update(self, ref: DocumentRef, data: dict) -> None: ...
    def delete(self, ref: DocumentRef) -> None: ...
    def commit(self) -> None: ...


class DocStore(Protocol):
    def collection(self, name: str) -> CollectionRef: ...
    def batch(self) -> WriteBatch: ...


class DocStoreBase:
    """Marker base for neutral stores. `as_docstore` passes these through."""


def as_docstore(client: Any) -> DocStore:
    """The neutral store for `client`: itself if already neutral, else wrapped."""
    if isinstance(client, DocStoreBase):
        return client
    return FirestoreDocStore(client)


def firestore_client(**kwargs: Any) -> Any:
    """A raw `firestore.Client(**kwargs)`, imported only when one is built."""
    from google.cloud import firestore

    return firestore.Client(**kwargs)


# --- the Firestore adapter -------------------------------------------------


class FirestoreDocStore(DocStoreBase):
    """A `firestore.Client` (or a stand-in for one) behind the neutral API."""

    def __init__(self, client: Any) -> None:
        from google.api_core import exceptions
        from google.cloud import firestore
        from google.cloud.firestore_v1.base_query import FieldFilter as _FsFilter

        self._client = client
        self._fs = firestore
        self._fs_filter = _FsFilter
        self._errors = (
            (exceptions.AlreadyExists, AlreadyExists),
            (exceptions.FailedPrecondition, FailedPrecondition),
            (exceptions.NotFound, NotFound),
        )

    def collection(self, name: str) -> "_FsQuery":
        return _FsQuery(self, self._client.collection(name))

    def batch(self) -> "_FsBatch":
        return _FsBatch(self, self._client.batch())

    @contextmanager
    def _translated(self) -> Iterator[None]:
        try:
            yield
        except Exception as exc:
            for google_type, neutral in self._errors:
                if isinstance(exc, google_type):
                    raise neutral(str(exc)) from exc
            raise

    def _out(self, data: Any) -> Any:
        """Neutral transforms to Firestore's. Unchanged data is passed as is."""
        if data is DELETE_FIELD:
            return self._fs.DELETE_FIELD
        if isinstance(data, ArrayUnion):
            return self._fs.ArrayUnion(list(data.values))
        if isinstance(data, Increment):
            return self._fs.Increment(data.value)
        if isinstance(data, dict):
            out = {k: self._out(v) for k, v in data.items()}
            return data if all(out[k] is data[k] for k in data) else out
        return data

    def _snapshot(self, raw: Any, doc_id: Optional[str] = None) -> Snapshot:
        data = raw.to_dict()
        return Snapshot(
            getattr(raw, "id", doc_id),
            bool(getattr(raw, "exists", data is not None)),
            data,
            getattr(raw, "update_time", None),
        )


class _FsDocument:
    def __init__(self, store: FirestoreDocStore, raw: Any, doc_id: str) -> None:
        self._store, self._raw, self.id = store, raw, doc_id

    def get(self) -> Snapshot:
        with self._store._translated():
            raw = self._raw.get()
        return self._store._snapshot(raw, self.id)

    def create(self, data: dict) -> None:
        with self._store._translated():
            self._raw.create(self._store._out(data))

    def set(self, data: dict, merge: bool = False) -> None:
        with self._store._translated():
            if merge:
                self._raw.set(self._store._out(data), merge=True)
            else:
                self._raw.set(self._store._out(data))

    def update(self, data: dict) -> None:
        with self._store._translated():
            self._raw.update(self._store._out(data))

    def delete(self) -> None:
        with self._store._translated():
            self._raw.delete()


class _FsQuery:
    def __init__(self, store: FirestoreDocStore, raw: Any) -> None:
        self._store, self._raw = store, raw

    def document(self, doc_id: str) -> _FsDocument:
        return _FsDocument(self._store, self._raw.document(doc_id), doc_id)

    def where(self, *, filter: FieldFilter) -> "_FsQuery":
        translated = self._store._fs_filter(filter.field_path, filter.op_string,
                                            filter.value)
        return _FsQuery(self._store, self._raw.where(filter=translated))

    def order_by(self, field: str, direction: str = ASCENDING) -> "_FsQuery":
        return _FsQuery(self._store, self._raw.order_by(field, direction=direction))

    def limit(self, n: int) -> "_FsQuery":
        return _FsQuery(self._store, self._raw.limit(n))

    def stream(self) -> Iterator[Snapshot]:
        with self._store._translated():
            for raw in self._raw.stream():
                yield self._store._snapshot(raw)

    def count(self) -> "_FsCount":
        return _FsCount(self._store, self._raw.count())


class _FsCount:
    def __init__(self, store: FirestoreDocStore, raw: Any) -> None:
        self._store, self._raw = store, raw

    def get(self) -> list:
        with self._store._translated():
            rows = self._raw.get()
        return [[Aggregation(int(result.value)) for result in row] for row in rows]


class _FsBatch:
    def __init__(self, store: FirestoreDocStore, raw: Any) -> None:
        self._store, self._raw = store, raw

    @staticmethod
    def _ref(ref: Any) -> Any:
        if not isinstance(ref, _FsDocument):
            raise TypeError("a batch takes references from the same store")
        return ref._raw

    def create(self, ref: _FsDocument, data: dict) -> None:
        self._raw.create(self._ref(ref), self._store._out(data))

    def set(self, ref: _FsDocument, data: dict, merge: bool = False) -> None:
        if merge:
            self._raw.set(self._ref(ref), self._store._out(data), merge=True)
        else:
            self._raw.set(self._ref(ref), self._store._out(data))

    def update(self, ref: _FsDocument, data: dict) -> None:
        self._raw.update(self._ref(ref), self._store._out(data))

    def delete(self, ref: _FsDocument) -> None:
        self._raw.delete(self._ref(ref))

    def commit(self) -> None:
        with self._store._translated():
            self._raw.commit()
