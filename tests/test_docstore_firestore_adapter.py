# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""The neutral document-store API and its Firestore adapter.

The writers speak only the neutral names in `tools.docstore`. In the cloud
edition `FirestoreDocStore` turns those names into Firestore's own, and turns
Firestore's exceptions back into neutral ones. If either translation were
missing, a writer would store a neutral sentinel as data, or would fail to
catch an `AlreadyExists` it relies on for idempotency.
"""

import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from google.api_core import exceptions as gexc
from google.cloud import firestore
from google.cloud.firestore_v1.base_query import FieldFilter as FsFieldFilter

from tools import docstore
from tools.docstore import (
    DELETE_FIELD,
    AlreadyExists,
    ArrayUnion,
    DocStoreBase,
    FailedPrecondition,
    FieldFilter,
    FirestoreDocStore,
    Increment,
    NotFound,
    Snapshot,
    as_docstore,
)

ROOT = Path(__file__).resolve().parents[1]

WRITERS = ["decisions", "assignments", "tickets", "exception_store",
           "scan_store", "reports", "finding_lookup", "delivery"]


@pytest.mark.parametrize("module", ["docstore", *WRITERS])
def test_writers_import_without_google(module):
    """With site-packages off, `google` is not importable at all, so this
    proves no module-level `google.*` import remains."""
    result = subprocess.run(
        [sys.executable, "-S", "-c", f"import tools.{module}"],
        cwd=ROOT, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr


def test_write_summary_imports_without_google():
    result = subprocess.run(
        [sys.executable, "-S", "-c", "from tools.reports import write_summary"],
        cwd=ROOT, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr


# --- a recording stand-in for firestore.Client ------------------------------

class _RawDoc:
    def __init__(self, client, path):
        self.client, self.path, self.id = client, path, path[1]

    def get(self):
        data = self.client.docs.get(self.path)
        return SimpleNamespace(id=self.id, exists=data is not None,
                               to_dict=lambda: data, update_time="t1")

    def _run(self, op, *args, **kwargs):
        self.client.calls.append((op, self.path, args, kwargs))
        if self.client.raise_on.get(op):
            raise self.client.raise_on[op]

    def create(self, data):
        self._run("create", data)

    def set(self, data, merge=False):
        self._run("set", data, merge=merge)

    def update(self, data):
        self._run("update", data)

    def delete(self):
        self._run("delete")


class _RawQuery:
    def __init__(self, client, name, ops=()):
        self.client, self.name, self.ops = client, name, ops

    def document(self, doc_id):
        return _RawDoc(self.client, (self.name, doc_id))

    def where(self, filter=None):
        return _RawQuery(self.client, self.name, self.ops + (("where", filter),))

    def order_by(self, field, direction=None):
        return _RawQuery(self.client, self.name,
                         self.ops + (("order_by", field, direction),))

    def limit(self, n):
        return _RawQuery(self.client, self.name, self.ops + (("limit", n),))

    def stream(self):
        self.client.queries.append(self.ops)
        for (name, doc_id), data in self.client.docs.items():
            if name == self.name:
                yield SimpleNamespace(id=doc_id, exists=True, to_dict=lambda d=data: d)

    def count(self):
        return SimpleNamespace(get=lambda: [[SimpleNamespace(value=2)]])


class _RawBatch:
    def __init__(self, client):
        self.client = client

    def create(self, ref, data):
        self.client.calls.append(("batch.create", ref.path, (data,), {}))

    def set(self, ref, data, merge=False):
        self.client.calls.append(("batch.set", ref.path, (data,), {"merge": merge}))

    def update(self, ref, data):
        self.client.calls.append(("batch.update", ref.path, (data,), {}))

    def delete(self, ref):
        self.client.calls.append(("batch.delete", ref.path, (), {}))

    def commit(self):
        if self.client.raise_on.get("commit"):
            raise self.client.raise_on["commit"]


class _RawClient:
    def __init__(self):
        self.docs, self.calls, self.queries, self.raise_on = {}, [], [], {}

    def collection(self, name):
        return _RawQuery(self, name)

    def batch(self):
        return _RawBatch(self)


def test_adapter_translates_array_union_increment_delete_field():
    raw = _RawClient()
    db = FirestoreDocStore(raw)
    ref = db.collection("tickets").document("RZ-1")

    ref.update({"history": ArrayUnion([{"a": 1}]), "nudges_sent": Increment(1),
                "plain": 3})
    batch = db.batch()
    batch.set(ref, {"resolved_cycle": DELETE_FIELD, "nested": {"gone": DELETE_FIELD}},
              merge=True)
    batch.update(ref, {"history": ArrayUnion([2])})
    batch.commit()

    (_, _, (update,), _), (_, _, (setdata,), setkw), (_, _, (bupdate,), _) = raw.calls
    assert isinstance(update["history"], firestore.ArrayUnion)
    assert update["history"].values == [{"a": 1}]
    assert isinstance(update["nudges_sent"], firestore.Increment)
    assert update["plain"] == 3
    assert setdata["resolved_cycle"] is firestore.DELETE_FIELD
    assert setdata["nested"]["gone"] is firestore.DELETE_FIELD
    assert setkw == {"merge": True}
    assert isinstance(bupdate["history"], firestore.ArrayUnion)

    # Filters are translated too, and results come back neutral.
    raw.docs[("decisions", "RZ-1-c001")] = {"finding_id": "RZ-1"}
    rows = list(db.collection("decisions")
                .where(filter=FieldFilter("finding_id", "==", "RZ-1"))
                .order_by("cycle", direction=docstore.DESCENDING)
                .limit(10).stream())
    (where, order, limit), = raw.queries
    assert isinstance(where[1], FsFieldFilter)
    assert (where[1].field_path, where[1].op_string, where[1].value) == (
        "finding_id", "==", "RZ-1")
    assert order == ("order_by", "cycle", "DESCENDING") and limit == ("limit", 10)
    assert rows == [Snapshot("RZ-1-c001", True, {"finding_id": "RZ-1"}, None)]
    assert rows[0].to_dict() == {"finding_id": "RZ-1"}
    assert db.collection("decisions").count().get()[0][0].value == 2

    snap = db.collection("decisions").document("RZ-1-c001").get()
    assert (snap.id, snap.exists, snap.update_time) == ("RZ-1-c001", True, "t1")
    assert db.collection("decisions").document("nope").get().exists is False


def test_adapter_translates_already_exists():
    raw = _RawClient()
    db = FirestoreDocStore(raw)
    ref = db.collection("decisions").document("RZ-1-c001")

    raw.raise_on["create"] = gexc.AlreadyExists("exists")
    with pytest.raises(AlreadyExists):
        ref.create({"x": 1})

    raw.raise_on["commit"] = gexc.AlreadyExists("exists")
    batch = db.batch()
    batch.create(ref, {"x": 1})
    with pytest.raises(AlreadyExists):
        batch.commit()

    raw.raise_on["update"] = gexc.NotFound("missing")
    with pytest.raises(NotFound):
        ref.update({"x": 2})
    raw.raise_on["set"] = gexc.FailedPrecondition("precondition")
    with pytest.raises(FailedPrecondition):
        ref.set({"x": 3})
    raw.raise_on["commit"] = gexc.FailedPrecondition("precondition")
    with pytest.raises(FailedPrecondition):
        db.batch().commit()

    # Anything else is not ours to rename.
    raw.raise_on["delete"] = gexc.PermissionDenied("no")
    with pytest.raises(gexc.PermissionDenied):
        ref.delete()


def test_as_docstore_wraps_raw_and_passes_neutral():
    raw = _RawClient()
    wrapped = as_docstore(raw)
    assert isinstance(wrapped, FirestoreDocStore)

    class Neutral(DocStoreBase):
        pass

    neutral = Neutral()
    assert as_docstore(neutral) is neutral
    assert as_docstore(wrapped) is wrapped


# --- the idempotency risk Ruling 14 names -----------------------------------

class _DecisionDoc:
    def __init__(self, client, key):
        self.client, self._key = client, key

    def get(self):
        data = self.client.docs.get(self._key)
        return SimpleNamespace(exists=data is not None, to_dict=lambda: data)

    def create(self, data):
        if self._key in self.client.docs:
            raise gexc.AlreadyExists("exists")
        self.client.docs[self._key] = dict(data)


class _DecisionBatch:
    """commit() loses a race: a concurrent writer's decision lands first."""

    def __init__(self, client):
        self.client = client

    def create(self, ref, data):
        self.ref, self.data = ref, data

    def commit(self):
        if self.client.racer is not None:
            self.client.docs[self.ref._key] = self.client.racer
        raise gexc.AlreadyExists("exists")


class _DecisionClient:
    def __init__(self, racer):
        self.docs, self.racer = {}, racer

    def collection(self, name):
        return SimpleNamespace(document=lambda doc_id: _DecisionDoc(self, (name, doc_id)))

    def batch(self):
        return _DecisionBatch(self)


def test_writer_with_raw_client_catches_firestore_already_exists():
    """The scripts pass a raw `firestore.Client`. Firestore's own
    AlreadyExists from commit() must still reach the writer's reconcile path:
    if it escaped uncaught, a resumed cycle would crash instead of keeping the
    first durable decision."""
    from tools.adjudication import Adjudication, AdjudicationOutcome, Proposal, Verdict
    from tools.clock import ClockMode, SimClock
    from tools.decisions import DecisionWriter, to_decision_document
    from tools.idempotency import InMemoryIdempotencyStore

    clock = SimClock(mode=ClockMode.REAL)
    proposal = Proposal("RZ-1", "high", 7, "Apply the vendor patch.",
                        ("in CISA KEV",), "Exploited in the wild.")
    adj = Adjudication("RZ-1", AdjudicationOutcome.RATIFIED, proposal,
                       (Verdict(ratified=True, reason="Matches."),), 1, "")

    # The racer's decision is found: the writer keeps it and returns its id.
    winner = to_decision_document(adj, clock, 1)
    writer = DecisionWriter(store=InMemoryIdempotencyStore(),
                            client=_DecisionClient(racer=winner), clock=clock)
    assert writer.record(adj, cycle=1) == "RZ-1-c001"

    # No decision behind the conflict: the existing reconciliation error, not
    # Firestore's exception, is what surfaces.
    writer = DecisionWriter(store=InMemoryIdempotencyStore(),
                            client=_DecisionClient(racer=None), clock=clock)
    with pytest.raises(RuntimeError, match="manual reconciliation required"):
        writer.record(adj, cycle=1)
