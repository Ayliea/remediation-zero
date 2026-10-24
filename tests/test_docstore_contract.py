# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""One behavioural contract, run against both document stores.

The writers in `tools/` were written against Firestore. The local edition runs
the same writers on `SQLiteDocStore`, so every Firestore behaviour a writer
relies on is pinned here and run against both implementations. The Firestore
half runs only against a real emulator (`FIRESTORE_EMULATOR_HOST`); it is never
faked, and it is skipped with a stated reason when no emulator is configured.
"""

import os
import sqlite3
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from tools.docstore import (
    DELETE_FIELD,
    DESCENDING,
    AlreadyExists,
    ArrayUnion,
    FieldFilter,
    Increment,
    NotFound,
    as_docstore,
)

ROOT = Path(__file__).resolve().parents[1]
COLLECTIONS = ("alpha", "beta")
SKIP_REASON = "FIRESTORE_EMULATOR_HOST not set: Firestore contract not run"


def _files(tmp_path: Path) -> dict:
    # alpha and beta live in different files, so a batch spanning them proves
    # atomicity across attached databases rather than within one file.
    return {"alpha": tmp_path / "alpha.sqlite3", "beta": tmp_path / "beta.sqlite3"}


@pytest.fixture(params=["sqlite", "firestore-emulator"])
def docstore(request, tmp_path):
    if request.param == "sqlite":
        from tools.sqlite_docstore import SQLiteDocStore

        store = SQLiteDocStore(_files(tmp_path))
        yield store
        store.close()
        return
    if not os.environ.get("FIRESTORE_EMULATOR_HOST"):
        pytest.skip(SKIP_REASON)
    from google.cloud import firestore

    from tools.docstore import FirestoreDocStore

    client = firestore.Client(project="rz-contract")
    for name in COLLECTIONS:
        for doc in client.collection(name).stream():
            doc.reference.delete()
    yield FirestoreDocStore(client)
    client.close()


def _get(store, collection, doc_id):
    return store.collection(collection).document(doc_id).get().to_dict()


# --- the brief's contract --------------------------------------------------


def test_create_then_create_raises_already_exists(docstore):
    ref = docstore.collection("alpha").document("d1")
    ref.create({"n": 1})
    with pytest.raises(AlreadyExists):
        ref.create({"n": 2})
    assert _get(docstore, "alpha", "d1") == {"n": 1}


def test_set_merge_keeps_other_fields(docstore):
    ref = docstore.collection("alpha").document("d1")
    ref.set({"a": 1, "b": 2})
    ref.set({"b": 3, "c": 4}, merge=True)
    assert _get(docstore, "alpha", "d1") == {"a": 1, "b": 3, "c": 4}


def test_update_missing_raises_not_found(docstore):
    with pytest.raises(NotFound):
        docstore.collection("alpha").document("missing").update({"a": 1})
    assert docstore.collection("alpha").document("missing").get().exists is False


def test_array_union_dedupes_and_appends(docstore):
    ref = docstore.collection("alpha").document("d1")
    ref.set({"tags": ["a", "b"]})
    ref.update({"tags": ArrayUnion(["b", "c", "c"])})
    assert _get(docstore, "alpha", "d1") == {"tags": ["a", "b", "c"]}


def test_increment_from_missing_field(docstore):
    ref = docstore.collection("alpha").document("d1")
    ref.set({"other": True})
    ref.update({"count": Increment(1)})
    ref.update({"count": Increment(2)})
    assert _get(docstore, "alpha", "d1") == {"other": True, "count": 3}
    fresh = docstore.collection("alpha").document("d2")
    fresh.set({"count": Increment(5)}, merge=True)
    assert _get(docstore, "alpha", "d2") == {"count": 5}


def test_delete_field_removes_key(docstore):
    ref = docstore.collection("alpha").document("d1")
    ref.set({"a": 1, "b": 2})
    ref.update({"a": DELETE_FIELD})
    assert _get(docstore, "alpha", "d1") == {"b": 2}


def test_where_equals_order_desc_limit(docstore):
    alpha = docstore.collection("alpha")
    for doc_id, kind, n in [("d1", "x", 1), ("d2", "x", 3), ("d3", "y", 9),
                            ("d4", "x", 2), ("d5", "x", 5)]:
        alpha.document(doc_id).set({"kind": kind, "n": n})
    alpha.document("d6").set({"n": 100})  # no `kind`: never matches
    rows = list(alpha.where(filter=FieldFilter("kind", "==", "x"))
                .order_by("n", direction=DESCENDING).limit(3).stream())
    assert [r.id for r in rows] == ["d5", "d2", "d4"]
    assert [r.to_dict()["n"] for r in rows] == [5, 3, 2]
    assert all(r.exists for r in rows)


def test_count_shape(docstore):
    alpha = docstore.collection("alpha")
    assert alpha.count().get()[0][0].value == 0
    for i, kind in enumerate(["x", "x", "y"]):
        alpha.document(f"d{i}").set({"kind": kind})
    assert alpha.count().get()[0][0].value == 3
    query = alpha.where(filter=FieldFilter("kind", "==", "x"))
    assert query.count().get()[0][0].value == 2


def test_batch_is_atomic_across_collections(docstore, request):
    docstore.collection("beta").document("taken").create({"v": "original"})
    batch = docstore.batch()
    batch.create(docstore.collection("alpha").document("new"), {"v": 1})
    batch.create(docstore.collection("beta").document("taken"), {"v": 2})
    with pytest.raises(AlreadyExists):
        batch.commit()
    assert docstore.collection("alpha").document("new").get().exists is False
    assert _get(docstore, "beta", "taken") == {"v": "original"}

    if "sqlite" in request.node.callspec.id:
        files = docstore.files
        assert files["alpha"].resolve() != files["beta"].resolve()
        with sqlite3.connect(files["beta"]) as raw:
            assert raw.execute("SELECT collection, id FROM docs").fetchall() == [
                ("beta", "taken")]
        raw.close()
        with sqlite3.connect(files["alpha"]) as raw:
            assert raw.execute("SELECT count(*) FROM docs").fetchone() == (0,)
        raw.close()


# --- Firestore behaviours the writers rely on (ruling 15) -------------------

NESTED = {"delivery": {"marker": "m1", "state": "pending"}, "x": 1}


def test_set_merge_deep_merges_nested_maps(docstore):
    ref = docstore.collection("alpha").document("t1")
    ref.set(NESTED)
    ref.set({"delivery": {"state": "sent"}}, merge=True)
    assert _get(docstore, "alpha", "t1") == {
        "delivery": {"marker": "m1", "state": "sent"}, "x": 1}


def test_update_replaces_nested_map(docstore):
    ref = docstore.collection("alpha").document("t1")
    ref.set(NESTED)
    ref.update({"delivery": {"state": "sent"}})
    assert _get(docstore, "alpha", "t1") == {"delivery": {"state": "sent"}, "x": 1}


def test_delete_field_inside_set_merge(docstore):
    ref = docstore.collection("alpha").document("t1")
    ref.set({"a": 1, "m": {"k": 1, "j": 2}})
    ref.set({"a": DELETE_FIELD, "b": 2}, merge=True)
    assert _get(docstore, "alpha", "t1") == {"b": 2, "m": {"k": 1, "j": 2}}
    ref.set({"m": {"k": DELETE_FIELD}}, merge=True)
    assert _get(docstore, "alpha", "t1") == {"b": 2, "m": {"j": 2}}


def test_batch_applies_writes_in_order_same_doc(docstore):
    ref = docstore.collection("alpha").document("t1")
    entry = {"action": "open_ticket", "cycle": 1}
    batch = docstore.batch()
    batch.set(ref, {"status": "open", "resolved_cycle": DELETE_FIELD}, merge=True)
    batch.update(ref, {"history": ArrayUnion([entry])})
    batch.commit()
    assert _get(docstore, "alpha", "t1") == {"status": "open", "history": [entry]}


def test_array_union_dedupes_dicts_by_value(docstore):
    ref = docstore.collection("alpha").document("t1")
    ref.set({"history": [{"a": 1}]})
    ref.update({"history": ArrayUnion([{"a": 1}])})
    assert _get(docstore, "alpha", "t1") == {"history": [{"a": 1}]}
    ref.update({"history": ArrayUnion([{"a": 2}])})
    assert _get(docstore, "alpha", "t1") == {"history": [{"a": 1}, {"a": 2}]}
    ref.update({"fresh": ArrayUnion([{"a": 1}])})
    assert _get(docstore, "alpha", "t1")["fresh"] == [{"a": 1}]


def test_order_by_excludes_missing_field(docstore):
    alpha = docstore.collection("alpha")
    alpha.document("d1").set({"n": 2})
    alpha.document("d2").set({"other": 1})
    alpha.document("d3").set({"n": 1})
    assert [r.id for r in alpha.order_by("n").stream()] == ["d3", "d1"]


# --- further Firestore semantics mirrored in SQLite -------------------------


def test_get_missing_returns_nonexistent_snapshot(docstore):
    snap = docstore.collection("alpha").document("nope").get()
    assert snap.exists is False
    assert snap.to_dict() is None
    assert snap.id == "nope"


def test_set_without_merge_replaces(docstore):
    ref = docstore.collection("alpha").document("d1")
    ref.set({"a": 1, "b": 2})
    ref.set({"c": 3})
    assert _get(docstore, "alpha", "d1") == {"c": 3}


def test_set_merge_on_missing_creates(docstore):
    docstore.collection("alpha").document("d1").set({"a": 1}, merge=True)
    assert _get(docstore, "alpha", "d1") == {"a": 1}


def test_delete_field_in_plain_set_is_an_error(docstore):
    ref = docstore.collection("alpha").document("d1")
    with pytest.raises(ValueError):
        ref.set({"a": DELETE_FIELD})
    assert ref.get().exists is False


def test_update_missing_in_batch_rolls_back_whole_batch(docstore):
    batch = docstore.batch()
    batch.create(docstore.collection("alpha").document("first"), {"v": 1})
    batch.update(docstore.collection("beta").document("missing"), {"v": 2})
    with pytest.raises(NotFound):
        batch.commit()
    assert docstore.collection("alpha").document("first").get().exists is False


def test_where_equality_ignores_missing_and_distinguishes_types(docstore):
    alpha = docstore.collection("alpha")
    alpha.document("d1").set({"f": 1})
    alpha.document("d2").set({"f": True})
    alpha.document("d3").set({"g": 1})
    alpha.document("d4").set({"f": {"k": [1, 2]}})
    one = alpha.where(filter=FieldFilter("f", "==", 1)).stream()
    assert [r.id for r in one] == ["d1"]
    nested = alpha.where(filter=FieldFilter("f", "==", {"k": [1, 2]})).stream()
    assert [r.id for r in nested] == ["d4"]


def test_delete_removes_document(docstore):
    ref = docstore.collection("alpha").document("d1")
    ref.set({"a": 1})
    ref.delete()
    assert ref.get().exists is False
    ref.delete()  # deleting a missing document is not an error


def test_snapshot_to_dict_is_a_copy(docstore):
    ref = docstore.collection("alpha").document("d1")
    ref.set({"a": 1})
    snap = ref.get()
    snap.to_dict()["a"] = 2
    assert snap.to_dict() == {"a": 1}


def test_update_time_changes_on_every_write(docstore):
    ref = docstore.collection("alpha").document("d1")
    ref.create({"a": 1})
    seen = [ref.get().update_time]
    ref.update({"a": 2})
    seen.append(ref.get().update_time)
    ref.set({"b": 3}, merge=True)
    seen.append(ref.get().update_time)
    assert None not in seen
    assert len(set(seen)) == 3
    assert docstore.collection("alpha").document("none").get().update_time is None


# --- SQLite only -------------------------------------------------------------


def test_sqlite_store_is_neutral(tmp_path):
    from tools.sqlite_docstore import SQLiteDocStore

    store = SQLiteDocStore(_files(tmp_path))
    try:
        assert as_docstore(store) is store
    finally:
        store.close()


def test_revision_increments_and_is_not_a_clock(tmp_path):
    """SQLite's update_time is a per-document revision (Ruling 16), not a time."""
    from tools.sqlite_docstore import SQLiteDocStore

    files = _files(tmp_path)
    store = SQLiteDocStore(files)
    try:
        ref = store.collection("alpha").document("d1")
        ref.create({"a": 1})
        assert ref.get().update_time == 1
        ref.update({"a": 2})
        assert ref.get().update_time == 2
        ref.set({"b": 3}, merge=True)
        revision = ref.get().update_time
        assert revision == 3 and type(revision) is int
        assert [r.update_time for r in store.collection("alpha").stream()] == [3]
        ref.delete()
        ref.set({"c": 1})  # a set that creates starts again at 1
        assert ref.get().update_time == 1
    finally:
        store.close()
    with sqlite3.connect(files["alpha"]) as raw:
        columns = [(row[1], row[2]) for row in raw.execute("PRAGMA table_info(docs)")]
    raw.close()
    assert columns == [("collection", "TEXT"), ("id", "TEXT"), ("data", "TEXT"),
                       ("revision", "INTEGER")]


def test_sqlite_concurrent_batches_one_wins(tmp_path):
    """Two stores, two threads, same files: one create wins, neither is locked."""
    from tools.sqlite_docstore import SQLiteDocStore

    files = _files(tmp_path)
    SQLiteDocStore(files).close()  # create both files and their tables first
    rounds = 20
    barrier = threading.Barrier(2)
    outcomes = {0: [], 1: []}

    def worker(slot: int) -> None:
        store = SQLiteDocStore(files)
        try:
            for i in range(rounds):
                barrier.wait()
                batch = store.batch()
                batch.create(store.collection("alpha").document(f"a{i}"), {"by": slot})
                batch.create(store.collection("beta").document(f"b{i}"), {"by": slot})
                try:
                    batch.commit()
                    outcomes[slot].append("won")
                except AlreadyExists:
                    outcomes[slot].append("already_exists")
                except Exception as exc:  # noqa: BLE001 - recorded for the assert
                    outcomes[slot].append(f"{type(exc).__name__}: {exc}")
        finally:
            store.close()

    threads = [threading.Thread(target=worker, args=(slot,)) for slot in (0, 1)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=120)
    assert not any(t.is_alive() for t in threads)

    for i in range(rounds):
        pair = sorted([outcomes[0][i], outcomes[1][i]])
        assert pair == ["already_exists", "won"], pair

    store = SQLiteDocStore(files)
    try:
        for i in range(rounds):
            a = _get(store, "alpha", f"a{i}")
            b = _get(store, "beta", f"b{i}")
            assert a == b  # the same winner wrote both halves
    finally:
        store.close()


def _read_only_store(tmp_path):
    from tools.sqlite_docstore import SQLiteDocStore

    files = _files(tmp_path)
    seed = SQLiteDocStore(files)
    seed.collection("beta").document("ref").set({"v": 1})
    seed.close()
    return SQLiteDocStore(files, writable=frozenset({"alpha"}))


def test_sqlite_read_only_collection_refuses_writes(tmp_path):
    store = _read_only_store(tmp_path)
    try:
        assert _get(store, "beta", "ref") == {"v": 1}
        message = "beta is read-only for this agent"
        ref = store.collection("beta").document("ref")
        for write in (lambda: ref.create({"v": 2}), lambda: ref.set({"v": 2}),
                      lambda: ref.set({"v": 2}, merge=True),
                      lambda: ref.update({"v": 2}), ref.delete):
            with pytest.raises(PermissionError) as caught:
                write()
            assert str(caught.value) == message
        batch = store.batch()
        with pytest.raises(PermissionError, match="^beta is read-only for this agent$"):
            batch.set(ref, {"v": 2})
        store.collection("alpha").document("ok").set({"v": 1})
        assert _get(store, "beta", "ref") == {"v": 1}
    finally:
        store.close()


def test_sqlite_read_only_file_is_refused_by_sqlite_too(tmp_path):
    store = _read_only_store(tmp_path)
    try:
        alias = store._alias_of("beta")
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            store._conn.execute(
                f"INSERT INTO {alias}.docs VALUES (?, ?, ?, ?)",
                ("beta", "x", "{}", 0.0))
    finally:
        store.close()


def test_sqlite_paths_with_uri_characters(tmp_path):
    from tools.sqlite_docstore import SQLiteDocStore

    odd = tmp_path / "we?ird#dir %20"
    odd.mkdir()
    files = {"alpha": odd / "a?b#c.sqlite3", "beta": odd / "b%3F.sqlite3"}
    store = SQLiteDocStore(files)
    store.collection("alpha").document("d").set({"v": 1})
    store.collection("beta").document("d").set({"v": 2})
    store.close()
    assert files["alpha"].exists() and files["beta"].exists()
    ro = SQLiteDocStore(files, writable=frozenset())
    try:
        assert _get(ro, "alpha", "d") == {"v": 1}
        assert _get(ro, "beta", "d") == {"v": 2}
    finally:
        ro.close()


def test_sqlite_missing_read_only_file_fails_clearly(tmp_path):
    from tools.sqlite_docstore import SQLiteDocStore

    with pytest.raises(FileNotFoundError, match="beta"):
        SQLiteDocStore(_files(tmp_path), writable=frozenset({"alpha"}))


def test_sqlite_unknown_collection_is_refused(tmp_path):
    from tools.sqlite_docstore import SQLiteDocStore

    store = SQLiteDocStore(_files(tmp_path))
    try:
        with pytest.raises(KeyError, match="gamma"):
            store.collection("gamma")
    finally:
        store.close()


def test_sqlite_ids_and_names_are_bound_not_interpolated(tmp_path):
    from tools.sqlite_docstore import SQLiteDocStore

    hostile = "x'); DROP TABLE docs; --"
    files = {hostile: tmp_path / "h.sqlite3"}
    store = SQLiteDocStore(files)
    try:
        store.collection(hostile).document(hostile).set({"v": 1})
        assert _get(store, hostile, hostile) == {"v": 1}
        assert [r.id for r in store.collection(hostile).stream()] == [hostile]
    finally:
        store.close()


def test_sqlite_shared_file_for_two_collections(tmp_path):
    from tools.sqlite_docstore import SQLiteDocStore

    shared = tmp_path / "shared.sqlite3"
    store = SQLiteDocStore({"alpha": shared, "beta": shared})
    try:
        store.collection("alpha").document("d").set({"v": "a"})
        store.collection("beta").document("d").set({"v": "b"})
        assert [r.to_dict() for r in store.collection("alpha").stream()] == [{"v": "a"}]
        assert [r.to_dict() for r in store.collection("beta").stream()] == [{"v": "b"}]
    finally:
        store.close()


def test_sqlite_docstore_is_stdlib_only():
    subprocess.run([sys.executable, "-S", "-c", "import tools.sqlite_docstore"],
                   cwd=ROOT, check=True)
