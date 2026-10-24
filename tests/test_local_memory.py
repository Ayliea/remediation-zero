# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
import json
import logging

from tools.local_memory import LocalMemory
from tools.sqlite_docstore import SQLiteDocStore


def _store(tmp_path):
    return SQLiteDocStore({"memories": tmp_path / "memories.sqlite3"})


def test_local_memory_recall_matches_terms_most_recent_first(tmp_path):
    mem = LocalMemory(_store(tmp_path))
    assert mem.remember_cycle("cycle-001", {"ratified": 3}, 100.0, 1000.0)
    assert mem.remember_cycle("cycle-002", {"ratified": 4}, 200.0, 3000.0)
    assert mem.remember_cycle("cycle-003", {"nudge": 2}, 300.0, 2000.0)
    got = mem.recall("RATIFIED findings")
    assert len(got) == 2 and "cycle-002" in got[0] and "cycle-001" in got[1]
    assert len(mem.recall("an of")) == 3  # no term of length >= 3: all match
    assert len(mem.recall("")) == 3
    assert mem.recall("zzzunmatched") == []


def test_recall_caps_at_five(tmp_path):
    mem = LocalMemory(_store(tmp_path))
    for i in range(7):
        mem.remember_cycle(f"cycle-{i:03d}", {"ratified": i}, float(i), float(i))
    assert len(mem.recall("")) == 5


def test_remember_same_cycle_overwrites(tmp_path):
    store = _store(tmp_path)
    mem = LocalMemory(store)
    mem.remember_cycle("cycle-001", {"ratified": 1}, 1.0, 2.0)
    mem.remember_cycle("cycle-001", {"ratified": 9}, 1.0, 2.0)
    assert len(list(store.collection("memories").stream())) == 1


def test_records_carry_both_clocks(tmp_path):
    store = _store(tmp_path)
    LocalMemory(store).remember_cycle("cycle-001", {"ratified": 1}, 123.5, 987654.25)
    doc = store.collection("memories").document("cycle-001").get().to_dict()
    assert doc["real_ts"] == 123.5 and doc["sim_ts"] == 987654.25
    assert doc["cycle_id"] == "cycle-001" and doc["counts"] == {"ratified": 1}
    assert "cycle-001" in doc["text"]


class _Broken:
    def collection(self, name):
        raise OSError("secret path /x/y")


def test_local_memory_never_raises_on_store_failure(caplog):
    mem = LocalMemory(_Broken())
    with caplog.at_level(logging.WARNING):
        assert mem.remember_cycle("cycle-001", {}, 1.0, 2.0) is False
        assert mem.recall("anything") == []
    events = [json.loads(r.getMessage()) for r in caplog.records]
    assert {e["event"] for e in events} == {"memory_write_failed", "memory_recall_failed"}
    assert all(e["error"] == "OSError" and e["cycle_id"] for e in events)
    assert "secret" not in caplog.text
