# Copyright 2026 Daviyon Daniels
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Seeding the reference collections, in batches.

Firestore caps a batch, so this commits in chunks. The failure mode of chunked
writing is the quiet one: an off-by-one leaves the last partial batch
uncommitted and the corpus is short by up to BATCH_LIMIT records, with no
error anywhere. Nothing downstream would report it either -- the fleet would
simply never see those findings.
"""

import json

import pytest

import scripts.ingest as ingest_module
from scripts.ingest import BATCH_LIMIT, main


class FakeBatch:
    def __init__(self, committed):
        self._committed = committed
        self.staged = []

    def set(self, ref, document):
        self.staged.append((ref, document))

    def commit(self):
        self._committed.extend(self.staged)
        self.staged = []


class FakeCollection:
    def __init__(self, name):
        self.name = name

    def document(self, doc_id):
        return (self.name, doc_id)


class FakeClient:
    def __init__(self):
        self.committed = []
        self.batches = 0

    def collection(self, name):
        return FakeCollection(name)

    def batch(self):
        self.batches += 1
        return FakeBatch(self.committed)


@pytest.fixture
def seeded(monkeypatch, tmp_path):
    """Run ingest against a corpus of a chosen size."""
    def go(counts):
        for kind, n in counts.items():
            records = []
            for i in range(n):
                key = {"findings": "finding_id", "assets": "asset_id",
                       "owners": "owner_id"}[kind]
                records.append({key: f"{kind[:3]}-{i:05d}", "status": "open"})
            (tmp_path / f"{kind}.json").write_text(json.dumps(records))

        client = FakeClient()
        monkeypatch.setattr(ingest_module, "DATA_DIR", tmp_path)
        monkeypatch.setattr(ingest_module.firestore, "Client",
                            lambda *a, **k: client)
        monkeypatch.setattr(ingest_module, "REFERENCE_COLLECTIONS",
                            tuple(counts))
        assert main() == 0
        return client
    return go


def test_every_record_is_committed(seeded):
    client = seeded({"findings": 7, "assets": 3, "owners": 2})
    assert len(client.committed) == 12


def test_a_partial_final_batch_is_not_left_uncommitted(seeded):
    """One more than a whole batch. The remainder is the record most likely to
    be silently dropped, and nothing downstream would ever report its absence."""
    client = seeded({"findings": BATCH_LIMIT + 1})
    assert len(client.committed) == BATCH_LIMIT + 1


def test_an_exact_multiple_does_not_commit_an_empty_batch(seeded):
    """The other side of the same off-by-one."""
    client = seeded({"findings": BATCH_LIMIT})
    assert len(client.committed) == BATCH_LIMIT


def test_a_corpus_larger_than_one_batch_is_chunked(seeded):
    client = seeded({"findings": BATCH_LIMIT * 2 + 5})
    assert len(client.committed) == BATCH_LIMIT * 2 + 5
    assert client.batches >= 3


def test_the_batch_limit_stays_under_the_firestore_cap():
    """Firestore rejects a batch over 500 writes outright."""
    assert 0 < BATCH_LIMIT <= 500


def test_the_natural_key_becomes_the_document_id(seeded):
    """Which is what makes re-ingest overwrite rather than duplicate."""
    client = seeded({"findings": 3})
    ids = [ref[1] for ref, _ in client.committed]
    assert ids == ["fin-00000", "fin-00001", "fin-00002"]


def test_the_document_id_is_not_left_inside_the_document(seeded):
    """_document_id is how ingest carries the key out; storing it as a field
    would put a redundant copy in every record."""
    client = seeded({"findings": 2})
    assert all("_document_id" not in doc for _, doc in client.committed)


def test_re_ingesting_writes_the_same_ids(seeded):
    """Overwrite in place, never a second copy alongside."""
    first = seeded({"findings": 4})
    second = seeded({"findings": 4})
    assert [r for r, _ in first.committed] == [r for r, _ in second.committed]
