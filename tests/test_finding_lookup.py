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

"""The one tool the deployed agent is given, and the reason it is safe.

An Agent Engine runs as a single service account, so every sub-agent attached
to the deployed orchestrator executes under one identity. That is why the
deployed agent is given a reader and nothing else: the moment it could write,
the per-agent identity boundary the rest of the system enforces would be a
boundary the headline deployment does not have.

The read-only property is asserted against the source, not just the behaviour,
because a write added later would pass every behavioural test in this file.
"""

from pathlib import Path

import pytest

from tools.finding_lookup import FindingNotFound, lookup_finding

SOURCE = (Path(__file__).resolve().parents[1] / "tools" / "finding_lookup.py").read_text()


class FakeDoc:
    def __init__(self, data):
        self._data = data

    @property
    def exists(self):
        return self._data is not None

    def to_dict(self):
        return self._data


class FakeCollection:
    def __init__(self, docs, log):
        self._docs, self._log = docs, log

    def document(self, doc_id):
        self._log.append(("document", doc_id))
        return self

    def get(self):
        return FakeDoc(self._docs)


class FakeClient:
    """Records every collection touched, and offers no write method at all."""

    def __init__(self, findings=None, assets=None):
        self.calls = []
        self._data = {"findings": findings, "assets": assets}

    def collection(self, name):
        self.calls.append(("collection", name))
        return FakeCollection(self._data.get(name), self.calls)


FINDING = {
    "finding_id": "RZ-0101",
    "cve_id": "CVE-2021-44228",
    "asset_id": "ast-001",
    "scanner_severity": "high",
    "scanner_cvss": 9.8,
    "scanner_comment": "routine scan output",
}
ASSET = {"hostname": "web-01.invalid", "environment": "prod",
         "criticality": "high", "internet_facing": True}


def test_it_renders_a_finding_the_way_both_agents_see_it():
    text = lookup_finding("RZ-0101", client=FakeClient(FINDING, ASSET))
    assert "finding_id: RZ-0101" in text
    assert "CVE-2021-44228" in text
    assert "ENRICHMENT" in text


def test_the_untrusted_comment_stays_fenced():
    """The fence is the boundary between system fact and scanner text."""
    text = lookup_finding("RZ-0101", client=FakeClient(FINDING, ASSET))
    assert "BEGIN UNTRUSTED SCANNER TEXT" in text
    assert "END UNTRUSTED SCANNER TEXT" in text


def test_a_missing_finding_raises_rather_than_returning_an_empty_shell():
    """An agent handed a blank finding will reason about the blank."""
    with pytest.raises(FindingNotFound):
        lookup_finding("RZ-9999", client=FakeClient(None, ASSET))


def test_a_missing_asset_still_produces_a_usable_finding():
    """Asset data is context. Its absence degrades the answer, not the tool."""
    text = lookup_finding("RZ-0101", client=FakeClient(FINDING, None))
    assert "finding_id: RZ-0101" in text


def test_it_only_ever_reads():
    client = FakeClient(FINDING, ASSET)
    lookup_finding("RZ-0101", client=client)
    assert [c for c in client.calls if c[0] == "collection"] == [
        ("collection", "findings"), ("collection", "assets")
    ]


@pytest.mark.parametrize("write_call", [
    ".set(", ".update(", ".delete(", ".add(", "batch(", "transaction(",
])
def test_the_source_contains_no_write_path(write_call):
    """Structural, not behavioural.

    The deployed agent's safety rests on this module being unable to mutate
    anything, and a write added later would pass every other test here.
    """
    assert write_call not in SOURCE


def test_it_reads_only_the_two_reference_collections():
    """findings and assets are seeded reference data, written by no agent."""
    for collection in ("decisions", "tickets", "human_queue", "exceptions",
                       "reports", "idempotency", "sla_clocks"):
        assert f'"{collection}"' not in SOURCE
