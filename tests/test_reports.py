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

"""The report, and what the model is allowed to see.

The reporting agent narrates figures it did not compute. That guarantee is
only worth something if the figures reach it in a form it cannot make worse,
and if the numbers are stored beside the prose so the narrative can be checked
against them rather than believed.
"""

import pytest

from tools.clock import ClockMode, SimClock
from tools.idempotency import InMemoryIdempotencyStore
from tools.reports import COLLECTION, ReportWriter, _presentable


class FakeDoc:
    def __init__(self, docs, key, log):
        self._docs, self._key, self._log = docs, key, log

    def set(self, data):
        self._log.append(self._key)
        self._docs[self._key] = dict(data)


class FakeCollection:
    def __init__(self, docs, name, log):
        self._docs, self._name, self._log = docs, name, log

    def document(self, doc_id):
        return FakeDoc(self._docs, (self._name, doc_id), self._log)


class FakeClient:
    def __init__(self):
        self.docs, self.writes = {}, []

    def collection(self, name):
        return FakeCollection(self.docs, name, self.writes)


METRICS = {"decisions_total": 21, "ratification_rate": 0.6190476190476191,
           "disagreement_rate": 0.14285714285714285,
           "rejection_reasons": ["Severity understates KEV.",
                                 "Severity understates KEV.",
                                 "  Evidence does not support critical.  "]}


@pytest.fixture
def client():
    return FakeClient()


@pytest.fixture
def writer(client):
    return ReportWriter(store=InMemoryIdempotencyStore(), client=client,
                        clock=SimClock(mode=ClockMode.REAL))


# --- what the model is handed -----------------------------------------------

def test_rates_are_rounded_before_the_model_sees_them():
    """Handing a model 0.6190476190476191 invites it to print
    0.6190476190476191. Presentation precision is the code's decision."""
    shown = _presentable(METRICS)
    assert shown["ratification_rate"] == "62%"
    assert shown["disagreement_rate"] == "14%"


def test_duplicate_rejection_reasons_are_collapsed():
    """The same objection six times reads as six problems."""
    shown = _presentable(METRICS)
    assert shown["rejection_reasons"].count("Severity understates KEV.") == 1


def test_rejection_reasons_are_trimmed_and_capped():
    many = {"rejection_reasons": [f"reason {n}" for n in range(30)]}
    shown = _presentable(many)
    assert len(shown["rejection_reasons"]) <= 6


def test_the_most_recent_reasons_survive_the_cap():
    """The oldest objection is the least useful one to keep."""
    many = {"rejection_reasons": [f"reason {n}" for n in range(30)]}
    shown = _presentable(many)
    assert "reason 29" in shown["rejection_reasons"]
    assert "reason 0" not in shown["rejection_reasons"]


def test_presenting_does_not_mutate_the_metrics_it_was_given():
    """The stored metrics must be the computed ones, not the rounded strings
    the model was shown. A report whose figures are percentages cannot be
    recomputed from."""
    before = dict(METRICS)
    _presentable(METRICS)
    assert METRICS == before
    assert isinstance(METRICS["ratification_rate"], float)


def test_blank_reasons_are_dropped():
    shown = _presentable({"rejection_reasons": ["", "   ", "a real one"]})
    assert shown["rejection_reasons"] == ["a real one"]


# --- what is stored ----------------------------------------------------------

def test_the_figures_are_stored_beside_the_prose(writer, client):
    """So the narrative can be checked against them rather than believed."""
    writer.record(METRICS, "Three findings need you this week.", cycle=4)

    document = client.docs[(COLLECTION, "report-c004")]
    assert document["summary"].startswith("Three findings")
    assert document["metrics"]["decisions_total"] == 21
    assert document["metrics"]["ratification_rate"] == pytest.approx(0.619, rel=1e-2)


def test_both_stamps_are_recorded(writer, client):
    writer.record(METRICS, "summary", cycle=4)
    document = client.docs[(COLLECTION, "report-c004")]
    assert "real_ts" in document and "sim_ts" in document


# --- once --------------------------------------------------------------------

def test_recording_the_same_period_twice_writes_once(writer, client):
    writer.record(METRICS, "summary", cycle=4)
    writes = len(client.writes)
    writer.record(METRICS, "a different summary", cycle=4)
    assert len(client.writes) == writes


def test_a_later_period_records_separately(writer, client):
    writer.record(METRICS, "summary", cycle=4)
    writer.record(METRICS, "summary", cycle=5)
    assert (COLLECTION, "report-c004") in client.docs
    assert (COLLECTION, "report-c005") in client.docs


def test_the_period_sentinel_does_not_collide_with_a_finding():
    """Reports are not per-finding, so the key uses a sentinel in that slot.
    It must not be a value a real finding could take."""
    from tools.idempotency import derive_key
    assert derive_key("__period__", "report", 4) != derive_key(
        "RZ-0001", "report", 4)


# ---------------------------------------------------------------------------
# Rates reach the model rounded
# ---------------------------------------------------------------------------

def test_every_rate_metrics_produces_is_rounded_before_the_model_sees_it():
    """RATE_KEYS has to keep step with metrics.py.

    It did not, once. `_rate` grew from two callers to four when the rescan
    landed, the rounding list stayed at two, and a report went out reading
    "we remediated 0.35570469798657717 of scanned findings" -- in the prose a
    person reads, from the one function whose docstring warns that handing a
    model a bare float invites it to print one.

    Derived from the source rather than restated, so a fifth rate cannot be
    added without this failing.
    """
    import re
    from pathlib import Path
    from tools.reports import RATE_KEYS

    source = (Path(__file__).resolve().parents[1] / "tools" / "metrics.py").read_text()
    produced = set(re.findall(r'"([a-z_]+)":\s*_rate\(', source))

    assert produced, "no _rate call sites found; the scan is broken"
    missing = produced - set(RATE_KEYS)
    assert not missing, (
        "metrics.py produces these rates and reports.RATE_KEYS does not round "
        f"them, so they reach the model as bare floats: {sorted(missing)}")

    stale = set(RATE_KEYS) - produced
    assert not stale, f"RATE_KEYS names rates metrics.py no longer produces: {sorted(stale)}"


def test_a_rate_is_rendered_as_a_whole_percent():
    """The precision the prose should carry, decided in code rather than asked
    of the model."""
    from tools.reports import _presentable

    shown = _presentable({"remediated_of_scanned": 0.35570469798657717,
                          "coverage_rate": 0.75, "rejection_reasons": []})
    assert shown["remediated_of_scanned"] == "36%"
    assert shown["coverage_rate"] == "75%"
