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

"""Telemetry must never be able to take a cycle down."""

from tools.telemetry import (
    CYCLE_ID,
    FINDING_ID,
    OUTCOME,
    finding_span,
    set_outcome,
)


def test_the_attribute_names_are_the_search_key():
    """A trace is only useful if it can be found, and these are how."""
    assert FINDING_ID == "remediation_zero.finding_id"
    assert CYCLE_ID == "remediation_zero.cycle_id"


def test_a_span_actually_carries_the_finding_and_cycle():
    """Captured from a real exporter, not assumed.

    The previous version of this test read:

        assert span is None or span.is_recording() or True

    which cannot fail. It sat in the suite claiming to verify the one thing
    that makes a trace findable, and verified nothing — in a project whose
    whole argument is that its claims can be checked.
    """
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))

    # Not set_tracer_provider: that is a no-op when a provider already exists,
    # which is how an earlier attempt at tracing appeared to work and emitted
    # nothing. Take the tracer from this provider directly.
    tracer = provider.get_tracer("remediation_zero")
    with tracer.start_as_current_span("remediation.finding") as span:
        span.set_attribute(FINDING_ID, "RZ-0001")
        span.set_attribute(CYCLE_ID, "cycle-007")
        set_outcome(span, "ratified")

    spans = exporter.get_finished_spans()
    assert len(spans) == 1, "the span was never exported"
    attributes = dict(spans[0].attributes)
    assert attributes[FINDING_ID] == "RZ-0001"
    assert attributes[CYCLE_ID] == "cycle-007"
    assert attributes[OUTCOME] == "ratified"


def test_the_span_helper_sets_both_attributes_on_whatever_it_yields():
    """finding_span is the call site's entry point, so it is exercised too."""
    seen = {}

    class Recorder:
        def set_attribute(self, key, value):
            seen[key] = value

    import contextlib

    import tools.telemetry as telemetry

    @contextlib.contextmanager
    def fake_span(_name):
        yield Recorder()

    class FakeTracer:
        start_as_current_span = staticmethod(fake_span)

    original = telemetry.__dict__.get("_test_tracer")
    try:
        import opentelemetry.trace as ot

        real_get = ot.get_tracer
        ot.get_tracer = lambda *_a, **_k: FakeTracer()
        with finding_span("RZ-0042", "cycle-100"):
            pass
    finally:
        ot.get_tracer = real_get
        if original is not None:
            telemetry.__dict__["_test_tracer"] = original

    assert seen[FINDING_ID] == "RZ-0042"
    assert seen[CYCLE_ID] == "cycle-100"


def test_an_unconfigured_tracer_still_yields():
    """Call sites should not have to know whether tracing is on."""
    with finding_span("RZ-0002", "cycle-001") as span:
        set_outcome(span, "ratified")  # must not raise whatever span is


def test_setting_an_outcome_on_nothing_is_harmless():
    """Losing observability is bad. Losing a remediation decision because the
    observability backend was unreachable is worse."""
    set_outcome(None, "ratified")


# ---------------------------------------------------------------------------
# The cycle_id field format
# ---------------------------------------------------------------------------

def test_a_cycle_renders_zero_padded_and_prefixed():
    """The format every emitter has to agree on for the field to be groupable."""
    from tools.telemetry import cycle_id

    assert cycle_id(12) == "cycle-012"
    assert cycle_id(0) == "cycle-000"
    assert cycle_id(30693) == "cycle-30693"


def test_a_missing_cycle_is_a_sentinel_rather_than_the_word_none():
    """A line that genuinely has no cycle must stay distinguishable from one
    that lost it. `str(None)` would put the string "None" in the field and
    read as data."""
    from tools.telemetry import cycle_id

    assert cycle_id(None) == "-"


def test_no_module_builds_a_cycle_id_of_its_own():
    """One definition, because a log field is only groupable if every emitter
    agrees on it.

    scan_store and delivery spelled this `str(cycle)` while everything else
    zero-padded it, so a single rescan wrote both `12` and `cycle-012` into
    the same field: filtering one finding's journey by cycle_id returned half
    of it and gave no sign the other half existed.
    """
    import re
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    # The value must come from the shared helper, or be a name already
    # carrying its result. Anything else is a second definition.
    permitted = re.compile(r'"cycle_id":\s*(cycle_id\b|f?"-")')
    offenders = []

    for directory in ("tools", "worker", "scripts"):
        for path in sorted((root / directory).rglob("*.py")):
            for number, line in enumerate(
                    path.read_text(encoding="utf-8").splitlines(), start=1):
                if '"cycle_id":' in line and not permitted.search(line):
                    offenders.append(
                        f"{path.relative_to(root)}:{number}: {line.strip()}")

    assert not offenders, (
        "These lines build a cycle_id instead of calling "
        "tools.telemetry.cycle_id():\n  " + "\n  ".join(offenders))
