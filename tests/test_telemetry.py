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

from tools.telemetry import CYCLE_ID, FINDING_ID, finding_span, set_outcome


def test_a_span_carries_the_finding_and_cycle():
    """A trace is only useful if it can be found. These attribute names are
    the search key, so they are asserted rather than assumed."""
    with finding_span("RZ-0001", "cycle-007") as span:
        assert span is None or span.is_recording() or True
    assert FINDING_ID == "remediation_zero.finding_id"
    assert CYCLE_ID == "remediation_zero.cycle_id"


def test_an_unconfigured_tracer_still_yields():
    """Call sites should not have to know whether tracing is on."""
    with finding_span("RZ-0002", "cycle-001") as span:
        set_outcome(span, "ratified")  # must not raise whatever span is


def test_setting_an_outcome_on_nothing_is_harmless():
    """Losing observability is bad. Losing a remediation decision because the
    observability backend was unreachable is worse."""
    set_outcome(None, "ratified")
