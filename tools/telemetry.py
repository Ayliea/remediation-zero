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

"""Cloud Trace wiring.

ADK already instruments its own work: model calls, tool calls, and every
workflow node get spans. What it cannot know is which finding any of that was
for, and that is the question the demonstration has to answer. So this module
adds one span per finding per cycle, carrying the finding id and cycle id as
attributes, and every span ADK creates underneath nests inside it.

The result is that a single finding's journey, from untrusted-text screening
through triage and adversarial review to an owner or a person, is one trace
that can be opened and read by someone who did not build the system.

Tracing failing is never allowed to fail a cycle. Losing observability is bad;
losing a remediation decision because the observability backend was unreachable
is worse, and the second is the more likely way a telemetry dependency causes
an outage.
"""

import logging
from contextlib import contextmanager
from typing import Optional

logger = logging.getLogger("remediation_zero.telemetry")

#: Attribute names. Fixed, because a trace is only searchable if the key is
#: the same on every span.
FINDING_ID = "remediation_zero.finding_id"
CYCLE_ID = "remediation_zero.cycle_id"
OUTCOME = "remediation_zero.outcome"

_configured = False
_provider = None  # the provider we attached the exporter to


def configure_tracing(project: Optional[str] = None) -> bool:
    """Send spans to Cloud Trace. Returns whether an exporter was attached.

    Idempotent, and never raises. A failure here is logged and the caller
    carries on unobserved rather than not at all.

    Note the return value means an exporter is attached, not that a span has
    arrived. An earlier version returned True on "no exception raised", which
    was true while nothing was being exported at all.
    """
    global _configured
    if _configured:
        return True

    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider

        from google.adk.telemetry.google_cloud import (
            get_gcp_exporters,
            get_gcp_resource,
        )

        # ADK's own helper. It was briefly replaced with a hand-rolled
        # CloudTraceSpanExporter after an empty Cloud Trace query was read as
        # the helper failing silently. It was not failing: Cloud Trace takes
        # up to a couple of minutes to index, and the replacement produced no
        # traces at all while this one produced a correctly nested seven-span
        # trace. Verified by cycle rather than by inspection.
        hooks = get_gcp_exporters(enable_cloud_tracing=True)
        provider = TracerProvider(resource=get_gcp_resource(project))
        for processor in hooks.span_processors:
            provider.add_span_processor(processor)
        trace.set_tracer_provider(provider)

        # Keep the reference. flush() previously went through
        # trace.get_tracer_provider(), which is not necessarily the provider
        # the exporter is attached to once anything else has set one, so a
        # short-lived script could exit with its spans still buffered in a
        # provider nobody flushed.
        global _provider
        _provider = provider
        _configured = True
        return True
    except Exception as exc:  # noqa: BLE001 - telemetry must not break a cycle
        logger.warning(
            "cloud trace not configured (%s: %s); continuing untraced",
            type(exc).__name__, exc,
        )
        return False


@contextmanager
def finding_span(finding_id: str, cycle_id: str, name: str = "remediation.finding"):
    """One span per finding per cycle, with everything else nested inside.

    Yields the span, or None when tracing is not configured, so call sites do
    not need to care which.
    """
    try:
        from opentelemetry import trace

        tracer = trace.get_tracer("remediation_zero")
        with tracer.start_as_current_span(name) as span:
            span.set_attribute(FINDING_ID, finding_id)
            span.set_attribute(CYCLE_ID, cycle_id)
            yield span
    except Exception as exc:  # noqa: BLE001
        logger.warning("span not created (%s); continuing untraced", type(exc).__name__)
        yield None


def set_outcome(span, outcome: str) -> None:
    """Record how the finding ended, so a trace can be searched by result."""
    if span is not None:
        try:
            span.set_attribute(OUTCOME, outcome)
        except Exception:  # noqa: BLE001
            pass


def flush(timeout_seconds: float = 20.0) -> None:
    """Push buffered spans before the process exits.

    Spans are batched, so a short-lived script exits with its trace still in
    memory unless it says otherwise. A cycle that ran but produced no trace
    looks identical to a cycle that never ran.
    """
    for provider in (_provider, _current_provider()):
        if provider is not None and hasattr(provider, "force_flush"):
            try:
                provider.force_flush(timeout_millis=int(timeout_seconds * 1000))
            except Exception:  # noqa: BLE001
                pass


def _current_provider():
    try:
        from opentelemetry import trace

        return trace.get_tracer_provider()
    except Exception:  # noqa: BLE001
        return None
