# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""D2 SDK – Telemetry helpers (metrics definitions + exporter bootstrap).

We now have a *single* environment variable – ``D2_TELEMETRY`` – that
controls both OpenTelemetry metrics *and* raw usage-event collection.

``D2_TELEMETRY`` values (case-insensitive):

* ``off``/``none``/``0`` – disable *everything*
* ``metrics`` – enable OTLP metric export only
* ``usage`` – enable raw usage events only (handled elsewhere)
* ``all``/``true``/``1``/``yes``/``*`` *(default)* – enable both

This file cares only about the *metrics* side.  We spin up an
``OTLPMetricExporter`` automatically when the mode is either ``metrics`` or
``all``.  The exporter honours the standard ``OTEL_*`` env-vars.

If the optional deps (``opentelemetry-sdk`` + OTLP exporter) are missing, we
*warn* and fall back to the default no-op provider – we never crash the host
app.
"""

from __future__ import annotations

import os
import logging

from opentelemetry import metrics, trace

from .utils import get_telemetry_mode, TelemetryMode


# ---------------------------------------------------------------------------
# Optional: auto-configure an OTLP MetricExporter when telemetry mode enables
# metrics (D2_TELEMETRY=metrics/all)
# ---------------------------------------------------------------------------


def _maybe_install_otlp_provider():  # pragma: no cover — optional init
    """Installs a PeriodicExportingMetricReader + OTLP exporter if telemetry is on."""

    mode = get_telemetry_mode()
    if mode not in (TelemetryMode.METRICS, TelemetryMode.ALL):
        return  # metrics disabled

    provider = metrics.get_meter_provider()
    # Avoid clobbering a provider that the host application already set up.
    if provider.__class__.__name__ != "_DefaultMeterProvider":
        logging.getLogger(__name__).debug(
            "Telemetry metrics enabled but a custom MeterProvider is already active; skipping auto-init."
        )
        return

    try:
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
        from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter

        otlp_exporter = OTLPMetricExporter()  # honours OTEL_* env-vars
        metrics.set_meter_provider(
            MeterProvider(
                metric_readers=[PeriodicExportingMetricReader(otlp_exporter)]
            )
        )

        logging.getLogger(__name__).info(
            "Telemetry mode '%s' – OTLP MetricExporter initialised (endpoint: %s)",
            mode.value,
            os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "default collector"),
        )
    except ImportError as exc:
        logging.getLogger(__name__).warning(
            "Telemetry metrics enabled but OpenTelemetry SDK/OTLP exporter not installed. "
            "Install with: pip install 'opentelemetry-sdk opentelemetry-exporter-otlp' (%s)",
            exc,
        )


# Execute on module import *before* creating meters
_maybe_install_otlp_provider()

# Global meter for all D2 SDK metrics (provider may have been swapped above)
meter = metrics.get_meter("d2.sdk")

def get_tracer(name: str) -> trace.Tracer:
    """Returns a tracer instance for a given module name."""
    return trace.get_tracer(name)

# --- Metrics Definition ---

# Counter for authorization decisions
authz_decision_total = meter.create_counter(
    name="d2.authz.decision.total",
    description="Counts the number of authorization decisions made.",
    unit="1",
)

# Counter for when a tool_id is not found in the policy
missing_policy_total = meter.create_counter(
    name="d2.authz.missing_policy.total",
    description="Counts checks for a tool_id that is not in the policy bundle.",
    unit="1",
)

# Counter for policy polling attempts
policy_poll_total = meter.create_counter(
    name="d2.policy.poll.total",
    description="Counts the number of policy polling attempts.",
    unit="1",
)

# Counter for when a poll results in a new policy
policy_poll_updated = meter.create_counter(
    name="d2.policy.poll.updated",
    description="Counts the number of times a new policy was fetched.",
    unit="1",
)

# Counter for local policy file reloads
policy_file_reload_total = meter.create_counter(
    name="d2.policy.file_reload.total",
    description="Counts the number of times a local policy file was reloaded on change.",
    unit="1",
)

# Counter for when a poll interval is clamped
policy_poll_clamped_total = meter.create_counter(
    name="d2.policy.poll.clamped.total",
    description="Counts the number of times the poll interval was clamped to the tier minimum.",
    unit="1",
)

# Counter for stale policy detection (N consecutive poll failures)
policy_poll_stale_total = meter.create_counter(
    name="d2.policy.poll.stale.total",
    description="Counts the number of times the listener entered a stale state (consecutive failures).",
    unit="1",
)

# Histogram for policy load latency (milliseconds)
policy_load_latency_ms = meter.create_histogram(
    name="d2.policy.load.latency.ms",
    description="Time taken to load & verify a policy bundle.",
    unit="ms",
) 

# Histogram for JWKS fetch latency (enhanced with rotation tracking)
jwks_fetch_latency_ms = meter.create_histogram(
    name="d2.jwks.fetch.latency.ms",
    description="Latency to download JWKS document, tagged by rotation trigger status.",
    unit="ms",
)

# Counter for JWKS rotation events
jwks_rotation_total = meter.create_counter(
    name="d2.jwks.rotation.total",
    description="Total JWKS rotation events triggered by control-plane.",
    unit="1",
)

# Up/Down counter for current tool count in local policy
local_tool_count = meter.create_up_down_counter(
    name="d2.policy.local.tool_count",
    description="Number of tools defined in the active local policy bundle.",
    unit="1",
) 

# Histogram for authorization decision latency
authz_decision_latency_ms = meter.create_histogram(
    name="d2.authz.decision.latency.ms",
    description="End-to-end time for a single authorization decision.",
    unit="ms",
)

# Counter for denied decisions by reason
authz_denied_reason_total = meter.create_counter(
    name="d2.authz.denied.reason.total",
    description="Counts denied authorization decisions partitioned by reason.",
    unit="1",
)

# Counter for tool invocations (post-auth)
tool_invocation_total = meter.create_counter(
    name="d2.tool.invocation.total",
    description="Counts successful or failed tool executions.",
    unit="1",
)

# Histogram for tool execution latency
tool_exec_latency_ms = meter.create_histogram(
    name="d2.tool.exec.latency.ms",
    description="Time spent inside the tool function after authorization succeeds.",
    unit="ms",
)

# Gauge (implemented as UpDownCounter) for current polling interval per client
policy_poll_interval_seconds = meter.create_up_down_counter(
    name="d2.policy.poll.interval.seconds",
    description="Current effective polling interval for policy updates on this client.",
    unit="s",
)

# Counter for polling failures
policy_poll_failure_total = meter.create_counter(
    name="d2.policy.poll.failure.total",
    description="Counts failed attempts to poll the policy bundle (non-2xx/304 or network errors).",
    unit="1",
)

# Gauge (UpDownCounter) for bundle age – updated on each successful decision
policy_bundle_age_seconds = meter.create_up_down_counter(
    name="d2.policy.bundle.age.seconds",
    description="Age of the currently loaded policy bundle.",
    unit="s",
)

# Context leak detection
context_leak_total = meter.create_counter(
    name="d2.context.leak.total",
    description="Counts authorization checks where no user context was present.",
    unit="1",
)

# Context *stale* detection – user context still present after a request finished
context_stale_total = meter.create_counter(
    name="d2.context.stale.total",
    description="Counts instances where the user context was *not* cleared at the end of a request.",
    unit="1",
)

# Mis-use counter for sync-in-async failures
sync_in_async_denied_total = meter.create_counter(
    name="d2.sync_in_async.denied.total",
    description="Counts instances where a sync tool was called from inside an event loop and was denied execution.",
    unit="1",
) 