# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""Runtime utilities for D2 telemetry (OTLP bootstrap, meters, tracers)."""

from __future__ import annotations

import logging
import os

from opentelemetry import metrics, trace

from ..utils import get_telemetry_mode, TelemetryMode


def _maybe_install_otlp_provider():  # pragma: no cover — optional init
    """Install PeriodicExportingMetricReader + OTLP exporter when enabled."""

    mode = get_telemetry_mode()
    if mode not in (TelemetryMode.METRICS, TelemetryMode.ALL):
        return  # metrics disabled

    provider = metrics.get_meter_provider()
    if provider.__class__.__name__ != "_DefaultMeterProvider":
        logging.getLogger(__name__).debug(
            "Telemetry metrics enabled but a custom MeterProvider is already active; skipping auto-init."
        )
        return

    try:
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
        from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter

        otlp_exporter = OTLPMetricExporter()
        metrics.set_meter_provider(
            MeterProvider(metric_readers=[PeriodicExportingMetricReader(otlp_exporter)])
        )

        logging.getLogger(__name__).info(
            "Telemetry mode '%s' – OTLP MetricExporter initialised (endpoint: %s)",
            mode.value,
            os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "default collector"),
        )
    except ImportError as exc:  # pragma: no cover — optional dependency
        logging.getLogger(__name__).warning(
            "Telemetry metrics enabled but OpenTelemetry SDK/OTLP exporter not installed. "
            "Install with: pip install 'opentelemetry-sdk opentelemetry-exporter-otlp' (%s)",
            exc,
        )


_maybe_install_otlp_provider()

meter = metrics.get_meter("d2.sdk")


def get_tracer(name: str) -> trace.Tracer:
    """Return a tracer instance for the given module name."""

    return trace.get_tracer(name)


__all__ = [
    "get_tracer",
    "meter",
]
