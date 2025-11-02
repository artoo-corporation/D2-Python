# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""Metric instrument definitions for the D2 SDK."""

from __future__ import annotations

from .runtime import meter

authz_decision_total = meter.create_counter(
    name="d2.authz.decision.total",
    description="Counts the number of authorization decisions made.",
    unit="1",
)

missing_policy_total = meter.create_counter(
    name="d2.authz.missing_policy.total",
    description="Counts checks for a tool_id that is not in the policy bundle.",
    unit="1",
)

policy_poll_total = meter.create_counter(
    name="d2.policy.poll.total",
    description="Counts the number of policy polling attempts.",
    unit="1",
)

policy_poll_updated = meter.create_counter(
    name="d2.policy.poll.updated",
    description="Counts the number of times a new policy was fetched.",
    unit="1",
)

policy_file_reload_total = meter.create_counter(
    name="d2.policy.file_reload.total",
    description="Counts the number of times a local policy file was reloaded on change.",
    unit="1",
)

policy_poll_clamped_total = meter.create_counter(
    name="d2.policy.poll.clamped.total",
    description="Counts the number of times the poll interval was clamped to the tier minimum.",
    unit="1",
)

policy_poll_stale_total = meter.create_counter(
    name="d2.policy.poll.stale.total",
    description="Counts the number of times the listener entered a stale state (consecutive failures).",
    unit="1",
)

policy_load_latency_ms = meter.create_histogram(
    name="d2.policy.load.latency.ms",
    description="Time taken to load & verify a policy bundle.",
    unit="ms",
)

jwks_fetch_latency_ms = meter.create_histogram(
    name="d2.jwks.fetch.latency.ms",
    description="Latency to download JWKS document, tagged by rotation trigger status.",
    unit="ms",
)

jwks_rotation_total = meter.create_counter(
    name="d2.jwks.rotation.total",
    description="Total JWKS rotation events triggered by control-plane.",
    unit="1",
)

local_tool_count = meter.create_up_down_counter(
    name="d2.policy.local.tool_count",
    description="Number of tools defined in the active local policy bundle.",
    unit="1",
)

authz_decision_latency_ms = meter.create_histogram(
    name="d2.authz.decision.latency.ms",
    description="End-to-end time for a single authorization decision.",
    unit="ms",
)

authz_denied_reason_total = meter.create_counter(
    name="d2.authz.denied.reason.total",
    description="Counts denied authorization decisions partitioned by reason.",
    unit="1",
)

tool_invocation_total = meter.create_counter(
    name="d2.tool.invocation.total",
    description="Counts successful or failed tool executions.",
    unit="1",
)

tool_exec_latency_ms = meter.create_histogram(
    name="d2.tool.exec.latency.ms",
    description="Time spent inside the tool function after authorization succeeds.",
    unit="ms",
)

policy_poll_interval_seconds = meter.create_up_down_counter(
    name="d2.policy.poll.interval.seconds",
    description="Current effective polling interval for policy updates on this client.",
    unit="s",
)

policy_poll_failure_total = meter.create_counter(
    name="d2.policy.poll.failure.total",
    description="Counts failed attempts to poll the policy bundle (non-2xx/304 or network errors).",
    unit="1",
)

policy_bundle_age_seconds = meter.create_up_down_counter(
    name="d2.policy.bundle.age.seconds",
    description="Age of the currently loaded policy bundle.",
    unit="s",
)

context_leak_total = meter.create_counter(
    name="d2.context.leak.total",
    description="Counts authorization checks where no user context was present.",
    unit="1",
)

context_stale_total = meter.create_counter(
    name="d2.context.stale.total",
    description="Counts instances where the user context was not cleared at the end of a request.",
    unit="1",
)

sync_in_async_denied_total = meter.create_counter(
    name="d2.sync_in_async.denied.total",
    description="Counts instances where a sync tool was called from inside an event loop and denied execution.",
    unit="1",
)


# ==============================================================================
# Tool Execution Metrics Recording
# ==============================================================================


def record_tool_metrics(manager, tool_id: str, status: str, started_at: float) -> None:
    """Record execution metrics and emit usage telemetry for a tool invocation.
    
    This function records:
    - OpenTelemetry metrics (latency histogram + invocation counter)
    - Usage telemetry events (if usage reporter is configured)
    
    Args:
        manager: Policy manager instance (may have _usage_reporter)
        tool_id: Tool identifier
        status: Execution status ("allowed", "denied", etc.)
        started_at: Timestamp from time.perf_counter() when execution started
    """
    import time
    
    duration_ms = (time.perf_counter() - started_at) * 1000.0
    tool_exec_latency_ms.record(duration_ms, {"tool_id": tool_id, "status": status})
    tool_invocation_total.add(1, {"tool_id": tool_id, "status": status})

    try:
        reporter = getattr(manager, "_usage_reporter", None)
        if reporter:
            policy_etag = None
            service_name = "unknown"

            if hasattr(manager, "_policy_bundle") and manager._policy_bundle:
                policy_etag = getattr(manager._policy_bundle, "etag", None)
                metadata = manager._policy_bundle.raw_bundle.get("metadata", {})
                service_name = metadata.get("name", "unknown")

            reporter.track_event(
                "tool_invoked",
                {
                    "tool_id": tool_id,
                    "decision": status,
                    "resource": tool_id,
                    "latency_ms": duration_ms,
                },
                policy_etag=policy_etag,
                service_name=service_name,
            )
    except Exception:
        # Telemetry must never interfere with user code
        pass


__all__ = [
    "authz_decision_total",
    "missing_policy_total",
    "policy_poll_total",
    "policy_poll_updated",
    "policy_file_reload_total",
    "policy_poll_clamped_total",
    "policy_poll_stale_total",
    "policy_load_latency_ms",
    "jwks_fetch_latency_ms",
    "jwks_rotation_total",
    "local_tool_count",
    "authz_decision_latency_ms",
    "authz_denied_reason_total",
    "tool_invocation_total",
    "tool_exec_latency_ms",
    "policy_poll_interval_seconds",
    "policy_poll_failure_total",
    "policy_bundle_age_seconds",
    "context_leak_total",
    "context_stale_total",
    "sync_in_async_denied_total",
    "record_tool_metrics",
]
