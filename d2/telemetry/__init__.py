# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""Telemetry package exposing metrics, tracers, and usage reporting."""

from .runtime import get_tracer, meter
from .metrics import (
    # Existing metrics
    authz_decision_total,
    missing_policy_total,
    policy_poll_total,
    policy_poll_updated,
    policy_file_reload_total,
    policy_poll_clamped_total,
    policy_poll_stale_total,
    policy_load_latency_ms,
    jwks_fetch_latency_ms,
    jwks_rotation_total,
    local_tool_count,
    authz_decision_latency_ms,
    authz_denied_reason_total,
    tool_invocation_total,
    tool_exec_latency_ms,
    policy_poll_interval_seconds,
    policy_poll_failure_total,
    policy_bundle_age_seconds,
    context_leak_total,
    context_stale_total,
    sync_in_async_denied_total,
    # New security & threat detection metrics
    sequence_pattern_blocked_total,
    sensitive_data_access_total,
    call_chain_depth_histogram,
    user_violation_attempts_total,
    # New operations & performance metrics
    guardrail_latency_ms,
    policy_cache_hits_total,
    tool_cooccurrence_total,
    # New business & product metrics
    feature_usage_total,
    policy_complexity_score,
    tool_cost_units_total,
    # New compliance & audit metrics
    data_flow_event_total,
    facts_recorded_total,
    data_flow_blocked_total,
)
from .usage import UsageReporter

__all__ = [
    "UsageReporter",
    # Existing metrics
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
    # New security & threat detection metrics
    "sequence_pattern_blocked_total",
    "sensitive_data_access_total",
    "call_chain_depth_histogram",
    "user_violation_attempts_total",
    # New operations & performance metrics
    "guardrail_latency_ms",
    "policy_cache_hits_total",
    "tool_cooccurrence_total",
    # New business & product metrics
    "feature_usage_total",
    "policy_complexity_score",
    "tool_cost_units_total",
    # New compliance & audit metrics
    "data_flow_event_total",
    "facts_recorded_total",
    "data_flow_blocked_total",
    # Utilities
    "get_tracer",
    "meter",
]
