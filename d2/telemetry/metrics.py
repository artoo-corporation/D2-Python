# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""Metric instrument definitions for the D2 SDK."""

from __future__ import annotations

import time

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
# Security & Threat Detection Metrics
# ==============================================================================

sequence_pattern_blocked_total = meter.create_counter(
    name="d2.sequence.pattern.blocked.total",
    description="Counts blocked sequence patterns with detailed pattern classification.",
    unit="1",
)

sensitive_data_access_total = meter.create_counter(
    name="d2.sensitive_data.access.total",
    description="Tracks access to sensitive data sources (tools in @sensitive_data group).",
    unit="1",
)

call_chain_depth_histogram = meter.create_histogram(
    name="d2.call_chain.depth",
    description="Distribution of call chain lengths within a request.",
    unit="1",
)

user_violation_attempts_total = meter.create_counter(
    name="d2.user.violation_attempts.total",
    description="Counts policy violation attempts by user/agent for insider threat detection.",
    unit="1",
)

# ==============================================================================
# Operations & Performance Metrics
# ==============================================================================

guardrail_latency_ms = meter.create_histogram(
    name="d2.guardrail.latency.ms",
    description="Time spent in guardrail processing (input validation, output sanitization, sequence checks).",
    unit="ms",
)

policy_cache_hits_total = meter.create_counter(
    name="d2.policy.cache.hits.total",
    description="Policy decision cache hit/miss tracking for performance monitoring.",
    unit="1",
)

tool_cooccurrence_total = meter.create_counter(
    name="d2.tool.cooccurrence.total",
    description="Tracks which tools are called together within time windows.",
    unit="1",
)

# ==============================================================================
# Business & Product Metrics
# ==============================================================================

feature_usage_total = meter.create_counter(
    name="d2.feature.usage.total",
    description="Tracks adoption and usage of D2 features.",
    unit="1",
)

policy_complexity_score = meter.create_up_down_counter(
    name="d2.policy.complexity.score",
    description="Policy complexity metrics (number of rules, tools, roles, etc.).",
    unit="1",
)

tool_cost_units_total = meter.create_counter(
    name="d2.tool.cost_units.total",
    description="Cost attribution for tool invocations (API credits, compute, etc.).",
    unit="1",
)

# ==============================================================================
# Compliance & Audit Metrics
# ==============================================================================

data_flow_event_total = meter.create_counter(
    name="d2.data_flow.event.total",
    description="Audit trail of data flows between tools for compliance.",
    unit="1",
)

facts_recorded_total = meter.create_counter(
    name="d2.facts.recorded.total",
    description="Counts facts (data flow labels) recorded during requests.",
    unit="1",
)

data_flow_blocked_total = meter.create_counter(
    name="d2.data_flow.blocked.total",
    description="Counts tools blocked due to data flow label violations.",
    unit="1",
)


__all__ = [
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
]
