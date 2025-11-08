# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""Helper functions used by the decorator guard logic."""

from __future__ import annotations

import logging
import time
from typing import Any, Mapping, Optional, Sequence

from ..exceptions import ConfigurationError, PermissionDeniedError
from ..telemetry.metrics import (
    authz_denied_reason_total,
    tool_invocation_total,
    guardrail_latency_ms,
    feature_usage_total,
    user_violation_attempts_total,
)
from .input_validation import get_input_validator, format_validation_reason

logger = logging.getLogger(__name__)


def _collect_condition_keys(conditions: Any) -> set[str]:
    keys: set[str] = set()

    if isinstance(conditions, Mapping):
        if "input" in conditions:
            input_rules = conditions.get("input") or {}
        elif "output" in conditions:
            input_rules = {}
        else:
            input_rules = conditions
        if isinstance(input_rules, Mapping):
            keys.update(str(k) for k in input_rules.keys())
    elif isinstance(conditions, Sequence) and not isinstance(conditions, (str, bytes, bytearray)):
        for item in conditions:
            keys.update(_collect_condition_keys(item))

    return keys




async def validate_inputs(
    manager,
    tool_id: str,
    arguments: Mapping[str, Any],
    user_context,
    *,
    allowed_params: Optional[Sequence[str]] = None,
    has_var_kwargs: bool = False,
) -> Optional[PermissionDeniedError]:
    """Run declarative input validation and emit telemetry on failure."""
    
    # Track guardrail latency
    validation_start = time.perf_counter()

    get_conditions = getattr(manager, "get_tool_conditions", None)
    if not callable(get_conditions):
        return None

    try:
        conditions = await get_conditions(tool_id)
    except TypeError:
        conditions = get_conditions(tool_id)

    if not conditions:
        return None
    
    # Track feature usage
    try:
        feature_usage_total.add(1, {"feature": "input_validation", "enabled": "true"})
    except Exception:
        pass

    if allowed_params is not None:
        condition_keys = _collect_condition_keys(conditions)
        if condition_keys and not has_var_kwargs:
            invalid = condition_keys - set(allowed_params)
        else:
            invalid = set()

        if invalid:
            logger.error(
                "Policy conditions for tool '%s' reference unknown arguments: %s",
                tool_id,
                ", ".join(sorted(invalid)),
            )
            raise ConfigurationError(
                f"Input conditions for tool '{tool_id}' reference undefined parameter(s): {sorted(invalid)}"
            )

    validation = get_input_validator().validate(conditions, dict(arguments))
    
    # Record guardrail latency (OTEL metric)
    validation_duration_ms = (time.perf_counter() - validation_start) * 1000.0
    guardrail_latency_ms.record(validation_duration_ms, {
        "type": "input_validation",
        "tool_id": tool_id,
        "result": "allowed" if validation.allowed else "denied"
    })
    
    # Send to D2 cloud for performance analytics
    try:
        reporter = getattr(manager, "_usage_reporter", None)
        if reporter:
            reporter.track_event(
                "guardrail_overhead",
                {
                    "tool_id": tool_id,
                    "guardrail_type": "input_validation",
                    "overhead_ms": validation_duration_ms,
                    "result": "allowed" if validation.allowed else "denied",
                }
            )
    except Exception:
        pass
    
    if validation.allowed:
        return None

    reason = format_validation_reason(tool_id, validation)
    error = PermissionDeniedError(
        tool_id=tool_id,
        user_id=user_context.user_id if user_context else "unknown",
        roles=user_context.roles if user_context else [],
        reason=reason,
    )

    tool_invocation_total.add(1, {"tool_id": tool_id, "status": "denied"})
    try:
        # OTEL metrics for observability
        authz_denied_reason_total.add(1, {"reason": "input_validation", "mode": manager.mode})
        user_violation_attempts_total.add(1, {
            "user_id": user_context.user_id if user_context else "unknown",
            "violation_type": "input_validation",
        })
        
        # D2 cloud event for security analytics
        reporter = getattr(manager, "_usage_reporter", None)
        if reporter:
            reporter.track_event(
                "authz_decision",
                {
                    "tool_id": tool_id,
                    "result": "denied",
                    "reason": "input_validation_failed",
                    "mode": manager.mode,
                    "violation_count": len(validation.violations),
                    "violations": [v.message for v in validation.violations],
                },
            )
    except Exception:
        pass

    return error


__all__ = [
    "validate_inputs",
]
