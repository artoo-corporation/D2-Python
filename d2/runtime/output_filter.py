# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""Runtime helpers for declarative output validation and sanitization.

This module provides runtime integration for output processing:
1. OutputValidator: Validates return values against constraints (deny if violated)
2. OutputSanitizer: Transforms return values (filter/redact/truncate sensitive data)

Both are applied in sequence:
- First validate (ensure return value meets schema/constraints)
- Then sanitize (remove/transform sensitive fields)
"""

from __future__ import annotations

import time
from typing import Any, Final

from ..context import get_user_context
from ..exceptions import PermissionDeniedError
from ..validation.output import OutputValidator
from ..sanitization.output import OutputSanitizer
from ..telemetry.metrics import (
    guardrail_latency_ms,
    feature_usage_total,
    user_violation_attempts_total,
    authz_denied_reason_total,
)

# Process-wide instances
_OUTPUT_VALIDATOR: Final[OutputValidator] = OutputValidator()
_OUTPUT_SANITIZER: Final[OutputSanitizer] = OutputSanitizer()


def get_output_validator() -> OutputValidator:
    """Return the process-wide output validator instance."""
    return _OUTPUT_VALIDATOR


def get_output_sanitizer() -> OutputSanitizer:
    """Return the process-wide output sanitizer instance."""
    return _OUTPUT_SANITIZER


async def apply_output_filters(manager, tool_id: str, value: Any, *, user_context=None) -> Any:
    """Apply declarative output validation and sanitization for *tool_id* to *value*.
    
    Processing order:
    1. Validation: Check constraints (type, min, max, etc.) without 'action' keyword
       - If validation fails → raise PermissionDeniedError
    2. Sanitization: Apply field actions (filter, redact, truncate)
       - Transform value (never denies)
    
    Args:
        manager: Policy manager instance
        tool_id: Tool identifier
        value: Return value to process
        user_context: Optional user context (for error messages)
        
    Returns:
        Processed (validated and sanitized) value
        
    Raises:
        PermissionDeniedError: If validation fails
    """
    overall_start = time.perf_counter()
    
    get_conditions = getattr(manager, "get_tool_conditions", None)
    if not callable(get_conditions):
        return value

    try:
        conditions = await get_conditions(tool_id)
    except TypeError:
        conditions = get_conditions(tool_id)

    if not conditions:
        return value
    
    # Track feature usage
    try:
        feature_usage_total.add(1, {"feature": "output_guardrails", "enabled": "true"})
    except Exception:
        pass

    # Phase 1: Validation (pure constraint checking)
    validation_start = time.perf_counter()
    validation_result = _OUTPUT_VALIDATOR.validate(conditions, value)
    validation_duration_ms = (time.perf_counter() - validation_start) * 1000.0
    
    # Record validation latency (OTEL metric)
    guardrail_latency_ms.record(validation_duration_ms, {
        "type": "output_validation",
        "tool_id": tool_id,
        "result": "allowed" if validation_result.allowed else "denied"
    })
    
    # Send to D2 cloud for performance analytics
    try:
        reporter = getattr(manager, "_usage_reporter", None)
        if reporter:
            reporter.track_event(
                "guardrail_overhead",
                {
                    "tool_id": tool_id,
                    "guardrail_type": "output_validation",
                    "overhead_ms": validation_duration_ms,
                    "result": "allowed" if validation_result.allowed else "denied",
                }
            )
    except Exception:
        pass
    
    if not validation_result.allowed:
        context = user_context
        if context is None:
            context = get_user_context()

        # Build denial reason from validation violations
        reasons = [v.message for v in validation_result.violations]
        reason = "Output validation failed:\n" + "\n".join(f"- {r}" for r in reasons)
        
        # Track denial telemetry
        try:
            # OTEL metrics for observability
            authz_denied_reason_total.add(1, {"reason": "output_validation", "mode": manager.mode})
            user_violation_attempts_total.add(1, {
                "user_id": context.user_id if context else "unknown",
                "violation_type": "output_validation",
            })
            
            # D2 cloud event for security analytics
            reporter = getattr(manager, "_usage_reporter", None)
            if reporter:
                reporter.track_event(
                    "authz_decision",
                    {
                        "tool_id": tool_id,
                        "result": "denied",
                        "reason": "output_validation_failed",
                        "mode": manager.mode,
                        "violation_count": len(validation_result.violations),
                        "violations": reasons,
                    }
                )
        except Exception:
            pass

        raise PermissionDeniedError(
            tool_id=tool_id,
            user_id=context.user_id if context else "unknown",
            roles=context.roles if context else [],
            reason=reason,
        )

    # Phase 2: Sanitization (transformation/filtering)
    sanitization_start = time.perf_counter()
    sanitization_result = _OUTPUT_SANITIZER.sanitize(conditions, value)
    sanitization_duration_ms = (time.perf_counter() - sanitization_start) * 1000.0
    
    # Record sanitization latency (OTEL metric)
    guardrail_latency_ms.record(sanitization_duration_ms, {
        "type": "output_sanitization",
        "tool_id": tool_id,
        "result": "completed"
    })
    
    # Send timing to D2 cloud for performance analytics (always)
    try:
        reporter = getattr(manager, "_usage_reporter", None)
        if reporter:
            reporter.track_event(
                "guardrail_overhead",
                {
                    "tool_id": tool_id,
                    "guardrail_type": "output_sanitization",
                    "overhead_ms": sanitization_duration_ms,
                    "result": "completed",
                }
            )
    except Exception:
        pass
    
    # Send modification event to D2 cloud if sanitization actually modified the output
    if sanitization_result.modified:
        try:
            context = user_context if user_context else get_user_context()
            reporter = getattr(manager, "_usage_reporter", None)
            if reporter:
                reporter.track_event(
                    "output_sanitized",
                    {
                        "tool_id": tool_id,
                        "modified": True,
                        "fields_modified": sanitization_result.fields_modified,
                        "actions_applied": sanitization_result.actions_applied,
                        "field_count": len(sanitization_result.fields_modified),
                    }
                )
        except Exception:
            pass

    return sanitization_result.value




__all__ = [
    "apply_output_filters",
    "get_output_validator",
    "get_output_sanitizer",
]



