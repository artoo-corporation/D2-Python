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

from typing import Any, Final

from ..context import get_user_context
from ..exceptions import PermissionDeniedError
from ..validation.output import OutputValidator
from ..sanitization.output import OutputSanitizer

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
    get_conditions = getattr(manager, "get_tool_conditions", None)
    if not callable(get_conditions):
        return value

    try:
        conditions = await get_conditions(tool_id)
    except TypeError:
        conditions = get_conditions(tool_id)

    if not conditions:
        return value

    # Phase 1: Validation (pure constraint checking)
    validation_result = _OUTPUT_VALIDATOR.validate(conditions, value)
    if not validation_result.allowed:
        context = user_context
        if context is None:
            context = get_user_context()

        # Build denial reason from validation violations
        reasons = [v.message for v in validation_result.violations]
        reason = "Output validation failed:\n" + "\n".join(f"- {r}" for r in reasons)

        raise PermissionDeniedError(
            tool_id=tool_id,
            user_id=context.user_id if context else "unknown",
            roles=context.roles if context else [],
            reason=reason,
        )

    # Phase 2: Sanitization (transformation/filtering)
    sanitization_result = _OUTPUT_SANITIZER.sanitize(conditions, value)

    return sanitization_result.value




__all__ = [
    "apply_output_filters",
    "get_output_validator",
    "get_output_sanitizer",
]



