# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""Runtime helpers for declarative input validation."""

from __future__ import annotations

from typing import Final

from ..validation import InputValidator, ValidationResult


_VALIDATOR: Final[InputValidator] = InputValidator()


def get_input_validator() -> InputValidator:
    """Return the process-wide input validator instance."""

    return _VALIDATOR


def format_validation_reason(tool_id: str, validation: ValidationResult) -> str:
    """Produce a human-readable denial reason for validation failures."""

    lines = [f"Input validation failed for tool '{tool_id}':"]
    for violation in validation.violations:
        lines.append(f" - {violation.message}")
    return "\n".join(lines)


__all__ = [
    "format_validation_reason",
    "get_input_validator",
]


