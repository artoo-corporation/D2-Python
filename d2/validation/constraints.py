# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""Shared constraint evaluation utilities for declarative rules."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Optional, Sequence

from .base import ValidationContext, ValidationResult, ValidationViolation


@dataclass
class ConstraintEvaluation:
    """Result of evaluating a single value against declarative constraints."""

    result: ValidationResult
    type_failed: bool = False


class ConstraintEvaluator:
    """Evaluate declarative constraint rules for a single value."""

    _ORDERED_OPERATORS: Sequence[str] = (
        "required",
        "type",
        "eq",
        "ne",
        "in",
        "not_in",
        "min",
        "max",
        "gt",
        "lt",
        "startsWith",
        "endsWith",
        "contains",
        "not_contains",
        "matches",
        "not_matches",
        "minLength",
        "maxLength",
        "max_bytes",
    )

    def __init__(self):
        self._operator_set = set(self._ORDERED_OPERATORS)

    def evaluate(
        self,
        rules: Mapping[str, Any],
        *,
        value_present: bool,
        value: Any,
        context: ValidationContext,
        operators: Optional[Iterable[str]] = None,
    ) -> ConstraintEvaluation:
        """Evaluate *rules* against the provided value.

        Args:
            rules: Mapping of operator name → expected value.
            value_present: Whether the argument was provided.
            value: Actual value to validate.
            context: ValidationContext describing the argument.
            operators: Optional whitelist of operators to evaluate.

        Returns:
            ConstraintEvaluation containing the ValidationResult and whether
            type validation failed (used for short-circuiting additional checks).
            
        Raises:
            ConfigurationError: If rules contain unknown operators.
        """
        from ..exceptions import ConfigurationError

        allowed_ops = set(operators) if operators is not None else None
        
        # Validate all operators are known before evaluation (security: catch typos)
        unknown_ops = []
        for operator in rules.keys():
            # Skip if restricted by whitelist
            if allowed_ops is not None and operator not in allowed_ops:
                continue
            # Check if operator exists
            if operator not in self._operator_set:
                handler = getattr(self, f"_check_{operator}", None)
                if handler is None:
                    unknown_ops.append(operator)
        
        if unknown_ops:
            valid_ops = ", ".join(sorted(self._ORDERED_OPERATORS))
            raise ConfigurationError(
                f"Unknown operator(s) for argument '{context.argument}': {', '.join(sorted(unknown_ops))}. "
                f"Valid operators: {valid_ops}"
            )

        violations: list[ValidationViolation] = []

        type_failed = False

        # Evaluate operators in deterministic order for stable diagnostics.
        for operator in self._ORDERED_OPERATORS:
            if allowed_ops is not None and operator not in allowed_ops:
                continue
            if operator not in rules:
                continue
            handler = getattr(self, f"_check_{operator}")
            violation = handler(rules[operator], value_present, value, context)
            if violation is not None:
                violations.append(violation)
                if operator == "type":
                    type_failed = True
                    break

        return ConstraintEvaluation(
            result=ValidationResult(allowed=not violations, violations=violations),
            type_failed=type_failed,
        )

    # ------------------------------------------------------------------
    # Operator handlers (mirrors InputValidator semantics)
    # ------------------------------------------------------------------

    def _check_required(
        self,
        expected: Any,
        value_present: bool,
        value: Any,
        context: ValidationContext,
    ) -> Optional[ValidationViolation]:
        if not expected:
            return None

        missing = (not value_present) or value is None
        if missing:
            return ValidationViolation(
                argument=context.argument,
                operator="required",
                expected=True,
                actual=None,
                message=f"Argument '{context.argument}' is required but missing.",
            )
        return None

    def _check_type(
        self,
        expected: Any,
        value_present: bool,
        value: Any,
        context: ValidationContext,
    ) -> Optional[ValidationViolation]:
        if not value_present or value is None:
            return None

        expected_types = expected if isinstance(expected, (list, tuple, set)) else [expected]
        resolved = [self._resolve_type_name(t) for t in expected_types]

        for type_name in resolved:
            if self._value_matches_type(value, type_name):
                return None

        return ValidationViolation(
            argument=context.argument,
            operator="type",
            expected=expected if isinstance(expected, (list, tuple, set)) else expected,
            actual=value,
            message=(
                f"Argument '{context.argument}' must be of type {resolved}, "
                f"got value {value!r} (type {type(value).__name__})."
            ),
        )

    def _check_eq(self, expected, value_present, value, context):
        if not value_present:
            return None
        if value == expected:
            return None
        return ValidationViolation(
            argument=context.argument,
            operator="eq",
            expected=expected,
            actual=value,
            message=f"Argument '{context.argument}' must equal {expected!r}, got {value!r}.",
        )

    def _check_ne(self, expected, value_present, value, context):
        if not value_present:
            return None
        if value != expected:
            return None
        return ValidationViolation(
            argument=context.argument,
            operator="ne",
            expected=expected,
            actual=value,
            message=f"Argument '{context.argument}' must not equal {expected!r}.",
        )

    def _check_in(self, expected, value_present, value, context):
        if not value_present:
            return None
        collection = list(expected) if isinstance(expected, Iterable) and not isinstance(expected, str) else [expected]
        if value in collection:
            return None
        return ValidationViolation(
            argument=context.argument,
            operator="in",
            expected=collection,
            actual=value,
            message=(
                f"Argument '{context.argument}' must be one of {collection!r}, got {value!r}."
            ),
        )

    def _check_not_in(self, expected, value_present, value, context):
        if not value_present:
            return None
        collection = list(expected) if isinstance(expected, Iterable) and not isinstance(expected, str) else [expected]
        if value not in collection:
            return None
        return ValidationViolation(
            argument=context.argument,
            operator="not_in",
            expected=collection,
            actual=value,
            message=f"Argument '{context.argument}' must not be one of {collection!r}.",
        )

    def _check_min(self, expected, value_present, value, context):
        if not value_present:
            return None
        if not self._is_comparable_number(value):
            return self._numeric_type_violation("min", expected, value, context)
        if value >= expected:
            return None
        return ValidationViolation(
            argument=context.argument,
            operator="min",
            expected=expected,
            actual=value,
            message=f"Argument '{context.argument}' must be ≥ {expected}, got {value}.",
        )

    def _check_max(self, expected, value_present, value, context):
        if not value_present:
            return None
        if not self._is_comparable_number(value):
            return self._numeric_type_violation("max", expected, value, context)
        if value <= expected:
            return None
        return ValidationViolation(
            argument=context.argument,
            operator="max",
            expected=expected,
            actual=value,
            message=f"Argument '{context.argument}' must be ≤ {expected}, got {value}.",
        )

    def _check_gt(self, expected, value_present, value, context):
        if not value_present:
            return None
        if not self._is_comparable_number(value):
            return self._numeric_type_violation("gt", expected, value, context)
        if value > expected:
            return None
        return ValidationViolation(
            argument=context.argument,
            operator="gt",
            expected=expected,
            actual=value,
            message=f"Argument '{context.argument}' must be > {expected}, got {value}.",
        )

    def _check_lt(self, expected, value_present, value, context):
        if not value_present:
            return None
        if not self._is_comparable_number(value):
            return self._numeric_type_violation("lt", expected, value, context)
        if value < expected:
            return None
        return ValidationViolation(
            argument=context.argument,
            operator="lt",
            expected=expected,
            actual=value,
            message=f"Argument '{context.argument}' must be < {expected}, got {value}.",
        )

    def _check_startsWith(self, expected, value_present, value, context):  # noqa: N802
        if not value_present:
            return None
        if not isinstance(value, str):
            return self._string_type_violation("startsWith", expected, value, context)
        if value.startswith(expected):
            return None
        return ValidationViolation(
            argument=context.argument,
            operator="startsWith",
            expected=expected,
            actual=value,
            message=f"Argument '{context.argument}' must start with {expected!r}, got {value!r}.",
        )

    def _check_endsWith(self, expected, value_present, value, context):  # noqa: N802
        if not value_present:
            return None
        if not isinstance(value, str):
            return self._string_type_violation("endsWith", expected, value, context)
        if value.endswith(expected):
            return None
        return ValidationViolation(
            argument=context.argument,
            operator="endsWith",
            expected=expected,
            actual=value,
            message=f"Argument '{context.argument}' must end with {expected!r}, got {value!r}.",
        )

    def _check_contains(self, expected, value_present, value, context):
        if not value_present:
            return None
        if isinstance(value, str):
            contains = expected in value
        elif isinstance(value, (list, tuple, set)):
            contains = expected in value
        else:
            return self._string_type_violation("contains", expected, value, context)
        if contains:
            return None
        return ValidationViolation(
            argument=context.argument,
            operator="contains",
            expected=expected,
            actual=value,
            message=f"Argument '{context.argument}' must contain {expected!r}.",
        )

    def _check_not_contains(self, expected, value_present, value, context):
        if not value_present:
            return None
        if isinstance(value, str):
            contains = expected in value
        elif isinstance(value, (list, tuple, set)):
            contains = expected in value
        else:
            return self._string_type_violation("not_contains", expected, value, context)
        if not contains:
            return None
        return ValidationViolation(
            argument=context.argument,
            operator="not_contains",
            expected=expected,
            actual=value,
            message=f"Argument '{context.argument}' must not contain {expected!r}.",
        )

    def _check_matches(self, expected, value_present, value, context):
        if not value_present:
            return None
        if not isinstance(value, str):
            return self._string_type_violation("matches", expected, value, context)
        pattern = re.compile(expected)
        if pattern.fullmatch(value):
            return None
        return ValidationViolation(
            argument=context.argument,
            operator="matches",
            expected=expected,
            actual=value,
            message=f"Argument '{context.argument}' must match regex {expected!r}.",
        )

    def _check_not_matches(self, expected, value_present, value, context):
        """Validate that a string does NOT match a regex pattern.
        
        Uses re.search() (not fullmatch) to detect forbidden patterns anywhere
        in the value. This is useful for blocking sensitive data patterns like
        SSNs, credit card numbers, etc.
        """
        if not value_present:
            return None
        if not isinstance(value, str):
            return self._string_type_violation("not_matches", expected, value, context)
        pattern = re.compile(expected)
        if not pattern.search(value):
            return None
        return ValidationViolation(
            argument=context.argument,
            operator="not_matches",
            expected=expected,
            actual="[value contains forbidden pattern]",
            message=f"Argument '{context.argument}' must not match regex {expected!r}.",
        )

    def _check_minLength(self, expected, value_present, value, context):  # noqa: N802
        if not value_present or value is None:
            return None
        if not hasattr(value, "__len__"):
            return ValidationViolation(
                argument=context.argument,
                operator="minLength",
                expected=expected,
                actual=value,
                message=f"Argument '{context.argument}' does not have a length for minLength validation.",
            )
        if len(value) >= expected:  # type: ignore[arg-type]
            return None
        return ValidationViolation(
            argument=context.argument,
            operator="minLength",
            expected=expected,
            actual=len(value),
            message=(
                f"Argument '{context.argument}' length must be ≥ {expected}, got {len(value)}."
            ),
        )

    def _check_maxLength(self, expected, value_present, value, context):  # noqa: N802
        if not value_present or value is None:
            return None
        if not hasattr(value, "__len__"):
            return ValidationViolation(
                argument=context.argument,
                operator="maxLength",
                expected=expected,
                actual=value,
                message=f"Argument '{context.argument}' does not have a length for maxLength validation.",
            )
        if len(value) <= expected:  # type: ignore[arg-type]
            return None
        return ValidationViolation(
            argument=context.argument,
            operator="maxLength",
            expected=expected,
            actual=len(value),
            message=(
                f"Argument '{context.argument}' length must be ≤ {expected}, got {len(value)}."
            ),
        )

    def _check_max_bytes(self, expected, value_present, value, context):
        """Validate that a value's byte size doesn't exceed the limit.
        
        This is distinct from maxLength which counts characters/items.
        For UTF-8 strings, a single character can be 1-4 bytes.
        Useful for limiting payload sizes in network requests.
        """
        if not value_present or value is None:
            return None
        
        # Calculate byte size based on type
        if isinstance(value, str):
            byte_size = len(value.encode("utf-8"))
        elif isinstance(value, bytes):
            byte_size = len(value)
        else:
            # For other types, try JSON serialization as a reasonable estimate
            import json
            try:
                byte_size = len(json.dumps(value).encode("utf-8"))
            except (TypeError, ValueError):
                return ValidationViolation(
                    argument=context.argument,
                    operator="max_bytes",
                    expected=expected,
                    actual=value,
                    message=f"Argument '{context.argument}' cannot be measured in bytes.",
                )
        
        if byte_size <= expected:
            return None
        return ValidationViolation(
            argument=context.argument,
            operator="max_bytes",
            expected=expected,
            actual=byte_size,
            message=(
                f"Argument '{context.argument}' byte size must be ≤ {expected}, got {byte_size}."
            ),
        )

    # ------------------------------------------------------------------
    # Helper utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_type_name(type_def: Any) -> str:
        if isinstance(type_def, str):
            return type_def
        if isinstance(type_def, type):
            return type_def.__name__
        raise TypeError(f"Unsupported type definition {type_def!r}")

    @staticmethod
    def _value_matches_type(value: Any, type_name: str) -> bool:
        if type_name == "int":
            return isinstance(value, int) and not isinstance(value, bool)
        if type_name == "float":
            return isinstance(value, float)
        if type_name == "number":
            return isinstance(value, (int, float)) and not isinstance(value, bool)
        if type_name in ("str", "string"):
            return isinstance(value, str)
        if type_name == "bool":
            return isinstance(value, bool)
        if type_name == "list":
            return isinstance(value, list)
        if type_name == "dict":
            return isinstance(value, dict)
        if type_name == "set":
            return isinstance(value, set)
        if type_name == "tuple":
            return isinstance(value, tuple)
        if type_name == "none":
            return value is None
        return False

    @staticmethod
    def _is_comparable_number(value: Any) -> bool:
        return isinstance(value, (int, float)) and not isinstance(value, bool)

    @staticmethod
    def _numeric_type_violation(operator: str, expected: Any, value: Any, context: ValidationContext) -> ValidationViolation:
        return ValidationViolation(
            argument=context.argument,
            operator=operator,
            expected=expected,
            actual=value,
            message=(
                f"Argument '{context.argument}' must be numeric for operator '{operator}', got {value!r}."
            ),
        )

    @staticmethod
    def _string_type_violation(operator: str, expected: Any, value: Any, context: ValidationContext) -> ValidationViolation:
        return ValidationViolation(
            argument=context.argument,
            operator=operator,
            expected=expected,
            actual=value,
            message=(
                f"Argument '{context.argument}' must be a string or sequence for operator '{operator}',"
                f" got {value!r}."
            ),
        )


__all__ = [
    "ConstraintEvaluator",
    "ConstraintEvaluation",
]


