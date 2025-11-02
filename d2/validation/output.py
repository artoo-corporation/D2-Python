# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""Output validation - validates return values against declarative constraints.

This module provides OutputValidator for checking function return values after execution.
It uses the shared ConstraintEvaluator to validate outputs against declarative rules.

Output validation is symmetric with input validation:
- InputValidator: checks arguments BEFORE function runs
- OutputValidator: checks return value AFTER function runs
- Both use the same constraint operators
- Both return ValidationResult
"""

from __future__ import annotations

import json
import re
from typing import Any, Mapping, Optional, Sequence, Tuple, Iterable

from .base import ValidationContext, ValidationResult, ValidationViolation
from .constraints import ConstraintEvaluator


class OutputValidator:
    """Validate output against declarative constraints (mirrors InputValidator).
    
    Output validation checks that return values satisfy specified constraints:
    - type, required, min, max, in, matches, minLength, maxLength, etc.
    - Returns ValidationResult (allowed: true/false + violations)
    - NEVER modifies the value
    - Denies (returns allowed=False) if any constraint violated
    
    This is the symmetric counterpart to InputValidator:
    - Input: validates arguments before function execution
    - Output: validates return value after function execution
    
    Example:
        ```python
        validator = OutputValidator()
        result = validator.validate(
            {"output": {
                "status": {"required": True, "in": ["ok", "error"]},
                "count": {"type": "int", "min": 0, "max": 1000}
            }},
            {"status": "ok", "count": 42}
        )
        assert result.allowed is True
        ```
    """

    def __init__(self):
        self._evaluator = ConstraintEvaluator()

    def validate(self, policy_conditions: Optional[Any], value: Any) -> ValidationResult:
        """Validate output value against declarative constraint rules.
        
        Args:
            policy_conditions: Policy conditions dict or list
            value: The return value to validate
            
        Returns:
            ValidationResult with allowed flag and any violations
        """
        if not policy_conditions:
            return ValidationResult(allowed=True)

        if isinstance(policy_conditions, Sequence) and not isinstance(policy_conditions, (str, bytes, bytearray)):
            aggregated = ValidationResult(allowed=True)
            for condition in policy_conditions:
                result = self.validate(condition, value)
                aggregated.merge(result)
            return aggregated

        # Accept either {"output": {...}} or direct mapping of field conditions
        if isinstance(policy_conditions, Mapping):
            if "output" in policy_conditions:
                output_rules = policy_conditions["output"] or {}
            elif "input" in policy_conditions and "output" not in policy_conditions:
                # Only input rules, no output validation
                return ValidationResult(allowed=True)
            else:
                output_rules = policy_conditions
        else:
            return ValidationResult(allowed=True)

        if not isinstance(output_rules, Mapping) or not output_rules:
            return ValidationResult(allowed=True)

        combined = ValidationResult(allowed=True)

        # Validate each field that has constraint operators (no 'action' keyword)
        for field_name, rules in output_rules.items():
            # Skip global rules (not field-level constraints)
            if field_name in ("require_fields_absent", "deny_if_patterns", "max_bytes"):
                continue

            if not isinstance(rules, Mapping):
                continue

            # Handle deny actions at validation time
            action = (rules.get("action") or "").lower()
            if action == "deny":
                trigger, message = self._should_deny_field(value, field_name, rules)
                if trigger:
                    violation = self._make_violation(field_name, "deny", message)
                    combined.merge(ValidationResult(allowed=False, violations=[violation]))
                continue

            # Skip other actions (filter/redact/truncate) – sanitization handles those
            if "action" in rules:
                continue

            # This is a pure validation rule (no action)
            context = ValidationContext(argument=field_name, arguments={field_name: None})
            value_present, field_value = self._resolve_field_value(value, field_name)

            evaluation = self._evaluator.evaluate(
                rules,
                value_present=value_present,
                value=field_value,
                context=context,
            )
            combined.merge(evaluation.result)

        # Evaluate global denial rules
        for violation in self._evaluate_global_rules(output_rules, value):
            combined.merge(ValidationResult(allowed=False, violations=[violation]))

        return combined

    def _evaluate_global_rules(self, rules: Mapping[str, Any], value: Any) -> Iterable[ValidationViolation]:
        if "require_fields_absent" in rules:
            reason = self._require_fields_absent(value, rules["require_fields_absent"])
            if reason:
                yield self._make_violation("output", "require_fields_absent", reason)

        if "deny_if_patterns" in rules:
            reason = self._deny_if_patterns(value, rules["deny_if_patterns"])
            if reason:
                yield self._make_violation("output", "deny_if_patterns", reason)

        if "max_bytes" in rules:
            reason = self._enforce_max_bytes(value, int(rules["max_bytes"]))
            if reason:
                yield self._make_violation("output", "max_bytes", reason)

    _VIOLATION_OPERATORS = {
        "required",
        "type",
        "min",
        "max",
        "gt",
        "lt",
        "minLength",
        "maxLength",
    }

    def _should_deny_field(self, value: Any, field: str, rule: Mapping[str, Any]) -> Tuple[bool, str | None]:
        conditions = {k: v for k, v in rule.items() if k != "action"}

        if not conditions:
            return (self._field_exists(value, field), f"Field '{field}' is not allowed.")

        value_present, field_value = self._resolve_field_value(value, field)
        if not value_present:
            return False, None

        trigger = False
        reason: str | None = None

        violation_rules = {k: v for k, v in conditions.items() if k in self._VIOLATION_OPERATORS}
        if violation_rules:
            context = ValidationContext(argument=field, arguments={field: field_value})
            evaluation = self._evaluator.evaluate(
                violation_rules,
                value_present=True,
                value=field_value,
                context=context,
                operators=self._VIOLATION_OPERATORS,
            )
            if not evaluation.result.allowed and evaluation.result.violations:
                trigger = True
                reason = evaluation.result.violations[0].message

        for operator, expected in conditions.items():
            if operator in self._VIOLATION_OPERATORS:
                continue
            handler = getattr(self, f"_detect_{operator}", None)
            if handler is None:
                continue
            matched, message = handler(expected, field_value, field)
            if matched:
                trigger = True
                if message:
                    reason = reason or message

        if trigger and not reason:
            reason = f"Field '{field}' triggered deny action."

        return trigger, reason

    def _resolve_field_value(self, value: Any, field: str) -> Tuple[bool, Any]:
        """Find field value in potentially nested structure."""
        if isinstance(value, Mapping):
            # Direct key access
            if field in value:
                return True, value[field]
            
            # Support nested field syntax: "user.name"
            if "." in field:
                parts = field.split(".", 1)
                if parts[0] in value:
                    return self._resolve_field_value(value[parts[0]], parts[1])
            
            # Recurse into nested values
            for nested_value in value.values():
                present, field_value = self._resolve_field_value(nested_value, field)
                if present:
                    return present, field_value
            return False, None

        if self._is_sequence(value):
            for item in value:
                present, field_value = self._resolve_field_value(item, field)
                if present:
                    return present, field_value

        return False, None

    @staticmethod
    def _is_sequence(value: Any) -> bool:
        return isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray))

    def _field_exists(self, value: Any, field: str) -> bool:
        present, _ = self._resolve_field_value(value, field)
        return present

    def _deny_if_patterns(self, value: Any, patterns: Iterable[str]) -> str | None:
        compiled = self._ensure_patterns(patterns)
        if not compiled:
            return None

        for text in self._iter_strings(value):
            for pattern in compiled:
                if pattern.search(text):
                    return f"Output matched forbidden pattern '{pattern.pattern}'."
        return None

    def _require_fields_absent(self, value: Any, fields: Iterable[str]) -> str | None:
        forbidden = set(fields)
        if not forbidden:
            return None

        found = sorted(self._collect_fields(value, forbidden))
        if found:
            return f"Output contains forbidden field(s): {', '.join(found)}."
        return None

    def _enforce_max_bytes(self, value: Any, max_bytes: int) -> str | None:
        if max_bytes < 0:
            return None

        size = self._measure_bytes(value)
        if size > max_bytes:
            return f"Output exceeds max_bytes ({size} > {max_bytes})."
        return None

    def _iter_strings(self, value: Any) -> Iterable[str]:
        if isinstance(value, str):
            yield value
        elif isinstance(value, Mapping):
            for item in value.values():
                yield from self._iter_strings(item)
        elif self._is_sequence(value):
            for item in value:
                yield from self._iter_strings(item)

    def _collect_fields(self, value: Any, forbidden: set[str]) -> set[str]:
        found: set[str] = set()
        if isinstance(value, Mapping):
            for key, item in value.items():
                if key in forbidden:
                    found.add(key)
                found.update(self._collect_fields(item, forbidden))
        elif self._is_sequence(value):
            for item in value:
                found.update(self._collect_fields(item, forbidden))
        return found

    def _measure_bytes(self, value: Any) -> int:
        try:
            serialized = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
        except (TypeError, ValueError):
            serialized = str(value)
        return len(serialized.encode("utf-8"))

    @staticmethod
    def _ensure_patterns(patterns: Iterable[Any]) -> Tuple[re.Pattern[str], ...]:
        compiled = []
        for pattern in patterns:
            if isinstance(pattern, re.Pattern):
                compiled.append(pattern)
            else:
                compiled.append(re.compile(str(pattern)))
        return tuple(compiled)

    def _detect_matches(self, expected: Any, value: Any, field: str) -> Tuple[bool, str | None]:
        if not isinstance(value, str):
            return False, None
        pattern = re.compile(str(expected))
        if pattern.search(value):
            return True, f"Field '{field}' matched forbidden pattern '{pattern.pattern}'."
        return False, None

    def _detect_contains(self, expected: Any, value: Any, field: str) -> Tuple[bool, str | None]:
        if isinstance(value, str) and str(expected) in value:
            return True, f"Field '{field}' contains forbidden value {expected!r}."
        if isinstance(value, (list, tuple, set)) and expected in value:
            return True, f"Field '{field}' contains forbidden value {expected!r}."
        return False, None

    def _detect_in(self, expected: Any, value: Any, field: str) -> Tuple[bool, str | None]:
        collection = list(expected) if isinstance(expected, Iterable) and not isinstance(expected, str) else [expected]
        if value in collection:
            return True, f"Field '{field}' matched restricted value {value!r}."
        return False, None

    def _detect_eq(self, expected: Any, value: Any, field: str) -> Tuple[bool, str | None]:
        if value == expected:
            return True, f"Field '{field}' matched restricted value {expected!r}."
        return False, None

    def _detect_max(self, expected: Any, value: Any, field: str) -> Tuple[bool, str | None]:
        if not self._is_comparable_number(value):
            return False, None
        if value > expected:
            return True, f"Field '{field}' exceeds max {expected}, got {value}."
        return False, None

    def _detect_min(self, expected: Any, value: Any, field: str) -> Tuple[bool, str | None]:
        if not self._is_comparable_number(value):
            return False, None
        if value < expected:
            return True, f"Field '{field}' below minimum {expected}, got {value}."
        return False, None

    def _detect_maxLength(self, expected: Any, value: Any, field: str) -> Tuple[bool, str | None]:  # noqa: N802
        if value is None or not hasattr(value, "__len__"):
            return False, None
        if len(value) > expected:  # type: ignore[arg-type]
            return True, f"Field '{field}' length exceeds {expected}."
        return False, None

    def _detect_minLength(self, expected: Any, value: Any, field: str) -> Tuple[bool, str | None]:  # noqa: N802
        if value is None or not hasattr(value, "__len__"):
            return False, None
        if len(value) < expected:  # type: ignore[arg-type]
            return True, f"Field '{field}' length below {expected}."
        return False, None

    @staticmethod
    def _is_comparable_number(value: Any) -> bool:
        return isinstance(value, (int, float)) and not isinstance(value, bool)

    def _make_violation(self, argument: str, operator: str, message: str) -> ValidationViolation:
        return ValidationViolation(
            argument=argument,
            operator=operator,
            expected=None,
            actual=None,
            message=message,
        )


__all__ = ["OutputValidator"]
