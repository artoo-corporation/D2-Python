# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""Output sanitization - transforms return values to remove/redact sensitive data.

This module provides OutputSanitizer for applying field actions (filter/redact/truncate/deny)
to transform sensitive data before returning it to callers.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, MutableSequence, Sequence, Tuple

from ..validation.base import ValidationContext, ValidationResult
from ..validation.constraints import ConstraintEvaluator

REDACTED_TOKEN = "[REDACTED]"


# ==============================================================================
# OUTPUT SANITIZATION (Transform via field actions)
# ==============================================================================


@dataclass
class SanitizationResult:
    """Represents the outcome of applying output sanitization.
    
    Hard denials are enforced earlier by OutputValidator.
    Sanitization only transforms data (filter/redact/truncate).
    """

    value: Any
    modified: bool
    fields_modified: list[str] = None  # Fields that were sanitized
    actions_applied: dict[str, str] = None  # field_name -> action_type
    
    def __post_init__(self):
        if self.fields_modified is None:
            self.fields_modified = []
        if self.actions_applied is None:
            self.actions_applied = {}


class OutputSanitizer:
    """Apply transformation actions to sanitize sensitive output data.
    
    Output sanitization transforms return values using field actions:
    - action: filter → Remove field entirely
    - action: redact → Replace value with [REDACTED] (or pattern substitute)
    - action: truncate → Limit length (strings/arrays)
    
    Hard denials are enforced earlier by :class:`OutputValidator`.
    
    Actions can be conditional (only trigger on constraint violation):
    - {salary: {max: 100000, action: redact}} → only redact if > 100000
    - {score: {max: 100, action: filter}} → only remove if > 100
    
    Returns SanitizationResult with:
    - value: Transformed output (or original if no actions triggered)
    - modified: Whether any transformations were applied
    - fields_modified: List of field names that were sanitized
    - actions_applied: Dictionary mapping field names to action types
    
    Example:
        ```python
        sanitizer = OutputSanitizer()
        result = sanitizer.sanitize(
            {"output": {
                "ssn": {"action": "filter"},
                "salary": {"max": 100000, "action": "redact"}
            }},
            {"name": "Alice", "ssn": "123-45-6789", "salary": 150000}
        )
        # result.value == {"name": "Alice", "salary": "[REDACTED]"}
        # result.modified == True
        # result.fields_modified == ["ssn", "salary"]
        # result.actions_applied == {"ssn": "filter", "salary": "redact"}
        ```
    """

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

    def __init__(self) -> None:
        self._constraints = ConstraintEvaluator()

    def sanitize(self, policy_conditions: Any, value: Any) -> SanitizationResult:
        """Apply sanitization rules (field actions) to output value.
        
        Args:
            policy_conditions: Policy conditions dict or list
            value: The return value to sanitize
            
        Returns:
            SanitizationResult with transformed value and metadata
        """
        if not policy_conditions:
            return SanitizationResult(value=value, modified=False)

        if isinstance(policy_conditions, Sequence) and not isinstance(policy_conditions, (str, bytes, bytearray)):
            current = value
            modified = False
            all_fields_modified: list[str] = []
            all_actions_applied: dict[str, str] = {}
            
            for condition in policy_conditions:
                result = self.sanitize(condition, current)
                current = result.value
                modified = modified or result.modified
                if result.modified:
                    all_fields_modified.extend(result.fields_modified)
                    all_actions_applied.update(result.actions_applied)
            
            return SanitizationResult(
                value=current, 
                modified=modified,
                fields_modified=all_fields_modified,
                actions_applied=all_actions_applied
            )

        if isinstance(policy_conditions, Mapping):
            if "output" in policy_conditions:
                rules = policy_conditions.get("output") or {}
            elif "input" in policy_conditions and "output" not in policy_conditions:
                return SanitizationResult(value=value, modified=False)
            else:
                rules = policy_conditions
        else:
            return SanitizationResult(value=value, modified=False)

        if not isinstance(rules, Mapping) or not rules:
            return SanitizationResult(value=value, modified=False)

        current = value
        modified = False
        fields_modified: list[str] = []
        actions_applied: dict[str, str] = {}

        # Apply field-level actions
        field_rules = self._extract_field_rules(rules)
        if field_rules:
            current, changed, fields, actions = self._apply_field_rules(current, field_rules)
            modified = modified or changed
            if changed:
                fields_modified.extend(fields)
                actions_applied.update(actions)

        return SanitizationResult(
            value=current, 
            modified=modified,
            fields_modified=fields_modified,
            actions_applied=actions_applied
        )

    # ------------------------------------------------------------------
    # Field transformation helpers
    # ------------------------------------------------------------------

    def _filter_fields(self, value: Any, fields: Iterable[str]) -> Tuple[Any, bool]:
        fields_set = set(fields)
        if not fields_set:
            return value, False

        if isinstance(value, Mapping):
            modified = False
            new_mapping = {}
            for key, item in value.items():
                if key in fields_set:
                    # Filter this field out
                    modified = True
                else:
                    # Keep the field, but recurse into its value
                    filtered_value, changed = self._filter_fields(item, fields_set)
                    new_mapping[key] = filtered_value
                    modified = modified or changed
            return new_mapping, modified

        if self._is_sequence(value):
            modified = False
            filtered_items = []
            for item in value:
                filtered, changed = self._filter_fields(item, fields_set)
                filtered_items.append(filtered)
                modified = modified or changed
            return self._rebuild_sequence(value, filtered_items), modified

        return value, False

    def _redact_fields(self, value: Any, fields: Iterable[str]) -> Tuple[Any, bool]:
        fields_set = set(fields)
        if not fields_set:
            return value, False

        if isinstance(value, Mapping):
            modified = False
            new_mapping = {}
            for key, item in value.items():
                if key in fields_set and item != REDACTED_TOKEN:
                    new_mapping[key] = REDACTED_TOKEN
                    modified = True
                else:
                    # Recurse into the value even if this key isn't being redacted
                    redacted_value, changed = self._redact_fields(item, fields_set)
                    new_mapping[key] = redacted_value
                    modified = modified or changed
            return new_mapping, modified

        if self._is_sequence(value):
            modified = False
            redacted_items = []
            for item in value:
                redacted, changed = self._redact_fields(item, fields_set)
                redacted_items.append(redacted)
                modified = modified or changed
            return self._rebuild_sequence(value, redacted_items), modified

        return value, False

    def _redact_field_pattern(self, value: Any, field: str, pattern: str) -> Tuple[Any, bool]:
        """Redact matching pattern within a specific field."""
        compiled_pattern = re.compile(str(pattern))

        def _redact_in_value(val: Any) -> Tuple[Any, bool]:
            if isinstance(val, Mapping):
                modified = False
                new_mapping = {}
                for key, item in val.items():
                    if key == field and isinstance(item, str):
                        # Apply pattern substitution to this field
                        redacted, count = compiled_pattern.subn(REDACTED_TOKEN, item)
                        if count > 0:
                            if redacted.startswith(REDACTED_TOKEN):
                                new_mapping[key] = REDACTED_TOKEN
                            else:
                                new_mapping[key] = redacted
                            modified = True
                        else:
                            new_mapping[key] = item
                    else:
                        # Recurse into nested structures
                        redacted_value, changed = _redact_in_value(item)
                        new_mapping[key] = redacted_value
                        modified = modified or changed
                return new_mapping, modified

            if self._is_sequence(val):
                modified = False
                redacted_items = []
                for item in val:
                    redacted, changed = _redact_in_value(item)
                    redacted_items.append(redacted)
                    modified = modified or changed
                return self._rebuild_sequence(val, redacted_items), modified

            return val, False

        return _redact_in_value(value)

    def _redact_patterns(self, value: Any, patterns: Iterable[str]) -> Tuple[Any, bool]:
        compiled = self._ensure_patterns(patterns)
        if not compiled:
            return value, False

        return self._apply_patterns(value, compiled)

    def _truncate_sequence(self, value: Any, max_items: int) -> Tuple[Any, bool]:
        if max_items < 0 or not self._is_sequence(value):
            return value, False

        sequence: Sequence[Any] = value  # type: ignore[assignment]
        if len(sequence) <= max_items:
            return value, False

        truncated = sequence[:max_items]
        return self._rebuild_sequence(value, truncated), True

    def _truncate_string(self, value: Any, max_length: int) -> Tuple[Any, bool]:
        if max_length < 0 or not isinstance(value, str):
            return value, False

        if len(value) <= max_length:
            return value, False

        return value[:max_length], True

    @staticmethod
    def _is_sequence(value: Any) -> bool:
        return isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray))

    @staticmethod
    def _rebuild_sequence(original: Sequence[Any], items: Iterable[Any]) -> Any:
        if isinstance(original, tuple):
            return tuple(items)
        if isinstance(original, list):
            return list(items)
        if isinstance(original, MutableSequence):
            return type(original)(items)
        return list(items)

    @staticmethod
    def _ensure_patterns(patterns: Iterable[Any]) -> Tuple[re.Pattern[str], ...]:
        compiled = []
        for pattern in patterns:
            if isinstance(pattern, re.Pattern):
                compiled.append(pattern)
            else:
                compiled.append(re.compile(str(pattern)))
        return tuple(compiled)

    def _apply_patterns(self, value: Any, patterns: Sequence[re.Pattern[str]]) -> Tuple[Any, bool]:
        if isinstance(value, str):
            original = value
            modified = False
            for pattern in patterns:
                value, count = pattern.subn(REDACTED_TOKEN, value)
                if count > 0:
                    modified = True
                    if value.startswith(REDACTED_TOKEN):
                        return REDACTED_TOKEN, True
            return value, modified

        if isinstance(value, Mapping):
            modified = False
            new_mapping = {}
            for key, item in value.items():
                redacted, changed = self._apply_patterns(item, patterns)
                new_mapping[key] = redacted
                modified = modified or changed
            return new_mapping, modified

        if self._is_sequence(value):
            modified = False
            redacted_items = []
            for item in value:
                redacted, changed = self._apply_patterns(item, patterns)
                redacted_items.append(redacted)
                modified = modified or changed
            return self._rebuild_sequence(value, redacted_items), modified

        return value, False

    # ------------------------------------------------------------------
    # Field rule helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_field_rules(rules: Mapping[str, Any]) -> Mapping[str, Mapping[str, Any]]:
        """Extract field rules that have an 'action' keyword."""
        field_rules: dict[str, Mapping[str, Any]] = {}
        for key, value in rules.items():
            if isinstance(value, Mapping) and value.get("action"):
                field_rules[key] = value
        return field_rules

    def _apply_field_rules(
        self,
        value: Any,
        field_rules: Mapping[str, Mapping[str, Any]],
    ) -> Tuple[Any, bool, list[str], dict[str, str]]:
        """Apply field-level sanitization rules and track what was modified.
        
        Returns:
            Tuple of (modified_value, was_modified, fields_modified, actions_applied)
        """
        if not field_rules:
            return value, False, [], {}

        current = value
        modified = False
        fields_modified: list[str] = []
        actions_applied: dict[str, str] = {}

        for field, rule in field_rules.items():
            action = (rule.get("action") or "").lower()
            trigger, reason = self._should_trigger_field(current, field, rule)

            if not trigger:
                continue

            if action == "deny":
                continue

            if action == "filter":
                current, changed = self._filter_fields(current, [field])
                if changed:
                    modified = True
                    fields_modified.append(field)
                    actions_applied[field] = "filter"
                continue

            if action == "redact":
                # Check if this is pattern-based redaction
                if "matches" in rule:
                    # Pattern-based: substitute matching portions
                    current, changed = self._redact_field_pattern(current, field, rule["matches"])
                    if changed:
                        modified = True
                        fields_modified.append(field)
                        actions_applied[field] = "redact_pattern"
                else:
                    # Field-based: redact entire field value
                    current, changed = self._redact_fields(current, [field])
                    if changed:
                        modified = True
                        fields_modified.append(field)
                        actions_applied[field] = "redact"
                continue

            if action == "truncate":
                current, changed = self._truncate_field(current, field, rule)
                if changed:
                    modified = True
                    fields_modified.append(field)
                    actions_applied[field] = "truncate"
                continue

        return current, modified, fields_modified, actions_applied

    def _should_trigger_field(
        self,
        value: Any,
        field: str,
        rule: Mapping[str, Any],
    ) -> Tuple[bool, str | None]:
        action = (rule.get("action") or "").lower()
        conditions = {k: v for k, v in rule.items() if k != "action"}

        if not conditions:
            if action == "deny":
                return self._field_exists(value, field), f"Field '{field}' is not allowed."
            return self._field_exists(value, field), None

        value_present, field_value = self._resolve_field_value(value, field)
        if not value_present:
            return False, None

        trigger = False
        reason: str | None = None

        violation_rules = {k: v for k, v in conditions.items() if k in self._VIOLATION_OPERATORS}
        if violation_rules:
            evaluation = self._constraints.evaluate(
                violation_rules,
                value_present=True,
                value=field_value,
                context=ValidationContext(argument=field, arguments={field: field_value}),
                operators=self._VIOLATION_OPERATORS,
            )
            if not evaluation.result.allowed:
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

        return trigger, reason

    def _resolve_field_value(self, value: Any, field: str) -> Tuple[bool, Any]:
        if isinstance(value, Mapping):
            if field in value:
                return True, value[field]
            # Recurse into nested values to find the field
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

    def _field_exists(self, value: Any, field: str) -> bool:
        present, _ = self._resolve_field_value(value, field)
        return present

    def _truncate_field(
        self,
        value: Any,
        field: str,
        rule: Mapping[str, Any],
    ) -> Tuple[Any, bool]:
        max_length = rule.get("maxLength")

        if max_length is None:
            return value, False

        def _truncate_item(item: Any) -> Tuple[Any, bool]:
            if isinstance(item, str):
                return self._truncate_string(item, int(max_length))
            if self._is_sequence(item):
                return self._truncate_sequence(item, int(max_length))
            return item, False

        if isinstance(value, Mapping):
            if field not in value:
                return value, False
            truncated, changed = _truncate_item(value[field])
            if not changed:
                return value, False
            new_mapping = dict(value)
            new_mapping[field] = truncated
            return new_mapping, True

        if self._is_sequence(value):
            changed = False
            updated_items = []
            for item in value:
                updated, item_changed = self._truncate_field(item, field, rule)
                updated_items.append(updated)
                changed = changed or item_changed
            if not changed:
                return value, False
            return self._rebuild_sequence(value, updated_items), True

        return value, False

    # ------------------------------------------------------------------
    # Detection handlers
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Denial helpers
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

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
    def _is_comparable_number(value: Any) -> bool:
        return isinstance(value, (int, float)) and not isinstance(value, bool)


__all__ = [
    "OutputSanitizer",
    "SanitizationResult",
    "REDACTED_TOKEN",
]
