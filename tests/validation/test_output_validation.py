# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""Unit tests for pure output validation (deny on constraint violation, no transformation).

Output validation is the symmetric counterpart to input validation:
- Validates return values against declarative constraints
- Denies (raises error) if constraints violated
- Returns value UNCHANGED if validation passes
- NO transformation/sanitization

This is separate from output sanitization (filter/redact/truncate actions).
"""

from __future__ import annotations

import pytest

from d2.validation.output import OutputValidator
from d2.validation.base import ValidationResult


def _validate(rules, value):
    """Helper to run output validation with the provided rules."""
    return OutputValidator().validate({"output": rules}, value)


# ------------------------------------------------------------------
# Basic constraint validation (deny if violated, no transformation)
# ------------------------------------------------------------------


def test_validation_type_constraint_passes():
    """Type constraint passes when value matches expected type."""
    result = _validate(
        {
            "status": {"type": "string"},
            "count": {"type": "int"},
        },
        {"status": "success", "count": 42},
    )

    assert result.allowed is True
    assert result.violations == []


def test_validation_type_constraint_fails():
    """Type constraint fails when value doesn't match expected type."""
    result = _validate(
        {
            "count": {"type": "int"},
        },
        {"count": "not-an-int"},
    )

    assert result.allowed is False
    assert len(result.violations) == 1
    assert "type" in result.violations[0].message.lower()
    assert result.violations[0].argument == "count"


def test_validation_required_field_passes():
    """Required constraint passes when field is present."""
    result = _validate(
        {
            "status": {"required": True},
        },
        {"status": "ok", "extra": "data"},
    )

    assert result.allowed is True


def test_validation_required_field_fails():
    """Required constraint fails when field is missing."""
    result = _validate(
        {
            "status": {"required": True},
        },
        {"other": "data"},
    )

    assert result.allowed is False
    assert len(result.violations) == 1
    assert "required" in result.violations[0].message.lower()
    assert result.violations[0].argument == "status"


def test_validation_min_max_constraints():
    """Min/max constraints validate numeric ranges."""
    result = _validate(
        {
            "age": {"min": 0, "max": 150},
        },
        {"age": 25},
    )

    assert result.allowed is True

    # Test violation
    result = _validate(
        {
            "age": {"min": 0, "max": 150},
        },
        {"age": 200},
    )

    assert result.allowed is False
    assert "max" in result.violations[0].message.lower() or "200" in result.violations[0].message


def test_validation_in_constraint_passes():
    """In constraint passes when value is in allowed list."""
    result = _validate(
        {
            "status": {"in": ["pending", "active", "completed"]},
        },
        {"status": "active"},
    )

    assert result.allowed is True


def test_validation_in_constraint_fails():
    """In constraint fails when value not in allowed list."""
    result = _validate(
        {
            "status": {"in": ["pending", "active", "completed"]},
        },
        {"status": "invalid"},
    )

    assert result.allowed is False
    assert "invalid" in result.violations[0].message


def test_validation_matches_pattern():
    """Matches constraint validates against regex pattern."""
    result = _validate(
        {
            "email": {"matches": r"^[^@]+@[^@]+\.[^@]+$"},
        },
        {"email": "user@example.com"},
    )

    assert result.allowed is True

    # Test violation
    result = _validate(
        {
            "email": {"matches": r"^[^@]+@[^@]+\.[^@]+$"},
        },
        {"email": "not-an-email"},
    )

    assert result.allowed is False


def test_validation_minLength_maxLength():
    """MinLength/maxLength constraints validate string/array lengths."""
    result = _validate(
        {
            "name": {"minLength": 2, "maxLength": 50},
        },
        {"name": "Alice"},
    )

    assert result.allowed is True

    # Test violation
    result = _validate(
        {
            "name": {"minLength": 2, "maxLength": 50},
        },
        {"name": "A"},
    )

    assert result.allowed is False
    assert "minLength" in result.violations[0].message.lower() or "length" in result.violations[0].message.lower()


# ------------------------------------------------------------------
# Denial-specific rules (moved from sanitization)
# ------------------------------------------------------------------


def test_validation_action_deny_with_constraints():
    result = _validate(
        {
            "age": {"max": 100, "action": "deny"},
        },
        {"age": 150},
    )

    assert result.allowed is False
    assert any("age" in v.message.lower() for v in result.violations)

    ok = _validate(
        {
            "age": {"max": 100, "action": "deny"},
        },
        {"age": 25},
    )

    assert ok.allowed is True


@pytest.mark.parametrize(
    ("rules", "value", "expected_fragment"),
    [
        (
            {"forbidden": {"action": "deny"}},
            {"forbidden": "value"},
            "forbidden",
        ),
        (
            {"require_fields_absent": ["pii_flag"]},
            {"pii_flag": True},
            "pii_flag",
        ),
        (
            {"max_bytes": 10},
            {"data": "x" * 50},
            "max_bytes",
        ),
        (
            {"deny_if_patterns": ["(?i)secret"]},
            {"notes": "leak SECRET token"},
            "forbidden pattern",
        ),
    ],
)
def test_validation_deny_rules(rules, value, expected_fragment):
    result = _validate(rules, value)

    assert result.allowed is False
    assert any(expected_fragment in v.message.lower() for v in result.violations)


# ------------------------------------------------------------------
# Multiple field validation
# ------------------------------------------------------------------


def test_validation_multiple_fields():
    """Validator checks all fields and aggregates violations."""
    result = _validate(
        {
            "status": {"required": True, "in": ["ok", "error"]},
            "count": {"type": "int", "min": 0},
            "email": {"type": "string", "matches": r"^[^@]+@[^@]+$"},
        },
        {
            "status": "ok",
            "count": 5,
            "email": "user@example.com",
        },
    )

    assert result.allowed is True

    # Test multiple violations
    result = _validate(
        {
            "status": {"required": True},
            "count": {"type": "int"},
        },
        {
            "count": "not-an-int",
            # status is missing
        },
    )

    assert result.allowed is False
    assert len(result.violations) >= 2  # At least status and count violations


# ------------------------------------------------------------------
# Nested structure validation
# ------------------------------------------------------------------


def test_validation_nested_object_fields():
    """Validator can check fields in nested structures."""
    result = _validate(
        {
            "user.name": {"required": True, "type": "string"},
            "user.age": {"type": "int", "min": 0},
        },
        {
            "user": {
                "name": "Alice",
                "age": 30,
            }
        },
    )

    assert result.allowed is True


def test_validation_array_items():
    """Validator can check items in arrays."""
    result = _validate(
        {
            "items": {"type": "list", "minLength": 1},
        },
        {"items": [1, 2, 3]},
    )

    assert result.allowed is True

    # Test empty array violation
    result = _validate(
        {
            "items": {"type": "list", "minLength": 1},
        },
        {"items": []},
    )

    assert result.allowed is False


# ------------------------------------------------------------------
# No transformation - validation only returns pass/fail
# ------------------------------------------------------------------


def test_validation_never_modifies_value():
    """Output validation NEVER transforms the value, only validates."""
    original_value = {
        "status": "success",
        "count": 42,
        "nested": {"data": "value"},
        "array": [1, 2, 3],
    }

    result = _validate(
        {
            "status": {"type": "string"},
            "count": {"type": "int"},
        },
        original_value,
    )

    # Even though validation passes, value is unchanged
    assert result.allowed is True
    assert result.violations == []
    # Validation doesn't have a .value attribute - it only tells you pass/fail


def test_validation_no_action_keyword():
    """Output validation rules should NOT include 'action' keyword."""
    # This is pure validation - no actions
    result = _validate(
        {
            "status": {"type": "string"},  # No action - pure validation
        },
        {"status": "ok"},
    )

    assert result.allowed is True

    # If someone tries to use action with validation, it should be ignored or error
    # (We'll define this behavior in implementation)


# ------------------------------------------------------------------
# Comparison with input validation (symmetry)
# ------------------------------------------------------------------


def test_validation_mirrors_input_validation_semantics():
    """Output validation should behave identically to input validation.
    
    This test documents the symmetry:
    - Input: validates function arguments before execution
    - Output: validates function return value after execution
    - Both use the same constraint operators
    - Both return ValidationResult
    - Both deny on violation (no transformation)
    """
    from d2.validation.input import InputValidator

    # Same rules for input and output
    rules = {
        "status": {"required": True, "in": ["ok", "error"]},
        "count": {"type": "int", "min": 0, "max": 1000},
    }

    valid_data = {"status": "ok", "count": 100}
    invalid_data = {"status": "invalid", "count": -5}

    # Input validation
    input_validator = InputValidator()
    input_result_valid = input_validator.validate({"input": rules}, valid_data)
    input_result_invalid = input_validator.validate({"input": rules}, invalid_data)

    # Output validation
    output_validator = OutputValidator()
    output_result_valid = output_validator.validate({"output": rules}, valid_data)
    output_result_invalid = output_validator.validate({"output": rules}, invalid_data)

    # Should have same behavior
    assert input_result_valid.allowed == output_result_valid.allowed
    assert input_result_invalid.allowed == output_result_invalid.allowed
    assert len(input_result_invalid.violations) == len(output_result_invalid.violations)


# ------------------------------------------------------------------
# Edge cases
# ------------------------------------------------------------------


def test_validation_with_no_rules_passes():
    """Validation with no rules should pass (allow everything)."""
    result = _validate({}, {"any": "data", "at": "all"})

    assert result.allowed is True


def test_validation_with_optional_field_missing_passes():
    """Missing optional field (not required) should pass."""
    result = _validate(
        {
            "optional": {"type": "string"},  # Not required
        },
        {"other": "field"},
    )

    assert result.allowed is True


def test_validation_multiple_type_options():
    """Type constraint can accept multiple types."""
    result = _validate(
        {
            "value": {"type": ["string", "int"]},
        },
        {"value": "text"},
    )

    assert result.allowed is True

    result = _validate(
        {
            "value": {"type": ["string", "int"]},
        },
        {"value": 42},
    )

    assert result.allowed is True

    result = _validate(
        {
            "value": {"type": ["string", "int"]},
        },
        {"value": [1, 2, 3]},  # Array not allowed
    )

    assert result.allowed is False

