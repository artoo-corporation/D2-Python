# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""Unit tests for unified constraint model across input and output."""

from __future__ import annotations

from d2.sanitization.output import OutputSanitizer
from d2.validation.output import OutputValidator


def _apply(rules, value):
    """Helper to run output sanitization with the provided rules."""
    return OutputSanitizer().sanitize({"output": rules}, value)


def _validate(rules, value):
    return OutputValidator().validate({"output": rules}, value)


# ------------------------------------------------------------------
# Field-level actions with constraint operators
# ------------------------------------------------------------------


def test_field_level_filter_action_no_conditions():
    """Filter removes field unconditionally when no conditions specified."""
    result = _apply(
        {
            "ssn": {"action": "filter"},
        },
        {"name": "Alice", "ssn": "123-45-6789"},
    )

    assert result.modified is True
    assert result.value == {"name": "Alice"}


def test_field_level_redact_action_no_conditions():
    """Redact masks field value unconditionally."""
    result = _apply(
        {
            "password": {"action": "redact"},
        },
        {"username": "alice", "password": "secret123"},
    )

    assert result.modified is True
    assert result.value == {"username": "alice", "password": "[REDACTED]"}


def test_field_level_deny_on_type_mismatch():
    """Deny action triggers when field violates type constraint."""
    result = _validate(
        {
            "count": {"type": "int", "action": "deny"},
        },
        {"count": "not-an-int"},
    )

    assert result.allowed is False
    assert any("type" in v.message.lower() for v in result.violations)


def test_field_level_filter_on_max_constraint():
    """Filter action removes field when max constraint violated."""
    result = _apply(
        {
            "score": {"max": 100, "action": "filter"},
        },
        {"player": "Alice", "score": 150},
    )

    assert result.modified is True
    assert result.value == {"player": "Alice"}


def test_field_level_redact_on_pattern_match():
    """Redact matching pattern within field (partial redaction)."""
    result = _apply(
        {
            "notes": {"matches": r"(?i)secret", "action": "redact"},
        },
        {"notes": "Contains SECRET details", "status": "ok"},
    )

    assert result.modified is True
    assert result.value["notes"] == "Contains [REDACTED] details"
    assert result.value["status"] == "ok"


def test_field_level_truncate_on_max_length():
    """Truncate action limits field length."""
    result = _apply(
        {
            "items": {"maxLength": 2, "action": "truncate"},
        },
        {"items": [1, 2, 3, 4]},
    )

    assert result.modified is True
    assert result.value == {"items": [1, 2]}


def test_multiple_field_actions_compose():
    """Multiple field-level actions apply independently."""
    result = _apply(
        {
            "ssn": {"action": "filter"},
            "salary": {"max": 100000, "action": "redact"},
            "notes": {"matches": r"(?i)breach", "action": "deny"},
        },
        {"name": "Alice", "ssn": "123-45-6789", "salary": 150000, "notes": "clean"},
    )

    assert result.modified is True
    assert "ssn" not in result.value
    assert result.value["salary"] == "[REDACTED]"
    # Sanitization doesn't deny - denials happen at validation layer


def test_field_action_deny_stops_processing():
    """Deny action halts evaluation immediately."""
    result = _validate(
        {
            "restricted": {"action": "deny"},
            "ssn": {"action": "filter"},
        },
        {"restricted": "present", "ssn": "123-45-6789"},
    )

    assert result.allowed is False
    assert any("restricted" in v.message.lower() for v in result.violations)




# ------------------------------------------------------------------
# Input-style constraints on output fields
# ------------------------------------------------------------------


def test_output_field_min_constraint():
    """Can use input-style 'min' operator on output fields."""
    result = _validate(
        {
            "age": {"min": 18, "action": "deny"},
        },
        {"name": "Alice", "age": 16},
    )

    assert result.allowed is False
    assert any("age" in v.message.lower() for v in result.violations)


def test_output_field_in_constraint():
    """Output 'in' operator triggers when value IS in the list (deny-list semantics)."""
    result = _validate(
        {
            "status": {"in": ["rejected", "blocked"], "action": "deny"},
        },
        {"request_id": "req-123", "status": "rejected"},
    )

    assert result.allowed is False


def test_output_field_minlength_constraint():
    """Can use input-style 'minLength' operator on output fields."""
    result = _validate(
        {
            "token": {"minLength": 10, "action": "deny"},
        },
        {"token": "short"},
    )

    assert result.allowed is False
    assert any("length" in v.message.lower() for v in result.violations)


def test_output_field_maxlength_constraint():
    """Can use input-style 'maxLength' operator on output fields."""
    result = _apply(
        {
            "description": {"maxLength": 50, "action": "filter"},
        },
        {"title": "Document", "description": "x" * 100},
    )

    assert result.modified is True
    assert "description" not in result.value


# ------------------------------------------------------------------
# Edge cases
# ------------------------------------------------------------------


def test_field_action_on_missing_field():
    """Action doesn't trigger if field is absent."""
    result = _validate(
        {
            "optional_field": {"action": "deny"},
        },
        {"name": "Alice"},
    )

    assert result.allowed is True


def test_field_action_with_no_action_key():
    """Field rule without 'action' key is ignored."""
    result = _apply(
        {
            "name": {"max": 10},  # no action specified
        },
        {"name": "Alice"},
    )

    assert result.modified is False
    # Sanitization doesn't deny - denials happen at validation layer


# ------------------------------------------------------------------
# Operator semantics note: input vs output
# ------------------------------------------------------------------


def test_operator_semantics_documentation():
    """Document operator behavior for audit purposes.
    
    Current state:
    - Input constraints use ConstraintEvaluator: 'in' is an allow-list (deny if NOT in).
    - Output detection handlers: 'in' is a deny-list (trigger if IS in).
    
    This asymmetry exists because:
    - Input: "table must be IN [allowed_tables]" → deny if outside
    - Output: "status is IN [forbidden_statuses]" → deny if present
    
    Future unification should add 'not_in' operator for both sides or
    introduce explicit allow-list vs deny-list semantics.
    """
    # Input-style: deny if NOT in allow-list (ConstraintEvaluator semantics)
    from d2.runtime.input_validation import get_input_validator
    from d2.validation.base import ValidationContext
    
    input_validation = get_input_validator().validate(
        {"input": {"table": {"in": ["users", "orders"]}}},
        {"table": "products"},
    )
    assert input_validation.allowed is False
    
    # Output-style: deny if IS in deny-list (detection handler semantics)
    output_result = _validate(
        {"status": {"in": ["blocked", "suspended"], "action": "deny"}},
        {"status": "blocked"},
    )
    assert output_result.allowed is False

