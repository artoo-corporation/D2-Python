# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""Unit tests for output sanitization (transformation via field actions).

Output sanitization transforms return values to remove/redact sensitive data:
- Uses 'action' keyword to specify transformation
- ALWAYS modifies the value when triggered
- Returns transformed value to caller
- Never denies; denial is handled by validation

This is separate from output validation (constraint checking).
"""

from __future__ import annotations

import pytest

from d2.sanitization.output import OutputSanitizer, SanitizationResult


def _sanitize(rules, value):
    """Helper to run output sanitization with the provided rules."""
    return OutputSanitizer().sanitize({"output": rules}, value)


# ------------------------------------------------------------------
# Field actions: filter, redact, truncate
# ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("rules", "value", "expected"),
    [
        (
            {"ssn": {"action": "filter"}},
            {"name": "Alice", "ssn": "123-45-6789"},
            {"name": "Alice"},
        ),
        (
            {
                "ssn": {"action": "filter"},
                "salary": {"action": "filter"},
                "password": {"action": "filter"},
            },
            {
                "name": "Alice",
                "ssn": "123-45-6789",
                "salary": 120000,
                "password": "secret",
            },
            {"name": "Alice"},
        ),
        (
            {"ssn": {"action": "filter"}},
            {
                "users": [
                    {"name": "Alice", "ssn": "123-45-6789"},
                    {"name": "Bob", "ssn": "987-65-4321"},
                ]
            },
            {"users": [{"name": "Alice"}, {"name": "Bob"}]},
        ),
    ],
)
def test_sanitize_filter_actions(rules, value, expected):
    result = _sanitize(rules, value)

    assert result.modified is True
    assert result.value == expected


@pytest.mark.parametrize(
    ("rules", "value", "expected", "modified"),
    [
        (
            {"password": {"action": "redact"}},
            {"username": "alice", "password": "secret123"},
            {"username": "alice", "password": "[REDACTED]"},
            True,
        ),
        (
            {"notes": {"matches": r"\d{3}-\d{2}-\d{4}", "action": "redact"}},
            {"notes": "SSN is 123-45-6789 and other text"},
            {"notes": "SSN is [REDACTED] and other text"},
            True,
        ),
        (
            {"notes": {"matches": r"SECRET", "action": "redact"}},
            {"notes": "This is clean text"},
            {"notes": "This is clean text"},
            False,
        ),
    ],
)
def test_sanitize_redact_actions(rules, value, expected, modified):
    result = _sanitize(rules, value)

    assert result.modified is modified
    assert result.value == expected


@pytest.mark.parametrize(
    ("rules", "value", "expected", "modified"),
    [
        (
            {"items": {"maxLength": 2, "action": "truncate"}},
            {"items": [1, 2, 3, 4, 5]},
            {"items": [1, 2]},
            True,
        ),
        (
            {"description": {"maxLength": 10, "action": "truncate"}},
            {"description": "This is a very long description"},
            {"description": "This is a "},
            True,
        ),
        (
            {"items": {"maxLength": 10, "action": "truncate"}},
            {"items": [1, 2, 3]},
            {"items": [1, 2, 3]},
            False,
        ),
    ],
)
def test_sanitize_truncate_actions(rules, value, expected, modified):
    result = _sanitize(rules, value)

    assert result.modified is modified
    assert result.value == expected


# ------------------------------------------------------------------
# Field action: deny (no longer handled by sanitization)
# ------------------------------------------------------------------


def test_sanitize_ignore_deny_action():
    """Sanitizer does not deny responses; deny actions are handled by validation."""
    result = _sanitize(
        {
            "forbidden": {"action": "deny"},
        },
        {"forbidden": "value", "allowed": "data"},
    )

    assert result.modified is False
    assert result.value == {"forbidden": "value", "allowed": "data"}


def test_sanitize_ignore_global_denials():
    """Global deny rules are ignored by sanitizer (handled by validation)."""
    result = _sanitize(
        {
            "require_fields_absent": ["pii_flag"],
            "max_bytes": 10,
            "deny_if_patterns": ["secret"],
        },
        {"pii_flag": True, "data": "secret payload"},
    )

    assert result.modified is False
    assert result.value == {"pii_flag": True, "data": "secret payload"}


# ------------------------------------------------------------------
# Conditional actions (only trigger on constraint violation)
# ------------------------------------------------------------------


def test_sanitize_conditional_filter():
    """Filter action with constraint only removes field if constraint violated."""
    result = _sanitize(
        {
            "score": {"max": 100, "action": "filter"},
        },
        {"player": "Alice", "score": 150},
    )

    assert result.modified is True
    assert result.value == {"player": "Alice"}

    # Should keep field if within constraint
    result = _sanitize(
        {
            "score": {"max": 100, "action": "filter"},
        },
        {"player": "Alice", "score": 50},
    )

    assert result.modified is False
    assert result.value == {"player": "Alice", "score": 50}


def test_sanitize_conditional_redact():
    """Redact action with constraint only redacts if constraint violated."""
    result = _sanitize(
        {
            "salary": {"max": 100000, "action": "redact"},
        },
        {"name": "Alice", "salary": 250000},
    )

    assert result.modified is True
    assert result.value["salary"] == "[REDACTED]"

    # Should keep original if within constraint
    result = _sanitize(
        {
            "salary": {"max": 100000, "action": "redact"},
        },
        {"name": "Alice", "salary": 75000},
    )

    assert result.modified is False
    assert result.value["salary"] == 75000


# ------------------------------------------------------------------
# Multiple field actions
# ------------------------------------------------------------------


def test_sanitize_multiple_actions():
    """Multiple field actions can be applied to same output."""
    result = _sanitize(
        {
            "ssn": {"action": "filter"},
            "password": {"action": "redact"},
            "items": {"maxLength": 2, "action": "truncate"},
        },
        {
            "name": "Alice",
            "ssn": "123-45-6789",
            "password": "secret",
            "items": [1, 2, 3, 4],
        },
    )

    assert result.modified is True
    assert result.value == {
        "name": "Alice",
        "password": "[REDACTED]",
        "items": [1, 2],
    }


# ------------------------------------------------------------------
# Sanitization always returns transformed value (validation handles denials)
# ------------------------------------------------------------------


def test_sanitize_returns_transformed_value():
    """Sanitization always returns a value (transformed or original)."""
    result = _sanitize(
        {
            "ssn": {"action": "filter"},
        },
        {"name": "Alice", "ssn": "123-45-6789"},
    )

    # Result has .value attribute with transformed data
    assert hasattr(result, "value")
    assert result.value == {"name": "Alice"}
    assert result.modified is True


def test_sanitize_without_rules_returns_original():
    """No sanitization rules should leave the value untouched."""
    value = {"status": "ok"}
    result = OutputSanitizer().sanitize({}, value)

    assert result.modified is False
    assert result.value == value


def test_sanitize_no_action_returns_original():
    """If no actions triggered, returns original value unchanged."""
    result = _sanitize(
        {
            "score": {"max": 100, "action": "filter"},  # Conditional
        },
        {"score": 50},  # Within limit, action doesn't trigger
    )

    assert result.modified is False
    assert result.value == {"score": 50}


# ------------------------------------------------------------------
# Distinction from validation
# ------------------------------------------------------------------


def test_sanitize_requires_action_keyword():
    """Sanitization rules MUST include 'action' keyword."""
    # Without action, this is validation, not sanitization
    # Sanitizer should ignore rules without actions
    result = _sanitize(
        {
            "status": {"type": "string"},  # No action - this is validation
        },
        {"status": "ok"},
    )

    # Sanitizer ignores this (no action specified)
    assert result.modified is False
    assert result.value == {"status": "ok"}


def test_sanitize_transforms_validation_denies():
    """Key difference: sanitization transforms, validation denies.
    
    Same field, different behavior:
    - Validation: {field: {max: 100}} → deny if violated
    - Sanitization: {field: {max: 100, action: filter}} → remove if violated
    """
    # This is tested implicitly by the conditional action tests above
    # Just documenting the key conceptual difference
    pass


# ------------------------------------------------------------------
# Tracking metadata (telemetry support)
# ------------------------------------------------------------------


def test_sanitize_tracks_fields_modified():
    """SanitizationResult should track which fields were modified."""
    result = _sanitize(
        {
            "ssn": {"action": "filter"},
            "salary": {"action": "redact"},
        },
        {"name": "Alice", "ssn": "123-45-6789", "salary": 150000},
    )

    assert result.modified is True
    assert "ssn" in result.fields_modified
    assert "salary" in result.fields_modified
    assert len(result.fields_modified) == 2


def test_sanitize_tracks_actions_applied():
    """SanitizationResult should track which actions were applied to each field."""
    result = _sanitize(
        {
            "ssn": {"action": "filter"},
            "password": {"action": "redact"},
            "items": {"maxLength": 2, "action": "truncate"},
        },
        {
            "name": "Alice",
            "ssn": "123-45-6789",
            "password": "secret",
            "items": [1, 2, 3, 4],
        },
    )

    assert result.modified is True
    assert result.actions_applied["ssn"] == "filter"
    assert result.actions_applied["password"] == "redact"
    assert result.actions_applied["items"] == "truncate"
    assert len(result.actions_applied) == 3


def test_sanitize_pattern_redact_tracks_action_type():
    """Pattern-based redaction should be tracked as 'redact_pattern'."""
    result = _sanitize(
        {
            "notes": {"matches": r"\d{3}-\d{2}-\d{4}", "action": "redact"},
        },
        {"notes": "SSN is 123-45-6789 here"},
    )

    assert result.modified is True
    assert result.actions_applied["notes"] == "redact_pattern"


def test_sanitize_no_modifications_empty_tracking():
    """When nothing is modified, tracking metadata should be empty."""
    result = _sanitize(
        {
            "score": {"max": 100, "action": "filter"},  # Conditional - won't trigger
        },
        {"score": 50},
    )

    assert result.modified is False
    assert result.fields_modified == []
    assert result.actions_applied == {}


def test_sanitize_conditional_actions_only_track_when_triggered():
    """Conditional actions should only be tracked when they actually trigger."""
    # High salary - should trigger
    result = _sanitize(
        {
            "salary": {"max": 100000, "action": "redact"},
        },
        {"name": "Alice", "salary": 250000},
    )

    assert result.modified is True
    assert "salary" in result.fields_modified
    assert result.actions_applied["salary"] == "redact"

    # Low salary - should NOT trigger
    result = _sanitize(
        {
            "salary": {"max": 100000, "action": "redact"},
        },
        {"name": "Bob", "salary": 75000},
    )

    assert result.modified is False
    assert result.fields_modified == []
    assert result.actions_applied == {}


def test_sanitize_multiple_conditions_aggregates_tracking():
    """When using multiple condition sets (list), tracking should aggregate."""
    # Using list of conditions (sequential application)
    sanitizer = OutputSanitizer()
    result = sanitizer.sanitize(
        [
            {"output": {"ssn": {"action": "filter"}}},
            {"output": {"salary": {"max": 100000, "action": "redact"}}},
        ],
        {"name": "Alice", "ssn": "123-45-6789", "salary": 150000},
    )

    assert result.modified is True
    assert "ssn" in result.fields_modified
    assert "salary" in result.fields_modified
    assert result.actions_applied["ssn"] == "filter"
    assert result.actions_applied["salary"] == "redact"


def test_sanitize_tracking_with_nested_fields():
    """Tracking should work with nested field sanitization."""
    result = _sanitize(
        {
            "password": {"action": "filter"},  # Nested password fields
            "api_key": {"action": "redact"},
        },
        {
            "user": {
                "name": "Alice",
                "password": "secret123",
            },
            "credentials": {
                "api_key": "sk_live_abc123",
            },
        },
    )

    # Both fields should be tracked even though they're nested
    assert result.modified is True
    assert "password" in result.fields_modified
    assert "api_key" in result.fields_modified

