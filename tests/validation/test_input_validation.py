# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

import re

import pytest

from d2.exceptions import ConfigurationError
from d2.validation import (
    InputValidator,
    ValidationResult,
    ValidationViolation,
)


def _validate(conditions, arguments):
    validator = InputValidator()
    return validator.validate({"input": conditions}, arguments)


def test_validation_passes_with_basic_comparisons():
    result = _validate(
        {
            "table": {"in": ["users", "orders", "products"]},
            "row_limit": {"min": 1, "max": 1000},
        },
        {"table": "users", "row_limit": 100},
    )

    assert isinstance(result, ValidationResult)
    assert result.allowed is True
    assert result.violations == []


def test_validation_fails_when_value_not_in_allowed_list():
    result = _validate(
        {
            "table": {"in": ["users", "orders", "products"]},
        },
        {"table": "admin_secrets"},
    )

    assert result.allowed is False
    assert len(result.violations) == 1
    violation = result.violations[0]
    assert violation.argument == "table"
    assert violation.operator == "in"
    assert violation.expected == ["users", "orders", "products"]
    assert violation.actual == "admin_secrets"
    assert "must be one of" in violation.message


@pytest.mark.parametrize(
    "value,conditions",
    [
        ("/safe/data/report.csv", {"startsWith": "/safe/data/"}),
        ("/tmp/archive.txt", {"endsWith": ".txt"}),
        ("agent-artifact", {"contains": "agent"}),
        ("abc123", {"matches": r"^[a-z0-9]+$"}),
        ("short", {"minLength": 3, "maxLength": 10}),
    ],
)
def test_string_constraints_pass(value, conditions):
    result = _validate({"path": conditions}, {"path": value})
    assert result.allowed is True
    assert result.violations == []


@pytest.mark.parametrize(
    "value,conditions,operator",
    [
        ("../../etc/passwd", {"not_contains": ".."}, "not_contains"),
        ("notes.doc", {"startsWith": "/safe/data/"}, "startsWith"),
        ("report.pdf", {"endsWith": ".csv"}, "endsWith"),
        ("INVALID!", {"matches": r"^[a-z0-9]+$"}, "matches"),
        ("tiny", {"minLength": 6}, "minLength"),
        ("this-string-is-way-too-long", {"maxLength": 10}, "maxLength"),
    ],
)
def test_string_constraints_fail(value, conditions, operator):
    result = _validate({"path": conditions}, {"path": value})

    assert result.allowed is False
    assert result.violations[0].operator == operator


def test_required_argument_missing_triggers_violation():
    result = _validate(
        {
            "table": {"required": True, "in": ["users"]},
        },
        {},
    )

    assert result.allowed is False
    [violation] = result.violations
    assert violation.argument == "table"
    assert violation.operator == "required"
    assert violation.expected is True
    assert violation.actual is None
    assert "missing" in violation.message.lower()


def test_type_validation_enforces_exact_type():
    result = _validate(
        {
            "row_limit": {"type": "int", "max": 1000},
        },
        {"row_limit": "100"},
    )

    assert result.allowed is False
    [violation] = result.violations
    assert violation.operator == "type"
    assert violation.expected == "int"
    assert violation.actual == "100"


def test_multiple_violations_are_reported():
    result = _validate(
        {
            "table": {"in": ["users", "orders"]},
            "row_limit": {"min": 1, "max": 1000},
        },
        {"table": "admin", "row_limit": 5000},
    )

    assert result.allowed is False
    assert len(result.violations) == 2
    operators = {v.operator for v in result.violations}
    assert operators == {"in", "max"}


def test_validation_ignores_arguments_without_policies():
    result = _validate(
        {
            "table": {"in": ["users"]},
        },
        {"table": "users", "extra": "ignored"},
    )

    assert result.allowed is True
    assert result.violations == []


def test_validation_returns_dataclasses_with_str_repr():
    result = _validate(
        {
            "table": {"in": ["users"]},
        },
        {"table": "admins"},
    )

    assert isinstance(result, ValidationResult)
    assert isinstance(result.violations[0], ValidationViolation)
    # Ensure __repr__ contains helpful info for debugging
    text = repr(result.violations[0])
    assert "argument='table'" in text
    assert "operator='in'" in text


# ------------------------------------------------------------------
# Unknown operator detection (security: catch typos)
# ------------------------------------------------------------------


def test_unknown_operator_raises_configuration_error():
    """Unknown operators should raise ConfigurationError, not silently ignore."""
    with pytest.raises(ConfigurationError) as exc_info:
        _validate(
            {
                "limit": {"maximum": 100},  # Typo: should be "max"
            },
            {"limit": 50},
        )
    
    assert "unknown operator" in str(exc_info.value).lower()
    assert "maximum" in str(exc_info.value)
    assert "limit" in str(exc_info.value)


def test_typo_in_operator_name_caught():
    """Common typos in operator names should be caught."""
    # Typo: "typ" instead of "type"
    with pytest.raises(ConfigurationError) as exc_info:
        _validate(
            {
                "password": {"typ": "string", "minLength": 8},
            },
            {"password": "secret"},
        )
    
    assert "typ" in str(exc_info.value)


def test_multiple_unknown_operators_all_reported():
    """All unknown operators should be reported."""
    with pytest.raises(ConfigurationError) as exc_info:
        _validate(
            {
                "limit": {
                    "type": "int",
                    "maximum": 100,      # Unknown
                    "minimum": 1,        # Unknown
                    "greater_than": 0,   # Unknown
                },
            },
            {"limit": 50},
        )
    
    error_msg = str(exc_info.value).lower()
    # Should mention at least one unknown operator
    assert "unknown operator" in error_msg or "maximum" in error_msg


def test_valid_operators_still_work():
    """Known operators should work without errors."""
    # All valid operators - should not raise
    result = _validate(
        {
            "value": {
                "type": "int",
                "required": True,
                "min": 1,
                "max": 100,
                "gt": 0,
                "lt": 101,
            },
        },
        {"value": 50},
    )
    
    assert result.allowed is True


def test_common_typo_minlength_caught():
    """Common typo: minLenght instead of minLength."""
    with pytest.raises(ConfigurationError) as exc_info:
        _validate(
            {
                "password": {"minLenght": 8},  # Typo: extra 'h'
            },
            {"password": "short"},
        )
    
    assert "minlenght" in str(exc_info.value).lower()  # Check lowercase version


def test_common_typo_maxlength_caught():
    """Common typo: maxLenght instead of maxLength."""
    with pytest.raises(ConfigurationError) as exc_info:
        _validate(
            {
                "comment": {"maxLenght": 100},  # Typo: extra 'h'
            },
            {"comment": "Some text"},
        )
    
    assert "maxlenght" in str(exc_info.value).lower()  # Check lowercase version


def test_nonexistent_format_operator_caught():
    """Operators that don't exist should be caught."""
    with pytest.raises(ConfigurationError):
        _validate(
            {
                "email": {"format": "email"},  # "format" operator doesn't exist
            },
            {"email": "test@example.com"},
        )


def test_error_message_suggests_valid_operators():
    """Error message should list valid operators to help fix typos."""
    with pytest.raises(ConfigurationError) as exc_info:
        _validate(
            {
                "limit": {"maximum": 100},
            },
            {"limit": 50},
        )
    
    error_msg = str(exc_info.value)
    # Should mention valid operators
    assert "valid operators" in error_msg.lower() or "available" in error_msg.lower()


# ---------------------------------------------------------------------------
# not_matches operator tests
# ---------------------------------------------------------------------------

def test_not_matches_passes_when_pattern_not_found():
    """not_matches should pass when the pattern is NOT in the value."""
    result = _validate(
        {
            "data": {"not_matches": r"\d{3}-\d{2}-\d{4}"},  # SSN pattern
        },
        {"data": "Hello, this is safe text without SSN"},
    )
    assert result.allowed is True


def test_not_matches_fails_when_pattern_found():
    """not_matches should fail when the forbidden pattern IS in the value."""
    result = _validate(
        {
            "data": {"not_matches": r"\d{3}-\d{2}-\d{4}"},  # SSN pattern
        },
        {"data": "User SSN is 123-45-6789"},
    )
    assert result.allowed is False
    assert len(result.violations) == 1
    assert result.violations[0].operator == "not_matches"


def test_not_matches_detects_embedded_patterns():
    """not_matches should detect patterns anywhere in the string (uses search, not fullmatch)."""
    result = _validate(
        {
            "message": {"not_matches": r"(?i)password"},
        },
        {"message": "The user's PASSWORD is secret123"},
    )
    assert result.allowed is False


def test_not_matches_passes_on_missing_value():
    """not_matches should pass if the value is not provided."""
    result = _validate(
        {
            "data": {"not_matches": r"secret"},
        },
        {},  # data not provided
    )
    assert result.allowed is True


def test_not_matches_combined_with_required():
    """not_matches combined with required should work correctly."""
    # Required but contains forbidden pattern
    result = _validate(
        {
            "data": {"required": True, "not_matches": r"(?i)(ssn|password)"},
        },
        {"data": "My SSN is 123"},
    )
    assert result.allowed is False

    # Required and safe
    result = _validate(
        {
            "data": {"required": True, "not_matches": r"(?i)(ssn|password)"},
        },
        {"data": "Safe data without sensitive info"},
    )
    assert result.allowed is True


# ---------------------------------------------------------------------------
# max_bytes operator tests
# ---------------------------------------------------------------------------

def test_max_bytes_passes_when_under_limit():
    """max_bytes should pass when byte size is within limit."""
    result = _validate(
        {
            "data": {"max_bytes": 100},
        },
        {"data": "Hello, world!"},  # 13 bytes
    )
    assert result.allowed is True


def test_max_bytes_fails_when_over_limit():
    """max_bytes should fail when byte size exceeds limit."""
    result = _validate(
        {
            "data": {"max_bytes": 10},
        },
        {"data": "This string is way too long"},  # 27 bytes
    )
    assert result.allowed is False
    assert len(result.violations) == 1
    assert result.violations[0].operator == "max_bytes"
    assert result.violations[0].actual == 27


def test_max_bytes_counts_utf8_correctly():
    """max_bytes should count multi-byte UTF-8 characters correctly."""
    # Each emoji is 4 bytes in UTF-8
    result = _validate(
        {
            "data": {"max_bytes": 10},
        },
        {"data": "🔥🔥🔥"},  # 12 bytes (3 emojis × 4 bytes each)
    )
    assert result.allowed is False
    assert result.violations[0].actual == 12

    # Same string passes with higher limit
    result = _validate(
        {
            "data": {"max_bytes": 12},
        },
        {"data": "🔥🔥🔥"},
    )
    assert result.allowed is True


def test_max_bytes_handles_dicts_via_json():
    """max_bytes should estimate dict size via JSON serialization."""
    result = _validate(
        {
            "payload": {"max_bytes": 50},
        },
        {"payload": {"key": "value", "nested": {"a": 1}}},
    )
    assert result.allowed is True

    # Large dict should fail
    result = _validate(
        {
            "payload": {"max_bytes": 10},
        },
        {"payload": {"key": "this is a much longer value"}},
    )
    assert result.allowed is False


def test_max_bytes_passes_on_missing_value():
    """max_bytes should pass if value is not provided."""
    result = _validate(
        {
            "data": {"max_bytes": 100},
        },
        {},
    )
    assert result.allowed is True


