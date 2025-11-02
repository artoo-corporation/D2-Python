import re

import pytest

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


