"""
Tests for @d2_guard decorator - RBAC authorization for function calls.

The @d2_guard decorator is the primary way to protect functions with RBAC policies.
It works by checking if the current user context has permission to execute a specific
tool before allowing the function to run.

Key concepts:
- Tool ID: Unique identifier for each protected function (e.g., "calc.square")
- Policy checking: Validates user permissions against loaded policy bundle
- Sync vs Async: Different execution paths with event loop detection
- Custom handlers: on_deny parameter allows custom permission denied behavior
- Strict mode: Prevents sync functions from running in async contexts

Security principles:
- Fail-closed: No policy means no access
- Context-aware: Uses current user context for authorization
- Async-safe: Proper handling of event loop contexts
"""
from __future__ import annotations

import asyncio

import pytest

from d2.decorator import d2_guard
from d2.exceptions import ConfigurationError, D2Error, PermissionDeniedError


class MockPolicyManagerAllowAll:  # pylint: disable=too-few-public-methods
    """Mock policy manager that allows all operations (for testing happy paths)."""
    
    mode = "file"
    
    async def is_tool_in_policy_async(self, _tool):  # noqa: D401
        """Always report that tools are in the policy."""
        return True

    async def check_async(self, _tool):  # noqa: D401
        """Always allow access to tools."""
        return True


class MockPolicyManagerDenyAll(MockPolicyManagerAllowAll):
    """Mock policy manager that denies all operations (for testing denial paths)."""
    
    async def check_async(self, _tool):  # noqa: D401
        """Always deny access to tools."""
        return False


class MockPolicyManagerWithConditions(MockPolicyManagerAllowAll):
    """Mock manager that supplies declarative input conditions."""

    def __init__(self, *, conditions_map):
        self._conditions_map = conditions_map

    async def get_tool_conditions(self, tool_id):
        return self._conditions_map.get(tool_id)


def test_sync_function_executes_when_policy_allows_access(monkeypatch):
    """
    GIVEN: A policy that allows access to calc.square tool
    WHEN: We call a sync function decorated with @d2_guard
    THEN: Function should execute normally and return its result
    
    This tests the happy path for synchronous function authorization.
    """
    # GIVEN: Policy manager that allows all operations
    monkeypatch.setattr("d2.decorator.get_policy_manager", 
                       lambda *_a, **_kw: MockPolicyManagerAllowAll())

    # WHEN: We define a protected function
    @d2_guard("calc.square", instance_name="default")
    def calculate_square(number):
        """Calculate the square of a number."""
        return number * number

    # THEN: Function should execute when policy allows it
    result = calculate_square(4)
    assert result == 16, "Function should execute and return correct result"


def test_custom_denial_handler_returns_specified_value(monkeypatch):
    """
    GIVEN: A policy that denies access to a tool
    WHEN: We call a function with a custom on_deny handler
    THEN: Should return the custom denial value instead of raising exception
    
    This tests the custom error handling mechanism that allows graceful
    degradation instead of hard failures.
    """
    # GIVEN: Policy manager that denies all operations
    monkeypatch.setattr("d2.decorator.get_policy_manager", 
                       lambda *_a, **_kw: MockPolicyManagerDenyAll())

    # WHEN: We define a function with custom denial handling
    @d2_guard("admin.shutdown", on_deny="🚫")
    def attempt_shutdown():
        """Attempt to shutdown the system."""
        return "system_shutting_down"

    # THEN: Should return the custom denial value
    result = attempt_shutdown()
    assert result == "🚫", "Should return custom denial value instead of executing function"


@pytest.mark.anyio
async def test_strict_mode_prevents_sync_functions_in_async_context(monkeypatch):
    """
    GIVEN: A sync function with strict=True in the decorator
    WHEN: We try to call it from within an async context (event loop)
    THEN: Should raise D2Error to prevent potential deadlocks
    
    This prevents sync functions from blocking the event loop, which
    could cause performance issues or deadlocks in async applications.
    """
    # GIVEN: Policy that would normally allow the operation
    monkeypatch.setattr("d2.decorator.get_policy_manager", 
                       lambda *_a, **_kw: MockPolicyManagerAllowAll())

    # AND: A sync function with strict mode enabled
    @d2_guard("math.add", strict=True)
    def add_numbers(a, b):
        """Add two numbers together."""
        return a + b

    # WHEN: We try to call it from async context
    # THEN: Should raise D2Error due to strict mode
    async def attempt_sync_call():
        """Try to call sync function from async context."""
        with pytest.raises(D2Error) as error:
            add_numbers(1, 2)
        
        # Verify it's the expected error type
        assert "event loop" in str(error.value).lower() or "async" in str(error.value).lower()

    await attempt_sync_call()


@pytest.mark.anyio
async def test_async_function_executes_when_policy_allows_access(monkeypatch):
    """
    GIVEN: A policy that allows access to an async tool
    WHEN: We call an async function decorated with @d2_guard
    THEN: Function should execute normally and return its result
    
    This tests the happy path for asynchronous function authorization.
    """
    # GIVEN: Policy manager that allows all operations
    monkeypatch.setattr("d2.decorator.get_policy_manager", 
                       lambda *_a, **_kw: MockPolicyManagerAllowAll())

    # WHEN: We define a protected async function
    @d2_guard("ping.api")
    async def ping_service():
        """Ping a remote service."""
        return "pong"

    # THEN: Function should execute and return result
    result = await ping_service()
    assert result == "pong", "Async function should execute and return correct result" 


def test_input_conditions_enforced_before_function_executes(monkeypatch):
    """Decorator should validate arguments using declarative input conditions."""

    manager = MockPolicyManagerWithConditions(
        conditions_map={
            "query_database": {
                "input": {
                    "table": {"in": ["users", "orders"]},
                    "row_limit": {"max": 1000},
                }
            }
        }
    )

    monkeypatch.setattr("d2.decorator.get_policy_manager", lambda *_a, **_kw: manager)

    executed = {"value": False}

    @d2_guard("query_database")
    def query_database(table: str, row_limit: int):
        executed["value"] = True
        return "ok"

    with pytest.raises(PermissionDeniedError) as exc:
        query_database("admins", 5000)

    assert executed["value"] is False, "Function body must not execute on validation failure"
    message = str(exc.value)
    assert "table" in message and "admins" in message
    assert "row_limit" in message and "1000" in message


def test_default_arguments_are_validated(monkeypatch):
    """Default parameter values must be checked against declared conditions."""

    manager = MockPolicyManagerWithConditions(
        conditions_map={
            "query_database": {
                "input": {
                    "row_limit": {"max": 1000},
                }
            }
        }
    )

    monkeypatch.setattr("d2.decorator.get_policy_manager", lambda *_a, **_kw: manager)

    executed = {"value": False}

    @d2_guard("query_database")
    def query_database(row_limit: int = 5000):
        executed["value"] = True
        return "ok"

    with pytest.raises(PermissionDeniedError) as exc:
        query_database()

    assert executed["value"] is False
    assert "row_limit" in str(exc.value)


def test_invalid_condition_argument_raises_configuration_error(monkeypatch):
    manager = MockPolicyManagerWithConditions(
        conditions_map={
            "query_database": {
                "input": {
                    "row_lmit": {"max": 1000},
                }
            }
        }
    )

    monkeypatch.setattr("d2.decorator.get_policy_manager", lambda *_a, **_kw: manager)

    @d2_guard("query_database")
    def query_database(table: str, row_limit: int):
        return "ok"

    with pytest.raises(ConfigurationError) as exc:
        query_database("users", 10)

    assert "row_lmit" in str(exc.value)


def test_output_conditions_filter_return_value(monkeypatch):
    """Decorator should sanitize outputs according to declarative rules."""

    manager = MockPolicyManagerWithConditions(
        conditions_map={
            "get_employee_record": {
                "output": {
                    "ssn": {"action": "filter"},
                    "salary": {"action": "redact"},
                    "notes": {"matches": r"\d{3}-\d{2}-\d{4}", "action": "redact"},
                }
            }
        }
    )

    monkeypatch.setattr("d2.decorator.get_policy_manager", lambda *_a, **_kw: manager)

    @d2_guard("get_employee_record")
    def get_employee_record():
        return {
            "name": "Eve",
            "ssn": "123-45-6789",
            "salary": "95000",
            "notes": "See SSN 123-45-6789",
        }

    filtered = get_employee_record()

    assert filtered == {
        "name": "Eve",
        "salary": "[REDACTED]",
        "notes": "See SSN [REDACTED]",
    }


def test_output_conditions_can_deny(monkeypatch):
    """Decorator should deny when output validation rules are violated."""

    manager = MockPolicyManagerWithConditions(
        conditions_map={
            "export_sensitive": {
                "output": {
                    "deny_if_patterns": [r"(?i)secret"],
                }
            }
        }
    )

    monkeypatch.setattr("d2.decorator.get_policy_manager", lambda *_a, **_kw: manager)

    @d2_guard("export_sensitive")
    def export_sensitive():
        return {"notes": "Top Secret budget"}

    with pytest.raises(PermissionDeniedError) as exc:
        export_sensitive()

    assert "secret" in (exc.value.reason or "").lower()


def test_output_field_actions_apply(monkeypatch):
    """Decorator should honor field-level actions for output constraints."""

    manager = MockPolicyManagerWithConditions(
        conditions_map={
            "export_summary": {
                "output": {
                    "secret": {"action": "filter"},
                    "password": {"action": "redact"},
                    "notes": {"matches": "(?i)restricted", "action": "deny"},
                }
            }
        }
    )

    monkeypatch.setattr("d2.decorator.get_policy_manager", lambda *_a, **_kw: manager)

    @d2_guard("export_summary")
    def export_summary():
        return {
            "secret": "top secret",
            "password": "p@ssw0rd",
            "notes": "restricted area",
        }

    with pytest.raises(PermissionDeniedError) as exc:
        export_summary()

    assert "restricted" in (exc.value.reason or "").lower()