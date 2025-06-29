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
from d2.exceptions import D2Error, PermissionDeniedError


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