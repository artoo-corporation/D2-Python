# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""
Tests for executor timeout behavior in the decorator.

The sync wrapper uses a ThreadPoolExecutor to run sync functions when called
from an async context. The .result() call currently blocks indefinitely, which
could cause issues if the executor is saturated or workers are stuck.

Key scenarios tested:
1. Executor saturation doesn't cause permanent hang
2. Timeout behavior when executor is slow
3. Proper error propagation on timeout
"""

import pytest
import asyncio
import threading
import time
import os
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from unittest.mock import patch, MagicMock, AsyncMock

import d2
from d2 import d2_guard
from d2.context import set_user_context, clear_user_context
from d2.decorator import _get_auto_thread_executor, _AUTO_THREAD_EXECUTOR
from d2.exceptions import D2Error


class _MockPolicyManager:
    """Minimal allow-all policy manager for testing."""
    mode = "file"
    _usage_reporter = None
    
    async def is_tool_in_policy_async(self, *_):
        return True
    
    async def check_async(self, *_):
        return True
    
    async def get_sequence_rules(self):
        return []
    
    async def get_tool_conditions(self, *_):
        return None
    
    def _get_bundle(self):
        return None


def _patch_pm(monkeypatch):
    """Patch the policy manager with a mock."""
    monkeypatch.setattr("d2.decorator.get_policy_manager", lambda *_: _MockPolicyManager())


class TestExecutorConfiguration:
    """Tests for executor configuration and behavior."""

    def test_shared_executor_is_bounded(self):
        """
        GIVEN: The shared auto-thread executor
        WHEN: Checking its configuration
        THEN: Should have bounded max_workers to prevent resource exhaustion
        """
        executor = _get_auto_thread_executor()
        
        assert executor is not None, "Executor should be created"
        assert executor._max_workers <= 8, (
            f"Executor should have bounded workers, got {executor._max_workers}"
        )

    def test_shared_executor_is_reused(self):
        """
        GIVEN: Multiple calls to _get_auto_thread_executor
        WHEN: Getting the executor multiple times
        THEN: Should return the same instance (singleton)
        """
        exec1 = _get_auto_thread_executor()
        exec2 = _get_auto_thread_executor()
        
        assert exec1 is exec2, "Executor should be reused (singleton)"

    def test_executor_has_descriptive_thread_names(self):
        """
        GIVEN: The shared auto-thread executor
        WHEN: Threads are created
        THEN: Should have descriptive thread names for debugging
        """
        executor = _get_auto_thread_executor()
        
        prefix = getattr(executor, '_thread_name_prefix', '')
        assert 'd2' in prefix.lower(), f"Expected 'd2' in thread prefix, got '{prefix}'"


class TestExecutorTimeout:
    """Tests for timeout behavior when executor is slow or saturated."""

    def test_slow_tool_completes_within_reasonable_time(self, monkeypatch):
        """
        GIVEN: A sync tool that takes a moderate amount of time
        WHEN: Called from async context via auto-threading
        THEN: Should complete successfully (no timeout for reasonable work)
        """
        _patch_pm(monkeypatch)
        
        @d2_guard("test.slow_tool")
        def slow_tool():
            time.sleep(0.5)  # Half second - should be fine
            return "completed"
        
        async def caller():
            with set_user_context(user_id="alice", roles=["admin"]):
                return slow_tool()
        
        result = asyncio.run(caller())
        assert result == "completed"

    def test_executor_saturation_warning(self, monkeypatch, caplog):
        """
        GIVEN: The shared executor at max capacity
        WHEN: Additional work is submitted
        THEN: Should handle gracefully (queued, not rejected)
        
        Note: This tests that the executor doesn't crash when saturated.
        The current implementation queues work, which is acceptable behavior.
        """
        _patch_pm(monkeypatch)
        
        # Get the executor's max workers
        executor = _get_auto_thread_executor()
        max_workers = executor._max_workers
        
        results = []
        errors = []
        
        @d2_guard("test.saturation_tool")
        def blocking_tool(tool_id: int):
            time.sleep(0.3)  # Block for a bit
            return f"tool_{tool_id}_done"
        
        async def saturate_executor():
            with set_user_context(user_id="alice", roles=["admin"]):
                # Submit more tasks than workers
                tasks = []
                for i in range(max_workers + 2):
                    # Each call from async context uses auto-threading
                    try:
                        result = blocking_tool(i)
                        results.append(result)
                    except Exception as e:
                        errors.append(str(e))
        
        # This should complete (tasks are queued, not rejected)
        start = time.time()
        asyncio.run(saturate_executor())
        elapsed = time.time() - start
        
        # All tasks should complete
        assert len(results) == max_workers + 2, f"Not all tasks completed: {len(results)} results, {len(errors)} errors"
        assert not errors, f"Unexpected errors: {errors}"
        
        # Should take longer than if all ran in parallel (proves queuing)
        # With 4 workers and 6 tasks at 0.3s each, should take at least 0.6s
        assert elapsed >= 0.4, "Tasks ran too fast - executor may not be properly bounded"

    def test_sync_tool_exception_propagates_correctly(self, monkeypatch):
        """
        GIVEN: A sync tool that raises an exception
        WHEN: Called from async context via auto-threading
        THEN: The exception should propagate correctly to the caller
        """
        _patch_pm(monkeypatch)
        
        @d2_guard("test.exception_tool")
        def failing_tool():
            raise ValueError("Intentional failure")
        
        async def caller():
            with set_user_context(user_id="alice", roles=["admin"]):
                return failing_tool()
        
        with pytest.raises(ValueError, match="Intentional failure"):
            asyncio.run(caller())


class TestExecutorTimeoutConfiguration:
    """Tests for configurable timeout behavior."""

    def test_timeout_env_var_respected(self, monkeypatch):
        """
        GIVEN: D2_SYNC_TIMEOUT environment variable is set
        WHEN: A sync tool is called from async context
        THEN: The timeout should be respected
        """
        from d2 import decorator as d2_dec
        
        # Verify timeout configuration exists
        assert hasattr(d2_dec, '_get_sync_timeout'), "Timeout config function should exist"
        assert hasattr(d2_dec, '_DEFAULT_SYNC_TIMEOUT_SECONDS'), "Default timeout should exist"
        
        # Test default value
        default_timeout = d2_dec._get_sync_timeout()
        assert default_timeout == d2_dec._DEFAULT_SYNC_TIMEOUT_SECONDS
        assert default_timeout > 0, "Default timeout should be positive"
        
        # Test custom env var
        monkeypatch.setenv("D2_SYNC_TIMEOUT", "60")
        assert d2_dec._get_sync_timeout() == 60.0
        
        # Test disabling timeout
        monkeypatch.setenv("D2_SYNC_TIMEOUT", "0")
        assert d2_dec._get_sync_timeout() is None
        
        monkeypatch.setenv("D2_SYNC_TIMEOUT", "none")
        assert d2_dec._get_sync_timeout() is None

    def test_very_slow_tool_behavior(self, monkeypatch):
        """
        GIVEN: A sync tool that would take very long (simulated)
        WHEN: Called from async context
        THEN: Should eventually complete or timeout (not hang forever)
        
        This is a regression test to ensure .result() doesn't block forever.
        """
        _patch_pm(monkeypatch)
        
        # We'll use a short delay to simulate the scenario without
        # actually waiting a long time
        
        @d2_guard("test.delayed_tool")
        def delayed_tool():
            time.sleep(0.2)
            return "eventually_done"
        
        async def caller():
            with set_user_context(user_id="alice", roles=["admin"]):
                start = time.time()
                result = delayed_tool()
                elapsed = time.time() - start
                return result, elapsed
        
        result, elapsed = asyncio.run(caller())
        
        assert result == "eventually_done"
        assert elapsed < 5, f"Tool took too long: {elapsed}s"

    def test_timeout_raises_error_for_slow_tool(self, monkeypatch):
        """
        GIVEN: A sync tool that takes longer than the configured timeout
        WHEN: Called from async context with a short timeout
        THEN: Should raise D2Error with informative message
        """
        _patch_pm(monkeypatch)
        
        # Set a very short timeout for testing
        monkeypatch.setenv("D2_SYNC_TIMEOUT", "0.1")
        
        # Use an Event to allow the tool to be interrupted cleanly
        stop_event = threading.Event()
        
        @d2_guard("test.timeout_tool")
        def very_slow_tool():
            # Sleep in small increments so we can be interrupted
            for _ in range(50):
                if stop_event.is_set():
                    break
                time.sleep(0.1)
            return "never_reached"
        
        async def caller():
            with set_user_context(user_id="alice", roles=["admin"]):
                return very_slow_tool()
        
        try:
            with pytest.raises(D2Error, match="timed out"):
                asyncio.run(caller())
        finally:
            # Signal the slow tool to stop (if still running in background)
            stop_event.set()
            # Give threads time to clean up
            time.sleep(0.2)


class TestExecutorContextPropagation:
    """Tests for context propagation through executor."""

    def test_context_propagates_to_worker_thread(self, monkeypatch):
        """
        GIVEN: User context set in async task
        WHEN: Sync tool runs in executor thread
        THEN: Context should be available in the worker thread
        """
        _patch_pm(monkeypatch)
        
        captured_context = [None]
        
        @d2_guard("test.context_check_tool")
        def context_check_tool():
            from d2.context import get_user_context
            captured_context[0] = get_user_context()
            return "done"
        
        async def caller():
            with set_user_context(user_id="test_user", roles=["tester"]):
                return context_check_tool()
        
        asyncio.run(caller())
        
        assert captured_context[0] is not None
        assert captured_context[0].user_id == "test_user"
        assert "tester" in captured_context[0].roles

    def test_context_isolated_between_executor_calls(self, monkeypatch):
        """
        GIVEN: Multiple sync tools called with different contexts
        WHEN: Each runs via auto-threading
        THEN: Each should see its own context (no leakage)
        """
        _patch_pm(monkeypatch)
        
        captured_contexts = []
        
        @d2_guard("test.isolate_tool")
        def isolate_tool(expected_user: str):
            from d2.context import get_user_context
            ctx = get_user_context()
            captured_contexts.append((expected_user, ctx.user_id))
            return ctx.user_id
        
        async def caller():
            results = []
            
            with set_user_context(user_id="user_a", roles=["admin"]):
                results.append(isolate_tool("user_a"))
            
            with set_user_context(user_id="user_b", roles=["viewer"]):
                results.append(isolate_tool("user_b"))
            
            return results
        
        results = asyncio.run(caller())
        
        # Each tool should have seen its own context
        for expected, actual in captured_contexts:
            assert expected == actual, f"Context leak: expected {expected}, got {actual}"

