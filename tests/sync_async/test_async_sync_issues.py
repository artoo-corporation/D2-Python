# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""
Tests for async/sync edge cases and bug fixes.

This module tests specific issues identified in code review:
1. Double tool call recording when using anyio.run() path
2. UsageReporter.start() without running event loop
3. File watcher hot-reload cross-thread scheduling
"""

import pytest
import asyncio
import threading
import time
from unittest.mock import patch, MagicMock, AsyncMock

import anyio

import d2
from d2.context import (
    set_user_context,
    get_user_context,
    clear_user_context,
    record_tool_call,
    _request_state_store,
    _state_store_lock,
)
from d2.telemetry.usage import UsageReporter


class _MockPolicyManager:
    """Minimal allow-all policy manager for testing."""
    mode = "file"
    _usage_reporter = None
    
    async def is_tool_in_policy_async(self, *_):
        return True
    
    async def check_async(self, *_):
        return True
    
    async def get_sequence_rules(self):
        return None, []
    
    async def get_tool_conditions(self, *_):
        return None
    
    def _get_bundle(self):
        return None


def _patch_pm(monkeypatch):
    """Patch the policy manager with a mock."""
    monkeypatch.setattr("d2.decorator.get_policy_manager", lambda *_: _MockPolicyManager())


class TestDoubleToolCallRecording:
    """Tests for the double tool call recording issue.
    
    When a sync decorated function is called without an event loop,
    it uses anyio.run() which creates a temporary event loop. Context
    changes inside don't propagate back, so the code re-records the
    tool call outside. But we must ensure it's only recorded ONCE total.
    """

    def test_sync_tool_records_call_once_no_event_loop(self, monkeypatch):
        """
        GIVEN: A sync decorated function called without an event loop
        WHEN: The function executes via anyio.run() path
        THEN: The tool call should be recorded exactly once in call_history
        """
        _patch_pm(monkeypatch)
        
        @d2.d2_guard("test.single_record")
        def my_tool():
            return "done"
        
        with set_user_context(user_id="alice", roles=["admin"]):
            # Call sync tool - no event loop running
            result = my_tool()
            
            # Get context and check call history
            ctx = get_user_context()
            call_count = ctx.call_history.count("test.single_record")
            
            assert result == "done"
            assert call_count == 1, (
                f"Tool call recorded {call_count} times, expected exactly 1. "
                f"Full history: {ctx.call_history}"
            )

    def test_sync_tool_records_call_once_in_async_context(self, monkeypatch):
        """
        GIVEN: A sync decorated function called from async context (auto-thread path)
        WHEN: The function executes via ThreadPoolExecutor
        THEN: The tool call should be recorded exactly once in call_history
        """
        _patch_pm(monkeypatch)
        
        @d2.d2_guard("test.autothread_record")
        def my_tool():
            return "done"
        
        async def caller():
            with set_user_context(user_id="alice", roles=["admin"]):
                result = my_tool()  # Sync in async = auto-thread
                ctx = get_user_context()
                return result, ctx.call_history
        
        result, history = anyio.run(caller)
        call_count = history.count("test.autothread_record")
        
        assert result == "done"
        assert call_count == 1, (
            f"Tool call recorded {call_count} times, expected exactly 1. "
            f"Full history: {history}"
        )

    def test_multiple_sync_tools_each_recorded_once(self, monkeypatch):
        """
        GIVEN: Multiple sync decorated functions called in sequence
        WHEN: Each function executes
        THEN: Each tool call should appear exactly once in call_history
        """
        _patch_pm(monkeypatch)
        
        @d2.d2_guard("test.tool_a")
        def tool_a():
            return "a"
        
        @d2.d2_guard("test.tool_b")
        def tool_b():
            return "b"
        
        @d2.d2_guard("test.tool_c")
        def tool_c():
            return "c"
        
        with set_user_context(user_id="alice", roles=["admin"]):
            tool_a()
            tool_b()
            tool_c()
            
            ctx = get_user_context()
            
            assert ctx.call_history.count("test.tool_a") == 1
            assert ctx.call_history.count("test.tool_b") == 1
            assert ctx.call_history.count("test.tool_c") == 1
            assert len(ctx.call_history) == 3


class TestUsageReporterEventLoopGuard:
    """Tests for UsageReporter.start() event loop handling."""

    def test_start_without_event_loop_does_not_crash(self):
        """
        GIVEN: UsageReporter instance
        WHEN: start() is called without a running event loop
        THEN: Should not raise, should log warning and return gracefully
              Task should NOT be created (no RuntimeError about unawaited coroutine)
        """
        reporter = UsageReporter(
            api_token="test_token",
            api_url="https://test.example.com"
        )
        
        # Ensure no event loop is running
        try:
            asyncio.get_running_loop()
            pytest.skip("Event loop already running, cannot test sync scenario")
        except RuntimeError:
            pass  # Good, no loop running
        
        # This should not raise
        errors = []
        try:
            reporter.start()
        except RuntimeError as e:
            errors.append(str(e))
        
        # Should succeed without crashing
        assert not errors, f"start() crashed without event loop: {errors}"
        
        # Task should NOT be created without event loop (the fix)
        assert reporter._task is None, (
            "Task was created without event loop - this causes 'coroutine never awaited' warning"
        )

    @pytest.mark.asyncio
    async def test_start_with_event_loop_creates_task(self):
        """
        GIVEN: UsageReporter instance
        WHEN: start() is called with a running event loop
        THEN: Should create the background task
        """
        reporter = UsageReporter(
            api_token="test_token",
            api_url="https://test.example.com"
        )
        
        assert reporter._task is None
        
        reporter.start()
        
        assert reporter._task is not None
        assert not reporter._task.done()
        
        # Cleanup
        await reporter.shutdown()

    def test_start_called_twice_logs_warning(self):
        """
        GIVEN: UsageReporter that has already been started
        WHEN: start() is called again
        THEN: Should log warning and not create duplicate task
        """
        async def run_test():
            reporter = UsageReporter(
                api_token="test_token",
                api_url="https://test.example.com"
            )
            
            reporter.start()
            first_task = reporter._task
            
            with patch('d2.telemetry.usage.logger') as mock_logger:
                reporter.start()
                mock_logger.warning.assert_called()
            
            # Should still be the same task
            assert reporter._task is first_task
            
            await reporter.shutdown()
        
        asyncio.run(run_test())


class TestFileWatcherCrossThread:
    """Tests for file watcher hot-reload cross-thread scheduling."""

    def test_schedule_policy_update_from_different_thread(self):
        """
        GIVEN: PolicyManager with a running event loop in main thread
        WHEN: _schedule_policy_update is called from a different thread (like watchdog)
        THEN: Should successfully schedule the update via run_coroutine_threadsafe
        """
        from d2.policy.manager import PolicyManager
        
        # Track if reload was scheduled
        reload_scheduled = threading.Event()
        
        async def mock_load_and_verify():
            reload_scheduled.set()
        
        async def setup_and_test():
            # Create a minimal PolicyManager-like object
            class MockPM:
                def __init__(self):
                    self._main_loop = asyncio.get_running_loop()
                    
                async def _load_and_verify_policy(self):
                    reload_scheduled.set()
            
            pm = MockPM()
            
            # Simulate watchdog thread calling schedule
            errors = []
            def watchdog_callback():
                try:
                    # This runs in a separate thread (no event loop)
                    PolicyManager._schedule_policy_update(pm)
                except Exception as e:
                    errors.append(str(e))
            
            # Run in separate thread
            thread = threading.Thread(target=watchdog_callback)
            thread.start()
            thread.join(timeout=2.0)
            
            # Give async task time to run
            await asyncio.sleep(0.2)
            
            return reload_scheduled.is_set(), errors
        
        result, errors = asyncio.run(setup_and_test())
        
        assert not errors, f"Cross-thread scheduling failed with errors: {errors}"
        assert result, "Policy reload was not scheduled from different thread"

    def test_schedule_policy_update_same_thread_uses_create_task(self):
        """
        GIVEN: PolicyManager with a running event loop in current thread
        WHEN: _schedule_policy_update is called from the same thread
        THEN: Should use create_task (faster path)
        """
        from d2.policy.manager import PolicyManager
        
        reload_scheduled = threading.Event()
        
        async def run_test():
            class MockPM:
                def __init__(self):
                    self._main_loop = asyncio.get_running_loop()
                    
                async def _load_and_verify_policy(self):
                    reload_scheduled.set()
            
            pm = MockPM()
            
            # Call from same thread as event loop
            PolicyManager._schedule_policy_update(pm)
            
            # Give task time to run
            await asyncio.sleep(0.1)
            
            return reload_scheduled.is_set()
        
        result = asyncio.run(run_test())
        assert result, "Policy reload was not scheduled in same thread"

    def test_schedule_policy_update_no_loop_logs_warning(self):
        """
        GIVEN: PolicyManager with no event loop anywhere
        WHEN: _schedule_policy_update is called
        THEN: Should log warning and not crash
        """
        from d2.policy.manager import PolicyManager
        
        # Ensure no event loop
        try:
            asyncio.get_running_loop()
            pytest.skip("Event loop running")
        except RuntimeError:
            pass
        
        class MockPM:
            _main_loop = None  # No stored loop either
            
            async def _load_and_verify_policy(self):
                pass
        
        pm = MockPM()
        
        with patch('d2.policy.manager.logger') as mock_logger:
            # Should not raise
            try:
                PolicyManager._schedule_policy_update(pm)
            except Exception as e:
                pytest.fail(f"_schedule_policy_update crashed: {e}")
            
            # Should have logged warning about no event loop
            mock_logger.warning.assert_called()


class TestContextGatherIsolation:
    """Tests for context sharing across asyncio.gather() tasks."""

    @pytest.mark.asyncio
    async def test_call_history_shared_across_gather_tasks(self, monkeypatch):
        """
        GIVEN: Multiple async tools called via asyncio.gather()
        WHEN: Each tool records its call
        THEN: All calls should be visible in the shared call_history
        """
        _patch_pm(monkeypatch)
        
        @d2.d2_guard("test.gather_a")
        async def tool_a():
            await asyncio.sleep(0.01)
            return "a"
        
        @d2.d2_guard("test.gather_b")
        async def tool_b():
            await asyncio.sleep(0.01)
            return "b"
        
        @d2.d2_guard("test.gather_c")
        async def tool_c():
            await asyncio.sleep(0.01)
            return "c"
        
        with set_user_context(user_id="alice", roles=["admin"]):
            # Call all tools concurrently
            results = await asyncio.gather(tool_a(), tool_b(), tool_c())
            
            ctx = get_user_context()
            
            # All three should be in history (order may vary due to concurrency)
            assert "test.gather_a" in ctx.call_history
            assert "test.gather_b" in ctx.call_history
            assert "test.gather_c" in ctx.call_history
            assert len(ctx.call_history) == 3
            assert set(results) == {"a", "b", "c"}


class TestAsyncExceptionContextCleanup:
    """Tests for context cleanup after exceptions."""

    @pytest.mark.asyncio
    async def test_context_cleared_after_async_exception(self, monkeypatch):
        """
        GIVEN: An async decorated function that raises an exception
        WHEN: The function raises inside set_user_context
        THEN: Context should still be cleared in finally block
        """
        _patch_pm(monkeypatch)
        
        @d2.d2_guard("test.exception_tool")
        async def failing_tool():
            raise ValueError("intentional failure")
        
        try:
            with set_user_context(user_id="alice", roles=["admin"]):
                await failing_tool()
        except ValueError:
            pass  # Expected
        
        # Context should be cleared after exiting the context manager
        ctx = get_user_context()
        assert ctx.user_id is None
        assert ctx.roles is None

    def test_context_cleared_after_sync_exception(self, monkeypatch):
        """
        GIVEN: A sync decorated function that raises an exception
        WHEN: The function raises inside set_user_context
        THEN: Context should still be cleared in finally block
        """
        _patch_pm(monkeypatch)
        
        @d2.d2_guard("test.sync_exception_tool")
        def failing_tool():
            raise ValueError("intentional failure")
        
        try:
            with set_user_context(user_id="alice", roles=["admin"]):
                failing_tool()
        except ValueError:
            pass  # Expected
        
        # Context should be cleared after exiting the context manager
        ctx = get_user_context()
        assert ctx.user_id is None
        assert ctx.roles is None

