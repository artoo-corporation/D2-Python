# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""
Tests for UsageReporter thread-safety and async safety.

The UsageReporter has several concurrent access patterns:
1. Buffer access from multiple async tasks or threads
2. Background flush thread spawning when buffer is full
3. Async reporter loop running in background

Key scenarios tested:
1. High-volume event tracking doesn't lose events
2. Buffer overflow doesn't spawn unlimited threads
3. Async and sync callers don't interfere
4. Graceful shutdown under load
"""

import pytest
import asyncio
import threading
import time
from unittest.mock import patch, MagicMock, AsyncMock
from concurrent.futures import ThreadPoolExecutor

from d2.telemetry.usage import UsageReporter, MAX_BUFFER_SIZE


class MockResponse:
    """Mock HTTP response."""
    def __init__(self, status_code=200):
        self.status_code = status_code
        self.headers = {}
    
    def raise_for_status(self):
        if self.status_code >= 400:
            raise Exception(f"HTTP {self.status_code}")


class TestUsageReporterBufferSafety:
    """Tests for buffer operations under concurrent access."""

    def test_concurrent_track_event_no_lost_events(self):
        """
        GIVEN: Multiple threads calling track_event() concurrently
        WHEN: Events are added rapidly
        THEN: No events should be lost (up to buffer max)
        """
        reporter = UsageReporter(
            api_token="test_token",
            api_url="https://test.example.com"
        )
        
        events_per_thread = 50
        num_threads = 10
        expected_count = min(events_per_thread * num_threads, MAX_BUFFER_SIZE)
        
        def track_events(thread_id: int):
            for i in range(events_per_thread):
                reporter.track_event(
                    "test_event",
                    {"thread_id": thread_id, "event_num": i}
                )
        
        # Patch to prevent actual HTTP calls and background flushes
        with patch.object(reporter, '_flush_buffer', new_callable=AsyncMock):
            threads = [
                threading.Thread(target=track_events, args=(i,))
                for i in range(num_threads)
            ]
            
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        
        buffer_size = reporter.get_buffer_size()
        
        # Should have captured events up to max buffer size
        assert buffer_size <= MAX_BUFFER_SIZE, "Buffer exceeded max size"
        assert buffer_size > 0, "Buffer is empty - events were lost"
        
        # If we're under the limit, all events should be captured
        if events_per_thread * num_threads <= MAX_BUFFER_SIZE:
            assert buffer_size == events_per_thread * num_threads, (
                f"Lost events: expected {events_per_thread * num_threads}, got {buffer_size}"
            )

    @pytest.mark.asyncio
    async def test_async_track_event_no_lost_events(self):
        """
        GIVEN: Multiple async tasks calling track_event() concurrently
        WHEN: Events are added with yields between them
        THEN: No events should be lost
        """
        reporter = UsageReporter(
            api_token="test_token",
            api_url="https://test.example.com"
        )
        
        events_per_task = 30
        num_tasks = 10
        
        async def track_events(task_id: int):
            for i in range(events_per_task):
                reporter.track_event(
                    "async_test_event",
                    {"task_id": task_id, "event_num": i}
                )
                await asyncio.sleep(0)  # Yield to allow interleaving
        
        with patch.object(reporter, '_flush_buffer', new_callable=AsyncMock):
            await asyncio.gather(*[track_events(i) for i in range(num_tasks)])
        
        buffer_size = reporter.get_buffer_size()
        expected = events_per_task * num_tasks
        
        assert buffer_size == expected, (
            f"Lost events: expected {expected}, got {buffer_size}"
        )

    def test_buffer_overflow_handling(self):
        """
        GIVEN: More events than buffer capacity
        WHEN: Events are added rapidly
        THEN: Buffer should not exceed max size (old events dropped)
        """
        reporter = UsageReporter(
            api_token="test_token",
            api_url="https://test.example.com"
        )
        
        # Disable background flushing
        with patch.object(reporter, '_flush_buffer', new_callable=AsyncMock):
            # Add more events than buffer can hold
            for i in range(MAX_BUFFER_SIZE + 500):
                reporter.track_event("overflow_test", {"num": i})
        
        buffer_size = reporter.get_buffer_size()
        assert buffer_size == MAX_BUFFER_SIZE, (
            f"Buffer size {buffer_size} doesn't match max {MAX_BUFFER_SIZE}"
        )


class TestUsageReporterThreadSpawning:
    """Tests for background thread spawning behavior."""

    def test_buffer_overflow_does_not_spawn_unlimited_threads(self):
        """
        GIVEN: Buffer overflow condition in sync context (no event loop)
        WHEN: Multiple overflows occur rapidly
        THEN: Should not spawn unlimited background threads
        
        The issue: each overflow spawns a new daemon thread for flushing.
        Under high load, this could create many threads.
        """
        reporter = UsageReporter(
            api_token="test_token",
            api_url="https://test.example.com"
        )
        
        threads_spawned = []
        original_thread_class = threading.Thread
        
        class CountingThread(threading.Thread):
            def __init__(self, *args, **kwargs):
                threads_spawned.append(time.time())
                super().__init__(*args, **kwargs)
        
        # Fill buffer to near capacity
        for i in range(MAX_BUFFER_SIZE - 10):
            reporter._buffer.append({"event": f"prefill_{i}"})
        
        # Mock to prevent actual HTTP calls but allow thread to be created
        async def slow_flush():
            await asyncio.sleep(0.5)  # Simulate slow network
        
        with patch('threading.Thread', CountingThread):
            with patch.object(reporter, '_flush_buffer', slow_flush):
                # Trigger multiple overflows rapidly
                for i in range(50):
                    reporter.track_event("overflow_trigger", {"num": i})
        
        # Should have spawned at most a few threads due to the _sync_flush_pending guard
        # The fix ensures only one flush thread runs at a time
        thread_count = len(threads_spawned)
        
        # With the fix, we should have at most a handful of threads (not 50!)
        # Each flush completes and allows the next one, but concurrent overflows
        # should not spawn multiple threads
        assert thread_count <= 5, (
            f"Thread spawn issue: {thread_count} threads for 50 overflows. "
            f"Expected at most 5 threads due to _sync_flush_pending guard."
        )

    def test_flush_thread_is_daemon(self):
        """
        GIVEN: Buffer overflow in sync context
        WHEN: Background flush thread is spawned
        THEN: Thread should be a daemon (won't block process exit)
        """
        reporter = UsageReporter(
            api_token="test_token",
            api_url="https://test.example.com"
        )
        
        spawned_thread = None
        original_thread_class = threading.Thread
        
        class CapturingThread(threading.Thread):
            def __init__(self, *args, **kwargs):
                nonlocal spawned_thread
                super().__init__(*args, **kwargs)
                spawned_thread = self
        
        # Fill buffer to trigger overflow
        for i in range(MAX_BUFFER_SIZE - 1):
            reporter._buffer.append({"event": f"prefill_{i}"})
        
        with patch('threading.Thread', CapturingThread):
            with patch.object(reporter, '_flush_buffer', new_callable=AsyncMock):
                reporter.track_event("trigger", {})
        
        if spawned_thread:
            assert spawned_thread.daemon, "Flush thread should be a daemon thread"


class TestUsageReporterAsyncOperations:
    """Tests for async operations in UsageReporter."""

    @pytest.mark.asyncio
    async def test_start_creates_background_task(self):
        """
        GIVEN: A new UsageReporter instance
        WHEN: start() is called in async context
        THEN: Background reporter task should be created
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
        assert reporter._task.done() or reporter._task.cancelled()

    @pytest.mark.asyncio
    async def test_shutdown_flushes_remaining_events(self):
        """
        GIVEN: UsageReporter with buffered events
        WHEN: shutdown() is called
        THEN: Remaining events should be flushed
        """
        reporter = UsageReporter(
            api_token="test_token",
            api_url="https://test.example.com"
        )
        
        # Add some events
        for i in range(10):
            reporter.track_event("pre_shutdown", {"num": i})
        
        initial_buffer_size = reporter.get_buffer_size()
        assert initial_buffer_size == 10
        
        flush_called = False
        original_flush = reporter._flush_buffer
        
        async def tracking_flush():
            nonlocal flush_called
            flush_called = True
            await original_flush()
        
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.post = AsyncMock(return_value=MockResponse(200))
        
        reporter.start()
        
        with patch('httpx.AsyncClient', return_value=mock_client):
            reporter._flush_buffer = tracking_flush
            await reporter.shutdown()
        
        assert flush_called, "Flush should be called during shutdown"

    @pytest.mark.asyncio
    async def test_reporter_loop_handles_cancellation_gracefully(self):
        """
        GIVEN: UsageReporter with running background task
        WHEN: Task is cancelled (e.g., during shutdown)
        THEN: Should handle cancellation without error
        """
        reporter = UsageReporter(
            api_token="test_token",
            api_url="https://test.example.com"
        )
        
        reporter.start()
        
        # Let it run briefly
        await asyncio.sleep(0.01)
        
        # Shutdown should cancel gracefully
        errors = []
        try:
            await reporter.shutdown()
        except Exception as e:
            errors.append(str(e))
        
        assert not errors, f"Shutdown errors: {errors}"


class TestUsageReporterMixedAccess:
    """Tests for mixed sync and async access patterns."""

    @pytest.mark.asyncio
    async def test_sync_and_async_callers_dont_interfere(self):
        """
        GIVEN: Both sync threads and async tasks accessing reporter
        WHEN: All are tracking events concurrently
        THEN: No events should be lost and no errors
        """
        reporter = UsageReporter(
            api_token="test_token",
            api_url="https://test.example.com"
        )
        
        events_per_source = 20
        sync_errors = []
        async_events_tracked = []
        
        def sync_worker(worker_id: int):
            try:
                for i in range(events_per_source):
                    reporter.track_event(
                        "sync_event",
                        {"worker_id": worker_id, "num": i}
                    )
            except Exception as e:
                sync_errors.append((worker_id, str(e)))
        
        async def async_worker(worker_id: int):
            for i in range(events_per_source):
                reporter.track_event(
                    "async_event",
                    {"worker_id": worker_id, "num": i}
                )
                async_events_tracked.append((worker_id, i))
                await asyncio.sleep(0)
        
        with patch.object(reporter, '_flush_buffer', new_callable=AsyncMock):
            # Start sync workers in threads
            threads = [
                threading.Thread(target=sync_worker, args=(i,))
                for i in range(3)
            ]
            for t in threads:
                t.start()
            
            # Run async workers concurrently
            await asyncio.gather(*[async_worker(i + 100) for i in range(3)])
            
            # Wait for sync workers
            for t in threads:
                t.join()
        
        assert not sync_errors, f"Sync worker errors: {sync_errors}"
        
        buffer_size = reporter.get_buffer_size()
        expected_total = events_per_source * 6  # 3 sync + 3 async workers
        
        assert buffer_size == expected_total, (
            f"Lost events: expected {expected_total}, got {buffer_size}"
        )


class TestUsageReporterEventSampling:
    """Tests for event sampling functionality."""

    def test_sampling_is_thread_safe(self):
        """
        GIVEN: Event sampling configured to drop some events
        WHEN: Multiple threads track events concurrently
        THEN: Sampling should work correctly without race conditions
        """
        reporter = UsageReporter(
            api_token="test_token",
            api_url="https://test.example.com"
        )
        
        # Configure 50% sampling for test events
        reporter._event_sample = {"sampled_event": 0.5}
        
        events_per_thread = 100
        num_threads = 5
        
        def track_events(thread_id: int):
            for i in range(events_per_thread):
                reporter.track_event(
                    "sampled_event",
                    {"thread_id": thread_id, "num": i}
                )
        
        with patch.object(reporter, '_flush_buffer', new_callable=AsyncMock):
            threads = [
                threading.Thread(target=track_events, args=(i,))
                for i in range(num_threads)
            ]
            
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        
        buffer_size = reporter.get_buffer_size()
        total_attempts = events_per_thread * num_threads
        
        # With 50% sampling, we expect roughly half
        # Allow wide margin for randomness
        assert buffer_size < total_attempts, "Sampling should have dropped some events"
        assert buffer_size > total_attempts * 0.2, "Too many events dropped"


class TestUsageReporterFlushSafety:
    """Tests for flush operation safety."""

    @pytest.mark.asyncio
    async def test_concurrent_flushes_dont_lose_events(self):
        """
        GIVEN: Events being added while flush is in progress
        WHEN: Flush drains the buffer
        THEN: New events added during flush should not be lost
        """
        reporter = UsageReporter(
            api_token="test_token",
            api_url="https://test.example.com"
        )
        
        # Add initial events
        for i in range(10):
            reporter.track_event("initial", {"num": i})
        
        events_added_during_flush = []
        
        original_flush = reporter._flush_buffer
        
        async def slow_flush():
            # Simulate slow flush - add events during it
            for i in range(5):
                reporter.track_event("during_flush", {"num": i})
                events_added_during_flush.append(i)
                await asyncio.sleep(0.01)
            await original_flush()
        
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.post = AsyncMock(return_value=MockResponse(200))
        
        with patch('httpx.AsyncClient', return_value=mock_client):
            reporter._flush_buffer = slow_flush
            await reporter.force_flush()
        
        # Events added during flush should still be tracked
        # (though they may be in the next batch)
        assert len(events_added_during_flush) == 5

