# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""
Tests for Listener thread-safety, specifically around shutdown signaling.

The PollingListener uses asyncio.Event for shutdown signaling, but asyncio.Event
is NOT thread-safe. These tests verify that shutdown can be safely triggered
from different threads without causing issues.

Key scenarios tested:
1. Shutdown called from a different thread than the event loop
2. Concurrent shutdown attempts from multiple threads
3. Shutdown during active polling
"""

import pytest
import asyncio
import threading
import time
from unittest.mock import patch, MagicMock, AsyncMock

from d2.listener import PollingListener


class MockResponse:
    """Mock HTTP response for polling endpoint."""
    
    def __init__(self, status_code=200, etag=None):
        self.status_code = status_code
        self.headers = {"ETag": etag} if etag else {}
        self.text = "{}"
    
    def json(self):
        return {"policy": {}}


class TestListenerShutdownThreadSafety:
    """Tests for shutdown signaling across threads."""

    @pytest.mark.asyncio
    async def test_shutdown_from_different_thread(self):
        """
        GIVEN: A running PollingListener with its event loop
        WHEN: shutdown() is triggered from a different thread
        THEN: The listener should stop gracefully without deadlock or crash
        
        This test exposes the issue with asyncio.Event not being thread-safe.
        Before the fix, this could cause undefined behavior or hang.
        """
        update_callback = AsyncMock()
        listener = PollingListener(
            bundle_url="https://example.com/bundle",
            update_callback=update_callback,
            initial_interval=1,
        )
        
        # Track shutdown completion
        shutdown_completed = threading.Event()
        shutdown_errors = []
        
        async def mock_get(*args, **kwargs):
            await asyncio.sleep(0.1)
            return MockResponse(status_code=304)
        
        async def run_listener():
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client.get = mock_get
            
            with patch('httpx.AsyncClient', return_value=mock_client):
                await listener.start()
                # Let it run for a bit
                await asyncio.sleep(0.2)
        
        # Start listener in main async context
        listener_task = asyncio.create_task(run_listener())
        
        # Give listener time to start
        await asyncio.sleep(0.1)
        
        # Trigger shutdown from a different thread
        def shutdown_from_thread():
            try:
                # This should work safely even from a different thread
                # Before fix: might cause issues because asyncio.Event isn't thread-safe
                asyncio.run(listener.shutdown())
                shutdown_completed.set()
            except Exception as e:
                shutdown_errors.append(str(e))
                shutdown_completed.set()
        
        shutdown_thread = threading.Thread(target=shutdown_from_thread)
        shutdown_thread.start()
        
        # Wait for shutdown with timeout
        shutdown_thread.join(timeout=5)
        
        # Cancel listener task if still running
        if not listener_task.done():
            listener_task.cancel()
            try:
                await listener_task
            except asyncio.CancelledError:
                pass
        
        # Verify no errors and thread completed
        assert not shutdown_thread.is_alive(), "Shutdown thread hung - possible deadlock"
        assert not shutdown_errors, f"Shutdown errors: {shutdown_errors}"
        assert shutdown_completed.is_set(), "Shutdown did not complete"

    @pytest.mark.asyncio
    async def test_shutdown_signal_is_thread_safe(self):
        """
        GIVEN: A PollingListener instance
        WHEN: Multiple threads try to signal shutdown simultaneously
        THEN: All signals should be handled safely without race conditions
        """
        update_callback = AsyncMock()
        listener = PollingListener(
            bundle_url="https://example.com/bundle",
            update_callback=update_callback,
            initial_interval=1,
        )
        
        # Start the listener
        async def mock_get(*args, **kwargs):
            await asyncio.sleep(0.05)
            return MockResponse(status_code=304)
        
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = mock_get
        
        with patch('httpx.AsyncClient', return_value=mock_client):
            await listener.start()
        
        # Wait for listener to be running
        await asyncio.sleep(0.1)
        
        # Try to signal shutdown from multiple threads
        signal_errors = []
        signal_lock = threading.Lock()
        
        def signal_shutdown(thread_id: int):
            try:
                # Access the shutdown event directly
                # After fix, this should use threading.Event which is thread-safe
                listener._shutdown_event.set()
            except Exception as e:
                with signal_lock:
                    signal_errors.append((thread_id, str(e)))
        
        threads = [threading.Thread(target=signal_shutdown, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=2)
        
        # Cleanup
        await listener.shutdown()
        
        # All threads should complete without error
        alive_threads = [t for t in threads if t.is_alive()]
        assert not alive_threads, f"{len(alive_threads)} threads still alive"
        assert not signal_errors, f"Signal errors: {signal_errors}"

    @pytest.mark.asyncio
    async def test_shutdown_event_can_be_checked_from_any_thread(self):
        """
        GIVEN: A PollingListener with shutdown event
        WHEN: The event is checked (is_set()) from different threads
        THEN: The check should be thread-safe and return consistent results
        """
        update_callback = AsyncMock()
        listener = PollingListener(
            bundle_url="https://example.com/bundle",
            update_callback=update_callback,
        )
        
        # Initially not set
        results = []
        results_lock = threading.Lock()
        
        def check_event(thread_id: int):
            try:
                is_set = listener._shutdown_event.is_set()
                with results_lock:
                    results.append((thread_id, is_set))
            except Exception as e:
                with results_lock:
                    results.append((thread_id, f"error: {e}"))
        
        # Check before setting
        threads = [threading.Thread(target=check_event, args=(i,)) for i in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=2)
        
        # All should return False
        for thread_id, result in results:
            assert result == False, f"Thread {thread_id} got unexpected result: {result}"
        
        # Now set and check again
        listener._shutdown_event.set()
        results.clear()
        
        threads = [threading.Thread(target=check_event, args=(i,)) for i in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=2)
        
        # All should return True
        for thread_id, result in results:
            assert result == True, f"Thread {thread_id} got unexpected result: {result}"


class TestListenerConcurrentOperations:
    """Tests for listener behavior under concurrent access."""

    @pytest.mark.asyncio
    async def test_poll_loop_respects_shutdown_during_sleep(self):
        """
        GIVEN: A polling listener sleeping between polls
        WHEN: Shutdown is signaled during sleep
        THEN: The listener should wake up and exit promptly
        """
        update_callback = AsyncMock()
        listener = PollingListener(
            bundle_url="https://example.com/bundle",
            update_callback=update_callback,
            initial_interval=10,  # Long interval
        )
        
        poll_count = [0]
        
        async def mock_get(*args, **kwargs):
            poll_count[0] += 1
            return MockResponse(status_code=304)
        
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = mock_get
        
        with patch('httpx.AsyncClient', return_value=mock_client):
            await listener.start()
            
            # Wait for first poll
            await asyncio.sleep(0.2)
            assert poll_count[0] >= 1, "Listener didn't start polling"
            
            # Shutdown while sleeping (should wake up quickly)
            start_time = time.time()
            await listener.shutdown()
            elapsed = time.time() - start_time
            
            # Should exit much faster than the 10-second interval
            assert elapsed < 2, f"Shutdown took {elapsed}s - listener didn't wake from sleep"


