# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""
Tests for d2.usage_reporter – buffer logic & HTTP send path.

The UsageReporter collects telemetry events in memory and periodically
sends them to the D2 cloud service. These tests verify:

1. Event buffering and flushing behavior
2. HTTP request format and error handling  
3. Buffer overflow protection
4. Telemetry payload enrichment with system metadata

Key concepts:
- Events are buffered in memory (deque) up to a size limit
- Periodic flushing sends events via HTTP POST
- Each event gets enriched with service, host, pid, etc.
- Buffer overflow drops oldest events (LRU behavior)
"""
from collections import deque

import pytest

from d2.telemetry import UsageReporter


@pytest.mark.anyio
async def test_successful_event_flush_clears_buffer(monkeypatch, httpx_ok):
    """
    GIVEN: Events are buffered in the reporter
    WHEN: We flush the buffer successfully  
    THEN: Events should be sent via HTTP POST and buffer should be cleared
    
    This tests the happy path of telemetry collection and transmission.
    """
    # Track what gets sent to verify the HTTP request
    http_requests_sent = []

    class HttpSpyClient(httpx_ok.__class__):  # type: ignore[misc]
        """Mock HTTP client that records requests for verification."""
        
        async def post(self, url, json=None, headers=None, **kwargs):  # noqa: D401
            """Record the HTTP POST request details."""
            if json and "events" in json:
                http_requests_sent.extend(json["events"])
            return await super().post(url, json=json, headers=headers, **kwargs)

    # Use our spy client instead of the default mock
    monkeypatch.setattr("httpx.AsyncClient", lambda: HttpSpyClient())

    # GIVEN: A reporter with one buffered event
    reporter = UsageReporter(api_token="test-token", api_url="http://test-api")
    reporter.track_event("tool_invoked", {"tool_id": "ping"})
    
    # Verify event is buffered before flush
    assert len(reporter._buffer) == 1  # pylint: disable=protected-access

    # WHEN: We flush the buffer
    await reporter._flush_buffer()  # pylint: disable=protected-access

    # THEN: Event should be sent via HTTP with enriched payload
    assert len(http_requests_sent) == 1, "Should send exactly one event"
    
    sent_event = http_requests_sent[0]
    assert sent_event["event_type"] == "tool_invoked", "Should preserve event type"
    
    # Verify payload enrichment (new telemetry format)
    payload = sent_event["payload"]
    assert payload["tool_id"] == "ping", "Should preserve original event data"
    assert "service" in payload, "Should add service identification"
    assert "host" in payload, "Should add host identification"  
    assert "pid" in payload, "Should add process identification"
    assert "flush_interval_s" in payload, "Should add operational metadata"
    
    assert "occurred_at" in sent_event, "Should add timestamp"
    
    # AND: Buffer should be empty after successful flush
    assert len(reporter._buffer) == 0, "Buffer should be cleared after flush"  # pylint: disable=protected-access


@pytest.mark.anyio
async def test_buffer_overflow_drops_oldest_events_first(monkeypatch, httpx_ok):
    """
    GIVEN: A usage reporter with limited buffer size
    WHEN: We add more events than the buffer can hold
    THEN: Should drop the oldest events (LRU behavior) to stay within limits
    
    This prevents memory exhaustion in long-running applications that
    generate many telemetry events.
    """
    monkeypatch.setattr("d2.telemetry.usage.MAX_BUFFER_SIZE", 2, raising=False)

    reporter = UsageReporter(api_token="x")  # uses patched MAX_BUFFER_SIZE

    # Sanity-check deque length cap
    assert reporter._buffer.maxlen == 2  # pylint: disable=protected-access

    reporter.track_event("e1", {})
    reporter.track_event("e2", {})
    reporter.track_event("e3", {})  # This should evict e1

    # v2 payloads do not have 'type' at top level; inspect payloads via transform
    assert len(reporter._buffer) == 2  # pylint: disable=protected-access

    # Flush succeeds and only emits the remaining two events
    sent: list[str] = []

    class _SpyClient(httpx_ok.__class__):  # type: ignore[misc]
        async def post(self, _url, json=None, headers=None, **kwargs):  # noqa: D401
            if json and "events" in json:
                sent.extend(e["event_type"] for e in json["events"])
            return await super().post(_url, json=json, headers=headers, **kwargs)

    monkeypatch.setattr("httpx.AsyncClient", lambda: _SpyClient())

    await reporter._flush_buffer()  # pylint: disable=protected-access
    assert sent == ["e2", "e3"]


def test_flush_interval_respects_plan_limits(monkeypatch):
    """
    GIVEN: Server returns custom event_flush_interval_seconds in plan quotas
    WHEN: UsageReporter is initialized
    THEN: Should use the plan-specified flush interval instead of hardcoded default
    
    This allows dynamic control of telemetry flush intervals based on customer plan:
    - Free tier: longer intervals (e.g., 300s) to reduce server load
    - Paid tier: shorter intervals (e.g., 30s) for real-time analytics
    - Debug mode: very short intervals (e.g., 5s) for testing
    """
    # Mock resolve_limits to return a custom flush interval
    def mock_resolve_limits(token):
        return {
            "max_tools": 100,
            "event_batch": 1000,
            "event_flush_interval_seconds": 120,  # 2 minutes instead of default 60s
            "event_sample": {},
        }
    
    monkeypatch.setattr("d2.telemetry.usage.resolve_limits", mock_resolve_limits)
    
    # WHEN: Creating a UsageReporter
    reporter = UsageReporter(api_token="test-token", api_url="http://test-api")
    
    # THEN: Should use the plan-specified interval
    assert reporter._flush_interval_s == 120  # pylint: disable=protected-access


def test_flush_interval_falls_back_to_default_when_not_in_plan(monkeypatch):
    """
    GIVEN: Server doesn't return event_flush_interval_seconds in quotas (older server)
    WHEN: UsageReporter is initialized
    THEN: Should fall back to the default 60-second interval
    
    This ensures backward compatibility with older API versions.
    """
    # Mock resolve_limits without the flush interval field
    def mock_resolve_limits(token):
        return {
            "max_tools": 100,
            "event_batch": 1000,
            "event_sample": {},
            # No event_flush_interval_seconds
        }
    
    monkeypatch.setattr("d2.telemetry.usage.resolve_limits", mock_resolve_limits)
    
    # WHEN: Creating a UsageReporter
    reporter = UsageReporter(api_token="test-token", api_url="http://test-api")
    
    # THEN: Should fall back to default 60 seconds
    assert reporter._flush_interval_s == 60  # pylint: disable=protected-access


class TestRequestIdCorrelation:
    """Tests for request_id correlation across multiple user requests.
    
    The request_id is a per-request context variable that should be included
    in telemetry events to enable call chain correlation on the control plane.
    It must NOT be cached once and reused, as that would lead to incorrect
    correlation across different user requests.
    
    Note: request_id is auto-generated by set_user_context for security reasons
    (to prevent user tampering). Tests verify the value changes, not specific values.
    """

    def test_request_id_refreshes_per_event_not_cached_once(self, monkeypatch):
        """
        GIVEN: UsageReporter tracks events across multiple user requests
        WHEN: User context changes between events (different auto-generated request_ids)
        THEN: Each event should capture the CURRENT request_id, not a stale cached one
        
        BUG: The original implementation cached request_id once in _extract_policy_context
        and reused it for all subsequent events. This breaks telemetry correlation.
        """
        from d2.context import set_user_context, clear_user_context, get_user_context
        
        reporter = UsageReporter(api_token="test-token", api_url="http://test-api")
        
        # GIVEN: First request (request_id is auto-generated)
        with set_user_context(user_id="alice", roles=["admin"]):
            first_request_id = get_user_context().request_id
            reporter.track_event("tool_invoked", {"tool_id": "tool_a"})
        
        # Get the first event
        first_event = reporter._buffer[0]  # pylint: disable=protected-access
        
        clear_user_context()
        
        # WHEN: Second request (new auto-generated request_id)
        with set_user_context(user_id="bob", roles=["viewer"]):
            second_request_id = get_user_context().request_id
            reporter.track_event("tool_invoked", {"tool_id": "tool_b"})
        
        # Get the second event
        second_event = reporter._buffer[1]  # pylint: disable=protected-access
        
        # Sanity check: the two requests have different IDs
        assert first_request_id != second_request_id, \
            "Each set_user_context call should generate a unique request_id"
        
        # THEN: Each event should have its own correct request_id (not stale cached value)
        assert first_event["payload"].get("request_id") == first_request_id, \
            "First event should have request_id from first request"
        assert second_event["payload"].get("request_id") == second_request_id, \
            "Second event should have request_id from second request (NOT cached stale value)"

    def test_request_id_updates_when_context_changes_mid_request(self, monkeypatch):
        """
        GIVEN: UsageReporter is tracking events
        WHEN: Context changes (e.g., nested request creates new request_id)
        THEN: New events should use the updated request_id
        
        This ensures telemetry accurately reflects the current request context.
        """
        from d2.context import set_user_context, clear_user_context, get_user_context
        
        reporter = UsageReporter(api_token="test-token", api_url="http://test-api")
        
        # First context
        with set_user_context(user_id="alice", roles=["admin"]):
            outer_request_id = get_user_context().request_id
            reporter.track_event("tool_invoked", {"tool_id": "outer_tool"})
            
            # Nested context (e.g., sub-request) generates new request_id
            with set_user_context(user_id="alice", roles=["admin"]):
                inner_request_id = get_user_context().request_id
                reporter.track_event("tool_invoked", {"tool_id": "inner_tool"})
        
        events = list(reporter._buffer)  # pylint: disable=protected-access
        
        # Sanity check: nested context creates new request_id
        assert outer_request_id != inner_request_id
        
        # Each event should have the request_id that was active when it was tracked
        assert events[0]["payload"].get("request_id") == outer_request_id
        assert events[1]["payload"].get("request_id") == inner_request_id

    def test_request_id_none_when_no_context_set(self, monkeypatch):
        """
        GIVEN: No user context is set
        WHEN: An event is tracked
        THEN: request_id should be absent or None (not a stale cached value)
        """
        from d2.context import clear_user_context
        
        clear_user_context()  # Ensure no context
        
        reporter = UsageReporter(api_token="test-token", api_url="http://test-api")
        reporter.track_event("tool_invoked", {"tool_id": "anonymous_tool"})
        
        event = reporter._buffer[0]  # pylint: disable=protected-access
        
        # request_id should be absent when no context is set
        assert "request_id" not in event["payload"] or event["payload"].get("request_id") is None


class TestSyncContextBufferFlush:
    """Tests for non-blocking buffer flush behavior in sync contexts.
    
    When buffer overflows in a sync context (no event loop), the flush should
    be non-blocking to avoid introducing unexpected latency into user code.
    """

    def test_buffer_overflow_in_sync_context_does_not_block(self, monkeypatch):
        """
        GIVEN: UsageReporter buffer is at max capacity in a sync context
        WHEN: A new event is added (triggering overflow flush)
        THEN: Should spawn a daemon thread instead of blocking with asyncio.run()
        
        This prevents unexpected latency spikes when telemetry buffer fills up
        in sync applications (Flask, Django, etc.).
        """
        import threading
        import time
        
        # Track spawned threads
        spawned_threads = []
        original_thread_init = threading.Thread.__init__
        
        def tracking_thread_init(self, *args, **kwargs):
            original_thread_init(self, *args, **kwargs)
            spawned_threads.append(self)
        
        monkeypatch.setattr(threading.Thread, "__init__", tracking_thread_init)
        
        # Set tiny buffer to trigger overflow quickly
        monkeypatch.setattr("d2.telemetry.usage.MAX_BUFFER_SIZE", 2, raising=False)
        
        # Mock HTTP to avoid actual network calls
        async def mock_post(*args, **kwargs):
            class MockResponse:
                status_code = 200
                def raise_for_status(self):
                    pass
            return MockResponse()
        
        class MockAsyncClient:
            async def __aenter__(self):
                return self
            async def __aexit__(self, *args):
                pass
            post = mock_post
        
        monkeypatch.setattr("httpx.AsyncClient", MockAsyncClient)
        
        reporter = UsageReporter(api_token="test-token", api_url="http://test-api")
        
        # Clear any threads spawned during init
        spawned_threads.clear()
        
        # Add events to fill buffer and trigger overflow
        reporter.track_event("e1", {})
        reporter.track_event("e2", {})
        
        # Record time before overflow event
        start_time = time.perf_counter()
        reporter.track_event("e3", {})  # This should trigger overflow flush
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        
        # THEN: Should return quickly (< 50ms) instead of waiting for HTTP
        # Network timeout is 5s, so if we block we'd see much longer times
        assert elapsed_ms < 100, f"Buffer flush took {elapsed_ms}ms - appears to be blocking"
        
        # AND: Should have spawned a daemon thread for the flush
        daemon_threads = [t for t in spawned_threads if t.daemon]
        assert len(daemon_threads) >= 1, "Should spawn daemon thread for background flush"

    @pytest.mark.anyio
    async def test_buffer_overflow_in_async_context_uses_task(self, monkeypatch):
        """
        GIVEN: UsageReporter buffer is at max capacity in an async context
        WHEN: A new event is added (triggering overflow flush)
        THEN: Should NOT spawn a thread (should use loop.create_task instead)
        
        In async contexts, using create_task is more efficient than threads.
        """
        import asyncio
        import threading
        
        # Track spawned threads
        spawned_threads = []
        original_thread_start = threading.Thread.start
        
        def tracking_thread_start(self):
            spawned_threads.append(self)
            return original_thread_start(self)
        
        monkeypatch.setattr(threading.Thread, "start", tracking_thread_start)
        
        # Mock HTTP
        async def mock_post(*args, **kwargs):
            class MockResponse:
                status_code = 200
                def raise_for_status(self):
                    pass
            return MockResponse()
        
        class MockAsyncClient:
            async def __aenter__(self):
                return self
            async def __aexit__(self, *args):
                pass
            post = mock_post
        
        monkeypatch.setattr("httpx.AsyncClient", MockAsyncClient)
        
        reporter = UsageReporter(api_token="test-token", api_url="http://test-api")
        # Manually set the buffer maxlen
        reporter._buffer = deque(maxlen=2)  # pylint: disable=protected-access
        spawned_threads.clear()
        
        # Add events to trigger overflow
        reporter.track_event("e1", {})
        reporter.track_event("e2", {})
        reporter.track_event("e3", {})  # Overflow
        
        # Give a moment for async task to be scheduled
        await asyncio.sleep(0.01)
        
        # In async context, should NOT spawn threads (should use loop.create_task)
        assert len(spawned_threads) == 0, \
            f"Should use asyncio task, not thread, in async context. Spawned threads: {len(spawned_threads)}" 