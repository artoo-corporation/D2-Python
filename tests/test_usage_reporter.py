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

from d2.usage_reporter import UsageReporter


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
    monkeypatch.setattr("d2.usage_reporter.MAX_BUFFER_SIZE", 2, raising=False)

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