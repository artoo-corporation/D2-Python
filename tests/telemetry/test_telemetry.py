# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

import asyncio, os, json, inspect
import types
import importlib

import pytest

# Ensure env var flush interval small for tests
os.environ["D2_USAGE_FLUSH_SEC"] = "1"

from d2.telemetry import UsageReporter


def test_track_event_buffers_correctly(monkeypatch):
    """Test that track_event properly buffers events."""
    reporter = UsageReporter(api_token="t", api_url="http://example.com")
    
    # Track a simple event
    reporter.track_event("tool_invoked", {"tool_id": "summarizer", "role": "admin"})
    assert reporter.get_buffer_size() == 1
    
    # Track another event
    reporter.track_event("authz_decision", {"tool_id": "test", "result": "allowed"})
    assert reporter.get_buffer_size() == 2


def test_shutdown_hook_force_flush(monkeypatch):
    # Use a temporary reporter with very short interval
    reporter = UsageReporter(api_token="t", api_url="http://example.com")
    reporter.track_event("test_event", {"data": "test"})

    # Monkeypatch httpx.AsyncClient to avoid real network I/O
    import httpx

    async def dummy_post(self, url, json=None, headers=None):
        class Resp:
            status_code = 200

            def raise_for_status(self):
                return None
        return Resp()

    async def _ac_enter(self):
        return self

    async def _ac_exit(self, exc_type, exc, tb):
        return False

    monkeypatch.setattr(httpx.AsyncClient, "__aenter__", _ac_enter)
    monkeypatch.setattr(httpx.AsyncClient, "__aexit__", _ac_exit)
    monkeypatch.setattr(httpx.AsyncClient, "post", dummy_post)

    # Force flush manually (simulating atexit handler)
    asyncio.run(reporter.force_flush())
    assert reporter.get_buffer_size() == 0


def test_usage_metrics_isolation():
    import pathlib, re

    telemetry_path = pathlib.Path(__file__).resolve().parents[2] / "d2" / "telemetry.py"
    content = telemetry_path.read_text()
    # no reference to UsageReporter (case-sensitive search)
    assert "UsageReporter" not in content, "telemetry.py must not reference UsageReporter"


# ---------------------------------------------------------------------------
# New test: host field auto-population and override
# ---------------------------------------------------------------------------


def test_track_event_host(monkeypatch):
    """Ensure host field defaults to socket.gethostname and can be overridden."""

    # Patch gethostname to deterministic value
    monkeypatch.setattr("socket.gethostname", lambda: "test-host")

    reporter = UsageReporter(api_token="t")
    reporter.track_event("test_event", {"action": "test"})
    event = reporter._buffer[-1]  # pylint: disable=protected-access
    assert event.get("payload", {}).get("host") == "test-host"

    # Override via constructor
    reporter2 = UsageReporter(api_token="t", host_id="override")
    reporter2.track_event("test_event", {"action": "test"})
    event2 = reporter2._buffer[-1]  # pylint: disable=protected-access
    assert event2.get("payload", {}).get("host") == "override" 