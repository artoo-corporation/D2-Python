# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""Tests for CloudPolicyLoader – async correctness and resource management.

These tests ensure:
1. No blocking calls (time.sleep) in async contexts
2. HTTP clients are properly closed (no resource leaks)
3. Retry logic works correctly
"""
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from d2.policy.loaders.cloud import CloudPolicyLoader


class TestCloudLoaderAsyncCorrectness:
    """Test async correctness in CloudPolicyLoader."""

    @pytest.mark.anyio
    async def test_retry_uses_async_sleep_not_blocking_sleep(self, monkeypatch):
        """
        GIVEN: Cloud loader needs to retry due to 5xx/429 error
        WHEN: Retry backoff occurs
        THEN: Should use asyncio.sleep, NOT blocking time.sleep
        
        Blocking time.sleep in an async context stalls the entire event loop,
        degrading performance for all concurrent tasks.
        """
        # Track which sleep function gets called
        blocking_sleep_called = False
        async_sleep_called = False
        
        def blocking_sleep_spy(duration):
            nonlocal blocking_sleep_called
            blocking_sleep_called = True
            # Don't actually sleep
        
        async def async_sleep_spy(duration):
            nonlocal async_sleep_called
            async_sleep_called = True
            # Don't actually sleep
        
        # Mock the CacheManager to avoid file system access
        mock_cache = MagicMock()
        mock_cache.get_polling_state.return_value = {"next_poll_at": 0}
        mock_cache.get_cached_bundle.return_value = None
        mock_cache.get_cached_etag.return_value = None
        mock_cache.get_context.return_value = None
        mock_cache.save_bundle = MagicMock()
        mock_cache.save_context = MagicMock()
        mock_cache.save_polling_state = MagicMock()
        
        # Mock require_app_name to avoid file system access
        monkeypatch.setattr("d2.policy.loaders.cloud.require_app_name", lambda: "test-app")
        monkeypatch.setattr("d2.policy.loaders.cloud.CacheManager", lambda *a, **kw: mock_cache)
        
        # First response: 503 (triggers retry)
        # Second response: 200 OK
        call_count = 0
        
        class MockResponse:
            def __init__(self, status_code):
                self.status_code = status_code
                self.headers = {"ETag": "test-etag", "X-D2-Poll-Seconds": "60"}
            
            def raise_for_status(self):
                if self.status_code >= 400:
                    raise Exception(f"HTTP {self.status_code}")
            
            def json(self):
                return {"jws": "test-jws", "version": 1}
        
        class MockClient:
            async def __aenter__(self):
                return self
            
            async def __aexit__(self, *args):
                pass
            
            async def get(self, *args, **kwargs):
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    return MockResponse(503)  # First call: error
                return MockResponse(200)  # Second call: success
        
        monkeypatch.setattr("httpx.AsyncClient", MockClient)
        monkeypatch.setattr("time.sleep", blocking_sleep_spy)
        monkeypatch.setattr("asyncio.sleep", async_sleep_spy)
        
        loader = CloudPolicyLoader(
            policy_manager=MagicMock(),
            api_url="http://test.example.com",
            api_token="test-token"
        )
        
        # Execute load_policy which should trigger retry
        await loader.load_policy()
        
        # THEN: async sleep should have been used, NOT blocking sleep
        assert async_sleep_called, "Should use asyncio.sleep for retry backoff"
        assert not blocking_sleep_called, "Should NOT use blocking time.sleep in async context"
    
    @pytest.mark.anyio
    async def test_httpx_client_is_always_closed(self, monkeypatch):
        """
        GIVEN: Cloud loader makes HTTP requests
        WHEN: Any code path executes (success, error, 304, etc.)
        THEN: httpx.AsyncClient should always be properly closed
        
        Unclosed clients leak connections and file descriptors.
        """
        clients_created = []
        clients_closed = []
        
        class TrackingClient:
            def __init__(self):
                clients_created.append(self)
            
            async def __aenter__(self):
                return self
            
            async def __aexit__(self, *args):
                clients_closed.append(self)
            
            async def get(self, *args, **kwargs):
                class Resp:
                    status_code = 200
                    headers = {"ETag": "etag", "X-D2-Poll-Seconds": "60"}
                    def raise_for_status(self): pass
                    def json(self): return {"jws": "test", "version": 1}
                return Resp()
        
        # Mock the CacheManager
        mock_cache = MagicMock()
        mock_cache.get_polling_state.return_value = {"next_poll_at": 0}
        mock_cache.get_cached_bundle.return_value = None
        mock_cache.get_cached_etag.return_value = None
        mock_cache.get_context.return_value = None
        mock_cache.save_bundle = MagicMock()
        mock_cache.save_context = MagicMock()
        mock_cache.save_polling_state = MagicMock()
        
        monkeypatch.setattr("d2.policy.loaders.cloud.require_app_name", lambda: "test-app")
        monkeypatch.setattr("d2.policy.loaders.cloud.CacheManager", lambda *a, **kw: mock_cache)
        monkeypatch.setattr("httpx.AsyncClient", TrackingClient)
        
        loader = CloudPolicyLoader(
            policy_manager=MagicMock(),
            api_url="http://test.example.com",
            api_token="test-token"
        )
        
        await loader.load_policy()
        
        # All created clients should be closed
        assert len(clients_created) > 0, "Should create at least one client"
        assert len(clients_closed) == len(clients_created), \
            f"All {len(clients_created)} clients should be closed, but only {len(clients_closed)} were"

    @pytest.mark.anyio
    async def test_304_response_with_missing_cache_closes_client(self, monkeypatch):
        """
        GIVEN: Cloud loader receives 304 Not Modified
        WHEN: Cached bundle is missing (edge case)
        THEN: The fallback fresh fetch should also properly close its client
        
        This tests the specific code path where cached_bundle is None after 304.
        """
        clients_created = []
        clients_closed = []
        call_count = 0
        
        class TrackingClient:
            def __init__(self):
                clients_created.append(self)
            
            async def __aenter__(self):
                return self
            
            async def __aexit__(self, *args):
                clients_closed.append(self)
            
            async def get(self, *args, **kwargs):
                nonlocal call_count
                call_count += 1
                
                class Resp304:
                    status_code = 304
                    headers = {"X-D2-Poll-Seconds": "60"}
                    def raise_for_status(self): pass
                    def json(self): return {}
                
                class Resp200:
                    status_code = 200
                    headers = {"ETag": "new-etag", "X-D2-Poll-Seconds": "60"}
                    def raise_for_status(self): pass
                    def json(self): return {"jws": "fresh-jws", "version": 1}
                
                if call_count == 1:
                    return Resp304()  # First: 304 Not Modified
                return Resp200()  # Second: fresh fetch
        
        # Mock cache that returns None for bundle (simulates missing cache)
        mock_cache = MagicMock()
        mock_cache.get_polling_state.return_value = {"next_poll_at": 0}
        mock_cache.get_cached_bundle.return_value = None  # Cache miss!
        mock_cache.get_cached_etag.return_value = "old-etag"
        mock_cache.get_context.return_value = None
        mock_cache.save_bundle = MagicMock()
        mock_cache.save_context = MagicMock()
        mock_cache.save_polling_state = MagicMock()
        
        monkeypatch.setattr("d2.policy.loaders.cloud.require_app_name", lambda: "test-app")
        monkeypatch.setattr("d2.policy.loaders.cloud.CacheManager", lambda *a, **kw: mock_cache)
        monkeypatch.setattr("httpx.AsyncClient", TrackingClient)
        
        loader = CloudPolicyLoader(
            policy_manager=MagicMock(),
            api_url="http://test.example.com",
            api_token="test-token"
        )
        
        await loader.load_policy()
        
        # Both the initial request and the fallback fresh fetch should close their clients
        assert len(clients_closed) == len(clients_created), \
            f"All {len(clients_created)} clients should be closed, but only {len(clients_closed)} were"

