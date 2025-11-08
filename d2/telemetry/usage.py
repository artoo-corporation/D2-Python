# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

import asyncio
import atexit
import json
import logging
import os
import random
import threading
import socket
from collections import deque
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Deque

import httpx
import uuid

from ..utils import DEFAULT_API_URL, JITTER_FACTOR
from ..validator import resolve_limits
from ..context import get_user_context

logger = logging.getLogger(__name__)

# --- Constants ---
REPORTING_INTERVAL_SECONDS = 60  # Report events every 60 seconds
MAX_BUFFER_SIZE = 1000  # Max number of events to hold in memory before dropping
EVENTS_ENDPOINT_PATH = "/v1/events/ingest"

# Caller is responsible for instantiating UsageReporter only when telemetry
# mode includes *usage* events.


class UsageReporter:
    """
    A class responsible for collecting and reporting raw usage events to the D2 cloud.
    
    This reporter is a "dumb" event recorder. It buffers events in memory and periodically
    sends them to the server for aggregation and analysis. It does not perform any
    analysis or calculation itself.

    It is designed to be resilient, failing silently if it cannot reach the server,
    ensuring that telemetry issues do not impact the host application.
    """

    def __init__(self, api_token: str, api_url: str = DEFAULT_API_URL, host_id: Optional[str] = None, policy_manager=None):
        self._api_token = api_token
        self._endpoint = f"{api_url.rstrip('/')}{EVENTS_ENDPOINT_PATH}"
        
        # Host identifier (can be overridden by caller)
        self._host = host_id or socket.gethostname()
        
        # Process ID for anomaly detection
        self._pid = os.getpid()
        
        self._buffer = deque(maxlen=MAX_BUFFER_SIZE)
        self._buffer_lock = threading.Lock()
        
        self._task: Optional[asyncio.Task] = None
        
        # Reference to policy manager for automatic context extraction
        self._policy_manager = policy_manager
        
        # Cached policy context (extracted once, reused for all events)
        self._service_name: Optional[str] = None
        self._policy_etag: Optional[str] = None
        self._request_id: Optional[str] = None
        self._context_extracted = False

        # Resolve quotas (cached)
        limits = resolve_limits(self._api_token)
        self._max_events_per_request: int = int(limits.get("event_batch", 1000))
        self._max_request_bytes: int = int(limits.get("event_payload_max_bytes", 32 * 1024))
        self._event_sample: Dict[str, float] = dict(limits.get("event_sample", {}))
        
        # Flush interval for analytics (plan-controlled with fallback to default)
        self._flush_interval_s = int(limits.get("event_flush_interval_seconds", REPORTING_INTERVAL_SECONDS))

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def track_event(self, event_type: str, event_data: Dict[str, Any], policy_etag: Optional[str] = None, token_kid: Optional[str] = None, service_name: Optional[str] = None):  # noqa: D401
        """Record a single usage event (tool_invoked, etc.) in canonical shape with analytics fields."""
        # Server-driven sampling: drop event probabilistically when configured
        try:
            rate = float(self._event_sample.get(event_type, 1.0))
            if rate < 1.0:
                if random.random() > max(0.0, min(1.0, rate)):
                    return
        except Exception:
            # On malformed rates, default to send
            pass
        
        # Extract policy context once on first call (lazy initialization)
        if not self._context_extracted:
            self._extract_policy_context()
        
        # Use cached or explicitly provided context
        service_name = service_name or self._service_name or "unknown"
        policy_etag = policy_etag or self._policy_etag
        
        # Enrich payload with standard analytics fields
        enriched_payload = {
            "service": service_name,
            "host": self._host,
            "pid": self._pid,
            "flush_interval_s": self._flush_interval_s,
            **event_data  # Original event data
        }
        
        # Add user_id from context (unless explicitly provided in event_data)
        if "user_id" not in enriched_payload:
            try:
                user_ctx = get_user_context()
                if user_ctx and user_ctx.user_id:
                    enriched_payload["user_id"] = user_ctx.user_id
            except Exception:
                # Context may not be set in all scenarios
                pass
        
        # Add request_id for call chain correlation
        if self._request_id:
            enriched_payload["request_id"] = self._request_id
        
        # Add policy context if available
        if policy_etag:
            enriched_payload["policy_etag"] = policy_etag
        if token_kid:
            enriched_payload["token_kid"] = token_kid
            
        event = {
            "event_type": event_type,
            "payload": enriched_payload,
            "occurred_at": datetime.now(timezone.utc).isoformat(),
        }
        with self._buffer_lock:
            self._buffer.append(event)

        if len(self._buffer) == self._buffer.maxlen:
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(self._flush_buffer())
            except RuntimeError:
                asyncio.run(self._flush_buffer())

    # ------------------------------------------------------------------
    # Test helpers / public async utilities
    # ------------------------------------------------------------------

    def get_buffer_size(self) -> int:  # noqa: D401
        """Return current in-memory buffer length (for unit-tests)."""
        with self._buffer_lock:
            return len(self._buffer)

    async def force_flush(self) -> None:  # noqa: D401
        """Immediately flush all buffered events (exposed for tests/shutdown)."""
        await self._flush_buffer()

    def start(self):
        """Starts the background reporting task."""
        if self._task is not None:
            logger.warning("UsageReporter has already been started.")
            return
        
        logger.debug("Starting UsageReporter background task.")
        self._task = asyncio.create_task(self._reporter_loop())

    async def shutdown(self):
        """Stops the background reporting task and flushes any remaining events."""
        if self._task is None:
            return

        logger.debug("Shutting down UsageReporter.")
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass  # Expected on cancellation

        logger.debug("Flushing remaining usage events before final shutdown.")
        await self._flush_buffer()
        logger.info("UsageReporter shut down successfully.")

    async def _reporter_loop(self):
        """The main loop for the background reporting task."""
        while True:
            try:
                jitter = random.uniform(-self._flush_interval_s * JITTER_FACTOR, self._flush_interval_s * JITTER_FACTOR)
                sleep_duration = self._flush_interval_s + jitter
                await asyncio.sleep(sleep_duration)
                await self._flush_buffer()
            except asyncio.CancelledError:
                logger.debug("Usage reporter task cancelled.")
                break
            except Exception:
                logger.exception("Unexpected error in UsageReporter loop. This should not happen.")

    async def _flush_buffer(self):
        """Sends all events currently in the buffer to the server."""
        events_to_send: List[Dict[str, Any]] = []
        with self._buffer_lock:
            # Drain the buffer quickly within the lock
            while self._buffer:
                events_to_send.append(self._buffer.popleft())

        if not events_to_send:
            return

        payload_events = events_to_send

        # Enforce overall request size cap (from quotas) and event count cap by chunking
        chunks: List[List[Dict[str, Any]]] = []
        current_chunk: List[Dict[str, Any]] = []
        current_size = 0
        for ev in payload_events:
            ev_bytes = json.dumps(ev, separators=(",", ":")).encode()
            wrapper_size = len(b"{\"events\":[\n]}" )  # minimal overhead estimate
            # roll over chunk if adding this event would exceed bytes or count caps
            if current_chunk and (
                (current_size + len(ev_bytes) + wrapper_size) > self._max_request_bytes
                or len(current_chunk) >= self._max_events_per_request
            ):
                chunks.append(current_chunk)
                current_chunk = []
                current_size = 0
            current_chunk.append(ev)
            current_size += len(ev_bytes)
        if current_chunk:
            chunks.append(current_chunk)

        headers = {"Authorization": f"Bearer {self._api_token}"}

        for chunk in chunks:
            body = {"events": chunk}
            try:
                async with httpx.AsyncClient() as client:
                    response = await client.post(self._endpoint, json=body, headers={**headers, "X-Request-Id": str(uuid.uuid4())}, timeout=5.0)
                    if response.status_code == 429:
                        retry_after_raw = response.headers.get("Retry-After")
                        try:
                            retry_after = int(retry_after_raw) if retry_after_raw else self._flush_interval_s
                        except (TypeError, ValueError):
                            retry_after = self._flush_interval_s
                        logger.warning("Events ingest rate-limited (429). Backing off for %ds.", retry_after)
                        await asyncio.sleep(retry_after)
                        continue
                    if response.status_code == 413 and len(chunk) > 1:
                        # Payload too large – split chunk and retry once
                        mid = len(chunk) // 2
                        for sub in (chunk[:mid], chunk[mid:]):
                            try:
                                sub_body = {"events": sub}
                                r2 = await client.post(self._endpoint, json=sub_body, headers={**headers, "X-Request-Id": str(uuid.uuid4())}, timeout=5.0)
                                r2.raise_for_status()
                            except Exception as e:
                                logger.error("Failed to send split payload: %s", e)
                        continue
                    response.raise_for_status()
            except httpx.HTTPStatusError as e:
                logger.error("Failed to send usage data to D2 cloud: %s", e)
            except Exception:
                logger.exception("An unexpected error occurred while sending usage data.") 

    def _extract_policy_context(self) -> None:
        """Extract policy context (service_name, policy_etag, request_id) from policy manager.
        
        This method is called once (lazily on first track_event call) to extract
        and cache the policy context. The cached values are then reused for all
        subsequent events.
        
        Why we send policy_etag:
        - Correlate events with specific policy versions (track behavior changes)
        - Debug policy rollouts (did issues start after policy update?)
        - Analytics on policy effectiveness over time
        - Track which policy was active when security events occurred
        
        Why we send request_id:
        - Correlate all events within a single user request
        - Reconstruct call chains on the control plane
        - Track data flows across multiple tool invocations
        - Enable cross-customer pattern analysis
        """
        self._context_extracted = True  # Mark as attempted, even if it fails
        
        # Extract policy context from policy manager
        if self._policy_manager:
            try:
                if hasattr(self._policy_manager, "_policy_bundle") and self._policy_manager._policy_bundle:
                    # Extract policy etag (for version tracking)
                    self._policy_etag = getattr(self._policy_manager._policy_bundle, "etag", None)
                    
                    # Extract service name from policy metadata
                    metadata = self._policy_manager._policy_bundle.raw_bundle.get("metadata", {})
                    self._service_name = metadata.get("name", None)
            except Exception:
                # Silently fail if policy context extraction fails
                pass
        
        # Extract request_id from current user context
        try:
            from ..context import get_user_context
            ctx = get_user_context()
            if ctx and ctx.request_id:
                self._request_id = ctx.request_id
        except Exception:
            # Silently fail if context extraction fails
            # This ensures telemetry never breaks user code
            pass

# Ensure buffered events are flushed at interpreter exit
atexit.register(lambda: None) 