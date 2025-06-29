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

from .utils import DEFAULT_API_URL, JITTER_FACTOR
from .validator import resolve_limits

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

    def __init__(self, api_token: str, api_url: str = DEFAULT_API_URL, host_id: Optional[str] = None):
        self._api_token = api_token
        self._endpoint = f"{api_url.rstrip('/')}{EVENTS_ENDPOINT_PATH}"
        
        # Host identifier (can be overridden by caller)
        self._host = host_id or socket.gethostname()
        
        # Process ID for anomaly detection
        self._pid = os.getpid()
        
        self._buffer = deque(maxlen=MAX_BUFFER_SIZE)
        self._buffer_lock = threading.Lock()
        
        self._task: Optional[asyncio.Task] = None

        # Resolve quotas (cached)
        limits = resolve_limits(self._api_token)
        self._max_events_per_request: int = int(limits.get("event_batch", 1000))
        self._max_request_bytes: int = int(limits.get("event_payload_max_bytes", 32 * 1024))
        self._event_sample: Dict[str, float] = dict(limits.get("event_sample", {}))
        
        # Flush interval for analytics
        self._flush_interval_s = REPORTING_INTERVAL_SECONDS

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
        # Enrich payload with standard analytics fields
        enriched_payload = {
            "service": service_name or "unknown",
            "host": self._host,
            "pid": self._pid,
            "flush_interval_s": self._flush_interval_s,
            **event_data  # Original event data
        }
        
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

    def emit_event(
        self,
        action: str,
        tool_name: Optional[str] = None,
        role: Optional[str] = None,
        **extra_fields: Any,
    ) -> None:
        """Record a granular usage event in canonical shape.

        Applies safety limits:
          * extra_fields must contain max 10 keys.
          * Serialized JSON size must not exceed 4096 bytes per event.
        Events violating these rules are dropped with a warning.
        """

        if len(extra_fields) > 10:
            logger.warning(
                "UsageReporter.emit_event dropped event – extra_fields > 10 (got %d).",
                len(extra_fields),
            )
            return

        # Service name should be passed as extra_field from policy bundle
        service_name = extra_fields.pop("service", "unknown")
        
        payload: Dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "service": service_name,
            "host": self._host,
            "pid": self._pid,
            "flush_interval_s": self._flush_interval_s,
        }

        if tool_name is not None:
            payload["tool_name"] = tool_name
        if role is not None:
            payload["role"] = role

        payload.update(extra_fields)

        try:
            payload_bytes = json.dumps(payload, separators=(",", ":")).encode()
        except (TypeError, ValueError) as exc:
            logger.warning("UsageReporter.emit_event dropped event – JSON serialisation failed: %s", exc)
            return

        if len(payload_bytes) > 4096:
            logger.warning(
                "UsageReporter.emit_event dropped event – size %d B exceeds 4 KiB cap.",
                len(payload_bytes),
            )
            return

        # Apply sampling for custom events if provided (keyed by action)
        try:
            rate = float(self._event_sample.get(action, 1.0))
            if rate < 1.0 and random.random() > max(0.0, min(1.0, rate)):
                return
        except Exception:
            pass

        with self._buffer_lock:
            self._buffer.append(
                {
                    "event_type": "custom",
                    "payload": payload,
                    "occurred_at": datetime.now(timezone.utc).isoformat(),
                }
            )

        # Size-triggered flush: if buffer is full, send immediately.
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
                jitter = random.uniform(-REPORTING_INTERVAL_SECONDS * JITTER_FACTOR, REPORTING_INTERVAL_SECONDS * JITTER_FACTOR)
                sleep_duration = REPORTING_INTERVAL_SECONDS + jitter
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
                            retry_after = int(retry_after_raw) if retry_after_raw else REPORTING_INTERVAL_SECONDS
                        except (TypeError, ValueError):
                            retry_after = REPORTING_INTERVAL_SECONDS
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

# Ensure buffered events are flushed at interpreter exit
atexit.register(lambda: None) 