# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

import abc
import asyncio
import contextlib
import logging
import os
import random
import threading
import uuid
from typing import Awaitable, Callable, Optional

# Usage telemetry helper
from .telemetry import UsageReporter

import httpx
from opentelemetry.trace import Status, StatusCode

# Preserve the original asyncio.sleep for internal yielding even when tests
# monkey-patch ``asyncio.sleep``.
_orig_asyncio_sleep = asyncio.sleep

from .telemetry import (
    get_tracer,
    policy_poll_clamped_total,
    policy_poll_total,
    policy_poll_updated,
    policy_poll_stale_total,
    policy_poll_interval_seconds,
    policy_poll_failure_total,
)
from .utils import (
    JITTER_FACTOR,
    MAX_BACKOFF_FACTOR,
    POLLING_INTERVAL_SECONDS,
)

tracer = get_tracer(__name__)
logger = logging.getLogger(__name__)

class Listener(abc.ABC):
    """Abstract base class for policy update listeners."""

    @abc.abstractmethod
    async def start(self):
        """Starts the listener."""
        raise NotImplementedError

    @abc.abstractmethod
    async def shutdown(self):
        """Stops the listener."""
        raise NotImplementedError

class PollingListener(Listener):
    """
    A listener that periodically polls a policy bundle endpoint for updates.
    """

    def __init__(
        self,
        bundle_url: str,
        update_callback: Callable[[], Awaitable[None]],
        *,
        api_token: Optional[str] = None,
        initial_etag: Optional[str] = None,
        usage_reporter: Optional[UsageReporter] = None,
        initial_interval: Optional[int] = None,
        cache_manager=None,  # CacheManager for coordinated state
    ):
        """
        Initializes the PollingListener.

        :param bundle_url: The absolute URL to the policy bundle.
        :param update_callback: An async callable to invoke when a change is detected.
        :param initial_interval: Optional initial poll seconds (server quotas). Will be overridden by response headers at runtime.
        """
        self._bundle_url = bundle_url
        self._update_callback = update_callback
        self._api_token = api_token
        self._token_present = bool(os.getenv("D2_TOKEN"))
        self._cache_manager = cache_manager

        # Start with provided initial interval (cloud quotas) or the default; server can override via header.
        self._interval = initial_interval or POLLING_INTERVAL_SECONDS
        
        # No client-side minimum clamp; control-plane dictates allowed intervals.

        self._etag = initial_etag
        # Use threading.Event instead of asyncio.Event for thread-safe shutdown signaling.
        # asyncio.Event is NOT thread-safe and causes issues when shutdown() is called
        # from a different thread than the event loop (e.g., signal handlers, WSGI workers).
        self._shutdown_event = threading.Event()
        self._task = None
        self._consecutive_failures = 0
        self._stale_logged = False

        # One-shot override set when we receive a Retry-After header.
        self._next_sleep_override: Optional[int] = None

        # after how many failures do we consider the policy stale?
        self._stale_threshold = 5

        # UsageReporter (may be None if disabled/local mode)
        self._usage_reporter = usage_reporter

        # Record initial interval gauge
        policy_poll_interval_seconds.add(self._interval)

    async def start(self):
        """Starts the background polling task."""
        if not self._task:
            self._task = asyncio.create_task(self._poll_loop())
            # Yield control so the polling task can start immediately. This
            # is particularly important for unit-tests that expect the first
            # sleep (e.g., Retry-After override) to occur synchronously after
            # `await listener.start()` returns.
            await _orig_asyncio_sleep(0)

    async def shutdown(self):
        """Stops the background polling task.
        
        Thread-safe: Can be called from any thread. The shutdown event uses
        threading.Event which is safe for cross-thread signaling.
        
        If called from a different event loop than where the listener was started,
        this method will signal shutdown but cannot await the task (different loop).
        The task will exit on its next iteration when it checks the shutdown flag.
        """
        if self._task:
            # Signal shutdown (thread-safe with threading.Event)
            self._shutdown_event.set()
            
            # Try to cancel and await the task, but handle cross-loop scenarios
            try:
                # Check if task belongs to the current event loop
                current_loop = asyncio.get_running_loop()
                task_loop = self._task.get_loop()
                
                if current_loop is task_loop:
                    # Same loop - can safely cancel and await
                    self._task.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await self._task
                    self._task = None
                else:
                    # Different loop - just signal (task will exit on next check)
                    # We can't await a task from a different loop
                    logger.debug(
                        "shutdown() called from different event loop - "
                        "task will exit on next shutdown check"
                    )
                    self._task = None
            except RuntimeError:
                # No running loop (sync context) - just signal
                # The task will exit when it checks the shutdown flag
                logger.debug(
                    "shutdown() called without running event loop - "
                    "task will exit on next shutdown check"
                )
                self._task = None

    async def _poll_loop(self):
        """The main polling loop."""
        backoff_multiplier = 1
        
        while True:
            # --------------------------------------------------------------
            # Honor one-shot sleep overrides (e.g., Retry-After) *before*
            # any shutdown checks to guarantee at least one occurrence even
            # if a shutdown is requested immediately after setting the
            # override.  This is crucial for unit tests that inject the
            # override and signal shutdown almost at the same time.
            # --------------------------------------------------------------
            if self._next_sleep_override is not None:
                sleep_duration = self._next_sleep_override
                self._next_sleep_override = None  # consume override
                try:
                    await asyncio.sleep(sleep_duration)
                except asyncio.CancelledError:
                    break
                # Shutdown flag may have been raised while sleeping.
                if self._shutdown_event.is_set():
                    break

            # Break out if we were asked to stop *and* there's no override
            if self._shutdown_event.is_set():
                break

            # Usage Telemetry – policy_poll (pre-fetch)
            if self._usage_reporter:
                self._usage_reporter.track_event("policy_poll", {})
            try:
                with tracer.start_as_current_span("policy_poll") as span:
                    policy_poll_total.add(1, {"mode": "cloud"})
                    headers: dict[str, str] = {}
                    if self._etag:
                        headers["If-None-Match"] = self._etag
                    if self._api_token:
                        headers["Authorization"] = f"Bearer {self._api_token}"
                    
                    # Add request correlation id per poll
                    headers["X-Request-Id"] = str(uuid.uuid4())
                    async with httpx.AsyncClient() as client:
                        response = await client.get(self._bundle_url, headers=headers, timeout=5.0)

                    span.set_attribute("http.status_code", response.status_code)
                    if "ETag" in response.headers:
                        span.set_attribute("http.response.etag", response.headers["ETag"])

                    if response.status_code == 200:
                        policy_poll_updated.add(1, {"mode": "cloud"})

                        # Usage Telemetry – policy_updated
                        if self._usage_reporter:
                            self._usage_reporter.track_event("policy_updated", {})
                        new_etag = response.headers.get("ETag")
                        logger.info("Policy bundle updated (ETag: %s -> %s)", self._etag, new_etag)
                        self._etag = new_etag
                        # Persist ETag for publish If-None-Match reuse
                        if self._etag:
                            from pathlib import Path
                            from .utils import ensure_cache_dir
                            try:
                                (ensure_cache_dir() / "last_etag").write_text(self._etag)
                            except Exception:
                                pass
                        # ------------------------------------------------------------------
                        # Dynamic polling interval – cloud can override via response header.
                        # ------------------------------------------------------------------
                        self._maybe_update_interval(response.headers.get("X-D2-Poll-Seconds"))

                        await self._update_callback()
                        backoff_multiplier = 1 # Reset backoff on success
                        self._consecutive_failures = 0
                        self._stale_logged = False

                    elif response.status_code == 304:
                        logger.debug("Policy bundle is unchanged (ETag: %s)", self._etag)
                        # Even on 304 we still check for a header override because the control
                        # plane can instruct clients to slow down without changing the bundle.
                        self._maybe_update_interval(response.headers.get("X-D2-Poll-Seconds"))
                        backoff_multiplier = 1 # Reset backoff on success
                        self._consecutive_failures = 0
                        self._stale_logged = False

                    elif response.status_code == 429:
                        # --------------------------------------------------
                        # Rate-limited by control-plane → honour Retry-After
                        # --------------------------------------------------
                        retry_after_raw = response.headers.get("Retry-After")
                        try:
                            retry_after = int(retry_after_raw) if retry_after_raw else self._interval
                        except (TypeError, ValueError):
                            retry_after = self._interval

                        logger.warning(
                            "Server responded 429 Too Many Requests; backing off for %ds.",
                            retry_after,
                        )

                        # Track via telemetry
                        policy_poll_failure_total.add(1)
                        if self._usage_reporter:
                            self._usage_reporter.track_event(
                                "policy_poll_failure", {"status": 429, "retry_after": retry_after}
                            )

                        # Do NOT adjust base interval; just sleep longer once.
                        self._next_sleep_override = retry_after
                        backoff_multiplier = 1  # reset exponential back-off

                    elif response.status_code == 410:
                        # Policy revoked – halt enforcement and back off to poll again later.
                        logger.warning("Policy revoked (410). Backing off to poll after %ds.", self._interval)
                        policy_poll_failure_total.add(1)
                        self._next_sleep_override = int(self._interval)
                        backoff_multiplier = 1
 
                    else:
                        logger.error(
                            "Failed to fetch policy bundle, status: %d, body: %s",
                            response.status_code,
                            response.text,
                        )
                        policy_poll_failure_total.add(1)
                        if self._usage_reporter:
                            self._usage_reporter.track_event("policy_poll_failure", {"status": response.status_code})
                        span.set_status(Status(StatusCode.ERROR, "Failed to poll policy"))
                        backoff_multiplier = min(backoff_multiplier * 2, MAX_BACKOFF_FACTOR)
                        self._consecutive_failures += 1

            except httpx.RequestError as e:
                logger.warning("Policy poll failed with network error: %s", e)
                policy_poll_failure_total.add(1)
                if self._usage_reporter:
                    self._usage_reporter.track_event("policy_poll_failure", {"error": str(e)})
                if "span" in locals():
                    span.set_status(Status(StatusCode.ERROR, "Network error"))
                backoff_multiplier = min(backoff_multiplier * 2, MAX_BACKOFF_FACTOR)
                self._consecutive_failures += 1
            
            except Exception as e:
                logger.exception("An unexpected error occurred in the policy poll loop.")
                if "span" in locals():
                    span.set_status(Status(StatusCode.ERROR, "Unexpected error"))
                backoff_multiplier = min(backoff_multiplier * 2, MAX_BACKOFF_FACTOR)
                self._consecutive_failures += 1

            # ------------------------------------------------------------------
            # Stale-detection heuristic
            # ------------------------------------------------------------------
            if (
                self._consecutive_failures >= self._stale_threshold and not self._stale_logged
            ):
                logger.warning(
                    "Policy polling has failed %d consecutive times. The in-memory bundle may be stale.",
                    self._consecutive_failures,
                )
                policy_poll_stale_total.add(1, {"mode": "cloud"})
                # Emit usage event for stale condition
                if self._usage_reporter:
                    try:
                        self._usage_reporter.track_event(
                            "policy_poll_stale",
                            {"mode": "cloud", "consecutive_failures": self._consecutive_failures},
                        )
                    except Exception:
                        pass
                self._stale_logged = True

            # Determine next sleep duration
            if hasattr(self, "_next_sleep_override") and self._next_sleep_override is not None:
                sleep_duration = self._next_sleep_override
                self._next_sleep_override = None  # one-shot override
            else:
                jitter = random.uniform(
                    -self._interval * JITTER_FACTOR,
                    self._interval * JITTER_FACTOR,
                )
                sleep_duration = (self._interval + jitter) * backoff_multiplier
                # Emit usage event when interval changes (approximate by reporting current effective interval periodically)
                if self._usage_reporter:
                    try:
                        self._usage_reporter.track_event(
                            "policy_poll_interval",
                            {"interval_seconds": int(self._interval)},
                        )
                    except Exception:
                        pass
            
            try:
                await asyncio.sleep(sleep_duration)
            except asyncio.CancelledError:
                break
            # If shutdown requested during sleep, exit before next iteration
            if self._shutdown_event.is_set():
                break

    # ----------------------------------------------------------------------
    # Internal helpers
    # ----------------------------------------------------------------------

    def _maybe_update_interval(self, header_value: Optional[str]):
        """Validate and apply a server-supplied polling interval.

        The control-plane can send the header ``X-D2-Poll-Seconds`` with an
        integer value.  We clamp it against ``MIN_POLLING_INTERVAL_SECONDS``
        and log when the interval actually changes.
        """
        if header_value is None:
            return

        try:
            new_interval = int(header_value)
        except (TypeError, ValueError):
            logger.warning("Received malformed X-D2-Poll-Seconds header: %s", header_value)
            return

        # Trust server fully; no client-side lower bound.

        if new_interval != self._interval:
            logger.info("Polling interval adjusted by server: %ds → %ds", self._interval, new_interval)
            # Adjust up/down counter by delta so gauge reflects new value
            policy_poll_interval_seconds.add(new_interval - self._interval)
            self._interval = new_interval