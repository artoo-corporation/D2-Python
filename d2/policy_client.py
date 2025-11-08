# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

import asyncio
import logging
import os
from typing import Callable, Optional, Awaitable, List

from .policy import PolicyManager
from .utils import DEFAULT_API_URL

logger = logging.getLogger(__name__)


class PolicyClient:
    """High-level façade that handles polling + JWS verification and fires updates."""

    def __init__(
        self,
        *,
        api_url: str = DEFAULT_API_URL,
        api_token: str,
        base_interval: int = 60,
        on_update: Callable[[dict], Awaitable[None]] = lambda b: None,
        pin_jwks_thumbprints: Optional[List[str]] = None,
    ) -> None:
        self._api_url = api_url.rstrip("/")
        self._token = api_token
        os.environ["D2_TOKEN"] = api_token
        self._on_update = on_update
        self._base_interval = base_interval
        try:
            self._loop = asyncio.get_running_loop()
        except RuntimeError:
            # create a loop for sync contexts (main thread)
            self._loop = asyncio.get_event_loop()
        self._pm = PolicyManager(
            instance_name="client",
            api_url=self._api_url,
            pin_jwks_thumbprints=pin_jwks_thumbprints,
        )
        self._task: Optional[asyncio.Task] = None

    async def _notify(self):
        """Internal hook: called by PolicyManager when bundle changes."""
        bundle = self._pm._policy_bundle  # type: ignore[attr-defined]
        if bundle is None:
            return
        try:
            if asyncio.iscoroutinefunction(self._on_update):
                await self._on_update(bundle.raw_bundle)
            else:
                self._on_update(bundle.raw_bundle)
        except Exception:
            logger.exception("on_update callback raised an exception.")

    async def start_polling(self):
        """Kick off background polling; returns immediately."""
        if self._task:
            return  # already running

        # Monkey-patch PolicyManager's _schedule_policy_update to call our notifier
        original = self._pm._schedule_policy_update

        def wrapper():
            original()
            asyncio.create_task(self._notify())

        self._pm._schedule_policy_update = wrapper  # type: ignore[method-assign]

        await self._pm.initialize()

        # Await PolicyManager's internal initialization task to ensure the
        # first bundle is fully loaded before we proceed.
        if getattr(self._pm, "_init_task", None):
            try:
                await self._pm._init_task
            except asyncio.CancelledError:
                pass

        # also call notify after initial load
        await self._notify()

    async def stop(self):
        if self._pm:
            await self._pm.shutdown() 