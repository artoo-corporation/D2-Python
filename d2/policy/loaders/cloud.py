# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

from typing import Dict, Any, Optional, Callable
import asyncio
import logging
import os
import time
import uuid

import httpx
from urllib.parse import urljoin

from .base import PolicyLoader
from ...cache import CacheManager
from ...exceptions import PolicyError, D2PlanLimitError
from ...listener import PollingListener
from ...telemetry import get_tracer
from ...validator import resolve_limits
from ...policy.files import require_app_name

logger = logging.getLogger(__name__)
tracer = get_tracer(__name__)


class CloudPolicyLoader(PolicyLoader):
    def __init__(self, policy_manager, api_url: str, api_token: str, **kwargs):
        self._policy_manager = policy_manager
        self._api_url = api_url.rstrip("/")
        self._api_token = api_token
        self._jwks_thumbprint = kwargs.get("jwks_thumbprint")

        self._bundle_url = urljoin(self._api_url + "/", "v1/policy/bundle")
        self._listener: Optional[PollingListener] = None
        
        # Cache manager will be initialized when we know the app_name
        self._cache: Optional[CacheManager] = None
        self._initial_etag: Optional[str] = None

    @property
    def mode(self) -> str:
        return "cloud"

    async def load_policy(self) -> Dict[str, Any]:
        """Fetches the latest policy bundle from the cloud using cache-aware polling."""
        
        # Initialize cache manager with app_name from policy file
        if not self._cache:
            try:
                app_name = require_app_name()
                logger.debug("Successfully read app_name from policy file: %s", app_name)
                self._cache = CacheManager(self._api_token, app_name)
            except Exception as e:
                logger.warning("Failed to read app_name from policy file, using 'default': %s", e)
                self._cache = CacheManager(self._api_token, "default")
        
        # Check if we should poll based on cached timing
        polling_state = self._cache.get_polling_state()
        now = time.time()
        if now < polling_state.get("next_poll_at", 0):
            # Use cached bundle if still within poll window
            cached_bundle = self._cache.get_cached_bundle()
            if cached_bundle:
                return {"jws": cached_bundle}
        
        # Build request headers with cached ETag for conditional fetch
        headers = {
            "Authorization": f"Bearer {self._api_token}", 
            "X-Request-Id": str(uuid.uuid4())
        }
        cached_etag = self._cache.get_cached_etag()
        if cached_etag:
            headers["If-None-Match"] = cached_etag
            
        try:
            attempts = 2
            last_exc: Optional[Exception] = None
            for i in range(attempts):
                try:
                    async with httpx.AsyncClient() as client:
                        response = await client.get(self._bundle_url, headers=headers, timeout=5.0)
                    # Retry on 5xx/429 once with small jitter
                    if response.status_code in (429, 500, 502, 503, 504) and i == 0:
                        await asyncio.sleep(0.3)  # Non-blocking sleep in async context
                        continue
                    break
                except httpx.RequestError as e:
                    last_exc = e
                    if i == 0:
                        await asyncio.sleep(0.3)  # Non-blocking sleep in async context
                        continue
                    raise
            if 'response' not in locals():
                assert last_exc is not None
                raise last_exc
                
            # Handle 304 Not Modified - use cached bundle
            if response.status_code == 304:
                cached_bundle = self._cache.get_cached_bundle()
                if cached_bundle:
                    # Update polling state but keep existing bundle
                    poll_seconds = int(response.headers.get("X-D2-Poll-Seconds", 60))
                    self._cache.save_polling_state(now + poll_seconds)
                    return {"jws": cached_bundle}
                else:
                    # Cached bundle missing, force fresh fetch (properly close client)
                    headers.pop("If-None-Match", None)
                    async with httpx.AsyncClient() as client:
                        response = await client.get(self._bundle_url, headers=headers, timeout=5.0)
            
            # --------------------------------------------------------------
            # Plan-limit upgrade path – map HTTP 402 to D2PlanLimitError so the
            # decorator can surface a clear nudge to the developer.
            # --------------------------------------------------------------
            if response.status_code == 402:
                try:
                    payload = response.json()
                    err_code = payload.get("error") or payload.get("code")
                except Exception:
                    err_code = None
                if err_code in ("tool_limit", "locked"):
                    raise D2PlanLimitError(reason=err_code)
            # Explicit guidance for common auth/permission failures
            if response.status_code == 401:
                raise PolicyError("Unauthorized: invalid or missing D2_TOKEN when fetching policy bundle.")
            if response.status_code == 403:
                raise PolicyError("Forbidden: token lacks permission to fetch policy bundle.")
            if response.status_code == 404:
                # Check if the server is telling us this is a token type issue
                try:
                    response_data = response.json()
                    error_detail = response_data.get("detail", "")
                    
                    if "app_name required for non-server tokens" in error_detail:
                        raise PolicyError(
                            "Policy not found (404). You appear to be using a client/dev token instead of a server token. "
                            "For cloud mode, you need a server token from the D2 dashboard. "
                            "To use local mode instead, unset D2_TOKEN."
                        )
                    
                    # Also check for other patterns that might indicate token type issues
                    if "server tokens have automatic app resolution" in error_detail:
                        raise PolicyError(
                            "Policy not found (404). You appear to be using a client/dev token instead of a server token. "
                            "For cloud mode, you need a server token from the D2 dashboard. "
                            "To use local mode instead, unset D2_TOKEN."
                        )
                        
                except PolicyError:
                    # Re-raise PolicyError exceptions (our custom errors)
                    raise
                except Exception as e:
                    # If we can't parse the response, log it for debugging
                    logger.debug("Failed to parse 404 response: %s", e)
                    pass
                raise PolicyError(f"Policy not found (404). The app may not exist or the token may lack access.")
            if response.status_code == 410:
                # Policy was revoked – surface a clear error, listener will continue polling later
                raise PolicyError("Policy revoked (410). Please publish or restore a policy.")
            # Fall-through to default behaviour for all other statuses.
            response.raise_for_status()
            
            # Cache the new bundle and metadata
            bundle_data = response.json()
            new_etag = response.headers.get("ETag")
            poll_seconds = int(response.headers.get("X-D2-Poll-Seconds", 60))
            
            if new_etag and "jws" in bundle_data:
                version = bundle_data.get("version", 0)
                self._cache.save_bundle(bundle_data["jws"], new_etag, version)
                
            # Save minimal context on first successful fetch
            context = self._cache.get_context()
            if not context:
                self._cache.save_context("runtime", "token-derived")
                
            # Update polling timing
            self._cache.save_polling_state(now + poll_seconds)
            
            # Capture initial ETag for listener
            self._initial_etag = new_etag
            return bundle_data
            
        except D2PlanLimitError:
            raise  # propagate up unchanged
        except httpx.RequestError as e:
            raise PolicyError(f"Network error fetching policy bundle: {e}") from e

    def start(self, policy_update_callback: callable):
        """Starts the background polling listener."""
        # Seed initial poll interval from quotas (cached), then header updates take over
        limits = resolve_limits(os.getenv("D2_TOKEN"))
        initial_interval = int(limits.get("poll_seconds", 60))
        
        # Pass cache manager to listener for coordinated state management
        self._listener = PollingListener(
            bundle_url=self._bundle_url,
            update_callback=policy_update_callback,
            api_token=self._api_token,
            initial_etag=self._initial_etag,
            usage_reporter=getattr(self._policy_manager, "_usage_reporter", None),
            initial_interval=initial_interval,
            cache_manager=self._cache,  # New parameter for cache coordination
        )
        asyncio.create_task(self._listener.start())

    async def shutdown(self):
        """Shuts down the background listener."""
        if self._listener:
            await self._listener.shutdown() 