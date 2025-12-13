# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later
import asyncio
import json
import logging
import os
import tempfile
import threading
import time
from typing import Dict, Optional, Any
from pathlib import Path
from collections import OrderedDict

import httpx
import jwt
from jwt.algorithms import RSAAlgorithm

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# JWKSCache – simple wrapper around PyJWT RSAAlgorithm helpers
# ------------------------------------------------------------------


class JWKSCache:
    """
    JWKS cache with disk persistence, LRU eviction, and automatic key rotation support.
    
    Features:
    - TTL-based expiration (default 300s)
    - LRU eviction (max 50 keys)  
    - Disk persistence for cold-start avoidance
    - Smart refresh with rate limiting for key rotation
    - Telemetry for rotation events and performance monitoring
    - Authorization header support for authenticated JWKS endpoints
    """

    def __init__(self, jwks_url: str, ttl_seconds: int = 300, max_keys: int = 50, api_token: Optional[str] = None):
        self._jwks_url = jwks_url.rstrip("/")
        self._ttl = ttl_seconds
        self._max_keys = max_keys
        self._api_token = api_token
        self._cache: OrderedDict[str, tuple[object, float]] = OrderedDict()
        
        # Thread-safety: Use threading.RLock (reentrant) to protect cross-thread access.
        # We use RLock instead of Lock to allow nested locking within the same thread,
        # which can happen in async code when multiple coroutines run on the same thread.
        # Note: asyncio.Lock is NOT suitable for multi-threaded use as it only protects
        # within a single event loop.
        self._thread_lock = threading.RLock()
        
        self._cache_dir = Path.home() / ".cache" / "d2" / "jwks"
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Rate limiting for JWKS refresh to prevent endpoint hammering
        self._last_refresh_time = 0.0
        self._min_refresh_interval = 5.0  # Minimum 5 seconds between refreshes
        self._refresh_in_progress = False
        
        # Track which keys we've attempted to find to avoid repeated JWKS fetches
        self._missing_keys: Dict[str, float] = {}  # kid -> timestamp when marked as missing
        self._missing_key_timeout = 30.0  # Don't retry missing keys for 30 seconds
        
        # Load from disk on init
        self._load_from_disk()

    def _load_from_disk(self) -> None:
        """Load cached keys from disk on startup."""
        now = time.time()
        for cache_file in self._cache_dir.glob("*.json"):
            try:
                kid = cache_file.stem
                data = json.loads(cache_file.read_text())
                expires_at = data.get("expires_at", 0)
                
                # Skip expired keys
                if expires_at <= now:
                    self._try_unlink(cache_file)
                    continue
                    
                jwk_dict = data.get("jwk")
                if jwk_dict:
                    key_obj = RSAAlgorithm.from_jwk(json.dumps(jwk_dict))
                    self._cache[kid] = (key_obj, expires_at)
                    logger.debug("Loaded cached JWK kid=%s from disk", kid)
            except Exception:
                logger.debug("Failed to load cached JWK from %s", cache_file)
                self._try_unlink(cache_file)

    def _save_to_disk(self, kid: str, jwk_dict: dict, expires_at: float) -> None:
        """Save key to disk cache."""
        try:
            cache_file = self._cache_dir / f"{kid}.json"
            data = {
                "jwk": jwk_dict,
                "expires_at": expires_at,
                "cached_at": time.time()
            }
            
            # Atomic write
            with tempfile.NamedTemporaryFile(
                mode='w', 
                dir=str(self._cache_dir),
                prefix=f".{kid}.",
                suffix=".tmp",
                delete=False
            ) as tmp:
                json.dump(data, tmp, indent=2)
                tmp.flush()
                os.fsync(tmp.fileno())
                tmp_path = tmp.name
            
            Path(tmp_path).replace(cache_file)
            logger.debug("Saved JWK kid=%s to disk cache", kid)
        except Exception:
            logger.debug("Failed to save JWK kid=%s to disk", kid)

    def _evict_lru(self) -> None:
        """Remove least recently used key if over max_keys limit."""
        while len(self._cache) >= self._max_keys:
            kid, _ = self._cache.popitem(last=False)  # Remove oldest
            cache_file = self._cache_dir / f"{kid}.json"
            self._try_unlink(cache_file)
            logger.debug("Evicted LRU JWK kid=%s", kid)

    async def _refresh(self) -> None:
        """Refresh JWKS from the endpoint.
        
        Thread-safe: Uses threading.Lock only for cache mutation, not across await points.
        """
        # Set refresh in progress flag (thread-safe)
        with self._thread_lock:
            self._refresh_in_progress = True
        
        try:
            headers = {}
            if self._api_token:
                headers["Authorization"] = f"Bearer {self._api_token}"
                
            # HTTP request is done WITHOUT holding the lock
            async with httpx.AsyncClient() as client:
                logger.debug("Fetching JWKS from %s", self._jwks_url)
                resp = await client.get(self._jwks_url, headers=headers, timeout=10.0)
                resp.raise_for_status()
                jwks = resp.json()

            # Now update cache with lock held (short critical section)
            now = time.time()
            with self._thread_lock:
                self._cache.clear()
                
                # Clean up old disk cache files
                for cache_file in self._cache_dir.glob("*.json"):
                    self._try_unlink(cache_file)
                    
                for jwk_dict in jwks.get("keys", []):
                    kid = jwk_dict.get("kid")
                    if not kid:
                        continue
                    try:
                        key_obj = RSAAlgorithm.from_jwk(json.dumps(jwk_dict))
                        expires_at = now + self._ttl
                        
                        # LRU eviction before adding new key
                        self._evict_lru()
                        
                        self._cache[kid] = (key_obj, expires_at)
                        self._save_to_disk(kid, jwk_dict, expires_at)
                    except Exception:
                        logger.exception("Failed to parse JWK kid=%s", kid)
                
                # Update refresh time for rate limiting
                self._last_refresh_time = now
                
                # Clean up old missing key entries
                self._cleanup_missing_keys()
        finally:
            # Always clear the refresh in progress flag
            with self._thread_lock:
                self._refresh_in_progress = False

    def _try_unlink(self, path: Path) -> None:
        """Attempt to remove a cache file while ignoring permission issues."""

        try:
            path.unlink(missing_ok=True)
        except PermissionError:
            logger.debug("Insufficient permissions to remove cache file %s", path)
        except OSError:
            logger.debug("Failed to remove cache file %s", path)

    async def get_key(self, kid: str):
        """Legacy method for backward compatibility - delegates to smart refresh."""
        return await self.get_key_with_refresh(kid, force_refresh=False)

    async def get_key_with_refresh(
        self, 
        kid: str, 
        force_refresh: bool = False,
        rotation_metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Get key with smart refresh logic for automatic key rotation support.
        
        Thread-safe: Uses both threading.Lock (for cross-thread safety) and
        asyncio.Lock (for coordination between coroutines in the same loop).
        
        Args:
            kid: Key ID to lookup
            force_refresh: If True, forces JWKS refresh (from jwks_refresh header)
            rotation_metadata: Optional rotation context from JWS header
            
        Returns:
            RSA public key object for signature verification
            
        Raises:
            ValueError: If kid not found after refresh attempts
        """
        now = time.time()
        
        # First, try cache lookup (thread-safe read)
        with self._thread_lock:
            entry = self._cache.get(kid)
            if entry and entry[1] > now and not force_refresh:
                # Cache hit and not expired, no refresh needed
                self._cache.move_to_end(kid)  # LRU update
                # Clear from missing keys if we found it
                self._missing_keys.pop(kid, None)
                return entry[0]
                
            # Check if this key was recently marked as missing to avoid repeated fetches
            if not force_refresh and kid in self._missing_keys:
                missing_time = self._missing_keys[kid]
                if (now - missing_time) < self._missing_key_timeout:
                    # Key was recently missing, don't retry yet unless it's a forced refresh
                    logger.debug("Skipping JWKS fetch for recently missing key %s", kid)
                    if entry:
                        # Return expired key if available rather than failing immediately
                        logger.warning("Using expired key %s due to recent missing key timeout", kid)
                        self._cache.move_to_end(kid)
                        return entry[0]
                    raise ValueError(f"kid {kid} recently marked as missing, not retrying yet")

        # Cache miss, expired, or forced refresh needed
        # Use threading lock for cross-thread coordination (RLock allows re-entry)
        with self._thread_lock:
            # Double-check after acquiring lock
            entry = self._cache.get(kid)
            if entry and entry[1] > time.time() and not force_refresh:
                self._cache.move_to_end(kid)
                return entry[0]
            
            # Check if we need to refresh (cache miss, expired key, or forced refresh)
            has_expired_key = entry and entry[1] <= time.time()
            needs_refresh = (
                not entry or  # Cache miss
                has_expired_key or  # Expired key
                force_refresh  # Forced refresh
            )
            
            # Determine if refresh should proceed based on rate limiting
            should_refresh = needs_refresh and self._should_refresh_jwks(force_refresh, has_expired_key)
            refresh_in_progress = self._refresh_in_progress
        
        # Avoid concurrent refreshes unless it's a forced refresh
        if should_refresh and refresh_in_progress and not force_refresh:
            logger.debug("JWKS refresh already in progress, waiting...")
            # Wait a bit and check cache again
            await asyncio.sleep(0.5)
            with self._thread_lock:
                entry = self._cache.get(kid)
                if entry:
                    self._cache.move_to_end(kid)
                    return entry[0]
        
        if should_refresh:
            try:
                await self._refresh_with_telemetry(rotation_metadata)
            except Exception as e:
                logger.warning("JWKS refresh failed: %s", e)
                # Retry once after brief delay if forced refresh or enough time has passed
                with self._thread_lock:
                    last_refresh = self._last_refresh_time
                if force_refresh or (now - last_refresh) > self._min_refresh_interval:
                    await asyncio.sleep(1)
                    try:
                        await self._refresh_with_telemetry(rotation_metadata)
                    except Exception as retry_e:
                        logger.error("JWKS refresh retry failed: %s", retry_e)
                        # Continue with cached keys if available
        
        # Final lookup after refresh attempt (thread-safe)
        with self._thread_lock:
            entry = self._cache.get(kid)
            if not entry:
                # Mark this key as missing to avoid repeated fetches
                self._missing_keys[kid] = time.time()
                logger.debug("Marked key %s as missing, will not retry for %d seconds", kid, self._missing_key_timeout)
                raise ValueError(f"kid {kid} not found in JWKS after refresh")
            
            # Key found - clear from missing keys and return
            self._missing_keys.pop(kid, None)
            self._cache.move_to_end(kid)
            return entry[0]

    def _should_refresh_jwks(self, force_refresh: bool, has_expired_keys: bool = False) -> bool:
        """
        Determine if JWKS refresh should proceed based on rate limiting.
        
        Args:
            force_refresh: True if control-plane requested refresh
            has_expired_keys: True if we have expired keys in cache
            
        Returns:
            True if refresh should proceed, False if rate limited
        """
        now = time.time()
        
        # Always allow forced refresh (from jwks_refresh header) - bypass rate limiting entirely
        if force_refresh:
            return True
        
        # If we have expired keys, use a more lenient rate limit (1 second instead of 5)
        if has_expired_keys:
            return (now - self._last_refresh_time) > 1.0
        
        # For normal refresh, use standard rate limiting
        return (now - self._last_refresh_time) > self._min_refresh_interval
    
    def _cleanup_missing_keys(self) -> None:
        """Remove old entries from missing keys tracking."""
        now = time.time()
        expired_keys = [
            kid for kid, timestamp in self._missing_keys.items()
            if (now - timestamp) > self._missing_key_timeout
        ]
        for kid in expired_keys:
            del self._missing_keys[kid]
        
        if expired_keys:
            logger.debug("Cleaned up %d expired missing key entries", len(expired_keys))

    async def _refresh_with_telemetry(self, rotation_metadata: Optional[Dict[str, Any]] = None):
        """
        Refresh JWKS with telemetry and rotation event tracking.
        
        Args:
            rotation_metadata: Optional rotation context for telemetry
        """
        start_time = time.time()
        old_kids = set(self._cache.keys())
        
        try:
            await self._refresh()
            new_kids = set(self._cache.keys())
            
            # Record successful refresh
            latency_ms = (time.time() - start_time) * 1000
            self._emit_rotation_telemetry(
                rotation_metadata=rotation_metadata,
                old_kids=old_kids,
                new_kids=new_kids,
                latency_ms=latency_ms,
                outcome="success"
            )
            
            if rotation_metadata:
                logger.info(
                    "JWKS refresh completed for rotation %s: %d old keys, %d new keys, %.1fms",
                    rotation_metadata.get("rotation_id", "unknown"),
                    len(old_kids), len(new_kids), latency_ms
                )
            
        except Exception as e:
            # Record failed refresh
            latency_ms = (time.time() - start_time) * 1000
            self._emit_rotation_telemetry(
                rotation_metadata=rotation_metadata,
                old_kids=old_kids,
                new_kids=set(),
                latency_ms=latency_ms,
                outcome="failure",
                error=str(e)
            )
            raise

    def _emit_rotation_telemetry(
        self, 
        rotation_metadata: Optional[Dict[str, Any]],
        old_kids: set,
        new_kids: set, 
        latency_ms: float,
        outcome: str,
        error: Optional[str] = None
    ):
        """
        Emit telemetry events for JWKS rotation monitoring.
        
        This helps the control-plane team monitor rotation propagation
        across all SDK instances in the fleet.
        """
        try:
            # Import here to avoid circular imports
            from .telemetry import jwks_fetch_latency_ms, jwks_rotation_total
            from .policy import get_policy_manager
            
            # Record latency metric
            tags = {"outcome": outcome}
            if rotation_metadata:
                tags["rotation_triggered"] = "true"
                tags["rotation_id"] = rotation_metadata.get("rotation_id", "unknown")
                tags["reason"] = rotation_metadata.get("reason", "unknown")
                
                # Record rotation event
                jwks_rotation_total.add(1, tags)
            else:
                tags["rotation_triggered"] = "false"
            
            jwks_fetch_latency_ms.record(latency_ms, tags)
            
            # Emit usage event if rotation was triggered
            if rotation_metadata:
                try:
                    manager = get_policy_manager()  # Get default instance
                    if hasattr(manager, "_usage_reporter") and manager._usage_reporter:
                        event_data = {
                            "rotation_id": rotation_metadata.get("rotation_id"),
                            "timestamp": rotation_metadata.get("timestamp"),
                            "reason": rotation_metadata.get("reason"),
                            "new_kid": rotation_metadata.get("new_kid"),
                            "old_kids": list(old_kids),
                            "new_kids": list(new_kids),
                            "latency_ms": latency_ms,
                            "outcome": outcome
                        }
                        
                        if error:
                            event_data["error"] = error
                        
                        manager._usage_reporter.track_event("jwks_rotation", event_data)
                        
                except Exception:
                    # Don't let telemetry failures break the rotation
                    pass
                    
        except Exception:
            # Don't let telemetry failures break the refresh
            pass

    async def get_jwks(self) -> dict:
        """Get all cached JWKS keys. Thread-safe."""
        with self._thread_lock:
            if not self._cache:
                need_refresh = True
            else:
                need_refresh = False
        
        if need_refresh:
            await self._refresh()
        
        with self._thread_lock:
            keys = []
            for kid, (key_obj, _) in self._cache.items():
                jwk_dict = json.loads(RSAAlgorithm.to_jwk(key_obj))
                jwk_dict["kid"] = kid
                keys.append(jwk_dict)
            return {"keys": keys} 