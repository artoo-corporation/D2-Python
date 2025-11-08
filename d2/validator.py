# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Set, Tuple, Optional
import os
import time
import logging

import httpx

from .exceptions import BundleExpiredError, TooManyToolsError, PolicyTooLargeError
from .utils import DEFAULT_API_URL

logger = logging.getLogger(__name__)

MAX_TOOLS_FREE = 25
MAX_EXPIRY_DAYS = 7  # 7 days for the free tier
MAX_BUNDLE_SIZE_FREE_MIB = 0.5

# ---------------------------------------------------------------------------
# Cloud quotas resolver with simple in-process caching
# ---------------------------------------------------------------------------

_cached_limits: Optional[Tuple[dict, float]] = None
_CACHE_TTL_SECONDS = 300  # 5 minutes


def resolve_limits(token: Optional[str]) -> dict:
    """Resolve policy/telemetry limits from cloud when a token is available.

    Falls back to local constants on error or missing fields. Result cached for
    _CACHE_TTL_SECONDS to avoid extra calls.
    """
    # Defaults for local mode
    defaults = {
        "max_tools": MAX_TOOLS_FREE,
        "bundle_size_bytes": int(MAX_BUNDLE_SIZE_FREE_MIB * 1024 * 1024),
        "poll_seconds": 60,
        "event_batch": 1000,
        "event_flush_interval_seconds": 60,  # Default telemetry flush interval
        # Default per-event sampling (server can override via /v1/accounts/me)
        "event_sample": {
            "authz_decision": 1.0,
            "tool_invoked": 1.0,
            "policy_poll_interval": 0.1,
            "missing_policy": 0.5,
        },
    }

    if not token:
        return defaults

    # Serve from cache if present and fresh
    global _cached_limits
    now = time.time()
    if _cached_limits and (now - _cached_limits[1]) < _CACHE_TTL_SECONDS:
        cached, _ts = _cached_limits
        merged = {**defaults, **cached}
        return merged

    try:
        resp = httpx.get(
            f"{DEFAULT_API_URL.rstrip('/')}/v1/accounts/me",
            headers={"Authorization": f"Bearer {token}"},
            timeout=10.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            q = data.get("quotas", {}) or {}
            cloud = {
                "max_tools": int(q.get("max_tools", defaults["max_tools"])),
                "event_batch": int(q.get("event_batch", defaults["event_batch"])),
                "poll_seconds": int(data.get("poll_seconds", defaults["poll_seconds"])),
                "event_flush_interval_seconds": int(q.get("ingest_interval", defaults["event_flush_interval_seconds"])),
                "plan": data.get("plan"),
                "account_id": data.get("account_id"),
                # Optional: per-event sampling policy controlled by server
                "event_sample": data.get("event_sample", defaults["event_sample"]),
            }
            _cached_limits = ({**defaults, **cloud}, now)
            return _cached_limits[0]
        else:
            logger.warning("/v1/accounts/me returned %s; falling back to local limits.", resp.status_code)
            return defaults
    except Exception as exc:
        logger.warning("Failed to resolve cloud quotas: %s – using local limits.", exc)
        return defaults


# ---------------------------------------------------------------------------
# Public entrypoints
# ---------------------------------------------------------------------------

def validate_bundle(bundle: Dict[str, Any], raw_bundle_size: int) -> int:
    """Validate a policy bundle using cloud limits (when token present).

    Returns the counted number of tools. In local mode, enforces expiry (≤7 days)
    and bundle size. In cloud mode, expiry is logged as a warning only, and size
    checks are skipped (server enforces on upload/fetch).
    """
    token = os.getenv("D2_TOKEN")
    limits = resolve_limits(token)

    if not token:
        # Local mode – enforce all local checks
        _check_local_policy_expiry(bundle)
        tool_count = _check_tool_count(bundle, limits["max_tools"])
        _check_bundle_size(raw_bundle_size)
        return tool_count

    # Cloud mode – relaxed expiry, cloud max_tools
    _warn_on_expiry_if_needed(bundle)
    tool_count = _check_tool_count(bundle, limits["max_tools"])
    # Skip local size checks; control-plane enforces size server-side
    return tool_count


# Backward-compatible alias used by existing code/tests

def validate_local_bundle(bundle: Dict[str, Any], raw_bundle_size: int):
    _check_local_policy_expiry(bundle)
    tool_count = _check_tool_count(bundle, MAX_TOOLS_FREE)
    _check_bundle_size(raw_bundle_size)
    return tool_count


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _warn_on_expiry_if_needed(bundle: Dict[str, Any]):
    expiry_str = bundle.get("metadata", {}).get("expires")
    if not expiry_str:
        logger.warning("Cloud mode: policy metadata.expires missing – consider adding it for ops visibility.")
        return
    try:
        expiry_date = datetime.fromisoformat(expiry_str)
        if expiry_date.tzinfo is None:
            expiry_date = expiry_date.replace(tzinfo=timezone.utc)
        if expiry_date < datetime.now(timezone.utc):
            logger.warning("Cloud mode: policy appears expired as of %s.", expiry_str)
    except Exception:
        logger.warning("Cloud mode: could not parse metadata.expires: %s", expiry_str)


def _check_local_policy_expiry(bundle: Dict[str, Any]):
    """Checks if the local policy has expired."""
    expiry_str = bundle.get("metadata", {}).get("expires")
    if not expiry_str:
        # For safety, policies in local mode must have an expiry date.
        raise BundleExpiredError(reason="Missing 'expires' timestamp in metadata")

    try:
        expiry_date = datetime.fromisoformat(expiry_str)
        if expiry_date.tzinfo is None:
            # Add UTC timezone if the timestamp is naive
            expiry_date = expiry_date.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        raise BundleExpiredError(reason=f"Could not parse 'expires' timestamp", expiry_date=expiry_str)

    if expiry_date < datetime.now(timezone.utc):
        raise BundleExpiredError(reason="Policy has expired", expiry_date=expiry_str)

    # Check that the expiry is not set too far in the future for the free tier
    max_expiry_date = datetime.now(timezone.utc) + timedelta(days=MAX_EXPIRY_DAYS)
    if expiry_date > max_expiry_date:
        raise BundleExpiredError(
            reason=f"Expiry cannot be set more than {MAX_EXPIRY_DAYS} days in the future",
            expiry_date=expiry_str,
        )


def _check_tool_count(bundle: Dict[str, Any], limit: int) -> int:
    """Counts non-wildcard tools and enforces the given limit."""
    defined_tools: Set[str] = set()

    for policy in bundle.get("policies", []):
        for perm in policy.get("permissions", []):
            if perm == "*":
                continue

            if isinstance(perm, dict):
                tool_id = perm.get("tool") or perm.get("id")
                if not tool_id:
                    continue
                defined_tools.add(tool_id)
                continue

            defined_tools.add(str(perm))

    tool_count = len(defined_tools)

    if tool_count > limit:
        raise TooManyToolsError(tool_count=tool_count, limit=limit)
    return tool_count


def _check_bundle_size(size_bytes: int):
    """Checks if the policy bundle exceeds the size limit for the free tier."""
    limit_bytes = MAX_BUNDLE_SIZE_FREE_MIB * 1024 * 1024
    if size_bytes > limit_bytes:
        raise PolicyTooLargeError(bundle_size=size_bytes, size_limit=limit_bytes) 