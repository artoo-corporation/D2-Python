# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""Multi-app local caching for D2 SDK.

Each D2_TOKEN gets its own isolated cache directory based on token hash:
~/.cache/d2/<token_hash>/ containing bundle.jws, etag, context.json, polling.json

Key features:
- Token-agnostic: no JWT parsing or assumptions about token format
- Concurrent-safe: atomic writes, no locking needed
- Auto-GC: cleans up unused caches after 30 days
- Context isolation: different tokens = different cache folders
"""

from __future__ import annotations

import hashlib
import logging
import json
import os
import shutil
import tempfile
import time
from pathlib import Path
from typing import Dict, Any, Optional

__all__ = [
    "get_cache_dir",
    "get_context_key", 
    "CacheManager",
    "gc_old_caches",
]


logger = logging.getLogger(__name__)


def get_context_key(token: str) -> str:
    """Return first 16 chars of SHA256 hash of token for cache isolation."""
    return hashlib.sha256(token.encode()).hexdigest()[:16]


def get_cache_dir(token: str, app_name: str) -> Path:
    """Return cache directory path for given token and app."""
    cache_root = Path.home() / ".cache" / "d2"
    context_key = get_context_key(token)
    return cache_root / context_key / app_name


class CacheManager:
    """Per-token-app cache manager for policy bundles and metadata."""
    
    def __init__(self, token: str, app_name: str):
        self.token = token
        self.app_name = app_name
        self.cache_dir = get_cache_dir(token, app_name)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # File paths
        self.bundle_path = self.cache_dir / "bundle.jws"
        self.etag_path = self.cache_dir / "etag" 
        self.version_path = self.cache_dir / "version"
        self.context_path = self.cache_dir / "context.json"
        self.polling_path = self.cache_dir / "polling.json"

    def get_cached_etag(self) -> Optional[str]:
        """Return cached ETag or None if not present."""
        try:
            return self.etag_path.read_text().strip()
        except (FileNotFoundError, OSError):
            return None

    def get_cached_bundle(self) -> Optional[str]:
        """Return cached bundle JWS or None if not present."""
        try:
            return self.bundle_path.read_text()
        except (FileNotFoundError, OSError):
            return None

    def get_context(self) -> Optional[Dict[str, Any]]:
        """Return cached context (account_id, app_name, scopes) or None."""
        try:
            return json.loads(self.context_path.read_text())
        except (FileNotFoundError, OSError, json.JSONDecodeError):
            return None

    def get_polling_state(self) -> Dict[str, Any]:
        """Return polling state with defaults."""
        try:
            return json.loads(self.polling_path.read_text())
        except (FileNotFoundError, OSError, json.JSONDecodeError):
            return {"next_poll_at": 0, "backoff_seconds": 60}

    def get_cached_version(self) -> Optional[int]:
        """Return cached version or None if not present."""
        try:
            return int(self.version_path.read_text().strip())
        except (FileNotFoundError, OSError, ValueError):
            return None

    def save_bundle(self, bundle_jws: str, etag: str, version: int) -> None:
        """Atomically save bundle, ETag, and version."""
        self._atomic_write(self.bundle_path, bundle_jws)
        self._atomic_write(self.etag_path, etag)
        self._atomic_write(self.version_path, str(version))

    def save_context(self, account_id: str, scopes: str) -> None:
        """Save token context info (called once on first API success)."""
        context = {
            "account_id": account_id,
            "app_name": self.app_name,  # Use instance app_name
            "scopes": scopes,
            "cached_at": time.time()
        }
        self._atomic_write(self.context_path, json.dumps(context, indent=2))

    def save_polling_state(self, next_poll_at: float, backoff_seconds: int = 60) -> None:
        """Save next poll time and backoff state."""
        state = {
            "next_poll_at": next_poll_at,
            "backoff_seconds": backoff_seconds,
            "updated_at": time.time()
        }
        self._atomic_write(self.polling_path, json.dumps(state, indent=2))

    def get_cache_age(self) -> Optional[float]:
        """Return age in seconds of cached bundle, or None if not cached."""
        try:
            mtime = self.bundle_path.stat().st_mtime
            return time.time() - mtime
        except (FileNotFoundError, OSError):
            return None

    def _atomic_write(self, path: Path, content: str) -> None:
        """Write content atomically using temp file + rename."""
        try:
            with tempfile.NamedTemporaryFile(
                mode='w',
                dir=str(path.parent),
                prefix=f".{path.name}.",
                suffix=".tmp",
                delete=False,
            ) as tmp:
                tmp.write(content)
                tmp.flush()
                os.fsync(tmp.fileno())
                tmp_path = tmp.name

            # Atomic rename
            Path(tmp_path).replace(path)
        except PermissionError:
            logger.debug("Skipping cache write for %s due to permission error", path)
        except OSError as exc:
            logger.debug("Failed to write cache file %s: %s", path, exc)


def gc_old_caches(max_age_days: int = 30, dry_run: bool = False) -> Dict[str, Any]:
    """Garbage collect old cache directories.
    
    Returns:
        Dict with 'cleaned_count', 'freed_bytes', 'errors' keys
    """
    cache_root = Path.home() / ".cache" / "d2"
    if not cache_root.exists():
        return {"cleaned_count": 0, "freed_bytes": 0, "errors": []}

    cutoff_time = time.time() - (max_age_days * 24 * 3600)
    cleaned_count = 0
    freed_bytes = 0
    errors = []

    for cache_dir in cache_root.iterdir():
        if not cache_dir.is_dir():
            continue
            
        # Check if any file in the directory is newer than cutoff
        try:
            newest_mtime = 0
            dir_size = 0
            
            for item in cache_dir.rglob("*"):
                if item.is_file():
                    stat = item.stat()
                    newest_mtime = max(newest_mtime, stat.st_mtime)
                    dir_size += stat.st_size
            
            if newest_mtime < cutoff_time:
                if not dry_run:
                    shutil.rmtree(cache_dir)
                cleaned_count += 1
                freed_bytes += dir_size
                
        except (OSError, PermissionError) as e:
            errors.append(f"Failed to process {cache_dir}: {e}")

    return {
        "cleaned_count": cleaned_count,
        "freed_bytes": freed_bytes, 
        "errors": errors
    }
