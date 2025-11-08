# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""Persistent local state for D2 SDK.

Stores per-app bundle metadata (ETag, version, last_checked) across Python
processes in a JSON file – ``~/.config/d2/bundles.json`` by default.  Override
path with ``D2_STATE_PATH``.  Use ``:memory:`` to disable persistence entirely.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import datetime as _dt
from pathlib import Path
from typing import Any, Dict, Optional

__all__ = [
    "get_bundle_state",
    "set_bundle_state",
    "list_bundles",
    "clear_bundle_state",
]

_LOCK = threading.Lock()
_state_cache: Optional[Dict[str, Any]] = None  # in-process cache

# ---------------------------------------------------------------------------
# Helpers – path resolution & disk I/O
# ---------------------------------------------------------------------------


def _state_path() -> Path:
    override = os.getenv("D2_STATE_PATH")
    if override and override.strip():
        if override == ":memory:":
            # Special sentinel: disable persistence.
            return Path(":memory:")
        return Path(override).expanduser()

    return Path.home() / ".config" / "d2" / "bundles.json"


def _load() -> Dict[str, Any]:
    global _state_cache
    if _state_cache is not None:
        return _state_cache

    path = _state_path()
    if path.as_posix() == ":memory:":
        _state_cache = {}
        return _state_cache

    if not path.exists():
        _state_cache = {}
        return _state_cache

    try:
        data = json.loads(path.read_text("utf-8"))
        if isinstance(data, dict):
            _state_cache = data  # type: ignore[assignment]
        else:
            _state_cache = {}
    except Exception:
        # Corrupted/unreadable – reset (don’t delete on disk yet).
        _state_cache = {}
    return _state_cache


def _save(state: Dict[str, Any]) -> None:
    path = _state_path()
    if path.as_posix() == ":memory:":
        return  # persistence disabled

    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix="bundles", suffix=".tmp")
    with os.fdopen(tmp_fd, "w", encoding="utf-8") as fp:
        json.dump(state, fp, indent=2, sort_keys=True)
        fp.flush()
        os.fsync(fp.fileno())
    os.replace(tmp_name, path)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_bundle_state(app_name: str) -> Optional[Dict[str, Any]]:
    """Return persisted state for *app_name* or ``None`` if absent."""
    with _LOCK:
        return _load().get(app_name)


def set_bundle_state(app_name: str, *, etag: Optional[str] = None, version: Optional[int] = None) -> None:
    """Merge a bundle entry and persist.

    ``last_checked`` is always updated to now (UTC).
    """
    now = _dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    with _LOCK:
        state = _load()
        entry = state.get(app_name, {})
        if etag is not None:
            entry["etag"] = etag
        if version is not None:
            entry["version"] = version
        entry["last_checked"] = now
        state[app_name] = entry
        _save(state)


def list_bundles() -> Dict[str, Any]:
    """Return a *copy* of the full mapping."""
    with _LOCK:
        return _load().copy()


def clear_bundle_state(app_name: Optional[str] = None) -> None:
    """Remove one bundle entry or clear all when *app_name* is None."""
    global _state_cache
    with _LOCK:
        if app_name is None:
            state = {}
        else:
            state = _load()
            state.pop(app_name, None)
        _save(state)
        _state_cache = state
