# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

import functools
from typing import Dict, Set, Optional, Any, Callable, Coroutine, TypeVar, cast
import logging, sys
import os

from opentelemetry.metrics import Counter

# Default configuration values
POLLING_INTERVAL_SECONDS = 60
JITTER_FACTOR = 0.1
MAX_BACKOFF_FACTOR = 8
HTTP_TIMEOUT_SECONDS = 15

DEFAULT_API_URL = os.getenv("D2_API_URL", "https://api.d2.artoo.love")

# ---------------------------------------------------------------------------
# Colored logging helper (ANSI) – used by CLI and can be enabled by users.
# ---------------------------------------------------------------------------


class ColorFormatter(logging.Formatter):  # pragma: no cover – cosmetic
    """Simple ANSI-colored formatter for terminal output.

    Usage:
        handler = logging.StreamHandler()
        handler.setFormatter(ColorFormatter())
        logging.getLogger().addHandler(handler)
    """

    _COLOR_MAP = {
        logging.DEBUG: "\033[34m",     # Blue
        logging.INFO: "\033[32m",      # Green
        logging.WARNING: "\033[33m",   # Yellow
        logging.ERROR: "\033[31m",     # Red
        logging.CRITICAL: "\033[1;31m", # Bold Red
    }

    _RESET = "\033[0m"

    def __init__(self, fmt: str = "[D2] [%(levelname)s] %(message)s", *, use_color: bool = True):
        super().__init__(fmt)
        self._use_color = use_color and sys.stderr.isatty() and os.getenv("NO_COLOR") is None

    def format(self, record: logging.LogRecord) -> str:  # type: ignore[override]
        msg = super().format(record)
        if self._use_color:
            color = self._COLOR_MAP.get(record.levelno, "")
            if color:
                msg = f"{color}{msg}{self._RESET}"
        return msg

def singleton(class_):
    """
    A singleton decorator. Note that this implementation is not thread-safe for
    the first instantiation.
    """
    _instances: Dict = {}
    @functools.wraps(class_)
    def get_instance(*args, **kwargs):
        if class_ not in _instances:
            _instances[class_] = class_(*args, **kwargs)
        return _instances[class_]
    return get_instance

# ---------------------------------------------------------------------------
# Telemetry flag helper (unified)
# ---------------------------------------------------------------------------

from enum import Enum


class TelemetryMode(str, Enum):
    """Canonical telemetry activation modes controlled via D2_TELEMETRY."""

    OFF = "off"
    METRICS = "metrics"
    USAGE = "usage"
    ALL = "all"


# Normalised aliases → TelemetryMode
_ALIAS_MAP: dict[str, TelemetryMode] = {
    "": TelemetryMode.OFF,
    "0": TelemetryMode.OFF,
    "none": TelemetryMode.OFF,
    "off": TelemetryMode.OFF,
    "metrics": TelemetryMode.METRICS,
    "usage": TelemetryMode.USAGE,
    "all": TelemetryMode.ALL,
    "*": TelemetryMode.ALL,
    "1": TelemetryMode.ALL,
    "true": TelemetryMode.ALL,
    "yes": TelemetryMode.ALL,
}


def get_telemetry_mode() -> TelemetryMode:
    """Return the active telemetry mode based on the ``D2_TELEMETRY`` env-var.

    If the variable is unset or unrecognised, we default to ``ALL`` to retain
    the existing behaviour of emitting both metrics and usage telemetry for
    cloud users.
    """

    raw: str = os.getenv("D2_TELEMETRY", "all").lower().strip()
    return _ALIAS_MAP.get(raw, TelemetryMode.ALL)

# ---------------------------------------------------------------------------
# Cache paths helper
# ---------------------------------------------------------------------------

from pathlib import Path

CACHE_DIR = Path.home() / ".cache" / "d2"

def ensure_cache_dir() -> Path:
    """Create ~/.cache/d2 if missing and return path."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return CACHE_DIR


# ---------------------------------------------------------------------------
# Policy helper – resolve metadata.name from local file
# ---------------------------------------------------------------------------


def require_app_name() -> str:
    from .policy.files import require_app_name as _require_app_name

    return _require_app_name()