# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

import asyncio
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Any, Optional

import anyio

# We import PyYAML lazily to avoid requiring it when policy file is JSON
try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover – handled later
    yaml = None

from .base import PolicyLoader
from ...exceptions import ConfigurationError
from ...telemetry import get_tracer, policy_file_reload_total
from ...telemetry import local_tool_count
from ...validator import validate_bundle

logger = logging.getLogger(__name__)
tracer = get_tracer(__name__)

try:
    from watchdog.observers import Observer  # type: ignore
    from watchdog.events import FileSystemEventHandler  # type: ignore
    WATCHDOG_AVAILABLE = True
except ImportError:  # pragma: no cover – optional dep
    WATCHDOG_AVAILABLE = False
    # Create a lightweight stand-in so the module can still import cleanly.

    class FileSystemEventHandler:  # type: ignore
        """Fallback stub when watchdog is not installed."""

        pass


if WATCHDOG_AVAILABLE:

    class _PolicyFileChangeHandler(FileSystemEventHandler):
        """Handles file system events for the policy file."""

        def __init__(self, policy_path: Path, callback: callable):
            self.policy_path = policy_path
            self._callback = callback

        def on_modified(self, event):  # type: ignore[override]
            if not event.is_directory and Path(event.src_path) == self.policy_path:
                logger.info("Policy file %s changed, triggering reload.", self.policy_path)
                policy_file_reload_total.add(1, {"mode": "file"})
                self._callback()
else:

    # Define a no-op placeholder to avoid NameErrors when watchdog is absent.
    class _PolicyFileChangeHandler:  # pylint: disable=too-few-public-methods
        def __init__(self, *_args, **_kwargs):
            raise RuntimeError(
                "File watching requires the optional 'watchdog' dependency. "
                "Install with: pip install 'd2[local]' or 'pip install watchdog'"
            )

class FilePolicyLoader(PolicyLoader):
    """Loads a policy from a local YAML or JSON file.

    Parameters
    ----------
    file_path : str | None
        Explicit override path to the policy file.  If ``None`` the loader
        searches default locations.
    suppress_log : bool, default ``False``
        When ``True`` the usual informational log line (“operating in
        local-file mode”) is skipped.  Useful for commands like ``d2 diagnose``
        that merely parse a file for linting.
    """

    def __init__(self, file_path: Optional[str] = None, *, suppress_log: bool = False):
        self.policy_path = self._find_policy_file(file_path)
        self._observer: Optional[Observer] = None  # type: ignore
        if not suppress_log:
            logger.info("Reading policy file: %s", self.policy_path)

    @property
    def mode(self) -> str:
        return "file"

    def _find_policy_file(self, file_path: Optional[str] = None) -> Path:
        if file_path:
            path = Path(file_path)
            if path.exists():
                logger.debug("Found policy file via file_path: %s", path)
                return path
        
        if "D2_POLICY_FILE" in os.environ:
            path = Path(os.environ["D2_POLICY_FILE"])
            if path.exists():
                logger.debug("Found policy file via D2_POLICY_FILE env var: %s", path)
                return path
        
        xdg_config_home = Path(os.environ.get("XDG_CONFIG_HOME", "~/.config")).expanduser()
        default_paths = [
            xdg_config_home / "d2/policy.yaml",
            xdg_config_home / "d2/policy.yml",
            xdg_config_home / "d2/policy.json",
            Path("policy.yaml"),
            Path("policy.yml"),
            Path("policy.json"),
        ]

        found: list[Path] = [p for p in default_paths if p.exists()]

        if len(found) > 1:
            # Ambiguous – user must pick one explicitly via env var
            logger.error("Multiple local policy files detected: %s. Set D2_POLICY_FILE to disambiguate.", found)
            raise ConfigurationError(
                "Multiple local policy files detected. Set the D2_POLICY_FILE environment variable to the file you want to use."
            )

        if found:
            logger.debug("Found policy file at default location: %s", found[0])
            return found[0]

        raise ConfigurationError(
            "Could not find a local policy file (e.g., 'policy.yaml'), and the D2_TOKEN is not set. "
            "To fix, you can either:\n"
            "1. Run `python -m d2 init` to create a default policy file.\n"
            "2. Set the D2_POLICY_FILE environment variable to point to your policy file.\n"
            "3. Set the D2_TOKEN environment variable to use cloud mode."
        )

    async def load_policy(self) -> Dict[str, Any]:
        """Loads the policy from file and returns the raw dictionary, performing validation."""
        logger.info("Loading policy from file: %s", self.policy_path)
        
        raw_content = self.policy_path.read_bytes()

        if self.policy_path.suffix in ['.yml', '.yaml']:
            if yaml is None:
                raise ConfigurationError(
                    "PyYAML is required to read YAML policy files. Install with: pip install \"d2[cli]\""
                )
            bundle = yaml.safe_load(raw_content)
        else:  # .json
            bundle = json.loads(raw_content)

        # Enforce free-tier limits & record tool count
        tool_count = validate_bundle(bundle, raw_bundle_size=len(raw_content))
        local_tool_count.add(tool_count, {})
        return bundle

    def start(self, policy_update_callback: callable):
        """Starts the file watcher if watchdog is available.
        
        The file watcher can be disabled by setting D2_DISABLE_FILE_WATCHER=1.
        This is useful in test scenarios where the watchdog fsevents extension
        on macOS can cause crashes during shutdown.
        """
        if os.getenv("D2_DISABLE_FILE_WATCHER", "").lower() in ("1", "true", "yes"):
            logger.debug("File watcher disabled via D2_DISABLE_FILE_WATCHER")
            return
            
        if WATCHDOG_AVAILABLE:
            self._start_watcher(policy_update_callback)

    def _start_watcher(self, callback: callable):
        event_handler = _PolicyFileChangeHandler(self.policy_path, callback)
        self._observer = Observer()
        self._observer.schedule(event_handler, path=str(self.policy_path.parent), recursive=False)
        self._observer.start()
        logger.info("Started watching policy file '%s' for changes.", self.policy_path)

    async def shutdown(self):
        observer = self._observer
        self._observer = None  # Clear reference first to prevent double-shutdown
        
        if observer:
            # IMPORTANT: The watchdog fsevents extension on macOS has fundamental
            # threading bugs that cause segfaults/illegal instructions when stop()
            # is called from a different async context or thread than where the
            # observer was started. This is especially problematic in pytest fixtures.
            #
            # The safest approach is to:
            # 1. Clear our reference first (above)
            # 2. Try to stop but catch ALL exceptions including BaseException
            # 3. Never call join() - let daemon thread die naturally
            # 4. If we're on macOS with fsevents, be extra cautious
            import sys
            import platform
            
            # On macOS, fsevents can crash. On Linux with inotify, it's usually safe.
            is_macos = platform.system() == "Darwin"
            
            try:
                if observer.is_alive():
                    observer.stop()
                    logger.info("Stopped policy file watcher.")
            except BaseException as e:
                # Catch BaseException to handle SystemExit, KeyboardInterrupt, etc.
                # that might come from the native fsevents code crashing
                if is_macos:
                    logger.debug("Error stopping file watcher on macOS (expected, non-fatal): %s", e)
                else:
                    logger.warning("Error stopping file watcher: %s", e)
            logger.info("Stopped policy file watcher.") 