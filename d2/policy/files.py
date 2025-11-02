# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""Helpers for locating and loading local policy files."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Iterable, Iterator, Optional

from ..exceptions import ConfigurationError

try:  # pragma: no cover - optional dependency, exercised via tests when installed
    import yaml  # type: ignore
except ImportError:  # pragma: no cover
    yaml = None


def iter_policy_candidates(project_root: Optional[Path] = None, *, env: Optional[dict[str, str]] = None) -> Iterator[Path]:
    """Yield candidate policy file paths in priority order."""

    env = env or os.environ
    project_root = project_root or Path.cwd()

    override = env.get("D2_POLICY_FILE")
    if override:
        yield Path(override).expanduser()
        return

    xdg_config_home = Path(env.get("XDG_CONFIG_HOME", "~/.config")).expanduser()
    config_dir = xdg_config_home / "d2"

    defaults: Iterable[Path] = (
        config_dir / "policy.yaml",
        config_dir / "policy.yml",
        config_dir / "policy.json",
        project_root / "policy.yaml",
        project_root / "policy.yml",
        project_root / "policy.json",
    )

    seen: set[Path] = set()
    for candidate in defaults:
        resolved = candidate.expanduser()
        if resolved in seen:
            continue
        seen.add(resolved)
        yield resolved


def locate_policy_file(
    policy_path: Optional[Path] = None,
    *,
    env: Optional[dict[str, str]] = None,
) -> Path:
    """Return the path to the local policy file or raise ``ConfigurationError``."""

    env = env or os.environ

    if policy_path is not None:
        candidate = Path(policy_path).expanduser()
        if candidate.exists():
            return candidate
        raise ConfigurationError(
            f"Policy file not found at {candidate}. Set D2_POLICY_FILE to a valid path or run `d2 init`."
        )

    existing = [candidate for candidate in iter_policy_candidates(env=env) if candidate.exists()]

    if not existing:
        searched = ", ".join(str(path) for path in iter_policy_candidates(env=env))
        raise ConfigurationError(
            "Could not find a local policy file. Looked for: "
            f"{searched}. Run `d2 init` to create one or set D2_POLICY_FILE."
        )

    if len(existing) > 1:
        pretty_files = "\n   • " + "\n   • ".join(str(p) for p in existing)
        raise ConfigurationError(
            "Multiple local policy files detected:" + pretty_files + "\n"
            "Only one policy file may exist. Delete duplicates or set D2_POLICY_FILE to disambiguate."
        )

    return existing[0]


def require_app_name(*, env: Optional[dict[str, str]] = None) -> str:
    """Return ``metadata.name`` from the local policy file."""

    path = locate_policy_file(env=env)
    raw = path.read_bytes()

    if path.suffix == ".json":
        data = json.loads(raw)
    else:
        if yaml is None:
            raise ConfigurationError(
                "PyYAML is required to parse YAML policy files. Install with: pip install \"d2[cli]\"."
            )
        data = yaml.safe_load(raw)

    if not isinstance(data, dict):
        raise ConfigurationError("Policy file must contain a mapping at the top level.")

    metadata = data.get("metadata", {}) if isinstance(data.get("metadata"), dict) else {}
    name = metadata.get("name") if isinstance(metadata, dict) else None

    if not isinstance(name, str) or not name.strip() or name.strip().startswith("<"):
        raise ConfigurationError("metadata.name is required in the policy file and cannot be a placeholder.")

    return name.strip()


__all__ = [
    "iter_policy_candidates",
    "locate_policy_file",
    "require_app_name",
]

