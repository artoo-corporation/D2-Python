# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

from __future__ import annotations

from .cli.commands import publish_command as _publish_policy
from .cli.discovery import (
    discover_tool_ids as _discover_tool_ids,
    discover_tools as _discover_tools,
    validate_condition_arguments as _validate_condition_arguments,
)
from .cli.main import main

__all__ = [
    "_discover_tool_ids",
    "_discover_tools",
    "_publish_policy",
    "_validate_condition_arguments",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main()) 