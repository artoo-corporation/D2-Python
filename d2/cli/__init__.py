# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""Command-line interface package for the D2 SDK."""

from .main import build_parser, main, run_command

__all__ = [
    "build_parser",
    "main",
    "run_command",
]

