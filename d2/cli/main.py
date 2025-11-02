# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from typing import Iterable, Optional

from ..exceptions import ConfigurationError, PolicyError
from ..utils import ColorFormatter
from . import commands


def _setup_logging(verbose: bool = False) -> None:
    root_logger = logging.getLogger()
    if not root_logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(ColorFormatter())
        root_logger.addHandler(handler)
    root_logger.setLevel(logging.DEBUG if verbose else logging.INFO)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m d2",
        description="D2 SDK Command-Line Interface. Manages local and cloud policies.",
    )
    subparsers = parser.add_subparsers(dest="command")

    init_parser = subparsers.add_parser(
        "init",
        help="Generate a starter policy file (local mode).",
    )
    init_parser.add_argument("--force", action="store_true", help="Overwrite the policy file if it already exists.")
    init_parser.add_argument(
        "-p",
        "--path",
        default=".",
        help="Project directory to scan for @d2_guard usages (pass your app root explicitly, default: current dir).",
    )
    init_parser.add_argument(
        "--format",
        choices=["yaml", "json"],
        default="yaml",
        help="Output format for the policy file (default: yaml).",
    )
    init_parser.set_defaults(func=commands.init_command, is_async=False)

    pull_parser = subparsers.add_parser(
        "pull",
        help="Download the cloud policy to a file (requires D2_TOKEN).",
    )
    pull_parser.add_argument("-o", "--output", help="Output file path (default: overwrite current policy file)")
    pull_parser.add_argument("--format", choices=["yaml", "json"], help="Force output format when downloading policy")
    pull_parser.add_argument("--app-name", help="Specify which app's policy to fetch (overrides local policy file)")
    pull_parser.add_argument("--stage", choices=["published", "draft"], default="published", help="Version to fetch")
    pull_parser.set_defaults(func=commands.pull_command, is_async=True)

    inspect_parser = subparsers.add_parser(
        "inspect",
        help="List permissions and roles (works for both cloud and local mode).",
    )
    inspect_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed output including roles and permissions.",
    )
    inspect_parser.add_argument(
        "--app-name",
        help="Explicit app name to fetch when using cloud mode (overrides local policy metadata).",
    )
    inspect_parser.set_defaults(func=commands.inspect_command, is_async=True)

    diagnose_parser = subparsers.add_parser(
        "diagnose",
        help="Validate local policy bundle against quotas.",
    )
    diagnose_parser.add_argument(
        "--path",
        default=".",
        help="Project directory to scan for @d2_guard usages when validating conditions (default: current dir).",
    )
    diagnose_parser.set_defaults(func=commands.diagnose_command, is_async=True)

    publish_parser = subparsers.add_parser(
        "publish",
        help="Publish the current policy bundle (requires token with policy:write).",
    )
    publish_parser.set_defaults(func=commands.publish_command, is_async=True)

    draft_parser = subparsers.add_parser(
        "draft",
        help="Upload a policy draft (requires token with policy:write).",
    )
    draft_parser.set_defaults(func=commands.draft_command, is_async=True)

    status_parser = subparsers.add_parser(
        "status",
        help="Show information about cached policy.",
    )
    status_parser.set_defaults(func=commands.status_command, is_async=True)

    switch_parser = subparsers.add_parser(
        "switch",
        help="Switch to a different app.",
    )
    switch_parser.add_argument("app_name", help="App name to switch to")
    switch_parser.set_defaults(func=commands.switch_command, is_async=True)

    license_parser = subparsers.add_parser(
        "license-info",
        help="Show license summary.",
    )
    license_parser.set_defaults(func=commands.license_info_command, is_async=False)

    return parser


def run_command(args: argparse.Namespace) -> None:
    func = getattr(args, "func", None)
    if func is None:
        raise ValueError("No command handler registered")

    if getattr(args, "is_async", False):
        asyncio.run(func(args))
    else:
        func(args)


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if not hasattr(args, "func"):
        parser.print_help()
        return 1

    _setup_logging(getattr(args, "verbose", False))
    asyncio.run(commands.run_gc_on_startup())

    try:
        run_command(args)
    except (ConfigurationError, PolicyError) as exc:
        logging.getLogger("d2.cli").error("%s", exc)
        return 1

    return 0


__all__ = ["build_parser", "main", "run_command"]
