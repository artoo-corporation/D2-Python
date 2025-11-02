# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

import argparse
import importlib
import logging
from datetime import datetime, timezone
from pathlib import Path

import yaml


def _get_subparser_names(parser: argparse.ArgumentParser) -> set[str]:
    subparser_actions = [
        action
        for action in parser._actions
        if isinstance(action, argparse._SubParsersAction)
    ]
    if not subparser_actions:
        raise AssertionError("expected at least one subparser action")
    names: set[str] = set()
    for action in subparser_actions:
        names.update(action.choices.keys())
    return names


def test_build_parser_registers_expected_commands():
    cli_main = importlib.import_module("d2.cli.main")
    parser = cli_main.build_parser()
    expected = {
        "init",
        "pull",
        "inspect",
        "diagnose",
        "publish",
        "draft",
        "status",
        "switch",
        "license-info",
    }
    assert expected.issubset(_get_subparser_names(parser))


def test_run_command_invokes_async_callable():
    cli_main = importlib.import_module("d2.cli.main")

    called = {}

    async def fake_async(args):  # pragma: no cover - executed via event loop
        called["async"] = args

    namespace = argparse.Namespace(func=fake_async, is_async=True, value=42)

    cli_main.run_command(namespace)

    assert called["async"].value == 42


def test_run_command_invokes_sync_callable():
    cli_main = importlib.import_module("d2.cli.main")

    called = {}

    def fake_sync(args):
        called["sync"] = args

    namespace = argparse.Namespace(func=fake_sync, is_async=False, value="ok")

    cli_main.run_command(namespace)

    assert called["sync"].value == "ok"


def test_inspect_parser_accepts_app_name():
    cli_main = importlib.import_module("d2.cli.main")
    parser = cli_main.build_parser()
    args = parser.parse_args(["inspect", "--app-name", "demo"])
    assert args.app_name == "demo"


def test_init_command_generates_metadata(tmp_path: Path, monkeypatch, caplog):
    monkeypatch.delenv("D2_POLICY_FILE", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))

    cli_commands = importlib.import_module("d2.cli.commands")
    with caplog.at_level(logging.WARNING, logger="d2.cli"):
        args = argparse.Namespace(force=True, path=tmp_path, format="yaml")
        cli_commands.init_command(args)

    assert any("Pass --path" in message for message in caplog.messages)

    policy_path = tmp_path / "config" / "d2" / "policy.yaml"
    assert policy_path.exists()

    data = yaml.safe_load(policy_path.read_text())
    metadata = data.get("metadata", {})
    assert metadata.get("name") == "<FILL_ME_IN>"
    assert metadata.get("description") == "Describe this policy bundle"

    expires = datetime.fromisoformat(metadata["expires"])
    delta_days = (expires - datetime.now(timezone.utc)).total_seconds() / 86400
    assert 6.5 <= delta_days <= 7.5

