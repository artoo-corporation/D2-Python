# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""Telemetry plan limit regressions: warning helper + decorator behaviour."""

from __future__ import annotations

import logging

import pytest

from d2 import d2_guard
from d2.exceptions import D2PlanLimitError


def test_emit_plan_limit_warning_logs_once(caplog):
    module = __import__("d2.telemetry.plan_limits", fromlist=["emit_plan_limit_warning"])
    emit_plan_limit_warning = module.emit_plan_limit_warning

    logger = logging.getLogger("d2.plan_limit.test")

    with caplog.at_level(logging.ERROR, logger=logger.name):
        emit_plan_limit_warning(logger)

    assert any("plan limit reached" in message.lower() for message in caplog.messages)


class _StubPM:
    mode = "cloud"

    async def is_tool_in_policy_async(self, _tool_id: str):
        return True

    async def check_async(self, _tool_id: str):
        raise D2PlanLimitError("tool_limit")


def test_plan_limit_upgrade_message(monkeypatch, caplog):
    monkeypatch.setattr("d2.policy.get_policy_manager", lambda _name="default": _StubPM())
    monkeypatch.setattr("d2.decorator.get_policy_manager", lambda _name="default": _StubPM())

    @d2_guard("dummy_tool")
    def _dummy_tool():
        return "ok"

    with caplog.at_level(logging.ERROR):
        with pytest.raises(D2PlanLimitError):
            _dummy_tool()

    assert any(
        "plan limit" in record.getMessage().lower() and "upgrade" in record.getMessage().lower()
        for record in caplog.records
    )

