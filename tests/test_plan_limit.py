import logging

import pytest

from d2.exceptions import D2PlanLimitError
from d2 import d2_guard  # public re-export


# ---------------------------------------------------------------------------
# Helper: stub PolicyManager that always raises plan-limit error
# ---------------------------------------------------------------------------

class _StubPM:
    mode = "cloud"

    async def is_tool_in_policy_async(self, _tool_id: str):
        return True  # pretend tool is present

    async def check_async(self, _tool_id: str):  # noqa: D401
        raise D2PlanLimitError("tool_limit")


def test_plan_limit_upgrade_message(monkeypatch, caplog):
    """Simulate HTTP 402 plan-limit response and assert upgrade nudge is logged."""

    # Patch get_policy_manager (both policy & decorator module) to return stub
    monkeypatch.setattr("d2.policy.get_policy_manager", lambda _name="default": _StubPM())
    monkeypatch.setattr("d2.decorator.get_policy_manager", lambda _name="default": _StubPM())

    # Define tool *after* patches so wrapper binds patched manager
    @d2_guard("dummy_tool")
    def _dummy_tool():
        return "ok"

    with caplog.at_level(logging.ERROR):
        with pytest.raises(D2PlanLimitError):
            _dummy_tool()

    # Ensure upgrade message logged
    assert any(
        "plan limit" in record.getMessage().lower() and "upgrade" in record.getMessage().lower()
        for record in caplog.records
    ) 