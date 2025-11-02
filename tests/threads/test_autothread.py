import anyio, pytest, asyncio

import d2
from d2.exceptions import D2Error

class _PM:  # minimal allow-all policy manager
    mode = "file"
    async def is_tool_in_policy_async(self, *_):
        return True
    async def check_async(self, *_):
        return True

def _patch_pm(monkeypatch):
    monkeypatch.setattr("d2.decorator.get_policy_manager", lambda *_: _PM())


def test_auto_thread_sync_in_async(monkeypatch):
    """Sync guarded tool called inside a running event-loop should succeed."""
    _patch_pm(monkeypatch)

    @d2.d2_guard("auto.thread.demo")
    def tool(x):
        return x * 2

    async def caller():
        # calling sync tool in async context – used to raise, now auto-threads
        return tool(3)

    result = anyio.run(caller)
    assert result == 6


def test_strict_mode_raises(monkeypatch):
    """strict=True restores the original hard-fail."""
    _patch_pm(monkeypatch)

    @d2.d2_guard("strict.demo", strict=True)
    def bad():
        return 1

    async def caller():
        with pytest.raises(D2Error):
            bad()

    anyio.run(caller) 