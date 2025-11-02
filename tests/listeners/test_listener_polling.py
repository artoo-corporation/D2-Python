import asyncio
import types

import pytest
from d2.listener import PollingListener


class DummyLoader:
    """Minimal stub to satisfy update_callback."""

    async def callback(self):
        self.called = True


@pytest.mark.asyncio
async def test_maybe_update_interval():
    # Start with default 60s
    dummy = DummyLoader()
    listener = PollingListener(
        bundle_url="https://example.com/v1/policy/bundle",
        update_callback=dummy.callback,
    )
    assert listener._interval == 60  # safeguard against future default change

    # Header bumps down to 10s
    listener._maybe_update_interval("10")
    assert listener._interval == 10

    # Header below minimum clamps
    listener._maybe_update_interval("1")
    assert listener._interval == 1


@pytest.mark.asyncio
async def test_retry_after_override(monkeypatch):
    """Ensure Retry-After sets a one-shot sleep override but keeps base interval."""

    # Patch sleep to fast-forward without delay
    sleep_calls = []

    async def fake_sleep(seconds):
        sleep_calls.append(seconds)
        # fast-forward instantly
        return

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    dummy = DummyLoader()
    listener = PollingListener(
        bundle_url="https://example.com/v1/policy/bundle",
        update_callback=dummy.callback,
    )

    # Manually set override and run single loop iteration
    listener._next_sleep_override = 30

    # We need to stop immediately after one cycle
    async def stop_after_one():
        await asyncio.sleep(0)  # trigger first sleep override
        listener._shutdown_event.set()

    asyncio.create_task(stop_after_one())
    await listener.start()
    # Allow tasks to run briefly
    await asyncio.sleep(0)

    # Verify the override was used
    assert 30 in sleep_calls
    # Base interval remains unchanged
    assert listener._interval == 60 