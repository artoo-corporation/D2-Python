"""Core behaviour tests for *d2.policy.PolicyManager* (local mode).

We monkey-patch the *FilePolicyLoader* so we can inject a hand-crafted bundle
without touching the file-system.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone, timedelta

import pytest

from d2.policy import PolicyManager, PolicyBundle
from d2.context import set_user_context, clear_user_context
from d2.exceptions import ConfigurationError


class _DummyLoader:  # pylint: disable=too-few-public-methods
    """Minimal stand-in for *FilePolicyLoader* returning an in-memory bundle."""

    def __init__(self, bundle):  # noqa: D401
        self._bundle = bundle
        self.mode = "file"

    async def load_policy(self):  # noqa: D401
        return self._bundle

    def start(self, *args, **kwargs):  # noqa: D401
        return None

    async def shutdown(self):  # noqa: D401
        return None


@pytest.mark.anyio
async def test_check_allowed(monkeypatch, dummy_policy_bundle):
    """User with role *admin* should be authorised for any tool (wildcard)."""
    monkeypatch.setattr("d2.policy.FilePolicyLoader", lambda *a, **kw: _DummyLoader(dummy_policy_bundle))

    pm = PolicyManager("t", api_url="http://api", pin_jwks_thumbprints=None)
    # Pretend the initial load already happened
    pm._policy_bundle = dummy_policy_bundle  # pylint: disable=protected-access
    pm._init_complete.set()

    with set_user_context(user_id="alice", roles=["admin"]):
        assert await pm.check_async("weather_api") is True

    # Context cleared automatically – double-check no leak
    clear_user_context()


@pytest.mark.anyio
async def test_check_denied(monkeypatch, dummy_policy_bundle):
    """User without the required role must be denied."""
    monkeypatch.setattr("d2.policy.FilePolicyLoader", lambda *a, **kw: _DummyLoader(dummy_policy_bundle))

    pm = PolicyManager("x", api_url="http://api", pin_jwks_thumbprints=None)
    pm._policy_bundle = dummy_policy_bundle  # pylint: disable=protected-access
    pm._init_complete.set()

    with set_user_context(user_id="bob", roles=["viewer"]):
        assert await pm.check_async("admin.dashboard") is False


@pytest.mark.anyio
async def test_sync_check_inside_loop(monkeypatch, dummy_policy_bundle):
    """Calling the *sync* API from within an event-loop must raise *ConfigurationError*."""
    monkeypatch.setattr("d2.policy.FilePolicyLoader", lambda *a, **kw: _DummyLoader(dummy_policy_bundle))
    pm = PolicyManager("sync", api_url="http://api", pin_jwks_thumbprints=None)
    pm._policy_bundle = dummy_policy_bundle  # pylint: disable=protected-access
    pm._init_complete.set()

    with set_user_context(user_id="carol", roles=["viewer"]):
        with pytest.raises(ConfigurationError):
            # We're already inside the anyio test loop
            pm.check("something")


@pytest.mark.anyio
async def test_expiry_warning(monkeypatch, caplog):
    """_check_for_expiry_warning should log when expiry <24h."""
    # Build a bundle expiring in 1 hour
    raw = {
        "metadata": {"expires": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()},
        "policies": [{"role": "viewer", "permissions": ["ping"]}],
    }
    bundle = PolicyBundle(raw_bundle=raw, mode="file")

    monkeypatch.setattr("d2.policy.FilePolicyLoader", lambda *a, **kw: _DummyLoader(bundle))
    pm = PolicyManager("warn", api_url="http://api", pin_jwks_thumbprints=None)
    pm._policy_bundle = bundle  # pylint: disable=protected-access

    # Trigger warning path
    pm._check_for_expiry_warning(bundle)  # pylint: disable=protected-access

    assert any("Local policy expires in" in rec.message for rec in caplog.records) 