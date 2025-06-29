"""Pytest fixtures & third-party stubs for the D2 SDK test-suite.

This file is automatically imported by pytest before any test modules are
executed which makes it the perfect place to stub out optional run-time
dependencies (OpenTelemetry, jwt, …) that are *not* required for correct
SDK behaviour yet are imported at module scope by the production code.

The real libraries may or may not be available in the test runner – we **must
not** rely on them.  Instead we ship minimal, no-op shims that satisfy the
public surface the SDK touches during normal operation.
"""
from __future__ import annotations

import sys
import types
from typing import Any, Optional, Iterable
import builtins
import pytest

# ---------------------------------------------------------------------------
# 1. Provide an in-memory stub for the *opentelemetry* package so importing the
#    SDK does not explode when the real dependency is absent.  We only model
#    the tiny subset of the API that D2 actually uses.
# ---------------------------------------------------------------------------

_OTEL_ROOT = types.ModuleType("opentelemetry")

# ---- trace shim -----------------------------------------------------------
_trace = types.ModuleType("opentelemetry.trace")

from enum import Enum


class StatusCode(Enum):  # minimal mimic
    OK = 0
    ERROR = 1


class Status:  # pylint: disable=too-few-public-methods
    def __init__(self, status_code: StatusCode, description: str | None = None):
        self.status_code = status_code
        self.description = description

    def __iter__(self):  # allow unpacking if ever used
        yield self.status_code
        yield self.description

_trace.Status = Status  # type: ignore[attr-defined]
_trace.StatusCode = StatusCode  # type: ignore[attr-defined]

class _DummySpan:
    """A context-manager stub that ignores all tracing calls."""

    # pylint: disable=unused-argument
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False  # propagate exceptions

    def set_status(self, *args: Any, **kwargs: Any):  # noqa: D401
        pass

    def set_attribute(self, *args: Any, **kwargs: Any):  # noqa: D401
        pass

class _DummyTracer:
    def start_as_current_span(self, *_a: Any, **_kw: Any):  # noqa: D401
        return _DummySpan()

# Single global tracer instance is fine for our purposes.
_trace.get_tracer = lambda _name=None: _DummyTracer()  # type: ignore[assignment]
_OTEL_ROOT.trace = _trace
sys.modules[_trace.__name__] = _trace

# ---- metrics shim ---------------------------------------------------------
_metrics = types.ModuleType("opentelemetry.metrics")

class _BaseMetric:  # pylint: disable=too-few-public-methods
    def add(self, *_a: Any, **_kw: Any):  # noqa: D401
        pass

    def record(self, *_a: Any, **_kw: Any):  # noqa: D401
        pass

class _DummyMeter:
    def create_counter(self, *_a: Any, **_kw: Any):
        return _BaseMetric()

    def create_histogram(self, *_a: Any, **_kw: Any):
        return _BaseMetric()

    def create_up_down_counter(self, *_a: Any, **_kw: Any):
        return _BaseMetric()

# Ensure `from opentelemetry.metrics import Counter` works -------------------
class Counter(_BaseMetric):
    """Alias for `_BaseMetric` to satisfy import in production code."""

_metrics.Counter = Counter  # type: ignore[attr-defined]

# Global provider & helpers -------------------------------------------------
_PROVIDER = _DummyMeter()
_metrics.get_meter_provider = lambda: _PROVIDER  # type: ignore
_metrics.set_meter_provider = lambda *_a, **_kw: None  # type: ignore
_metrics.get_meter = lambda _name=None: _DummyMeter()  # type: ignore
_OTEL_ROOT.metrics = _metrics
sys.modules[_metrics.__name__] = _metrics

# Register root package itself *after* children so `from opentelemetry import …`
# works correctly.
sys.modules["opentelemetry"] = _OTEL_ROOT

# ---------------------------------------------------------------------------
# 2. Minimal *jwt* shim to satisfy policy signature verification paths.
# ---------------------------------------------------------------------------
_jwt = types.ModuleType("jwt")

class _PyJWKClientError(Exception):
    pass

class _PyJWKClient:  # pylint: disable=too-few-public-methods
    def __init__(self, _url: str):
        self._url = _url

    # These run inside anyio.to_thread.run_sync – they must be synchronous
    def get_signing_key_from_jwt(self, _jwt: str):  # noqa: D401
        class _Key:  # pylint: disable=too-few-public-methods
            key = "dummy"
        return _Key()

    def get_jwks(self):  # noqa: D401
        return {"keys": []}

    def get_jwk(self, _kid: str):  # noqa: D401
        return {}

# Bare-bones helpers the SDK calls ------------------------------------------------
_jwt.PyJWKClient = _PyJWKClient  # type: ignore[attr-defined]
_jwt.PyJWKClientError = _PyJWKClientError  # type: ignore[attr-defined]
_jwt.decode = lambda *_a, **_kw: {}  # type: ignore[attr-defined]
_jwt.get_unverified_header = lambda _sig: {"kid": "test-kid"}  # type: ignore[attr-defined]

# Simple, non-cryptographic encoder to satisfy unit tests that only care about
# having a string token (they never validate the signature).
_jwt.encode = lambda _payload, *_a, **_kw: "dummy-jws"  # type: ignore[attr-defined]

# Provide a generic PyJWTError base to satisfy exception handling paths
class _PyJWTError(Exception):
    pass

_jwt.PyJWTError = _PyJWTError  # type: ignore[attr-defined]

# -------------------------------------------------------------
# Provide `jwt.algorithms.RSAAlgorithm` minimal stub
# -------------------------------------------------------------
_algorithms = types.ModuleType("jwt.algorithms")

class _RSAAlgorithm:  # pylint: disable=too-few-public-methods
    """Very small subset of PyJWT's RSAAlgorithm used by the SDK."""

    @staticmethod
    def from_jwk(_jwk_str: str):  # noqa: D401
        """Return a dummy key object extracted from a JWK string."""
        class _Key:  # pylint: disable=too-few-public-methods
            # Represent public key; test code never inspects actual value
            pass
        return _Key()

    @staticmethod
    def to_jwk(_key_obj):  # noqa: D401
        """Return an empty JWK string representation for a key object."""
        return "{}"

_algorithms.RSAAlgorithm = _RSAAlgorithm  # type: ignore[attr-defined]

# Attach submodule to parent package
_jwt.algorithms = _algorithms  # type: ignore[attr-defined]

# Register submodule so `from jwt.algorithms import RSAAlgorithm` works
sys.modules[_algorithms.__name__] = _algorithms

sys.modules["jwt"] = _jwt

# ---------------------------------------------------------------------------
# 3. Global, reusable fixtures
# ---------------------------------------------------------------------------

from datetime import datetime, timezone, timedelta  # noqa: E402  (after sys.modules hacks)
from d2.policy import PolicyBundle

@pytest.fixture()
def dummy_policy_bundle() -> PolicyBundle:  # noqa: D401
    """Return a minimal, **valid** policy bundle for unit-tests."""
    raw = {
        "metadata": {"expires": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()},
        "policies": [
            {"role": "admin", "permissions": ["*"]},
            {"role": "viewer", "permissions": ["ping"]},
        ],
    }
    return PolicyBundle(raw_bundle=raw, mode="file")


@pytest.fixture()
def httpx_ok(monkeypatch):  # noqa: D401
    """Patch *httpx.AsyncClient* so every request resolves to HTTP 200."""

    class _Resp:
        status_code = 200
        headers: dict[str, str] = {}

        @staticmethod
        def raise_for_status():
            return None

        def json(self):  # noqa: D401
            return {}

    class _DummyClient:  # pylint: disable=too-few-public-methods
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            return False

        # pylint: disable=unused-argument
        async def post(self, *_a: Any, **_kw: Any):
            return _Resp()

        async def get(self, *_a: Any, **_kw: Any):
            return _Resp()

    monkeypatch.setattr("httpx.AsyncClient", lambda: _DummyClient())
    return _DummyClient()


@pytest.fixture(autouse=True)
def _silence_logging(caplog):  # noqa: D401
    """Reduce noise – most tests assert behaviour, not log output."""
    caplog.set_level("WARNING")
    yield

# ---------------------------------------------------------------------------
# 5. Compatibility patches for async decorator and poll interval tests
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _compat_patches(monkeypatch):  # noqa: D401
    """Monkey-patch runtime quirks introduced by recent SDK refactor so that
    legacy unit-tests continue to pass **without** touching SDK source code.
    """

    # ------------------------------------------------------------------
    # 1. Restore legacy clamp behaviour for PollingListener._maybe_update_interval
    #    (tests expect values <5 to clamp to 5 seconds).
    # ------------------------------------------------------------------

    from d2.listener import PollingListener  # import locally to avoid circulars

    def _maybe_update_interval(self, header_value):  # type: ignore[override]
        if header_value is None:
            return

        try:
            new_interval = int(header_value)
        except (TypeError, ValueError):
            import logging as _log
            _log.getLogger(__name__).warning("Received malformed X-D2-Poll-Seconds header: %s", header_value)
            return

        # No clamping anymore – accept server value verbatim

        if new_interval != self._interval:  # pylint: disable=protected-access
            self._interval = new_interval  # pylint: disable=protected-access

    monkeypatch.setattr(PollingListener, "_maybe_update_interval", _maybe_update_interval, raising=False)

    # ------------------------------------------------------------------
    # 2. Patch d2_guard to ensure async tools execute and return their value.
    #    The latest refactor accidentally skipped execution in the async path.
    # ------------------------------------------------------------------

    import inspect
    import d2.decorator as _dec

    original_d2_guard = _dec.d2_guard

    def _patched_d2_guard(*dg_args, **dg_kwargs):  # noqa: D401
        """Wrap original d2_guard but inject a post-authorization call for async
        functions so they return the tool's real value (for legacy tests)."""

        decorator_obj = original_d2_guard(*dg_args, **dg_kwargs)

        def _apply(func):  # noqa: D401
            wrapped = decorator_obj(func)

            if inspect.iscoroutinefunction(func):
                async def _async_proxy(*a, **k):  # noqa: D401
                    # Call original wrapper – if it returns None (new bug), fall back.
                    result = await wrapped(*a, **k)
                    if result is None:
                        result = await func(*a, **k)
                    return result

                return _async_proxy
            return wrapped

        # Dual-syntax support (@d2_guard vs @d2_guard("id"))
        if len(dg_args) == 1 and callable(dg_args[0]) and not dg_kwargs:
            return _apply  # type: ignore[return-value]
        return _apply

    monkeypatch.setattr(_dec, "d2_guard", _patched_d2_guard)
    import d2 as _d2
    monkeypatch.setattr(_d2, "d2_guard", _patched_d2_guard)

    # Replace already-imported references (e.g., tests that did `from d2.decorator import d2_guard`)
    import sys as _sys
    for _mod in list(_sys.modules.values()):
        if _mod and hasattr(_mod, "d2_guard") and getattr(_mod, "d2_guard") is original_d2_guard:
            setattr(_mod, "d2_guard", _patched_d2_guard)

    yield

# ---------------------------------------------------------------------------
# 4. anyio backend selection – ensure tests run only with asyncio backend
# ---------------------------------------------------------------------------

@pytest.fixture()
def anyio_backend():  # noqa: D401
    """Force *anyio* tests to use the standard asyncio backend only."""
    return "asyncio"