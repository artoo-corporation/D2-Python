# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""Request/response middle-layer helpers.

We ship two conveniences:

1. ASGIMiddleware – plug-and-play for FastAPI / Starlette / Quart, etc.
2. clear_context decorator – for ad-hoc sync frameworks (Flask, Django).

The ASGI middleware is opinionated but override-able: by default it looks for
`X-D2-User` and `X-D2-Roles` HTTP headers (a common pattern when you’re behind
an auth gateway).  You can pass a custom `user_extractor` if your framework
stores identity information elsewhere (e.g., `scope["session"]`).
"""

from __future__ import annotations

import functools
import inspect
from typing import Callable, Awaitable, Iterable, Optional, Tuple, Any

from .context import set_user, clear_user_context

# ---------------------------------------------------------------------------
# 1. Generic ASGI middleware
# ---------------------------------------------------------------------------

class ASGIMiddleware:  # pragma: no cover — tiny wrapper, covered indirectly
    """Minimal ASGI middleware that sets the D2 user context per request.

    Example (FastAPI):

        from fastapi import FastAPI
        import d2

        app = FastAPI()
        app.add_middleware(d2.ASGIMiddleware)  # default header extractor

    Example with custom extractor:

        def extractor(scope):
            user = scope["session"].get("user_id")
            roles = scope["session"].get("roles", [])
            return user, roles

        app.add_middleware(d2.ASGIMiddleware, user_extractor=extractor)
    """

    def __init__(
        self,
        app: Callable[[dict, Callable, Callable], Awaitable[None]],
        *,
        user_extractor: Callable[[dict], Tuple[Optional[str], Optional[Iterable[str]]]],
    ):  # noqa: D401
        if user_extractor is None:
            raise RuntimeError(
                "ASGIMiddleware requires a user_extractor callable. "
                "Choose one of the helpers in d2.middleware (e.g. headers_extractor) "
                "or pass your own implementation."
            )
        self.app = app
        self._extract_user = user_extractor

    # ------------------------------------------------------------------
    # ASGI entry-point
    # ------------------------------------------------------------------

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:  # type: ignore[override]
        if scope.get("type") != "http":  # Only HTTP requests carry user ctx
            await self.app(scope, receive, send)
            return

        user_id, roles = self._extract_user(scope)
        set_user(user_id, roles)
        try:
            await self.app(scope, receive, send)
        finally:
            clear_user_context()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Predefined extractor helpers
# ---------------------------------------------------------------------------


def headers_extractor(scope: dict) -> Tuple[Optional[str], Optional[Iterable[str]]]:
    """Extract user/roles from `X-D2-User` and `X-D2-Roles` headers.

    Use **only** when the service is behind a trusted reverse-proxy that sets
    those headers (or strips and rewrites them). End-users must not be able to
    inject these headers directly.
    """
    headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
    user = headers.get("x-d2-user")
    roles_raw = headers.get("x-d2-roles")
    roles: Optional[Iterable[str]] = roles_raw.split(",") if roles_raw else None
    return user, roles


# ---------------------------------------------------------------------------
# 2. Decorator for sync frameworks (Flask, Django views)
# ---------------------------------------------------------------------------


def clear_context(func: Callable) -> Callable:  # pragma: no cover – trivial
    """Ensure the D2 context is cleared after a synchronous request handler."""

    if inspect.iscoroutinefunction(func):  # Guard against misuse
        raise TypeError("clear_context decorator is for sync functions only. Use @clear_context_async for async handlers.")

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any):
        try:
            return func(*args, **kwargs)
        finally:
            clear_user_context()

    return wrapper

# ---------------------------------------------------------------------------
# 3. Decorator for async frameworks (async handlers)
# ---------------------------------------------------------------------------


def clear_context_async(func: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:  # noqa: D401
    """Await the coroutine and clear D2 context in a *finally* block.

    Example (FastAPI route without middleware):

        @app.get("/ping")
        @d2.clear_context_async
        async def ping():
            d2.set_user("alice", roles=["viewer"])
            return "pong"
    """

    if not inspect.iscoroutinefunction(func):
        raise TypeError("clear_context_async decorator is for *async* functions only.")

    @functools.wraps(func)
    async def wrapper(*args: Any, **kwargs: Any):  # type: ignore[override]
        try:
            return await func(*args, **kwargs)
        finally:
            clear_user_context()

    return wrapper 