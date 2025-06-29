# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

import contextvars
from dataclasses import dataclass
from typing import Optional, Set, Iterable, ContextManager
from contextlib import contextmanager


@dataclass(frozen=True)
class UserContext:
    """Immutable dataclass to hold user identity information."""
    user_id: Optional[str] = None
    roles: Optional[frozenset[str]] = None

# Context variable to hold the UserContext for the current async task or thread.
_user_context = contextvars.ContextVar("d2_user_context", default=UserContext())

@contextmanager
def set_user_context(user_id: Optional[str] = None, roles: Optional[Iterable[str]] = None) -> ContextManager[None]:
    """
    A context manager to temporarily set the user context for a block of code.

    This is the primary way to inform the D2 SDK about the current user's identity.
    It is async-aware and safe to use in concurrent applications.

    Nesting Guarantees:
        This context manager is nestable. Exiting an inner context will always
        restore the context of the outer block.

        with set_user_context(user_id="alice", roles=["admin"]):
            # get_current_user() returns Alice
            with set_user_context(user_id="bob", roles=["viewer"]):
                # get_current_user() returns Bob
            # get_current_user() returns Alice again
    
    Async Isolation:
        Context is managed per-task. Two concurrent async tasks will never see
        each other's user context, even if running on the same thread.
    
    Context Flow Boundaries:
        This context flows within a single async task lineage and via to_thread.
        It does NOT cross:
        - Manual threads (threading.Thread, ThreadPoolExecutor.submit)
        - New processes (subprocess, multiprocessing)
        - Other services (HTTP requests, message queues)
        
        For these cases, set context explicitly in those contexts or use sealed tokens to propagate identity.
    """
    token = _user_context.set(UserContext(user_id=user_id, roles=frozenset(roles) if roles else None))
    try:
        yield
    finally:
        _user_context.reset(token)

@contextmanager
def run_as(user_id: str, roles: Optional[Iterable[str]] = None) -> ContextManager[None]:
    """
    A convenience context manager to run a block of code as a specific user.

    This is a more explicitly named alternative to `set_user_context` for running
    background tasks or tests as a specific, temporary user identity.
    """
    with set_user_context(user_id, roles):
        yield

def get_current_user() -> UserContext:
    """
    Retrieves the current user context.
    
    If no context has been explicitly set for the current task, this will
    return a default UserContext instance (with id=None, roles=None).
    """
    return _user_context.get()

# Maintain backwards compatibility for any code that may have used the old name.
get_user_context = get_current_user

def clear_user_context():
    """Explicitly clears the user context."""
    _user_context.set(UserContext())

# ---------------------------------------------------------------------------
# Stale context detection helpers
# ---------------------------------------------------------------------------

from typing import TYPE_CHECKING as _T
import logging as _logging

from .telemetry import context_stale_total as _context_stale_total


def is_context_set() -> bool:
    """Return True if user_id or roles are currently set in the context."""
    ctx = get_current_user()
    return bool(ctx.user_id or ctx.roles)


def warn_if_context_set(*, logger: Optional[_logging.Logger] = None) -> bool:
    """Warns (and records a metric) if the user context was not cleared.

    Usage::

        # At the end of a Flask route or Celery task
        d2.warn_if_context_set()

    The function returns True when a stale context was detected so callers can
    assert in tests.  It never raises.
    """
    if not is_context_set():
        return False

    _context_stale_total.add(1)
    ctx = get_current_user()
    log = logger or _logging.getLogger("d2.context")
    log.warning(
        "D2 user context leaked: user=%s roles=%s (call clear_user_context or use @clear_context)",
        ctx.user_id,
        list(ctx.roles) if ctx.roles else [],
    )
    return True

# ---------------------------------------------------------------------------
# Convenience one-liner setter (non-context-manager)
# ---------------------------------------------------------------------------

def set_user(user_id: Optional[str] = None, roles: Optional[Iterable[str]] = None) -> None:
    """Sets the `UserContext` for the current task **without** a context-manager.

    Useful in web-framework request handlers where a simple one-liner is
    preferred:

    ```python
    async def route(request):
        d2.set_user(request.user.id, request.user.roles)
        ...
    ```

    The context is automatically isolated per-task thanks to `contextvars`.
    Remember to call ``d2.clear_user_context()`` at the end of the request or
    use the provided ASGI middleware which handles this automatically.
    """
    _user_context.set(UserContext(user_id=user_id, roles=frozenset(roles) if roles else None)) 

# ---------------------------------------------------------------------------
# Getter helpers (used by PolicyManager and for public convenience)
# ---------------------------------------------------------------------------

def get_user_id() -> Optional[str]:
    """Return the current *user_id* or ``None`` when not set."""
    return get_current_user().user_id


def get_user_roles() -> Optional[frozenset[str]]:
    """Return the current set of roles (``None`` when none assigned)."""
    return get_current_user().roles

# ---------------------------------------------------------------------------
# Public export list – keeps internal helpers private
# ---------------------------------------------------------------------------

__all__ = [
    "UserContext",
    "set_user_context",
    "run_as",
    "get_current_user",
    "clear_user_context",
    "set_user",
    "get_user_id",
    "get_user_roles",
] 