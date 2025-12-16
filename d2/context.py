# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

import contextvars
import threading
import uuid
from dataclasses import dataclass, field
from typing import Optional, Set, Iterable, ContextManager, Dict, List
from contextlib import contextmanager


@dataclass(frozen=True)
class UserContext:
    """Immutable dataclass to hold user identity and request state.
    
    This dataclass holds:
    - User identity (user_id, roles)
    - Request correlation (request_id)
    - Sequence tracking (call_history) - NOTE: For the most up-to-date
      call_history across concurrent async tasks, use get_user_context()
      which retrieves from shared storage.
    - Data flow tracking (facts)
    """
    user_id: Optional[str] = None
    roles: Optional[frozenset[str]] = None
    call_history: tuple[str, ...] = ()  # Sequence of tool_ids called in this request
    request_id: Optional[str] = None  # Unique ID to correlate all events within a request
    facts: frozenset[str] = frozenset()  # Data flow labels accumulated during request


@dataclass
class _RequestState:
    """Mutable, thread-safe state shared across all tasks in a request.
    
    This solves the issue where asyncio.gather() creates tasks with isolated
    contextvars snapshots. By storing mutable state keyed by request_id,
    all tasks in the same request share the same call_history and facts.
    """
    call_history: List[str] = field(default_factory=list)
    facts: Set[str] = field(default_factory=set)


# Context variable to hold the UserContext for the current async task or thread.
_user_context = contextvars.ContextVar("d2_user_context", default=UserContext())

# Request-scoped shared state for call history and facts.
# This allows multiple async tasks within the same request to share state.
# Key: request_id, Value: _RequestState
_request_state_store: Dict[str, _RequestState] = {}

# Lock to protect access to the shared state store.
# This ensures thread-safety for concurrent access from different threads/tasks.
_state_store_lock = threading.Lock()

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
    
    Concurrent Task Support:
        Call history and facts are shared across concurrent async tasks within
        the same request context. This allows sequence enforcement to work
        correctly even when tools are called via asyncio.gather().
    
    Context Flow Boundaries:
        This context flows within a single async task lineage and via to_thread.
        It does NOT cross:
        - Manual threads (threading.Thread, ThreadPoolExecutor.submit)
        - New processes (subprocess, multiprocessing)
        - Other services (HTTP requests, message queues)
        
        For these cases, set context explicitly in those contexts or use sealed tokens to propagate identity.
    
    Request ID:
        A unique request_id is automatically generated to correlate all events
        within this context. This cannot be overridden by users for security reasons.
    """
    request_id = str(uuid.uuid4())
    
    # Initialize shared state for this request
    with _state_store_lock:
        _request_state_store[request_id] = _RequestState()
    
    token = _user_context.set(UserContext(
        user_id=user_id, 
        roles=frozenset(roles) if roles else None,
        request_id=request_id,  # Use the same request_id for shared state lookup
        facts=frozenset(),  # Initial facts (will be synced from shared state)
    ))
    try:
        yield
    finally:
        # Clean up shared state for this request
        with _state_store_lock:
            _request_state_store.pop(request_id, None)
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
    Retrieves the current user context with shared state merged in.
    
    If no context has been explicitly set for the current task, this will
    return a default UserContext instance (with id=None, roles=None).
    
    The returned context includes call_history and facts from the shared
    state store, which is updated by all concurrent tasks within the same
    request. This ensures sequence enforcement and data flow tracking work
    correctly even when tools are called via asyncio.gather().
    """
    ctx = _user_context.get()
    request_id = ctx.request_id
    
    if request_id:
        with _state_store_lock:
            state = _request_state_store.get(request_id)
            if state:
                # Return a new context with shared state merged in
                return UserContext(
                    user_id=ctx.user_id,
                    roles=ctx.roles,
                    call_history=tuple(state.call_history),
                    request_id=ctx.request_id,
                    facts=frozenset(state.facts),
                )
    
    return ctx

# Maintain backwards compatibility for any code that may have used the old name.
get_user_context = get_current_user

def clear_user_context():
    """Explicitly clears the user context and shared state."""
    # Clean up shared state for the current request
    ctx = _user_context.get()
    if ctx.request_id:
        with _state_store_lock:
            _request_state_store.pop(ctx.request_id, None)
    _user_context.set(UserContext())

# ---------------------------------------------------------------------------
# Stale context detection helpers
# ---------------------------------------------------------------------------

from typing import TYPE_CHECKING as _T
import logging as _logging

from .telemetry import context_stale_total as _context_stale_total
from .telemetry import facts_recorded_total as _facts_recorded_total


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
    
    Concurrent Task Support:
        Call history and facts are shared across concurrent async tasks within
        the same request context via the shared state store.
    
    A unique request_id is automatically generated to correlate all events
    within this request. This cannot be overridden by users for security reasons.
    
    Args:
        user_id: User identifier
        roles: User roles
    """
    # Clean up any existing shared state for the current request
    old_ctx = _user_context.get()
    if old_ctx.request_id:
        with _state_store_lock:
            _request_state_store.pop(old_ctx.request_id, None)
    
    # Create new request ID and shared state
    request_id = str(uuid.uuid4())
    with _state_store_lock:
        _request_state_store[request_id] = _RequestState()
    
    _user_context.set(UserContext(
        user_id=user_id, 
        roles=frozenset(roles) if roles else None,
        request_id=request_id,  # Use the same request_id for shared state lookup
        facts=frozenset(),  # Initial facts (will be synced from shared state)
    )) 

# ---------------------------------------------------------------------------
# Getter helpers (used by PolicyManager and for public convenience)
# ---------------------------------------------------------------------------

def get_user_id() -> Optional[str]:
    """Return the current *user_id* or ``None`` when not set."""
    return get_current_user().user_id


def get_user_roles() -> Optional[frozenset[str]]:
    """Return the current set of roles (``None`` when none assigned)."""
    return get_current_user().roles


def record_tool_call(tool_id: str) -> None:
    """Append a tool_id to the current request's call history.
    
    Used by the @d2_guard decorator to track the sequence of tool calls
    within a single request for sequence enforcement.
    
    Thread-safe: Uses shared state store with locking to ensure call history
    is shared correctly across concurrent async tasks within the same request.
    
    Args:
        tool_id: The ID of the tool being called
        
    Example:
        >>> set_user("alice", ["admin"])
        >>> record_tool_call("database.read")
        >>> record_tool_call("analytics.process")
        >>> ctx = get_user_context()
        >>> ctx.call_history
        ('database.read', 'analytics.process')
    """
    ctx = _user_context.get()
    request_id = ctx.request_id
    
    if request_id:
        # Use shared state store for concurrent task support
        with _state_store_lock:
            state = _request_state_store.get(request_id)
            if state:
                state.call_history.append(tool_id)
    else:
        # Fallback to per-context storage if no request_id.
        # This is an edge case that shouldn't happen in normal usage (set_user always
        # creates a request_id). ContextVar.set() is task-local so no lock needed here.
        _logging.getLogger("d2.context").debug(
            "record_tool_call called without request_id - sequence tracking may be incomplete"
        )
        new_history = ctx.call_history + (tool_id,)
        _user_context.set(UserContext(
            user_id=ctx.user_id,
            roles=ctx.roles,
            call_history=new_history,
            request_id=ctx.request_id,
            facts=ctx.facts,
        ))


# ---------------------------------------------------------------------------
# Data flow facts helpers
# ---------------------------------------------------------------------------

def record_fact(fact: str) -> None:
    """Add a data flow label (fact) to the current request.
    
    Facts are semantic labels that track what kind of data has entered
    the request. They persist across tool calls and can be used to block
    tools that shouldn't handle certain data types.
    
    Used by the @d2_guard decorator to record facts based on policy rules.
    
    Thread-safe: Uses shared state store with locking to ensure facts
    are shared correctly across concurrent async tasks within the same request.
    
    Args:
        fact: The fact label to record (e.g., "SENSITIVE", "UNTRUSTED")
        
    Example:
        >>> set_user("agent", ["researcher"])
        >>> record_fact("SENSITIVE")
        >>> record_fact("PII")
        >>> ctx = get_user_context()
        >>> ctx.facts
        frozenset({'SENSITIVE', 'PII'})
    """
    ctx = _user_context.get()
    request_id = ctx.request_id
    
    if request_id:
        # Use shared state store for concurrent task support
        with _state_store_lock:
            state = _request_state_store.get(request_id)
            if state:
                state.facts.add(fact)
    else:
        # Fallback to per-context storage if no request_id.
        # This is an edge case that shouldn't happen in normal usage.
        # ContextVar.set() is task-local so no lock needed here.
        new_facts = ctx.facts | {fact}
        _user_context.set(UserContext(
            user_id=ctx.user_id,
            roles=ctx.roles,
            call_history=ctx.call_history,
            request_id=ctx.request_id,
            facts=new_facts,
        ))
    
    # Emit telemetry for fact recording
    try:
        _facts_recorded_total.add(1, {"fact": fact})
    except Exception:
        pass  # Telemetry never interferes with core functionality


def record_facts(facts: Iterable[str]) -> None:
    """Add multiple data flow labels (facts) to the current request.
    
    Convenience function to add multiple facts at once.
    
    Thread-safe: Uses shared state store with locking to ensure facts
    are shared correctly across concurrent async tasks within the same request.
    
    Args:
        facts: Iterable of fact labels to record
        
    Example:
        >>> set_user("agent", ["researcher"])
        >>> record_facts(["SENSITIVE", "PII", "GDPR"])
        >>> get_facts()
        frozenset({'SENSITIVE', 'PII', 'GDPR'})
    """
    ctx = _user_context.get()
    request_id = ctx.request_id
    facts_set = frozenset(facts)
    
    if request_id:
        # Use shared state store for concurrent task support
        with _state_store_lock:
            state = _request_state_store.get(request_id)
            if state:
                state.facts.update(facts_set)
    else:
        # Fallback to per-context storage if no request_id.
        # This is an edge case that shouldn't happen in normal usage.
        # ContextVar.set() is task-local so no lock needed here.
        new_facts = ctx.facts | facts_set
        _user_context.set(UserContext(
            user_id=ctx.user_id,
            roles=ctx.roles,
            call_history=ctx.call_history,
            request_id=ctx.request_id,
            facts=new_facts,
        ))
    
    # Emit telemetry for each fact recorded
    try:
        for fact in facts_set:
            _facts_recorded_total.add(1, {"fact": fact})
    except Exception:
        pass  # Telemetry never interferes with core functionality


def get_facts() -> frozenset[str]:
    """Return the current accumulated facts for this request.
    
    Returns:
        Frozenset of fact labels accumulated during the request
        
    Example:
        >>> set_user("agent", ["researcher"])
        >>> record_fact("SENSITIVE")
        >>> get_facts()
        frozenset({'SENSITIVE'})
    """
    return get_user_context().facts


def has_fact(fact: str) -> bool:
    """Check if a specific fact has been recorded in this request.
    
    Args:
        fact: The fact label to check for
        
    Returns:
        True if the fact exists, False otherwise
        
    Example:
        >>> set_user("agent", ["researcher"])
        >>> record_fact("SENSITIVE")
        >>> has_fact("SENSITIVE")
        True
        >>> has_fact("SECRET")
        False
    """
    return fact in get_user_context().facts


def has_any_fact(facts: Iterable[str]) -> bool:
    """Check if any of the specified facts exist in this request.
    
    Args:
        facts: Iterable of fact labels to check for
        
    Returns:
        True if any of the facts exist, False otherwise
        
    Example:
        >>> set_user("agent", ["researcher"])
        >>> record_fact("PII")
        >>> has_any_fact(["SENSITIVE", "PII", "SECRET"])
        True
        >>> has_any_fact(["SENSITIVE", "SECRET"])
        False
    """
    return bool(get_user_context().facts & set(facts))


# ---------------------------------------------------------------------------
# Public export list – keeps internal helpers private
# ---------------------------------------------------------------------------

__all__ = [
    "UserContext",
    "set_user_context",
    "run_as",
    "get_current_user",
    "get_user_context",  # Backwards compatibility alias
    "clear_user_context",
    "set_user",
    "get_user_id",
    "get_user_roles",
    # Data flow facts
    "record_fact",
    "record_facts",
    "get_facts",
    "has_fact",
    "has_any_fact",
    # Sequence tracking
    "record_tool_call",
] 