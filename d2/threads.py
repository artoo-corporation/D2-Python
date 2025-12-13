# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""
D2-blessed cross-thread patterns for safe context propagation.

This module provides the canonical way to handle user context across manual
thread boundaries while maintaining security guarantees and observability.

Bounded Pool Behavior:
- Auto-threading (asyncio.to_thread) uses a dedicated, bounded executor
- For user-owned pools, behavior on saturation:
  * Write operations: Raise immediately (fail-fast)  
  * Read operations: Optionally block (configurable timeout)
- Always prefer explicit actor= for sensitive operations
- Context is always cleared on thread exit (leak prevention)
"""

import contextvars
import functools
import logging
import os
import socket
import threading
from typing import Optional, Callable, Any, Union
from concurrent.futures import Future

from .context import UserContext, get_current_user, set_user, clear_user_context
from .exceptions import D2NoContextError
from .telemetry import meter
from .policy import get_policy_manager

logger = logging.getLogger(__name__)

# Threading-specific telemetry with comprehensive tags
_meter = meter
_context_submissions_total = _meter.create_counter(
    "d2.context.submissions.total",
    description="Total thread submissions with context (by method)",
    unit="1"
)
_context_missing_actor_total = _meter.create_counter(
    "d2.context.missing_actor.total", 
    description="Thread submissions with no ambient or explicit actor",
    unit="1"
)
_context_leak_detected_total = _meter.create_counter(
    "d2.context.leak.detected.total",
    description="Context leaks detected at thread exit",
    unit="1"
)
_context_actor_override_total = _meter.create_counter(
    "d2.context.actor_override.total",
    description="Cases where explicit actor overrides different ambient context",
    unit="1"
)
_thread_entrypoint_total = _meter.create_counter(
    "d2.thread.entrypoint.total",
    description="Thread entrypoint invocations (by require_actor setting)",
    unit="1"
)

def _get_metric_tags(tool_id: Optional[str] = None) -> dict:
    """Get standard metric tags for threading operations."""
    # Get service name from policy bundle metadata, not environment
    service_name = "unknown"
    try:
        # Import at runtime to avoid circular imports during testing
        from .policy import get_policy_manager
        manager = get_policy_manager()
        if manager and hasattr(manager, '_get_bundle'):
            bundle = manager._get_bundle()
            if bundle and hasattr(bundle, 'raw_bundle'):
                service_name = bundle.raw_bundle.get("metadata", {}).get("name", "unknown")
    except Exception:
        # Fallback to unknown if policy manager not available or bundle not loaded
        # This is normal during testing or before policy initialization
        pass
    
    return {
        "service": service_name,
        "host": socket.gethostname(),
        "thread_name": threading.current_thread().name,
        "tool_id": tool_id or "unknown"
    }


def submit_with_context(
    executor, 
    fn: Callable, 
    *args, 
    actor: Optional[UserContext] = None, 
    **kw
) -> Future:
    """
    Submit work to executor with D2 context preserved or explicitly set.
    
    This is the canonical way to cross thread boundaries while maintaining
    identity guarantees. Always clears context on thread exit.
    
    Args:
        executor: ThreadPoolExecutor or similar executor
        fn: Function to execute with preserved/explicit context
        *args, **kw: Arguments to pass to fn
        actor: Optional explicit UserContext. If provided, overrides ambient context.
               Must be UserContext instance, not bare dict.
        
    Returns:
        Future object from executor.submit()
        
    Raises:
        D2NoContextError: If no ambient context and no explicit actor provided
        TypeError: If actor is not None and not a UserContext instance
        
    Example:
        # Use ambient context
        d2.set_user("alice", ["admin"])
        future = d2.threads.submit_with_context(executor, some_tool)
        
        # Use explicit actor (preferred for sensitive operations)
        actor = UserContext(user_id="bob", roles=frozenset(["viewer"]))
        future = d2.threads.submit_with_context(executor, some_tool, actor=actor)
    """
    # Type safety: reject bare dicts
    if actor is not None and not isinstance(actor, UserContext):
        raise TypeError(f"actor must be UserContext instance, got {type(actor)}")
    
    # Get current ambient context for comparison
    current_ambient = get_current_user()
    
    # Determine context source and detect disagreements
    if actor is not None:
        # Explicit actor provided
        target_context = actor
        context_source = "explicit"
        
        # Detect actor override (security event)
        if (current_ambient.user_id is not None and 
            current_ambient.user_id != actor.user_id):
            logger.warning(
                "Actor override: explicit actor %s differs from ambient %s (confused deputy?)",
                actor.user_id, current_ambient.user_id
            )
            tags = _get_metric_tags()
            tags.update({
                "ambient_user": current_ambient.user_id,
                "explicit_user": actor.user_id
            })
            _context_actor_override_total.add(1, tags)
        
        _context_submissions_total.add(1, dict(_get_metric_tags(), method="explicit_actor"))
    else:
        # Try ambient context
        if current_ambient.user_id is None:
            # No ambient context available - fail closed
            tags = _get_metric_tags()
            _context_missing_actor_total.add(1, tags)
            raise D2NoContextError("submit_with_context")
        
        target_context = current_ambient
        context_source = "ambient"
        _context_submissions_total.add(1, dict(_get_metric_tags(), method="ambient_snapshot"))
    
    # Snapshot target context at submit time WITHOUT mutating the caller's context.
    # We run the context setup in an isolated execution to avoid any possibility
    # of other coroutines observing a brief context change.
    def _create_context_with_target():
        """Create a context snapshot with the target user set.
        
        This runs in copy_context().run() so it doesn't affect the caller's context.
        """
        set_user(target_context.user_id, target_context.roles)
        return contextvars.copy_context()
    
    # Run in isolated context - the set_user() call only affects the copied context
    ctx = contextvars.copy_context().run(_create_context_with_target)
    
    logger.debug(
        "Submitting thread work with %s context: user_id=%s, roles=%s",
        context_source, target_context.user_id, target_context.roles
    )
    
    def _wrapped_fn(*args, **kw):
        """
        Wrapper that runs fn with snapshotted context and always clears on exit.
        
        The snapshotted context contains the target user identity (explicit actor
        or ambient context) that was determined and captured at submit time.
        """
        try:
            # Run function with the snapshotted target context
            # ctx.run() ensures all contextvars are properly set for the execution
            return ctx.run(fn, *args, **kw)
        finally:
            # Always clear context on thread exit - explicit finally block
            try:
                # Check for context leaks before clearing
                current = get_current_user()
                if current.user_id is not None:
                    logger.debug("Clearing context at thread exit: user_id=%s", current.user_id)
                clear_user_context()
            except Exception as e:
                # Don't let cleanup failures mask the original result/exception
                logger.warning("Failed to clear context at thread exit: %s", e)
                tags = _get_metric_tags()
                _context_leak_detected_total.add(1, tags)
                # Emit usage event for context leak detection
                try:
                    manager = get_policy_manager()
                    reporter = getattr(manager, "_usage_reporter", None)
                    if reporter:
                        reporter.track_event(
                            "context_leak_detected",
                            _get_metric_tags(),
                        )
                except Exception:
                    pass
    
    return executor.submit(_wrapped_fn, *args, **kw)


def thread_entrypoint(require_actor: bool = False):
    """
    Decorator for thread entry points that ensures proper context hygiene.
    
    This decorator handles context setup and cleanup for long-lived worker
    threads where the caller may not control the submission mechanism.
    
    Args:
        require_actor: If True, requires explicit 'actor' kwarg. If False,
                      allows ambient context fallback.
                      
    Raises:
        D2NoContextError: If require_actor=True and no actor kwarg provided,
                         or if require_actor=False and no ambient/actor context available
        TypeError: If actor is provided but not a UserContext instance
                         
    Example:
        @d2.threads.thread_entrypoint(require_actor=True)
        def rebuild_index(index_id: str, *, actor: UserContext):
            # Context is automatically set from actor parameter
            # All @d2_guard decorators will see this context
            sensitive_operation(index_id)
            
        @d2.threads.thread_entrypoint(require_actor=False)  
        def background_task():
            # Uses ambient context if available, fails if none
            routine_operation()
    """
    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args, **kw):
            tags = _get_metric_tags()
            tags["require_actor"] = str(require_actor)
            _thread_entrypoint_total.add(1, tags)
            
            # Extract and validate actor parameter
            explicit_actor = kw.pop('actor', None) if 'actor' in kw else None
            if explicit_actor is not None and not isinstance(explicit_actor, UserContext):
                raise TypeError(f"actor must be UserContext instance, got {type(explicit_actor)}")
            
            # Snapshot ambient context at entry time
            current_ambient = get_current_user()
            
            # Determine context source
            if require_actor:
                if explicit_actor is None:
                    raise D2NoContextError(f"{fn.__name__} (require_actor=True)")
                target_context = explicit_actor
                context_source = "required_explicit"
            else:
                if explicit_actor is not None:
                    # Check for disagreement with ambient context
                    if (current_ambient.user_id is not None and 
                        current_ambient.user_id != explicit_actor.user_id):
                        logger.warning(
                            "Thread entrypoint %s: explicit actor %s differs from ambient %s",
                            fn.__name__, explicit_actor.user_id, current_ambient.user_id
                        )
                        override_tags = _get_metric_tags()
                        override_tags.update({
                            "ambient_user": current_ambient.user_id,
                            "explicit_user": explicit_actor.user_id
                        })
                        _context_actor_override_total.add(1, override_tags)
                    
                    target_context = explicit_actor  
                    context_source = "optional_explicit"
                else:
                    # Fall back to ambient context
                    if current_ambient.user_id is None:
                        raise D2NoContextError(f"{fn.__name__} (no ambient context)")
                    target_context = current_ambient
                    context_source = "ambient_fallback"
            
            logger.debug(
                "Thread entrypoint %s using %s context: user_id=%s, roles=%s",
                fn.__name__, context_source, target_context.user_id, target_context.roles
            )
            
            try:
                # Set context for this thread
                set_user(target_context.user_id, target_context.roles)
                # Don't pass actor to the wrapped function - it's consumed by the decorator
                return fn(*args, **kw)
            finally:
                # EXPLICIT FINALLY: Always clear context on exit and detect leaks
                # This guarantees cleanup even if the wrapped function raises an exception
                try:
                    current = get_current_user()
                    if current.user_id is not None:
                        logger.debug(
                            "Clearing context at thread entrypoint exit: user_id=%s", 
                            current.user_id
                        )
                    clear_user_context()
                except Exception as cleanup_error:
                    # Don't let cleanup failures mask the original result/exception
                    logger.warning(
                        "Failed to clear context at thread entrypoint exit: %s", 
                        cleanup_error
                    )
                    leak_tags = _get_metric_tags()
                    _context_leak_detected_total.add(1, leak_tags)
                    # Emit usage event for context leak detection
                    try:
                        manager = get_policy_manager()
                        reporter = getattr(manager, "_usage_reporter", None)
                        if reporter:
                            reporter.track_event(
                                "context_leak_detected",
                                leak_tags,
                            )
                    except Exception:
                        pass
                    
        return wrapper
    return decorator


# Public API
__all__ = [
    "submit_with_context",
    "thread_entrypoint",
]

