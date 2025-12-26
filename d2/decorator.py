# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

# d2/decorator.py

import atexit
import anyio
import functools
import inspect
import asyncio
import os
from typing import Callable, Optional, Union, Any
import time
import concurrent.futures as _cf
import contextvars as _ctxvars

from .exceptions import PermissionDeniedError, MissingPolicyError, D2Error, D2PlanLimitError
import logging

from .policy import get_policy_manager
from .context import get_user_context
from .telemetry import (
    authz_decision_total,
    authz_denied_reason_total,
    missing_policy_total,
    tool_invocation_total,
    tool_exec_latency_ms,
    sync_in_async_denied_total,
    sequence_pattern_blocked_total,
    call_chain_depth_histogram,
    user_violation_attempts_total,
    guardrail_latency_ms,
    tool_cooccurrence_total,
    feature_usage_total,
    data_flow_event_total,
    data_flow_blocked_total,
    get_tracer,
)
from .runtime import apply_output_filters, validate_inputs
from .telemetry.plan_limits import emit_plan_limit_warning

# Sentinel object to detect if a parameter was provided by the user
_sentinel = object()

# Shared ThreadPoolExecutor for auto-threading sync functions called from async contexts.
# This avoids creating a new executor per-call which would cause resource exhaustion
# under high concurrency. The executor is bounded to prevent runaway thread creation.
_AUTO_THREAD_EXECUTOR: Optional[_cf.ThreadPoolExecutor] = None
_EXECUTOR_LOCK = _ctxvars.threading.Lock() if hasattr(_ctxvars, 'threading') else __import__('threading').Lock()

# Default timeout for sync tools called from async context (seconds).
# Can be overridden via D2_SYNC_TIMEOUT environment variable.
# Set to None to wait indefinitely (not recommended in production).
_DEFAULT_SYNC_TIMEOUT_SECONDS = 30.0

def _get_sync_timeout() -> Optional[float]:
    """Get the configured timeout for sync tool execution from async context.
    
    Environment variable D2_SYNC_TIMEOUT can be set to:
    - A number (seconds): e.g., "60" for 60 seconds
    - "0" or "none": Wait indefinitely (not recommended)
    
    Returns:
        Timeout in seconds, or None for no timeout.
    """
    env_value = os.getenv("D2_SYNC_TIMEOUT", "").strip().lower()
    if not env_value:
        return _DEFAULT_SYNC_TIMEOUT_SECONDS
    
    if env_value in ("0", "none", "false"):
        return None  # No timeout
    
    try:
        timeout = float(env_value)
        return timeout if timeout > 0 else None
    except (ValueError, TypeError):
        # Invalid value, use default
        return _DEFAULT_SYNC_TIMEOUT_SECONDS


def _get_auto_thread_executor() -> _cf.ThreadPoolExecutor:
    """Get or create the shared auto-thread executor.
    
    Lazy initialization to avoid creating threads if auto-threading is never used.
    """
    global _AUTO_THREAD_EXECUTOR
    if _AUTO_THREAD_EXECUTOR is None:
        with _EXECUTOR_LOCK:
            if _AUTO_THREAD_EXECUTOR is None:
                # Bounded executor with descriptive thread names for debugging
                _AUTO_THREAD_EXECUTOR = _cf.ThreadPoolExecutor(
                    max_workers=4,  # Reasonable bound for blocking I/O offload
                    thread_name_prefix="d2-auto-"
                )
    return _AUTO_THREAD_EXECUTOR


def _shutdown_auto_thread_executor() -> None:
    """Shutdown the shared executor at process exit."""
    global _AUTO_THREAD_EXECUTOR
    if _AUTO_THREAD_EXECUTOR is not None:
        try:
            _AUTO_THREAD_EXECUTOR.shutdown(wait=False)
        except Exception:
            pass  # Don't let shutdown failure break process exit


# Register executor cleanup at exit
atexit.register(_shutdown_auto_thread_executor)


def d2_guard(
    tool_id: Optional[Union[str, Callable]] = None,
    *,
    instance_name: str = "default",
    on_deny: Any = _sentinel,
    strict: Optional[bool] = None,
):
    """
    The primary decorator for the D2 SDK.

    This decorator wraps a tool function and ensures that a permission check is
    performed against the configured RBAC policy before the function is executed.

    :param tool_id: Optional. A specific ID for the tool. If not provided, one is
                    generated from the function's module and name.
    :param instance_name: Optional. The named instance of the PolicyManager to use.
                          Defaults to "default".
    :param on_deny: Optional. If provided, determines the behavior on permission
                    denial. If it is a callable, it will be invoked and its
                    result returned. The `PermissionDeniedError` instance will
                    be passed as an argument if the callable accepts it. If
                    it is any other value, that value will be returned
                    directly. If not provided, the PermissionDeniedError is raised.

    **Ways to Handle Permission Denial:**

    A key feature of `@d2_guard` is its flexible `on_deny` parameter, which
    lets you control what happens when a permission check fails, avoiding
    the need for `try...except` blocks in your application logic.

    .. code-block:: python

        from d2 import d2_guard
        from d2.exceptions import PermissionDeniedError
        import logging

        # Option 1: Raise an Exception (The Default)
        # If on_deny is not set, a PermissionDeniedError is raised. This is the
        # most secure default as it forces the failure to be handled.
        @d2_guard("tools.read")
        def read_data_aggressively(): ...

        # Option 2: Return a Static Value
        # The function will return the provided value instead of raising an error.
        @d2_guard("tools.read", on_deny=None)
        def read_data_silently(): ...

        # Option 3: Use a Simple, No-Argument Handler (e.g., a lambda)
        # Ideal for concise actions like logging a static message.
        @d2_guard("tools.write", on_deny=lambda: logging.warning("Write blocked!"))
        def write_data(): ...

        # Option 4: Use a Context-Aware Handler
        # The handler receives the PermissionDeniedError object, giving you full
        # access to the tool_id, user_id, and roles for rich, contextual handling.
        def my_handler(error: PermissionDeniedError):
            logging.error(f"Failed access for {error.user_id} on {error.tool_id}")
            return {"error": "ACCESS_DENIED", "details": error.message}
        
        @d2_guard("admin.panel", on_deny=my_handler)
        def access_admin_panel(): ...
    """
    _STRICT_ENV = os.getenv("D2_STRICT_SYNC", "0") not in ("", "0", "false", "no")

    def decorator(func: Callable):
        effective_tool_id = tool_id
        if effective_tool_id is None:
            effective_tool_id = f"{func.__module__}.{func.__qualname__}"


        signature = inspect.signature(func)
        allowed_params = tuple(signature.parameters.keys())
        has_var_kwargs = any(
            param.kind == inspect.Parameter.VAR_KEYWORD
            for param in signature.parameters.values()
        )

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            """Wrapper for synchronous functions."""
            manager = get_policy_manager(instance_name)
            # Mutable container to track if tool call was recorded inside check_and_run
            # Used to re-record in outer scope for anyio.run() path (context doesn't persist)
            _call_recorded = [False]

            async def check_and_run():
                """Helper to run the async check and then the sync function."""
                # Track total authorization overhead
                authz_start = time.perf_counter()
                
                try:
                    with get_tracer("d2.sdk").start_as_current_span(
                        f"d2.check:{effective_tool_id}",
                        attributes={"d2.tool_id": effective_tool_id, "mode": manager.mode},
                    ) as span:
                        if not await manager.is_tool_in_policy_async(effective_tool_id):
                            missing_policy_total.add(1, {"d2.tool_id": effective_tool_id, "mode": manager.mode})
                            # Track denial telemetry
                            try:
                                authz_denied_reason_total.add(1, {"reason": "missing_policy", "mode": manager.mode})
                                reporter = getattr(manager, "_usage_reporter", None)
                                if reporter:
                                    reporter.track_event(
                                        "authz_decision",
                                        {
                                            "tool_id": effective_tool_id,
                                            "result": "denied",
                                            "reason": "missing_policy",
                                            "mode": manager.mode,
                                        },
                                    )
                            except Exception:
                                pass
                            raise MissingPolicyError(tool_id=effective_tool_id)

                        # Layer 1: RBAC check
                        rbac_start = time.perf_counter()
                        is_allowed = await manager.check_async(effective_tool_id)
                        rbac_duration_ms = (time.perf_counter() - rbac_start) * 1000.0
                        guardrail_latency_ms.record(rbac_duration_ms, {
                            "type": "rbac_check",
                            "tool_id": effective_tool_id,
                            "result": "allowed" if is_allowed else "denied"
                        })
                        span.set_attribute("d2.is_allowed", is_allowed)

                        user_context = get_user_context()

                        if not is_allowed:
                            user_roles = list(user_context.roles) if user_context and user_context.roles else []
                            error = PermissionDeniedError(
                                tool_id=effective_tool_id,
                                user_id=user_context.user_id if user_context else "unknown",
                                roles=user_context.roles if user_context else [],
                                reason=f"rbac_denied: role_missing (present roles: {user_roles})",
                            )
                            # Record a denied tool invocation outcome for observability
                            tool_invocation_total.add(1, {"tool_id": effective_tool_id, "status": "denied"})
                            return await _handle_permission_denied(error)

                        # Layer 2: Input Validation
                        bound = inspect.signature(func).bind(*args, **kwargs)
                        bound.apply_defaults()
                        validation_error = await validate_inputs(
                            manager,
                            effective_tool_id,
                            bound.arguments,
                            user_context,
                            allowed_params=allowed_params,
                            has_var_kwargs=has_var_kwargs,
                        )
                        if validation_error is not None:
                            # Note: All telemetry (OTEL + D2 events) sent by validate_inputs() in guard.py
                            return await _handle_permission_denied(validation_error)

                        # Layer 3: Sequence enforcement
                        sequence_mode, sequence_rules = await manager.get_sequence_rules()
                        if sequence_rules:
                            sequence_start = time.perf_counter()
                            from .runtime.sequence import SequenceValidator
                            # Get tool_groups for lazy @group expansion
                            bundle = manager._get_bundle()
                            tool_groups = bundle.get_tool_groups() if bundle else {}
                            validator = SequenceValidator(tool_groups=tool_groups)
                            sequence_error = validator.validate_sequence(
                                current_history=user_context.call_history if user_context else (),
                                next_tool_id=effective_tool_id,
                                sequence_rules=sequence_rules,
                                mode=sequence_mode
                            )
                            sequence_duration_ms = (time.perf_counter() - sequence_start) * 1000.0
                            guardrail_latency_ms.record(sequence_duration_ms, {
                                "type": "sequence_check",
                                "tool_id": effective_tool_id,
                                "result": "denied" if sequence_error else "allowed"
                            })
                            
                            if sequence_error is not None:
                                # Comprehensive telemetry for sequence violation
                                try:
                                    history = user_context.call_history if user_context else ()
                                    
                                    # Determine pattern type based on chain length
                                    chain_length = len(history) + 1
                                    if chain_length == 2:
                                        pattern_type = "direct_2hop"
                                    elif chain_length == 3:
                                        pattern_type = "transitive_3hop"
                                    elif chain_length == 4:
                                        pattern_type = "complex_4hop"
                                    else:
                                        pattern_type = f"complex_{chain_length}hop"
                                    
                                    # Get source tool (most recent in history)
                                    source_tool = history[-1] if history else "none"
                                    
                                    # Record detailed sequence pattern
                                    sequence_pattern_blocked_total.add(1, {
                                        "pattern_type": pattern_type,
                                        "source_tool": source_tool,
                                        "target_tool": effective_tool_id,
                                        "chain_length": str(chain_length),
                                        "user_role": ",".join(user_context.roles) if user_context and user_context.roles else "unknown"
                                    })
                                    
                                    # Track user violation attempts (insider threat detection)
                                    user_violation_attempts_total.add(1, {
                                        "user_id": user_context.user_id if user_context else "unknown",
                                        "violation_type": "sequence",
                                    })
                                    
                                    # Existing basic metrics
                                    authz_denied_reason_total.add(
                                        1, {"reason": "sequence_violation", "mode": manager.mode}
                                    )
                                    
                                    # Send consolidated authz_decision event to D2 cloud
                                    reporter = getattr(manager, "_usage_reporter", None)
                                    if reporter:
                                        reporter.track_event(
                                            "authz_decision",
                                            {
                                                "tool_id": effective_tool_id,
                                                "result": "denied",
                                                "reason": "sequence_violation",
                                                "mode": manager.mode,
                                                # Sequence-specific context for analysis
                                                "pattern_type": pattern_type,
                                                "source_tool": source_tool,
                                                "chain_length": chain_length,
                                                "call_history": list(history) + [effective_tool_id],
                                                "user_role": ",".join(user_context.roles) if user_context and user_context.roles else "unknown",
                                            },
                                        )
                                except Exception:
                                    pass
                                tool_invocation_total.add(1, {"tool_id": effective_tool_id, "status": "denied"})
                                return await _handle_permission_denied(sequence_error)

                        # Layer 4: Data flow fact check
                        bundle = getattr(manager, '_get_bundle', lambda: None)()
                        if bundle and hasattr(bundle, 'get_blocking_labels_for_tool'):
                            blocking_labels = bundle.get_blocking_labels_for_tool(effective_tool_id)
                            if blocking_labels:
                                from .context import get_facts
                                current_facts = get_facts()
                                violated_facts = current_facts & blocking_labels
                                if violated_facts:
                                    data_flow_start = time.perf_counter()
                                    error = PermissionDeniedError(
                                        tool_id=effective_tool_id,
                                        user_id=user_context.user_id if user_context else "unknown",
                                        roles=user_context.roles if user_context else [],
                                        reason=f"data_flow_violation: tool blocked by labels {violated_facts}"
                                    )
                                    data_flow_duration_ms = (time.perf_counter() - data_flow_start) * 1000.0
                                    guardrail_latency_ms.record(data_flow_duration_ms, {
                                        "type": "data_flow_check",
                                        "tool_id": effective_tool_id,
                                        "result": "denied"
                                    })
                                    
                                    # Telemetry for data flow violation
                                    try:
                                        authz_denied_reason_total.add(
                                            1, {"reason": "data_flow_violation", "mode": manager.mode}
                                        )
                                        data_flow_blocked_total.add(1, {
                                            "tool_id": effective_tool_id,
                                            "blocking_label": ",".join(sorted(violated_facts)),
                                        })
                                        user_violation_attempts_total.add(1, {
                                            "user_id": user_context.user_id if user_context else "unknown",
                                            "violation_type": "data_flow",
                                        })
                                        reporter = getattr(manager, "_usage_reporter", None)
                                        if reporter:
                                            reporter.track_event(
                                                "authz_decision",
                                                {
                                                    "tool_id": effective_tool_id,
                                                    "result": "denied",
                                                    "reason": "data_flow_violation",
                                                    "mode": manager.mode,
                                                    "blocking_labels": list(blocking_labels),
                                                    "violated_facts": list(violated_facts),
                                                    "all_facts": list(current_facts),
                                                },
                                            )
                                    except Exception:
                                        pass
                                    
                                    tool_invocation_total.add(1, {"tool_id": effective_tool_id, "status": "denied"})
                                    return await _handle_permission_denied(error)
                except D2PlanLimitError:
                    emit_plan_limit_warning()
                    raise

                # Track comprehensive metrics for successful authorization
                # Note: Capture history BEFORE recording current call to track data flow correctly
                try:
                    history = user_context.call_history if user_context else ()
                    
                    # 1. Track call chain depth
                    call_chain_depth_histogram.record(len(history), {
                        "user_id": user_context.user_id if user_context else "unknown",
                        "current_tool": effective_tool_id
                    })
                    
                    if history:
                        source_tool = history[-1]
                        data_flow_event_total.add(1, {
                            "source_tool": source_tool,
                            "destination_tool": effective_tool_id,
                        })
                        # Send to D2 cloud
                        reporter = getattr(manager, "_usage_reporter", None)
                        if reporter:
                            reporter.track_event(
                                "data_flow",
                                {
                                    "source_tool": source_tool,
                                    "destination_tool": effective_tool_id,
                                }
                            )
                    
                    # 2. Track tool co-occurrence (which tools are called together)
                    if len(history) >= 1:
                        tool_cooccurrence_total.add(1, {
                            "tool_a": history[-1],
                            "tool_b": effective_tool_id,
                            "within_request": "true"
                        })
                    
                    # 3. Track anomalous call chain depth
                    if len(history) >= 5:  # 5+ hop chains are unusual
                        reporter = getattr(manager, "_usage_reporter", None)
                        if reporter:
                            reporter.track_event(
                                "anomaly_detected",
                                {
                                    "anomaly_type": "unusual_call_chain_depth",
                                    "call_chain_depth": len(history),
                                    "baseline": 3,  # Normal is typically 2-3 hops
                                    "tools_in_chain": list(history) + [effective_tool_id],
                                }
                            )
                except Exception:
                    # Telemetry never interferes
                    pass

                # Record total authorization overhead (all layers combined)
                authz_duration_ms = (time.perf_counter() - authz_start) * 1000.0
                guardrail_latency_ms.record(authz_duration_ms, {
                    "type": "total_authz_overhead",
                    "tool_id": effective_tool_id,
                })
                
                # Send authorization overhead to D2 cloud for performance analytics
                try:
                    reporter = getattr(manager, "_usage_reporter", None)
                    if reporter:
                        reporter.track_event(
                            "total_authz_overhead",
                            {
                                "tool_id": effective_tool_id,
                                "overhead_ms": authz_duration_ms,
                                "mode": manager.mode,
                            }
                        )
                except Exception:
                    pass

                # Set flag so outer scope knows to record (for anyio.run path)
                # NOTE: We do NOT record here because record_tool_call writes to a
                # shared state store keyed by request_id. When using anyio.run() or
                # ThreadPoolExecutor, the outer scope also calls record_tool_call,
                # which would result in double-recording. The outer scope is the
                # authoritative place to record since it persists in the caller's context.
                _call_recorded[0] = True

                # If permission is granted, execute the tool and record metrics
                exec_start = time.perf_counter()
                try:
                    # Execute the sync tool inline in the current thread
                    result = func(*args, **kwargs)
                    try:
                        result = await apply_output_filters(
                            manager,
                            effective_tool_id,
                            result,
                            user_context=user_context,
                        )
                    except PermissionDeniedError as error:
                        # Note: All telemetry (OTEL + authz_decision) sent by apply_output_filters() in output_filter.py
                        tool_invocation_total.add(1, {"tool_id": effective_tool_id, "status": "denied"})
                        duration_ms = (time.perf_counter() - exec_start) * 1000.0
                        tool_exec_latency_ms.record(duration_ms, {"tool_id": effective_tool_id, "status": "denied"})
                        return await _handle_permission_denied(error)

                    # Tool execution succeeded - record OTEL metrics
                    duration_ms = (time.perf_counter() - exec_start) * 1000.0
                    tool_exec_latency_ms.record(duration_ms, {"tool_id": effective_tool_id, "status": "success"})
                    tool_invocation_total.add(1, {"tool_id": effective_tool_id, "status": "success"})
                    
                    # Record data flow labels emitted by this tool
                    bundle = getattr(manager, '_get_bundle', lambda: None)()
                    if bundle and hasattr(bundle, 'get_labels_for_tool'):
                        emitted_labels = bundle.get_labels_for_tool(effective_tool_id)
                        if emitted_labels:
                            from .context import record_facts
                            record_facts(emitted_labels)
                            # Telemetry for fact emission
                            try:
                                feature_usage_total.add(1, {"feature": "data_flow_labels"})
                                reporter = getattr(manager, "_usage_reporter", None)
                                if reporter:
                                    reporter.track_event(
                                        "data_flow_labels_emitted",
                                        {
                                            "tool_id": effective_tool_id,
                                            "labels": list(emitted_labels),
                                        },
                                    )
                            except Exception:
                                pass
                    
                    return result
                except D2PlanLimitError as e:
                    emit_plan_limit_warning()
                    raise
                except PermissionDeniedError as error:
                    duration_ms = (time.perf_counter() - exec_start) * 1000.0
                    tool_exec_latency_ms.record(duration_ms, {"tool_id": effective_tool_id, "status": "denied"})
                    tool_invocation_total.add(1, {"tool_id": effective_tool_id, "status": "denied"})
                    raise
                except Exception:
                    duration_ms = (time.perf_counter() - exec_start) * 1000.0
                    tool_exec_latency_ms.record(duration_ms, {"tool_id": effective_tool_id, "status": "error"})
                    tool_invocation_total.add(1, {"tool_id": effective_tool_id, "status": "error"})
                    raise

            # Detect if an event loop is already running in this thread.
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                # No loop → run inline (fast path)
                # Note: anyio.run() context changes don't persist, so we re-record
                # the tool call in the outer scope if it was authorized
                result = anyio.run(check_and_run)
                if _call_recorded[0]:
                    from .context import record_tool_call
                    record_tool_call(effective_tool_id)
                return result
            else:
                # Loop running. Decide: strict or auto-thread
                effective_strict = strict if strict is not None else _STRICT_ENV
                if effective_strict:
                    sync_in_async_denied_total.add(1)
                    # Track denial telemetry
                    try:
                        authz_denied_reason_total.add(1, {"reason": "strict_sync", "mode": manager.mode})
                        reporter = getattr(manager, "_usage_reporter", None)
                        if reporter:
                            reporter.track_event(
                                "authz_decision",
                                {
                                    "tool_id": effective_tool_id,
                                    "result": "denied",
                                    "reason": "strict_sync_in_async",
                                    "mode": manager.mode,
                                },
                            )
                    except Exception:
                        pass
                    raise D2Error(
                        f"Cannot call decorated sync function '{func.__qualname__}' from a running event loop "
                        f"(strict mode). Set strict=False or unset D2_STRICT_SYNC to auto-thread."
                    )

                # Auto-thread: off-load entire operation to a background thread
                def _run_in_thread():
                    # Run the full async path (policy check + tool execution)
                    # inside a private event loop on a worker thread.
                    return asyncio.run(check_and_run())

                # Block this (event-loop) thread until the worker finishes and
                # return the real value (or raise the real exception). This keeps
                # the wrapper's sync contract for callers.
                # Copy current contextvars so user_id/roles propagate across threads
                _ctx = _ctxvars.copy_context()
                # Use shared executor to avoid per-call executor creation overhead
                _exec = _get_auto_thread_executor()
                _future = _exec.submit(lambda: _ctx.run(_run_in_thread))
                
                # Wait with timeout to prevent indefinite blocking if executor is saturated
                # or if the worker is stuck. Timeout is configurable via D2_SYNC_TIMEOUT.
                _timeout = _get_sync_timeout()
                try:
                    result = _future.result(timeout=_timeout)
                except _cf.TimeoutError:
                    # Worker is still running but we timed out waiting
                    # This prevents deadlocks when executor is saturated
                    raise D2Error(
                        f"Sync tool '{func.__qualname__}' timed out after {_timeout}s waiting for "
                        f"executor thread. This may indicate executor saturation or a hung worker. "
                        f"Increase D2_SYNC_TIMEOUT or investigate the tool's performance."
                    )
                
                # Re-record in main thread context (worker thread changes don't persist)
                if _call_recorded[0]:
                    from .context import record_tool_call
                    record_tool_call(effective_tool_id)
                return result

        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            """Wrapper for asynchronous functions."""
            manager = get_policy_manager(instance_name)
            
            # Track total authorization overhead
            authz_start = time.perf_counter()

            try:
                with get_tracer("d2.sdk").start_as_current_span(
                    f"d2.check:{effective_tool_id}",
                    attributes={"d2.tool_id": effective_tool_id, "mode": manager.mode},
                ) as span:
                    if not await manager.is_tool_in_policy_async(effective_tool_id):
                        missing_policy_total.add(1, {"d2.tool_id": effective_tool_id, "mode": manager.mode})
                        # Track denial telemetry
                        try:
                            authz_denied_reason_total.add(1, {"reason": "missing_policy", "mode": manager.mode})
                            reporter = getattr(manager, "_usage_reporter", None)
                            if reporter:
                                reporter.track_event(
                                    "authz_decision",
                                    {
                                        "tool_id": effective_tool_id,
                                        "result": "denied",
                                        "reason": "missing_policy",
                                        "mode": manager.mode,
                                    },
                                )
                        except Exception:
                            pass
                        raise MissingPolicyError(tool_id=effective_tool_id)
                    
                    # Layer 1: RBAC check
                    rbac_start = time.perf_counter()
                    is_allowed = await manager.check_async(effective_tool_id)
                    rbac_duration_ms = (time.perf_counter() - rbac_start) * 1000.0
                    guardrail_latency_ms.record(rbac_duration_ms, {
                        "type": "rbac_check",
                        "tool_id": effective_tool_id,
                        "result": "allowed" if is_allowed else "denied"
                    })
                    span.set_attribute("d2.is_allowed", is_allowed)

                    user_context = get_user_context()

                    if not is_allowed:
                        user_roles = list(user_context.roles) if user_context and user_context.roles else []
                        error = PermissionDeniedError(
                            tool_id=effective_tool_id,
                            user_id=user_context.user_id if user_context else "unknown",
                            roles=user_context.roles if user_context else [],
                            reason=f"rbac_denied: role_missing (present roles: {user_roles})",
                        )
                        # Record a denied tool invocation outcome for observability
                        tool_invocation_total.add(1, {"tool_id": effective_tool_id, "status": "denied"})
                        return await _handle_permission_denied(error)

                    bound = inspect.signature(func).bind(*args, **kwargs)
                    bound.apply_defaults()
                    validation_error = await validate_inputs(
                        manager,
                        effective_tool_id,
                        bound.arguments,
                        user_context,
                        allowed_params=allowed_params,
                        has_var_kwargs=has_var_kwargs,
                    )
                    if validation_error is not None:
                        # Note: All telemetry (OTEL + D2 events) sent by validate_inputs() in guard.py
                        return await _handle_permission_denied(validation_error)

                    # Layer 3: Sequence enforcement
                    sequence_mode, sequence_rules = await manager.get_sequence_rules()
                    if sequence_rules:
                        sequence_start = time.perf_counter()
                        from .runtime.sequence import SequenceValidator
                        # Get tool_groups for lazy @group expansion
                        bundle = manager._get_bundle()
                        tool_groups = bundle.get_tool_groups() if bundle else {}
                        validator = SequenceValidator(tool_groups=tool_groups)
                        sequence_error = validator.validate_sequence(
                            current_history=user_context.call_history if user_context else (),
                            next_tool_id=effective_tool_id,
                            sequence_rules=sequence_rules,
                            mode=sequence_mode
                        )
                        sequence_duration_ms = (time.perf_counter() - sequence_start) * 1000.0
                        guardrail_latency_ms.record(sequence_duration_ms, {
                            "type": "sequence_check",
                            "tool_id": effective_tool_id,
                            "result": "denied" if sequence_error else "allowed"
                        })
                        
                        if sequence_error is not None:
                            # Comprehensive telemetry for sequence violation
                            try:
                                history = user_context.call_history if user_context else ()
                                
                                # Determine pattern type based on chain length
                                chain_length = len(history) + 1
                                if chain_length == 2:
                                    pattern_type = "direct_2hop"
                                elif chain_length == 3:
                                    pattern_type = "transitive_3hop"
                                elif chain_length == 4:
                                    pattern_type = "complex_4hop"
                                else:
                                    pattern_type = f"complex_{chain_length}hop"
                                
                                # Get source tool (most recent in history)
                                source_tool = history[-1] if history else "none"
                                
                                # Record detailed sequence pattern
                                sequence_pattern_blocked_total.add(1, {
                                    "pattern_type": pattern_type,
                                    "source_tool": source_tool,
                                    "target_tool": effective_tool_id,
                                    "chain_length": str(chain_length),
                                    "user_role": ",".join(user_context.roles) if user_context and user_context.roles else "unknown"
                                })
                                
                                # Track user violation attempts (insider threat detection)
                                user_violation_attempts_total.add(1, {
                                    "user_id": user_context.user_id if user_context else "unknown",
                                    "violation_type": "sequence",
                                })
                                
                                # Existing basic metrics
                                authz_denied_reason_total.add(
                                    1, {"reason": "sequence_violation", "mode": manager.mode}
                                )
                                
                                # Send consolidated authz_decision event to D2 cloud
                                reporter = getattr(manager, "_usage_reporter", None)
                                if reporter:
                                    reporter.track_event(
                                        "authz_decision",
                                        {
                                            "tool_id": effective_tool_id,
                                            "result": "denied",
                                            "reason": "sequence_violation",
                                            "mode": manager.mode,
                                            # Sequence-specific context for analysis
                                            "pattern_type": pattern_type,
                                            "source_tool": source_tool,
                                            "chain_length": chain_length,
                                            "call_history": list(history) + [effective_tool_id],
                                            "user_role": ",".join(user_context.roles) if user_context and user_context.roles else "unknown",
                                        },
                                    )
                            except Exception:
                                pass
                            tool_invocation_total.add(1, {"tool_id": effective_tool_id, "status": "denied"})
                            return await _handle_permission_denied(sequence_error)

                    # Layer 4: Data flow fact check
                    bundle = getattr(manager, '_get_bundle', lambda: None)()
                    if bundle and hasattr(bundle, 'get_blocking_labels_for_tool'):
                        blocking_labels = bundle.get_blocking_labels_for_tool(effective_tool_id)
                        if blocking_labels:
                            from .context import get_facts
                            current_facts = get_facts()
                            violated_facts = current_facts & blocking_labels
                            if violated_facts:
                                data_flow_start = time.perf_counter()
                                error = PermissionDeniedError(
                                    tool_id=effective_tool_id,
                                    user_id=user_context.user_id if user_context else "unknown",
                                    roles=user_context.roles if user_context else [],
                                    reason=f"data_flow_violation: tool blocked by labels {violated_facts}"
                                )
                                data_flow_duration_ms = (time.perf_counter() - data_flow_start) * 1000.0
                                guardrail_latency_ms.record(data_flow_duration_ms, {
                                    "type": "data_flow_check",
                                    "tool_id": effective_tool_id,
                                    "result": "denied"
                                })
                                
                                # Telemetry for data flow violation
                                try:
                                    authz_denied_reason_total.add(
                                        1, {"reason": "data_flow_violation", "mode": manager.mode}
                                    )
                                    data_flow_blocked_total.add(1, {
                                        "tool_id": effective_tool_id,
                                        "blocking_label": ",".join(sorted(violated_facts)),
                                    })
                                    user_violation_attempts_total.add(1, {
                                        "user_id": user_context.user_id if user_context else "unknown",
                                        "violation_type": "data_flow",
                                    })
                                    reporter = getattr(manager, "_usage_reporter", None)
                                    if reporter:
                                        reporter.track_event(
                                            "authz_decision",
                                            {
                                                "tool_id": effective_tool_id,
                                                "result": "denied",
                                                "reason": "data_flow_violation",
                                                "mode": manager.mode,
                                                "blocking_labels": list(blocking_labels),
                                                "violated_facts": list(violated_facts),
                                                "all_facts": list(current_facts),
                                            },
                                        )
                                except Exception:
                                    pass
                                
                                tool_invocation_total.add(1, {"tool_id": effective_tool_id, "status": "denied"})
                                return await _handle_permission_denied(error)
            except D2PlanLimitError:
                emit_plan_limit_warning(
                    message=(
                        "⛔  Plan limit reached.  Upgrade to Essentials ($49/mo) or Pro ($199/mo) at "
                        "https://console.artoo.com/upgrade — 14-day trial auto-expires."
                    )
                )
                raise

            # Track comprehensive metrics for successful authorization
            # Note: Capture history BEFORE recording current call to track data flow correctly
            try:
                history = user_context.call_history if user_context else ()
                
                # 1. Track call chain depth
                call_chain_depth_histogram.record(len(history), {
                    "user_id": user_context.user_id if user_context else "unknown",
                    "current_tool": effective_tool_id
                })
                
                # 2. Track data flow events (what was called before this)
                if history:
                    source_tool = history[-1]
                    data_flow_event_total.add(1, {
                        "source_tool": source_tool,
                        "destination_tool": effective_tool_id,
                    })
                    # Send to D2 cloud
                    reporter = getattr(manager, "_usage_reporter", None)
                    if reporter:
                        reporter.track_event(
                            "data_flow",
                            {
                                "source_tool": source_tool,
                                "destination_tool": effective_tool_id,
                            }
                        )
                
                # 3. Track tool co-occurrence (which tools are called together)
                if len(history) >= 1:
                    tool_cooccurrence_total.add(1, {
                        "tool_a": history[-1],
                        "tool_b": effective_tool_id,
                        "within_request": "true"
                    })
                
                # 4. Track anomalous call chain depth
                if len(history) >= 5:  # 5+ hop chains are unusual
                    reporter = getattr(manager, "_usage_reporter", None)
                    if reporter:
                        reporter.track_event(
                            "anomaly_detected",
                            {
                                "anomaly_type": "unusual_call_chain_depth",
                                "call_chain_depth": len(history),
                                "baseline": 3,  # Normal is typically 2-3 hops
                                "tools_in_chain": list(history) + [effective_tool_id],
                            }
                        )
            except Exception:
                # Telemetry never interferes
                pass

            # Record total authorization overhead (all layers combined)
            authz_duration_ms = (time.perf_counter() - authz_start) * 1000.0
            guardrail_latency_ms.record(authz_duration_ms, {
                "type": "total_authz_overhead",
                "tool_id": effective_tool_id,
            })
            
            # Send authorization overhead to D2 cloud for performance analytics
            try:
                reporter = getattr(manager, "_usage_reporter", None)
                if reporter:
                    reporter.track_event(
                        "total_authz_overhead",
                        {
                            "tool_id": effective_tool_id,
                            "overhead_ms": authz_duration_ms,
                            "mode": manager.mode,
                        }
                    )
            except Exception:
                pass

            # Record this call in history AFTER capturing telemetry, BEFORE execution
            from .context import record_tool_call
            record_tool_call(effective_tool_id)

            # If permission is granted, execute the async tool and record metrics
            exec_start = time.perf_counter()
            try:
                result = await func(*args, **kwargs)
                try:
                    result = await apply_output_filters(
                        manager,
                        effective_tool_id,
                        result,
                        user_context=user_context,
                    )
                except PermissionDeniedError as error:
                    # Note: All telemetry (OTEL + authz_decision) sent by apply_output_filters() in output_filter.py
                    tool_invocation_total.add(1, {"tool_id": effective_tool_id, "status": "denied"})
                    duration_ms = (time.perf_counter() - exec_start) * 1000.0
                    tool_exec_latency_ms.record(duration_ms, {"tool_id": effective_tool_id, "status": "denied"})
                    return await _handle_permission_denied(error)

                # Tool execution succeeded - record OTEL metrics
                duration_ms = (time.perf_counter() - exec_start) * 1000.0
                tool_exec_latency_ms.record(duration_ms, {"tool_id": effective_tool_id, "status": "success"})
                tool_invocation_total.add(1, {"tool_id": effective_tool_id, "status": "success"})
                
                # Record data flow labels emitted by this tool
                bundle = getattr(manager, '_get_bundle', lambda: None)()
                if bundle and hasattr(bundle, 'get_labels_for_tool'):
                    emitted_labels = bundle.get_labels_for_tool(effective_tool_id)
                    if emitted_labels:
                        from .context import record_facts
                        record_facts(emitted_labels)
                        # Telemetry for fact emission
                        try:
                            feature_usage_total.add(1, {"feature": "data_flow_labels"})
                            reporter = getattr(manager, "_usage_reporter", None)
                            if reporter:
                                reporter.track_event(
                                    "data_flow_labels_emitted",
                                    {
                                        "tool_id": effective_tool_id,
                                        "labels": list(emitted_labels),
                                    },
                                )
                        except Exception:
                            pass
                
                return result
            except D2PlanLimitError:
                emit_plan_limit_warning(
                    message=(
                        "⛔  Plan limit reached.  Upgrade to Essentials ($49/mo) or Pro ($199/mo) at "
                        "https://artoo.love/ — 14-day trial auto-expires."
                    )
                )
                raise
            except PermissionDeniedError as error:
                duration_ms = (time.perf_counter() - exec_start) * 1000.0
                tool_exec_latency_ms.record(duration_ms, {"tool_id": effective_tool_id, "status": "denied"})
                tool_invocation_total.add(1, {"tool_id": effective_tool_id, "status": "denied"})
                raise
            except Exception:
                duration_ms = (time.perf_counter() - exec_start) * 1000.0
                tool_exec_latency_ms.record(duration_ms, {"tool_id": effective_tool_id, "status": "error"})
                tool_invocation_total.add(1, {"tool_id": effective_tool_id, "status": "error"})
                raise

        # ------------------------------------------------------------------
        # Shared helper for permission-denied flow (defined once per decorated
        # function so it captures `on_deny` and `_sentinel` from outer scope).
        # ------------------------------------------------------------------

        async def _handle_permission_denied(error: PermissionDeniedError):
            """Executes the user-supplied `on_deny` handler or raises by default."""

            if on_deny is _sentinel:
                raise error  # default behaviour

            # Static value supplied (e.g. None/False)
            if not callable(on_deny):
                return on_deny

            # Callable path – support async or sync, with or without the error arg.
            try:
                if inspect.iscoroutinefunction(on_deny):
                    # First try passing the error
                    try:
                        return await on_deny(error)
                    except TypeError:
                        # Handler accepts zero args
                        return await on_deny()
                else:
                    try:
                        return on_deny(error)
                    except TypeError:
                        return on_deny()
            except Exception:
                # Re-raise any exception produced by the handler so callers see it.
                raise

        # Choose the appropriate wrapper based on whether the decorated function is sync or async
        if inspect.iscoroutinefunction(func):
            wrapper = async_wrapper
        else:
            wrapper = sync_wrapper
        
        # Attach the tool_id for introspection if needed
        wrapper.__d2_tool_id__ = effective_tool_id
        return wrapper

    # This is the logic that enables the dual syntax (@d2_guard vs @d2_guard("..."))
    if callable(tool_id):
        # The decorator was used as @d2_guard without arguments.
        # 'tool_id' is actually the function to decorate.
        func_to_decorate = tool_id
        tool_id = None
        return decorator(func_to_decorate)
    else:
        # The decorator was used as @d2_guard(...) with arguments.
        return decorator 