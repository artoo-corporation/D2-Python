# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

# d2/decorator.py

import anyio
import functools
import inspect
import asyncio
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
    sync_in_async_denied_total,
    get_tracer,
)
from .runtime import apply_output_filters, record_tool_metrics, validate_inputs
from .telemetry.plan_limits import emit_plan_limit_warning

# Sentinel object to detect if a parameter was provided by the user
_sentinel = object()


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
    import os
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

            async def check_and_run():
                """Helper to run the async check and then the sync function."""
                try:
                    with get_tracer("d2.sdk").start_as_current_span(
                        f"d2.check:{effective_tool_id}",
                        attributes={"d2.tool_id": effective_tool_id, "mode": manager.mode},
                    ) as span:
                        if not await manager.is_tool_in_policy_async(effective_tool_id):
                            missing_policy_total.add(1, {"d2.tool_id": effective_tool_id, "mode": manager.mode})
                            # Emit usage event for missing policy
                            try:
                                reporter = getattr(manager, "_usage_reporter", None)
                                if reporter:
                                    reporter.track_event(
                                        "missing_policy",
                                        {"tool_id": effective_tool_id, "mode": manager.mode},
                                    )
                            except Exception:
                                pass
                            # Denied reason (metric + event) for missing policy
                            try:
                                authz_denied_reason_total.add(1, {"reason": "missing_policy", "mode": manager.mode})
                                reporter = getattr(manager, "_usage_reporter", None)
                                if reporter:
                                    reporter.track_event(
                                        "denied_reason",
                                        {"tool_id": effective_tool_id, "reason": "missing_policy"},
                                    )
                            except Exception:
                                pass
                            raise MissingPolicyError(tool_id=effective_tool_id)

                        is_allowed = await manager.check_async(effective_tool_id)
                        span.set_attribute("d2.is_allowed", is_allowed)

                        user_context = get_user_context()

                        if not is_allowed:
                            error = PermissionDeniedError(
                                tool_id=effective_tool_id,
                                user_id=user_context.user_id if user_context else "unknown",
                                roles=user_context.roles if user_context else [],
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
                            return await _handle_permission_denied(validation_error)
                except D2PlanLimitError:
                    emit_plan_limit_warning()
                    raise

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
                        tool_invocation_total.add(1, {"tool_id": effective_tool_id, "status": "denied"})
                        try:
                            authz_denied_reason_total.add(
                                1, {"reason": "output_validation", "mode": manager.mode}
                            )
                            reporter = getattr(manager, "_usage_reporter", None)
                            if reporter:
                                reporter.track_event(
                                    "denied_reason",
                                    {"tool_id": effective_tool_id, "reason": "output_validation"},
                                )
                        except Exception:
                            pass
                        record_tool_metrics(manager, effective_tool_id, "denied", exec_start)
                        return await _handle_permission_denied(error)

                    record_tool_metrics(manager, effective_tool_id, "success", exec_start)
                    return result
                except D2PlanLimitError as e:
                    emit_plan_limit_warning()
                    raise
                except PermissionDeniedError as error:
                    record_tool_metrics(manager, effective_tool_id, "denied", exec_start)
                    raise
                except Exception:
                    record_tool_metrics(manager, effective_tool_id, "error", exec_start)
                    raise

            # Detect if an event loop is already running in this thread.
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                # No loop → run inline (fast path)
                return anyio.run(check_and_run)
            else:
                # Loop running. Decide: strict or auto-thread
                effective_strict = strict if strict is not None else _STRICT_ENV
                if effective_strict:
                    sync_in_async_denied_total.add(1)
                    # Emit usage event for sync-in-async denial
                    try:
                        reporter = getattr(manager, "_usage_reporter", None)
                        if reporter:
                            reporter.track_event(
                                "sync_in_async_denied",
                                {"tool_id": effective_tool_id, "reason": "strict_mode"},
                            )
                    except Exception:
                        pass
                    # Denied reason (metric + event) for strict sync-in-async
                    try:
                        authz_denied_reason_total.add(1, {"reason": "strict_sync", "mode": manager.mode})
                        reporter = getattr(manager, "_usage_reporter", None)
                        if reporter:
                            reporter.track_event(
                                "denied_reason",
                                {"tool_id": effective_tool_id, "reason": "strict_sync"},
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
                with _cf.ThreadPoolExecutor(max_workers=1) as _exec:
                    _future = _exec.submit(lambda: _ctx.run(_run_in_thread))
                    return _future.result()

        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            """Wrapper for asynchronous functions."""
            manager = get_policy_manager(instance_name)

            try:
                with get_tracer("d2.sdk").start_as_current_span(
                    f"d2.check:{effective_tool_id}",
                    attributes={"d2.tool_id": effective_tool_id, "mode": manager.mode},
                ) as span:
                    if not await manager.is_tool_in_policy_async(effective_tool_id):
                        missing_policy_total.add(1, {"d2.tool_id": effective_tool_id, "mode": manager.mode})
                        # Emit usage event for missing policy
                        try:
                            reporter = getattr(manager, "_usage_reporter", None)
                            if reporter:
                                reporter.track_event(
                                    "missing_policy",
                                    {"tool_id": effective_tool_id, "mode": manager.mode},
                                )
                        except Exception:
                            pass
                        # Denied reason (metric + event) for missing policy
                        try:
                            authz_denied_reason_total.add(1, {"reason": "missing_policy", "mode": manager.mode})
                            reporter = getattr(manager, "_usage_reporter", None)
                            if reporter:
                                reporter.track_event(
                                    "denied_reason",
                                    {"tool_id": effective_tool_id, "reason": "missing_policy"},
                                )
                        except Exception:
                            pass
                        raise MissingPolicyError(tool_id=effective_tool_id)
                    
                    is_allowed = await manager.check_async(effective_tool_id)
                    span.set_attribute("d2.is_allowed", is_allowed)

                    user_context = get_user_context()

                    if not is_allowed:
                        error = PermissionDeniedError(
                            tool_id=effective_tool_id,
                            user_id=user_context.user_id if user_context else "unknown",
                            roles=user_context.roles if user_context else [],
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
                        return await _handle_permission_denied(validation_error)
            except D2PlanLimitError:
                emit_plan_limit_warning(
                    message=(
                        "⛔  Plan limit reached.  Upgrade to Essentials ($49/mo) or Pro ($199/mo) at "
                        "https://console.artoo.com/upgrade — 14-day trial auto-expires."
                    )
                )
                raise

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
                    tool_invocation_total.add(1, {"tool_id": effective_tool_id, "status": "denied"})
                    try:
                        authz_denied_reason_total.add(
                            1, {"reason": "output_validation", "mode": manager.mode}
                        )
                        reporter = getattr(manager, "_usage_reporter", None)
                        if reporter:
                            reporter.track_event(
                                "denied_reason",
                                {"tool_id": effective_tool_id, "reason": "output_validation"},
                            )
                    except Exception:
                        pass
                    record_tool_metrics(manager, effective_tool_id, "denied", exec_start)
                    return await _handle_permission_denied(error)

                record_tool_metrics(manager, effective_tool_id, "success", exec_start)
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
                record_tool_metrics(manager, effective_tool_id, "denied", exec_start)
                raise
            except Exception:
                record_tool_metrics(manager, effective_tool_id, "error", exec_start)
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