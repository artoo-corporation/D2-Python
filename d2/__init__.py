# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""
Artoo SDK: A client-side library for enforcing RBAC on LLM tools.

Public API is stable as of 1.2.1. Backward-incompatible changes will only occur
in a new major version. Deprecated symbols (if any) will be retained for at least
one minor version and warned via release notes before removal.
"""

__version__ = "1.2.1"

# Export the simple setter alongside the context-manager variant
from .context import (
    set_user_context,  # context-manager form
    set_user,          # simple one-liner setter
    get_user_context,
    clear_user_context,
    UserContext,
    warn_if_context_set,
    # Data flow facts
    record_fact,
    record_facts,
    get_facts,
    has_fact,
    has_any_fact,
)
from .decorator import d2_guard as d2_guard
# Alias for backwards-compat & docs examples that use `@d2`
d2 = d2_guard
from .middleware import ASGIMiddleware, clear_context, clear_context_async
from .middleware import headers_extractor
from . import threads  # D2-blessed cross-thread patterns
from .exceptions import (
    D2Error,
    PermissionDeniedError,
    PolicyError,
    InvalidSignatureError,
    PolicyTooLargeError,
    MissingPolicyError,
    ConfigurationError,
    ContextLeakWarning,
    BundleExpiredError,
    TooManyToolsError,
    D2PlanLimitError,
    D2NoContextError,
)
from .policy import (
    configure_rbac,
    configure_rbac_sync,
    get_policy_manager,
    shutdown_all_rbac,
    shutdown_rbac,
)
# Alias for clarity: async variant
configure_rbac_async = configure_rbac
__all__ = [
    # Main decorator
    "d2_guard",
    "d2", # alias for decorator

    # Configuration
    "configure_rbac_async",
    "configure_rbac_sync",
    "get_policy_manager",
    "shutdown_rbac",
    "shutdown_all_rbac",

    # Context Management
    "set_user_context",
    "get_user_context",
    "clear_user_context",
    "warn_if_context_set",
    "set_user",  # new convenience setter
    "UserContext",
    "ASGIMiddleware",
    "clear_context",
    "clear_context_async",
    "headers_extractor",

    # Data Flow Facts
    "record_fact",
    "record_facts",
    "get_facts",
    "has_fact",
    "has_any_fact",

    # Exceptions
    "D2Error",
    "PermissionDeniedError",
    "PolicyError",
    "InvalidSignatureError",
    "PolicyTooLargeError",
    "MissingPolicyError",
    "ConfigurationError",
    "ContextLeakWarning",
    "BundleExpiredError",
    "TooManyToolsError",
    "D2PlanLimitError",
    "D2NoContextError",
] 