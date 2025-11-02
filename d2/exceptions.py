# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""D2-Python custom exceptions"""

from typing import Optional

class D2Error(Exception):
    """Base exception for all D2 SDK errors."""
    pass

class PermissionDeniedError(D2Error):
    """Raised when a tool call is denied by policy."""

    def __init__(
        self,
        tool_id: str,
        user_id: Optional[str],
        roles: Optional[set[str]],
        *,
        reason: Optional[str] = None,
    ):
        self.tool_id = tool_id
        self.user_id = user_id
        self.roles = roles
        self.reason = reason
        base = (
            f"Permission denied for user '{user_id}' (roles: {list(roles) if roles else []}) "
            f"to access tool '{tool_id}'."
        )
        message = base if not reason else f"{base} {reason}"
        super().__init__(message)


class PolicyError(D2Error):
    """Base class for policy-related errors."""
    pass

class InvalidSignatureError(PolicyError):
    """Raised when a policy bundle's signature is invalid."""


class PolicyTooLargeError(PolicyError):
    """Raised when the fetched policy bundle exceeds the configured size limit."""
    def __init__(self, bundle_size: int, size_limit: int):
        self.bundle_size = bundle_size
        self.size_limit = size_limit
        message = (
            f"Policy bundle size ({bundle_size} bytes) exceeds limit ({size_limit} bytes). "
            "Upgrade to the D2 Cloud plan to lift this limit."
        )
        super().__init__(message)


class MissingPolicyError(D2Error):
    """Raised when a tool is invoked but is not defined in the policy bundle at all."""
    def __init__(self, tool_id: str):
        self.tool_id = tool_id
        message = f"Tool '{tool_id}' not found in the policy bundle. It may be misspelled or not defined."
        super().__init__(message)


class D2NoContextError(D2Error):
    """Raised when no user context is set and no actor override is provided."""
    def __init__(self, tool_id: str):
        self.tool_id = tool_id
        message = (
            f"No user context set for tool '{tool_id}'. "
            "Call d2.set_user() or use d2.run_as() to set identity. "
            "Context does not cross manual threads or processes - set context explicitly in those cases."
        )
        super().__init__(message)


class ConfigurationError(D2Error):
    """Raised for misconfiguration of the D2 SDK."""
    pass


class ContextLeakWarning(Warning):
    """Issued when configure_rbac is called while a user context is already set."""
    pass


class BundleExpiredError(PolicyError):
    """Raised when a local policy bundle has expired or is invalid."""
    def __init__(self, reason: str, expiry_date: Optional[str] = None):
        self.reason = reason
        self.expiry_date = expiry_date
        
        if expiry_date:
            message = (
                f"Policy bundle expiry error: {reason}. (Expiry date: {expiry_date}) "
                "Upgrade to the D2 Cloud plan for auto-rotating, long-lived policies."
            )
        else:
            message = f"Policy bundle expiry error: {reason}."
        super().__init__(message)

class TooManyToolsError(PolicyError):
    """Raised when a local policy defines more tools than the allowed limit."""
    def __init__(self, tool_count: int, limit: int):
        self.tool_count = tool_count
        self.limit = limit
        message = (
            f"Policy defines {tool_count} tools, exceeding the limit of {limit}. "
            "Upgrade to the D2 Cloud plan to support larger policies."
        )
        super().__init__(message) 

class D2PlanLimitError(D2Error):
    """Raised when the account exceeds the subscribed plan limits (HTTP 402)."""

    def __init__(self, reason: Optional[str] = None):
        self.reason = reason or "plan_limit"
        super().__init__(
            f"Plan limit reached ({self.reason}). Upgrade to Essentials ($49/mo) or Pro ($199/mo) at https://console.artoo.com/upgrade — 14-day trial auto-expires."
        )

# ---------------------------------------------------------------------------
# Optional mapping → HTTP status → Exception helper (used by HTTP wrappers)
# ---------------------------------------------------------------------------

STATUS_MAP: dict[int, type[D2Error]] = {
    402: D2PlanLimitError,
} 