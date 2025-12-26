# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

# d2/policy/manager.py

import asyncio
import base64
import hashlib
import json
import logging
import os
import threading
import warnings
import time
from typing import Dict, Any, Optional, List, Mapping
from datetime import datetime, timezone, timedelta

import anyio
import functools
import jwt
from cryptography.hazmat.primitives import serialization
from opentelemetry.trace import Status, StatusCode

from ..context import get_user_context, get_user_roles
from ..exceptions import (
    ConfigurationError,
    InvalidSignatureError,
    ContextLeakWarning,
    D2NoContextError,
)
from ..telemetry import (
    get_tracer,
    authz_decision_total,
    authz_decision_latency_ms,
    authz_denied_reason_total,
    missing_policy_total,
    policy_bundle_age_seconds,
    context_leak_total,
    policy_load_latency_ms,
    jwks_fetch_latency_ms,
)
from .loaders import PolicyLoader, CloudPolicyLoader, FilePolicyLoader
from ..jwks_cache import JWKSCache
from ..telemetry import UsageReporter
from ..utils import get_telemetry_mode, TelemetryMode, DEFAULT_API_URL
from .bundle import PolicyBundle

tracer = get_tracer(__name__)
logger = logging.getLogger(__name__)


class PolicyManager:
    """
    Manages loading, verifying, and checking RBAC policies.
    This class is the central point of contact for the @d2 decorator.
    """

    def __init__(
        self,
        instance_name: str,
        api_url: str,
        pin_jwks_thumbprints: Optional[List[str]],
        jwks_url: Optional[str] = None,
    ):
        self._lock = threading.Lock()
        self.instance_name = instance_name
        self._policy_bundle: Optional[PolicyBundle] = None
        self._jwks_cache: Optional[JWKSCache] = None
        self._jwks_thumbprints = set(pin_jwks_thumbprints) if pin_jwks_thumbprints else None
        self._init_complete = asyncio.Event()
        self._usage_reporter: Optional[UsageReporter] = None
        # Store reference to the main event loop for cross-thread scheduling
        # (e.g., file watcher callbacks run in a separate thread)
        self._main_loop: Optional[asyncio.AbstractEventLoop] = None

        token = os.getenv("D2_TOKEN")
        jwks_url = jwks_url or os.getenv("D2_JWKS_URL")

        # ------------------------------------------------------------------
        # Telemetry (UsageReporter) – active in cloud mode when the unified
        # telemetry flag allows *usage* events.
        # ------------------------------------------------------------------

        if token:
            self._policy_loader: PolicyLoader = CloudPolicyLoader(
                policy_manager=self,
                api_url=api_url,
                api_token=token,
                jwks_thumbprint=pin_jwks_thumbprints
            )
            if get_telemetry_mode() in (TelemetryMode.USAGE, TelemetryMode.ALL):
                self._usage_reporter = UsageReporter(api_token=token, api_url=api_url, policy_manager=self)
            else:
                logger.info(
                    "Telemetry mode '%s' – raw usage events disabled.",
                    get_telemetry_mode().value,
                )

            effective_jwks_url = jwks_url or f"{api_url}/.well-known/jwks.json"
            self._jwks_cache = JWKSCache(effective_jwks_url, api_token=token)
        else:
            self._print_startup_banner()
            self._policy_loader: PolicyLoader = FilePolicyLoader()
            self._jwks_cache = None
        self._init_task: Optional[asyncio.Task] = None

    async def initialize(self):
        """Loads the initial policy and starts background updates."""
        self._init_task = asyncio.create_task(self._initialize_internal())

    async def _initialize_internal(self):
        # Capture the main event loop for cross-thread scheduling
        # (file watcher callbacks run in a separate thread)
        self._main_loop = asyncio.get_running_loop()
        
        if self.mode == "cloud":
            # Pre-fetch the JWKS keys to validate thumbprints early
            await self._validate_jwks_thumbprints()
        
        if self._usage_reporter:
            self._usage_reporter.start()
            
        await self._load_and_verify_policy()
        self._policy_loader.start(policy_update_callback=self._schedule_policy_update)
        self._init_complete.set()

    async def shutdown(self):
        """Gracefully shuts down the policy manager and its background tasks."""
        logger.debug("Shutting down policy manager...")
        if self._init_task and not self._init_task.done():
            self._init_task.cancel()
        if self._usage_reporter:
            await self._usage_reporter.shutdown()
        await self._policy_loader.shutdown()
        logger.info("Policy manager shut down successfully.")

    def trigger_reload(self):
        """Public method to trigger a policy reload, suitable for callbacks."""
        self._schedule_policy_update()

    def _schedule_policy_update(self):
        """Callback to trigger a policy reload in the background.
        
        This method is called from various contexts:
        1. From the polling listener (same event loop) - uses create_task
        2. From file watcher callback (different thread) - uses run_coroutine_threadsafe
        3. From sync applications (no event loop) - logs warning
        
        Note: In sync-only applications (Flask, Django without async), policy
        hot-reload via file watcher will be skipped since there's no event loop.
        Restart the application to pick up policy changes in sync mode.
        """
        # First, try to schedule in the current thread's event loop
        try:
            loop = asyncio.get_running_loop()
            # Same thread as event loop - use create_task
            asyncio.create_task(self._load_and_verify_policy())
            return
        except RuntimeError:
            pass  # No loop in this thread, try cross-thread scheduling
        
        # Try cross-thread scheduling using the main loop captured during init
        if self._main_loop is not None and self._main_loop.is_running():
            try:
                # Schedule from a different thread (e.g., file watcher callback)
                future = asyncio.run_coroutine_threadsafe(
                    self._load_and_verify_policy(),
                    self._main_loop
                )
                # Don't wait for result - this is fire-and-forget
                logger.debug("Scheduled policy reload via cross-thread scheduling.")
                return
            except RuntimeError as e:
                logger.debug("Cross-thread scheduling failed: %s", e)
        
        # No event loop available anywhere - sync-only application
        logger.warning(
            "Policy update skipped - no event loop available. "
            "In sync applications, restart to pick up policy changes. "
            "Consider using an async framework or configure_rbac_async() for hot-reload support."
        )


    async def _load_and_verify_policy(self):
        """Fetches, verifies (if cloud), and activates a new policy bundle."""
        start_ts = time.perf_counter()
        with tracer.start_as_current_span(f"policy.{self.mode}.load") as span:
            try:
                raw_bundle = await self._policy_loader.load_policy()
                span.set_attribute("mode", self.mode)

                if self.mode == "cloud":
                    await self._verify_signature(raw_bundle)

                with self._lock:
                    self._policy_bundle = PolicyBundle(
                        raw_bundle=raw_bundle,
                        mode=self.mode,
                        signature=raw_bundle.get("signature"),
                        etag=raw_bundle.get("etag")  # For analytics tracking
                    )
                logger.info("Successfully loaded and verified policy bundle in %s mode.", self.mode)
                self._check_for_expiry_warning(self._policy_bundle)
                # Record latency
                load_latency_ms = (time.perf_counter() - start_ts) * 1000
                policy_load_latency_ms.record(load_latency_ms, {"mode": self.mode})
                
                # Send to D2 cloud
                try:
                    if self._usage_reporter:
                        # Calculate policy complexity
                        tool_count = len(self._policy_bundle.tool_to_roles)
                        role_count = len(set(role for roles in self._policy_bundle.tool_to_roles.values() for role in roles))
                        sequence_rule_count = sum(len(rules) for rules in self._policy_bundle.role_to_sequences.values())
                        
                        self._usage_reporter.track_event(
                            "policy_loaded",
                            {
                                "mode": self.mode,
                                "load_latency_ms": load_latency_ms,
                                "tool_count": tool_count,
                                "role_count": role_count,
                                "sequence_rule_count": sequence_rule_count,
                                "policy_etag": self._policy_bundle.etag,
                            }
                        )
                except Exception:
                    pass

                # ------------------------------------------------------------------
                # Usage Telemetry – policy_updated
                # ------------------------------------------------------------------
                if self._usage_reporter:
                    # Emit detailed policy load/update event (includes latency)
                    self._usage_reporter.track_event(
                        "policy_load",
                        {
                            "mode": self.mode,
                            "tool_count": len(self._policy_bundle.all_known_tools),
                            "latency_ms": load_latency_ms,
                        },
                    )
                    # Maintain existing policy_updated semantic for consumers
                    self._usage_reporter.track_event(
                        "policy_updated",
                        {
                            "mode": self.mode,
                            "tool_count": len(self._policy_bundle.all_known_tools),
                        },
                    )

            except Exception as e:
                logger.error("Fatal error during policy bundle update: %s", e, exc_info=True)
                # In a real-world scenario, you might want a more robust retry/fallback mechanism.
                # For now, we'll log the error and the system will continue with the old policy.
                span.set_status(Status(StatusCode.ERROR), description=str(e))
                # Record failure latency as well
                policy_load_latency_ms.record((time.perf_counter() - start_ts) * 1000, {"mode": self.mode, "error": "1"})
                
                # Send to D2 cloud
                try:
                    if self._usage_reporter:
                        self._usage_reporter.track_event(
                            "policy_load_failed",
                            {
                                "mode": self.mode,
                                "error_type": type(e).__name__,
                                "error_message": str(e),
                                "latency_ms": (time.perf_counter() - start_ts) * 1000,
                            }
                        )
                except Exception:
                    pass


    async def _verify_signature(self, bundle: Dict[str, Any]):
        """
        Verifies the JWT signature of the policy bundle.

        Accepts either legacy form {policy: base64, signature: JWS} or
        compact JWS under key 'jws'.
        
        Enhanced with automatic JWKS refresh for seamless key rotation:
        - Detects jwks_refresh control messages in JWS headers
        - Triggers smart cache refresh before verification
        - Implements rate limiting to prevent endpoint hammering
        """
        if not self._jwks_cache:
            raise ConfigurationError("JWKS cache not configured (file mode).")
            
        # Detect compact JWS vs legacy structure
        compact_jws = bundle.get("jws")
        if compact_jws:
            signature = compact_jws
            encoded_policy = None
        else:
            encoded_policy = bundle.get("policy")
            signature = bundle.get("signature")

        if not signature and not encoded_policy:
            raise InvalidSignatureError("Bundle missing compact 'jws' or legacy 'policy'+'signature'.")

        try:
            # Inspect header to obtain kid and check for rotation control messages
            header = jwt.get_unverified_header(signature)
            kid = header.get("kid")
            if kid is None:
                raise InvalidSignatureError("Missing 'kid' in JWS header.")

            # Check for JWKS refresh control message from control-plane
            jwks_refresh_requested = header.get("jwks_refresh", False)
            rotation_metadata = None
            if jwks_refresh_requested:
                rotation_metadata = {
                    "rotation_id": header.get("rotation_id"),
                    "timestamp": header.get("timestamp"), 
                    "reason": header.get("reason"),
                    "new_kid": header.get("new_kid", kid)
                }
                logger.info(
                    "JWKS refresh requested by control-plane: rotation_id=%s, new_kid=%s",
                    rotation_metadata["rotation_id"], rotation_metadata["new_kid"]
                )

            # Attempt key lookup with smart refresh logic
            try:
                public_key = await self._jwks_cache.get_key_with_refresh(
                    kid, 
                    force_refresh=jwks_refresh_requested,
                    rotation_metadata=rotation_metadata
                )
            except Exception as e:
                raise InvalidSignatureError(f"Failed to resolve kid {kid}: {e}") from e
 
            # Thumbprint pinning check
            if self._jwks_thumbprints:
                der = public_key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                thumbprint = base64.urlsafe_b64encode(hashlib.sha256(der).digest()).rstrip(b"=").decode()
                if thumbprint not in self._jwks_thumbprints:
                    logging.getLogger(__name__).error(
                        "JWKS key thumbprint '%s' not in pinned set. Rejecting bundle.", thumbprint
                    )
                    # Send to D2 cloud
                    reporter = getattr(self, "_usage_reporter", None)
                    if reporter:
                        reporter.track_event(
                            "policy_verification_failed",
                            {
                                "reason": "thumbprint_mismatch",
                                "thumbprint": thumbprint,
                                "pinned_thumbprints": list(self._jwks_thumbprints),
                            }
                        )
                    raise InvalidSignatureError(
                        f"JWKS key thumbprint '{thumbprint}' not in pinned set."
                    )

            # Verify JWS signature (RS256) – with new audience format
            # First decode without audience verification to get the payload
            decode_fn = functools.partial(
                jwt.decode,
                signature,
                key=public_key,
                algorithms=["RS256"],
                options={"verify_signature": True, "verify_exp": True, "verify_aud": False},
            )
            payload = await anyio.to_thread.run_sync(decode_fn)
            
            # Debug: log the payload structure to understand what we're getting
            logger.debug("JWT payload keys: %s", list(payload.keys()) if isinstance(payload, dict) else "not a dict")
            
            # Verify audience claim manually with new format
            aud = payload.get("aud")
            if not aud:
                raise InvalidSignatureError("Token is missing the 'aud' claim")
            
            # Enforce new audience format only
            if not aud.startswith("d2-policy:"):
                raise InvalidSignatureError(f"Invalid audience claim: {aud}. Expected format: d2-policy:account:app")

            # If compact JWS, extract policy from the verified payload
            if compact_jws and not encoded_policy:
                try:
                    # Policy content is spread directly in JWT payload (flat structure)
                    # Extract metadata and policies fields directly
                    if "metadata" not in payload or "policies" not in payload:
                        raise ValueError("JWT payload missing required 'metadata' or 'policies' fields")
                    
                    # Reconstruct policy bundle from flat JWT payload
                    policy_data = {
                        "metadata": payload["metadata"],
                        "policies": payload["policies"]
                    }
                    
                    bundle["policy"] = policy_data
                    bundle["signature"] = compact_jws
                except Exception as exc:
                    raise InvalidSignatureError(f"Failed to extract policy from JWT payload: {exc}") from exc

        except jwt.PyJWTError as e:
            # Send to D2 cloud
            reporter = getattr(self, "_usage_reporter", None)
            if reporter:
                reporter.track_event(
                    "policy_verification_failed",
                    {
                        "reason": "jwt_signature_invalid",
                        "error": str(e),
                    }
                )
            raise InvalidSignatureError(f"JWT signature validation failed: {e}") from e


    async def _validate_jwks_thumbprints(self):
        """Fetches JWKS and validates against pinned thumbprints if provided."""
        if not self._jwks_cache or not self._jwks_thumbprints:
            return
        try:
            start = time.perf_counter()
            logger.debug("Validating JWKS thumbprints...")
            await self._jwks_cache.get_jwks()
            jwks_fetch_latency_ms.record((time.perf_counter() - start) * 1000, {})
            logger.info("JWKS thumbprint validation successful.")

            # Usage Telemetry – jwks_fetch
            if self._usage_reporter:
                self._usage_reporter.track_event(
                    "jwks_fetch",
                    {"status": "success"},
                )

        except Exception as e:
            raise ConfigurationError(f"Failed to fetch or validate JWKS thumbprints: {e}") from e

    @property
    def mode(self) -> str:
        """Returns 'cloud' or 'file' depending on the active loader."""
        return self._policy_loader.mode

    def _get_bundle(self) -> PolicyBundle:
        """Safely gets the current policy bundle, handling the uninitialized case."""
        if not self._init_complete.is_set() or not self._policy_bundle:
            raise ConfigurationError("PolicyManager not yet initialized. Cannot perform checks.")
        return self._policy_bundle

    async def check_async(self, tool_id: str) -> bool:
        """Async: Checks if the current user has permission for a tool."""
        start_time = time.perf_counter()
        await self._init_complete.wait()
        user_context = get_user_context()

        with tracer.start_as_current_span("check_permission") as span:
            span.set_attribute("d2.tool_id", tool_id)
            if user_context and user_context.user_id:
                span.set_attribute("d2.user.id", user_context.user_id)
            if user_context and user_context.roles:
                span.set_attribute("d2.user.roles", ", ".join(user_context.roles))
            else:
                span.set_attribute("d2.user.roles", "")
            span.set_attribute("d2.instance_name", self.instance_name)
            span.set_attribute("d2.mode", self.mode)

            bundle = self._get_bundle()

            # Record bundle age gauge (now - loaded_at) each time we evaluate
            if bundle:
                age_seconds = (datetime.now(timezone.utc) - bundle.loaded_at).total_seconds()
                policy_bundle_age_seconds.add(age_seconds - getattr(self, "_last_bundle_age", 0))
                self._last_bundle_age = age_seconds
            # Emit expiry warnings (including per-request for critical <24h window)
            self._check_for_expiry_warning(bundle)
            if not bundle or (tool_id not in bundle.all_known_tools and "*" not in bundle.tool_to_roles):
                missing_policy_total.add(1, {"tool_id": tool_id, "mode": self.mode})
                span.set_status(Status(StatusCode.ERROR, "Policy not loaded"))
                return False

            # If the tool isn't explicitly listed and there is no wildcard in the policy, treat as missing.
            if tool_id not in bundle.all_known_tools and "*" not in bundle.tool_to_roles:
                missing_policy_total.add(1, {"tool_id": tool_id, "mode": self.mode})
                span.set_status(Status(StatusCode.ERROR, "Tool not in policy"))
                return False

            # Enforce context requirement - no anonymous access allowed
            if user_context is None or user_context.user_id is None:
                context_leak_total.add(1)
                if self._usage_reporter:
                    self._usage_reporter.track_event(
                        "context_leak",
                        {"tool_id": tool_id},
                    )
                span.set_status(Status(StatusCode.ERROR, "No user context"))
                raise D2NoContextError(tool_id)

            user_roles = set(user_context.roles if user_context.roles else [])

            # 1. Check if the user has a wildcard role that grants all permissions.
            if "*" in user_roles:
                is_allowed = True
            else:
                # 2. Get all roles that are allowed to use this tool.
                # This includes roles directly assigned to the tool, plus any roles
                # that have the wildcard '*' permission.
                allowed_roles = bundle.tool_to_roles.get(tool_id, set())
                admin_roles = bundle.tool_to_roles.get("*", set())
                effective_allowed_roles = allowed_roles.union(admin_roles)
                
                # 3. The check passes if the user's roles and the tool's roles are not disjoint.
                is_allowed = not user_roles.isdisjoint(effective_allowed_roles)
            
            result = "allowed" if is_allowed else "denied"
            
            # OpenTelemetry instrumentation (for the user)
            result_attr = {"tool_id": tool_id, "result": result, "mode": self.mode}
            authz_decision_total.add(1, result_attr)

            # Record decision latency
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            authz_decision_latency_ms.record(duration_ms, result_attr)

            # Internal usage reporting (for D2)
            if self._usage_reporter:
                # Consolidated authz decision event
                event_data = {
                    "tool_id": tool_id,
                    "result": result,
                    "decision_ms": duration_ms,
                    "mode": self.mode,
                }
                
                # Add reason field for denials
                if not is_allowed:
                    event_data["reason"] = "role_mismatch"
                
                self._usage_reporter.track_event("authz_decision", event_data)

            if is_allowed:
                span.set_status(Status(StatusCode.OK))
            else:
                # Tag denied reason for OTEL metrics
                authz_denied_reason_total.add(1, {"reason": "role_mismatch", "mode": self.mode})
            
            return is_allowed

    async def get_tool_conditions(self, tool_id: str) -> Optional[Any]:
        """Retrieve declarative conditions for a tool scoped to the current user."""

        await self._init_complete.wait()
        bundle = self._get_bundle()
        user_context = get_user_context()

        if user_context is None:
            return None

        user_roles = set(user_context.roles or [])
        if not user_roles or "*" in user_roles:
            # No roles or super-admin role bypasses additional conditions.
            return None

        applicable: List[Any] = []

        def _collect_conditions(tool_identifier: str):
            for entry in bundle.tool_conditions.get(tool_identifier, []):
                role = entry.get("role")
                if role in user_roles:
                    applicable.append(entry.get("conditions"))

        _collect_conditions(tool_id)
        _collect_conditions("*")

        if not applicable:
            return None

        if len(applicable) == 1:
            return applicable[0]

        return applicable

    async def get_sequence_rules(self) -> tuple[Optional[str], List[Dict[str, Any]]]:
        """Retrieve sequence rules and mode for the current user's roles.
        
        Returns:
            Tuple of (mode, rules_list)
            Mode is "deny" if any role uses deny mode, otherwise "allow" (or None if no rules).
            
        Example:
            ("allow", [{"deny": ["database.read", "web.request"], "reason": "Exfiltration"}])
        """
        await self._init_complete.wait()
        bundle = self._get_bundle()
        user_context = get_user_context()

        if user_context is None or not user_context.roles:
            return None, []

        user_roles = set(user_context.roles)
        
        # Admin wildcard role bypasses sequence enforcement
        if "*" in user_roles:
            return None, []

        # Collect all sequence rules and determine effective mode
        all_rules: List[Dict[str, Any]] = []
        effective_mode = "allow"
        has_rules = False

        for role in user_roles:
            sequence_data = bundle.get_sequence_rules(role)
            if sequence_data:
                has_rules = True
                role_mode = sequence_data.get("mode", "allow")
                role_rules = sequence_data.get("rules", [])
                
                # If any role uses 'deny' mode (allowlist), the whole check 
                # shifts to 'deny' mode for maximum security (least privilege).
                if role_mode.lower() == "deny":
                    effective_mode = "deny"
                
                all_rules.extend(role_rules)

        if not has_rules:
            return None, []

        return effective_mode, all_rules

    async def is_tool_in_policy_async(self, tool_id: str) -> bool:
        """Async: Checks if a tool ID is defined in the policy at all."""
        await self._init_complete.wait()
        bundle = self._get_bundle()
        if tool_id in bundle.all_known_tools:
            return True
        # If wildcard permission exists, treat all tools as potentially valid
        return "*" in bundle.tool_to_roles

    def check(self, tool_id: str) -> bool:
        """Sync: Checks if the current user has permission for a tool."""
        try:
            # Check if we're in an async context
            asyncio.get_running_loop()
            raise ConfigurationError(
                "Cannot call sync method from async context. Use check_async() instead."
            )
        except RuntimeError:
            # No event loop running, safe to use anyio.run
            return anyio.run(self.check_async, tool_id)

    def is_tool_in_policy(self, tool_id: str) -> bool:
        """Sync: Checks if a tool ID is defined in the policy at all."""
        try:
            # Check if we're in an async context
            asyncio.get_running_loop()
            raise ConfigurationError(
                "Cannot call sync method from async context. Use is_tool_in_policy_async() instead."
            )
        except RuntimeError:
            # No event loop running, safe to use anyio.run
            return anyio.run(self.is_tool_in_policy_async, tool_id)

    def _print_startup_banner(self):
        if os.getenv("D2_SILENT", "0").lower() in ("1", "true"):
            return
        
        if not getattr(PolicyManager, "_banner_printed", False):
            logger.info(
                "D2 is running in local-file mode. See https://artoo.love/d2/docs for details. "
                "Set the D2_TOKEN environment variable to enable cloud sync."
            )
            PolicyManager._banner_printed = True

    def _check_for_expiry_warning(self, bundle: PolicyBundle):
        # This warning only applies to local file mode.
        if bundle.mode != "file" or os.getenv("D2_SILENT", "0").lower() in ("1", "true"):
            return

        expiry_str = bundle.raw_bundle.get("metadata", {}).get("expires")
        if not expiry_str:
            return

        try:
            expiry_date = datetime.fromisoformat(expiry_str)
            if expiry_date.tzinfo is None:
                expiry_date = expiry_date.replace(tzinfo=timezone.utc)
            
            time_until_expiry = expiry_date - datetime.now(timezone.utc)

            # Critical window (<24 h): log on every check so operators can't miss it.
            if timedelta(days=0) < time_until_expiry <= timedelta(hours=24):
                logger.warning(
                    "⏰ Local policy expires in %d hours! Calls will hard-fail on expiry. "
                    "Run `d2 init --force` to refresh or set D2_TOKEN to switch to cloud mode.",
                    int(time_until_expiry.total_seconds() // 3600),
                )
            # Early heads-up (≤30 days but >24 h): emit once per boot to avoid noise.
            elif time_until_expiry <= timedelta(days=30):
                if not getattr(self, "_expiry_warning_logged", False):
                    logger.warning(
                        "Local policy expires in %d days. "
                        "Cloud-sync handles key rotation automatically. Set D2_TOKEN to upgrade.",
                        time_until_expiry.days,
                    )
                    self._expiry_warning_logged = True
        except (ValueError, TypeError) as e:
            logger.warning("Could not parse 'expires' timestamp in local policy file: %s", e)

_policy_manager_instances: Dict[str, PolicyManager] = {}
_manager_lock = threading.Lock()


async def configure_rbac(
    instance_name: str = "default",
    api_url: str = DEFAULT_API_URL,
    pin_jwks_thumbprints: Optional[List[str]] = None,
    jwks_url: Optional[str] = None,
):
    """
    Configures and initializes the D2 RBAC system for a given instance.
    This must be called and awaited before any @d2 decorators are checked.
    """
    global _policy_manager_instances
    
    if get_user_roles():
        warnings.warn(
            f"configure_rbac(instance_name='{instance_name}') called while a user context is active. "
            "This may indicate a context leak from a previous request. "
            "Use context clearing middleware to prevent this.",
            ContextLeakWarning
        )

    with _manager_lock:
        if instance_name in _policy_manager_instances:
            logger.warning("RBAC for instance '%s' already configured. Overwriting.", instance_name)
            await shutdown_rbac(instance_name)

        logger.info("Configuring D2 RBAC instance: '%s'", instance_name)
        instance = PolicyManager(
            instance_name=instance_name,
            api_url=api_url,
            pin_jwks_thumbprints=pin_jwks_thumbprints,
            jwks_url=jwks_url,
        )
        _policy_manager_instances[instance_name] = instance

    try:
        await instance.initialize()
    except Exception as e:
        logger.critical(
            "Initial policy load failed for instance '%s': %s. SDK will deny all requests until a policy is successfully loaded.",
            instance_name, e
        )

# ---------------------------------------------------------------------------
# Convenience wrapper for synchronous applications
# ---------------------------------------------------------------------------


def configure_rbac_sync(
    instance_name: str = "default",
    api_url: str = DEFAULT_API_URL,
    pin_jwks_thumbprints: Optional[List[str]] = None,
    jwks_url: Optional[str] = None,
):
    """Synchronous wrapper around :pyfunc:`configure_rbac`.

    Usage::

        # At start-up of a Flask / Django app (outside any event loop)
        import d2
        d2.configure_rbac_sync()

    Internally this spins up a temporary event loop via ``anyio.run`` and
    awaits :pyfunc:`configure_rbac`. It is safe to call from global scope or
    from ``if __name__ == "__main__"`` blocks.
    """

    return anyio.run(
        configure_rbac,
        instance_name,
        api_url,
        pin_jwks_thumbprints,
        jwks_url,
    )

async def shutdown_rbac(instance_name: str = "default"):
    """Gracefully shuts down a specific RBAC instance."""
    if instance_name in _policy_manager_instances:
        manager = _policy_manager_instances.pop(instance_name)
        await manager.shutdown()

async def shutdown_all_rbac():
    """Gracefully shuts down all configured RBAC instances."""
    tasks = [manager.shutdown() for manager in _policy_manager_instances.values()]
    await asyncio.gather(*tasks)
    _policy_manager_instances.clear()


def get_policy_manager(instance_name: str = "default") -> PolicyManager:
    """Retrieves a configured PolicyManager instance."""
    if instance_name not in _policy_manager_instances:
        if instance_name == "default" and not os.getenv("D2_TOKEN"):
            raise ConfigurationError(
                "RBAC system not configured. Even in local-file mode, you must call and await `configure_rbac()` at startup."
            )
        
        raise ConfigurationError(
            f"RBAC system instance '{instance_name}' not configured. "
            f"Please call `await configure_rbac(instance_name='{instance_name}')` before use."
        )
    return _policy_manager_instances[instance_name] 