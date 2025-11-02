"""Policy bundle data structures."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Set


logger = logging.getLogger(__name__)


@dataclass
class PolicyBundle:
    """A structured representation of the policy bundle."""

    raw_bundle: Dict[str, Any]
    mode: str  # 'file' or 'cloud'
    loaded_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    signature: Optional[str] = None
    etag: Optional[str] = None  # For analytics and caching
    tool_to_roles: Dict[str, Set[str]] = field(default_factory=dict, repr=False)
    tool_conditions: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict, repr=False)

    def __post_init__(self):
        """Parse the raw bundle into a more efficient, inverted structure."""

        # Handle both flat structure (local files) and nested structure (cloud bundles)
        if "policy" in self.raw_bundle:
            # Cloud mode: policy content is nested under "policy" field
            policy_content = self.raw_bundle["policy"]
        else:
            # Local mode: policy content is directly in raw_bundle
            policy_content = self.raw_bundle

        policies = policy_content.get("policies", [])
        logger.debug("Processing %d policies from %s mode", len(policies), self.mode)

        for policy in policies:
            role = policy.get("role")
            if not role:
                logger.debug("Skipping policy without role: %s", policy)
                continue

            permissions = policy.get("permissions", [])
            logger.debug(
                "Processing role '%s' with %d permissions: %s",
                role,
                len(permissions),
                permissions,
            )

            for permission in permissions:
                tool_id: Optional[str]
                allow = True
                conditions: Optional[Mapping[str, Any]] = None

                if isinstance(permission, str):
                    tool_id = permission
                elif isinstance(permission, Mapping):
                    tool_id = permission.get("tool") or permission.get("id")
                    allow = permission.get("allow", True)
                    conditions = permission.get("conditions")
                else:
                    logger.debug("Unsupported permission format: %s", permission)
                    continue

                if not tool_id:
                    logger.debug("Permission missing tool identifier: %s", permission)
                    continue

                if not allow:
                    logger.debug(
                        "Permission explicitly denied for tool '%s'; skipping role binding.",
                        tool_id,
                    )
                    continue

                self.tool_to_roles.setdefault(tool_id, set()).add(role)

                if conditions:
                    self.tool_conditions.setdefault(tool_id, []).append(
                        {"role": role, "conditions": conditions}
                    )

        logger.debug("Final tool_to_roles mapping: %s", dict(self.tool_to_roles))

    @property
    def all_known_tools(self) -> Set[str]:
        """Returns all tools defined in the policy."""

        return set(self.tool_to_roles.keys())


__all__ = ["PolicyBundle"]


