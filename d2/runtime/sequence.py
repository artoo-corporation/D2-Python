# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""Sequence enforcement for call-flow authorization.

This module implements temporal RBAC - validating that tool calls occur in
allowed sequences to prevent confused deputy attacks and data exfiltration
patterns in multi-agent systems.
"""

from typing import Optional, Sequence
import logging

from ..exceptions import PermissionDeniedError
from ..context import get_user_context

logger = logging.getLogger(__name__)


class SequenceValidator:
    """Validates tool call sequences against policy-defined flow rules.
    
    Prevents attacks like:
    - Direct exfiltration: database.read -> web.request
    - Secrets leakage: secrets.get -> web.request
    - Transitive laundering: db -> analytics -> web
    
    Supports lazy @group expansion: @group references in sequence patterns are
    matched at runtime without materializing the full cartesian product, preventing
    memory exhaustion from large group combinations.
    """

    def __init__(self, tool_groups: Optional[dict[str, list[str]]] = None):
        """Initialize sequence validator with optional tool groups for lazy expansion.
        
        Args:
            tool_groups: Dict mapping group names to lists of tool IDs.
                         Used for lazy @group expansion in sequence patterns.
        """
        self.tool_groups = tool_groups or {}
        # Convert to sets for O(1) membership testing
        self.tool_group_sets: dict[str, set[str]] = {
            name: set(tools) for name, tools in self.tool_groups.items()
        }

    def validate_sequence(
        self,
        current_history: Sequence[str],
        next_tool_id: str,
        sequence_rules: list[dict],
        mode: Optional[str] = None,
    ) -> Optional[PermissionDeniedError]:
        """Check if appending next_tool_id violates any sequence rule.
        
        Supports two enforcement modes:
        - "allow" (default): Blocklist approach - deny specific patterns, allow everything else
        - "deny": Allowlist approach - only allow specific patterns, deny everything else (zero-trust)
        
        In allow mode, deny rules block specific patterns, and allow rules override deny rules.
        In deny mode, only allow rules matter - if no allow rule matches, the sequence is blocked.
        
        Args:
            current_history: Sequence of tool_ids called so far in this request
            next_tool_id: The tool about to be called
            sequence_rules: List of sequence rules from policy
            mode: Enforcement mode - "allow" (blocklist) or "deny" (allowlist).
                  None defaults to "allow" for backward compatibility.
            
        Returns:
            PermissionDeniedError if violation detected, None otherwise
            
        Example:
            >>> validator = SequenceValidator()
            >>> rules = [{"deny": ["database.read", "web.request"], "reason": "Exfil"}]
            >>> error = validator.validate_sequence(
            ...     current_history=("database.read",),
            ...     next_tool_id="web.request",
            ...     sequence_rules=rules
            ... )
            >>> assert error is not None  # Violation!
        """
        # Normalize mode (case-insensitive, default to "allow")
        effective_mode = (mode or "allow").lower()
        if effective_mode not in ("allow", "deny"):
            effective_mode = "allow"  # Safe fallback for invalid modes
        
        # In deny mode with no rules, block everything (fail-closed)
        if effective_mode == "deny" and not sequence_rules:
            ctx = get_user_context()
            user_id = ctx.user_id if ctx and ctx.user_id else "(unknown)"
            roles = list(ctx.roles) if ctx and ctx.roles else []
            return PermissionDeniedError(
                tool_id=next_tool_id,
                user_id=user_id,
                roles=roles,
                reason="sequence_violation: No matching allow rule (deny mode with no rules)"
            )
        
        # In allow mode with no rules, allow everything
        if not sequence_rules:
            return None
        
        # Construct the proposed sequence (history + next call)
        proposed_sequence = list(current_history) + [next_tool_id]
        
        # Collect matching deny and allow rules
        matching_deny_rule = None
        has_matching_allow = False
        
        for rule in sequence_rules:
            is_deny = "deny" in rule
            is_allow = "allow" in rule
            
            if not is_deny and not is_allow:
                continue
            
            pattern = rule.get("deny") or rule.get("allow")
            
            # Skip malformed rules
            if not pattern or not isinstance(pattern, list):
                continue
            
            # In allow mode, single-step deny patterns don't make sense (need 2+ steps)
            # In deny mode, single-step allow patterns ARE valid (whitelist first calls)
            if effective_mode == "allow" and len(pattern) < 2:
                continue
            
            # Check if the proposed sequence matches the pattern
            # Check for match
            match = False
            
            if effective_mode == "deny" and is_allow:
                # In deny mode, we need strict control to prevent arbitrary extensions.
                # A sequence is allowed if:
                # 1. It is a valid prefix of an allowed pattern (progressing step-by-step)
                #    e.g. [A] matches start of [A, B]
                if self._is_prefix_match(proposed_sequence, pattern):
                    match = True
                # 2. It completes an allowed pattern (allowing gaps/subsequences)
                #    But it MUST end with the pattern's last element to prevent extension
                #    e.g. [A, ... B] is allowed, but [A, B, ... C] is not
                elif self._matches_pattern(proposed_sequence, pattern, effective_mode):
                    if self._tool_matches_element(next_tool_id, pattern[-1]):
                        match = True
            else:
                # In allow mode (or deny rules), use standard subsequence matching (supports gaps)
                match = self._matches_pattern(proposed_sequence, pattern, effective_mode)

            if match:
                if is_allow:
                    # Allow rule matches
                    has_matching_allow = True
                elif is_deny and not matching_deny_rule:
                    # Store first matching deny rule
                    matching_deny_rule = rule
        
        # Apply mode-specific logic
        if effective_mode == "deny":
            # Deny mode (allowlist): must have a matching allow rule
            if has_matching_allow:
                return None
            # No matching allow rule - block
            ctx = get_user_context()
            user_id = ctx.user_id if ctx and ctx.user_id else "(unknown)"
            roles = list(ctx.roles) if ctx and ctx.roles else []
            return PermissionDeniedError(
                tool_id=next_tool_id,
                user_id=user_id,
                roles=roles,
                reason="sequence_violation: No matching allow rule (deny mode)"
            )
        else:
            # Allow mode (blocklist): allow overrides deny
            if has_matching_allow:
                return None
            
            if matching_deny_rule:
                reason = matching_deny_rule.get("reason", "Denied sequence pattern")
                ctx = get_user_context()
                user_id = ctx.user_id if ctx and ctx.user_id else "(unknown)"
                roles = list(ctx.roles) if ctx and ctx.roles else []
                return PermissionDeniedError(
                    tool_id=next_tool_id,
                    user_id=user_id,
                    roles=roles,
                    reason=f"sequence_violation: {reason}"
                )
            
            return None
            
    def _is_prefix_match(self, sequence: list[str], pattern: list[str]) -> bool:
        """Check if sequence is a valid prefix of the pattern (strict order, no gaps).
        
        Used in deny mode to allow partial progress through an allowed sequence.
        """
        if len(sequence) > len(pattern):
            return False
        
        for i, tool in enumerate(sequence):
            if not self._tool_matches_element(tool, pattern[i]):
                return False
        return True

    def _matches_pattern(
        self, 
        sequence: list[str], 
        pattern: list[str],
        mode: str = "allow"
    ) -> bool:
        """Check if a pattern appears in the sequence (with possible gaps).
        
        Checks if all tools in the pattern appear in order in the sequence,
        even if there are other tools in between. This prevents evasion by
        inserting innocent calls between sensitive operations.
        
        Supports lazy @group expansion: @group references in patterns are matched
        at runtime by checking if the current tool is in the referenced group.
        This avoids materializing the cartesian product in memory.
        
        Args:
            sequence: The complete sequence of tool calls
            pattern: The pattern to match against (may contain @group references)
            mode: Enforcement mode ("allow" or "deny")
            
        Returns:
            True if pattern found in sequence (in order, gaps allowed), False otherwise
            
        Example:
            >>> validator = SequenceValidator()
            >>> # Consecutive match
            >>> validator._matches_pattern(
            ...     ["auth", "db.read", "web.post"],
            ...     ["db.read", "web.post"]
            ... )
            True
            >>> # Match with gaps (prevents evasion!)
            >>> validator._matches_pattern(
            ...     ["db.read", "analytics.process", "web.post"],
            ...     ["db.read", "web.post"]
            ... )
            True
            >>> # Lazy @group expansion
            >>> validator = SequenceValidator({"database": ["db.read", "db.write"]})
            >>> validator._matches_pattern(
            ...     ["db.read", "api.post"],
            ...     ["@database", "api.post"]
            ... )
            True
        """
        # Handle single-step patterns (only valid in deny mode for whitelisting first calls)
        if len(pattern) == 1:
            # For single-step patterns, just check if the last element of sequence matches
            if sequence:
                return self._tool_matches_element(sequence[-1], pattern[0])
            return False
        
        if len(pattern) > len(sequence):
            return False
        
        # Check if pattern appears in sequence order (gaps allowed)
        # This prevents attackers from evading detection by inserting innocent tools
        pattern_idx = 0
        for tool in sequence:
            # Check if current tool matches the current pattern element
            if self._tool_matches_element(tool, pattern[pattern_idx]):
                pattern_idx += 1
                if pattern_idx == len(pattern):
                    # All pattern elements found in order
                    return True
        
        return False

    def _tool_matches_element(self, tool_id: str, pattern_element: str) -> bool:
        """Check if a tool matches a pattern element (supports @group references).
        
        This enables lazy @group expansion without materializing cartesian products.
        
        Args:
            tool_id: The actual tool ID from the sequence
            pattern_element: Pattern element (either explicit tool ID or @group)
            
        Returns:
            True if tool matches the pattern element, False otherwise
            
        Example:
            >>> validator = SequenceValidator({"database": ["db.read", "db.write"]})
            >>> validator._tool_matches_element("db.read", "@database")
            True
            >>> validator._tool_matches_element("db.read", "db.read")
            True
            >>> validator._tool_matches_element("db.read", "db.write")
            False
        """
        if pattern_element.startswith("@"):
            # Lazy group expansion: check if tool is in the referenced group
            group_name = pattern_element[1:]  # Remove @ prefix
            return tool_id in self.tool_group_sets.get(group_name, set())
        else:
            # Exact tool ID match
            return tool_id == pattern_element


__all__ = ["SequenceValidator"]

