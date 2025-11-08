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
    ) -> Optional[PermissionDeniedError]:
        """Check if appending next_tool_id violates any sequence rule.
        
        Supports both deny and allow rules with precedence: allow overrides deny.
        
        Args:
            current_history: Sequence of tool_ids called so far in this request
            next_tool_id: The tool about to be called
            sequence_rules: List of sequence rules from policy
            
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
        if not sequence_rules:
            return None
        
        # Construct the proposed sequence (history + next call)
        proposed_sequence = list(current_history) + [next_tool_id]
        
        # Collect matching deny and allow rules (allow takes precedence)
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
            
            # Single-step patterns don't make sense for sequences
            if len(pattern) < 2:
                continue
            
            # Check if the proposed sequence matches the pattern
            if self._matches_pattern(proposed_sequence, pattern):
                if is_allow:
                    # Allow rule matches - override any denies
                    has_matching_allow = True
                elif is_deny and not matching_deny_rule:
                    # Store first matching deny rule
                    matching_deny_rule = rule
        
        # Apply precedence: allow overrides deny
        if has_matching_allow:
            return None
        
        if matching_deny_rule:
            reason = matching_deny_rule.get("reason", "Denied sequence pattern")
            return PermissionDeniedError(
                tool_id=next_tool_id,
                user_id="(sequence_context)",
                roles=[],
                reason=f"sequence_violation: {reason}"
            )
        
        return None

    def _matches_pattern(
        self, 
        sequence: list[str], 
        pattern: list[str]
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

