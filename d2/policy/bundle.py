# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""Policy bundle data structures."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Set

from ..exceptions import PolicyError, ConfigurationError


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
    # Map role -> SequenceRules object (holds rules list + mode)
    role_to_sequences: Dict[str, Any] = field(default_factory=dict, repr=False)
    # Data flow tracking: which labels each tool produces
    tool_labels: Dict[str, Set[str]] = field(default_factory=dict, repr=False)
    # Data flow tracking: which labels block which tools
    label_blocks: Dict[str, Set[str]] = field(default_factory=dict, repr=False)

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
        
        # Validate all regex patterns before processing policies
        self._validate_regex_patterns(policies)

        for policy in policies:
            # Support both single role (string) and multiple roles (list)
            # Priority: 'role' key takes precedence over 'roles' for backwards compatibility
            role_raw = policy.get("role") or policy.get("roles")
            if not role_raw:
                logger.debug("Skipping policy without role: %s", policy)
                continue

            # Normalize to list of roles
            if isinstance(role_raw, list):
                role_list = role_raw
            else:
                role_list = [role_raw]
            
            # Skip empty role lists
            if not role_list:
                logger.debug("Skipping policy with empty role list: %s", policy)
                continue

            permissions = policy.get("permissions", [])
            logger.debug(
                "Processing role(s) %s with %d permissions: %s",
                role_list,
                len(permissions),
                permissions,
            )

            # Process permissions for each role in the list
            for role in role_list:
                if not isinstance(role, str):
                    logger.warning("Skipping non-string role: %s (type: %s)", role, type(role))
                    continue
                
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

                # Parse sequence rules (apply to this specific role)
                sequence_raw = policy.get("sequence", [])
                
                # Handle both legacy list format and new nested format
                if isinstance(sequence_raw, dict):
                    # New format: {"mode": "deny", "rules": [...]}
                    mode = sequence_raw.get("mode")
                    rules_list = sequence_raw.get("rules", [])
                else:
                    # Legacy format: list of rules directly, default to allow mode
                    mode = "allow"
                    rules_list = sequence_raw if isinstance(sequence_raw, list) else []

                # Store sequence rules if they exist OR if mode is "deny" (empty deny = block all)
                if rules_list or (mode == "deny"):
                    logger.debug("Processing %d sequence rules for role '%s' (mode=%s)", len(rules_list), role, mode)
                    # Validate @group references without expanding (lazy expansion at runtime)
                    tool_groups = self._extract_tool_groups(policy_content)
                    validated_rules = self._validate_sequence_rules(rules_list, tool_groups)
                    
                    # Store as simple dict to avoid pickling issues with dataclasses
                    self.role_to_sequences[role] = {
                        "mode": mode,
                        "rules": validated_rules
                    }
                    logger.debug("Validated %d sequence rules for role '%s'", len(validated_rules), role)

        logger.debug("Final tool_to_roles mapping: %s", dict(self.tool_to_roles))
        logger.debug("Final role_to_sequences mapping: %s", dict(self.role_to_sequences))
        
        # Parse data_flow rules from metadata
        self._parse_data_flow(policy_content)

    @property
    def all_known_tools(self) -> Set[str]:
        """Returns all tools defined in the policy."""

        return set(self.tool_to_roles.keys())
    
    def get_sequence_rules(self, role: str) -> Dict[str, Any]:
        """Get sequence configuration for a specific role.
        
        Args:
            role: Role name
            
        Returns:
            Dict with 'mode' (str) and 'rules' (List[Dict]) keys.
            Returns None if no sequence rules defined for role.
        """
        return self.role_to_sequences.get(role)
    
    def get_tool_groups(self) -> Dict[str, List[str]]:
        """Get tool_groups from policy metadata for lazy sequence expansion.
        
        Returns:
            Dict mapping group names to tool ID lists
        """
        # Handle both flat structure (local files) and nested structure (cloud bundles)
        if "policy" in self.raw_bundle:
            policy_content = self.raw_bundle["policy"]
        else:
            policy_content = self.raw_bundle
        
        return self._extract_tool_groups(policy_content)
    
    def _validate_regex_patterns(self, policies: List[Dict[str, Any]]) -> None:
        """Validate all regex patterns in the policy bundle at load time.
        
        This catches malformed regex patterns early (during policy loading) rather than
        at runtime when a tool is called. This prevents runtime crashes and provides
        clear feedback to policy authors.
        
        Args:
            policies: List of policy dictionaries to validate
            
        Raises:
            ConfigurationError: If any regex pattern is invalid
        """
        errors = []
        
        for policy in policies:
            role = policy.get("role") or policy.get("roles", "unknown")
            permissions = policy.get("permissions", [])
            
            for permission in permissions:
                if not isinstance(permission, Mapping):
                    continue
                
                tool_id = permission.get("tool") or permission.get("id", "unknown")
                conditions = permission.get("conditions")
                
                if not conditions:
                    continue
                
                # Check input conditions
                if "input" in conditions and isinstance(conditions["input"], Mapping):
                    for field_name, rules in conditions["input"].items():
                        if not isinstance(rules, Mapping):
                            continue
                        
                        # Check 'matches' operator
                        if "matches" in rules:
                            pattern = rules["matches"]
                            try:
                                re.compile(pattern)
                            except re.error as e:
                                errors.append(
                                    f"Role '{role}', tool '{tool_id}', input field '{field_name}': "
                                    f"Invalid regex pattern in 'matches': '{pattern}' ({e})"
                                )
                        
                        # Check 'not_matches' operator
                        if "not_matches" in rules:
                            pattern = rules["not_matches"]
                            try:
                                re.compile(pattern)
                            except re.error as e:
                                errors.append(
                                    f"Role '{role}', tool '{tool_id}', input field '{field_name}': "
                                    f"Invalid regex pattern in 'not_matches': '{pattern}' ({e})"
                                )
                
                # Check output conditions
                if "output" in conditions and isinstance(conditions["output"], Mapping):
                    for field_name, rules in conditions["output"].items():
                        if not isinstance(rules, Mapping):
                            continue
                        
                        # Check 'matches' operator (used in validation)
                        if "matches" in rules:
                            pattern = rules["matches"]
                            try:
                                re.compile(pattern)
                            except re.error as e:
                                errors.append(
                                    f"Role '{role}', tool '{tool_id}', output field '{field_name}': "
                                    f"Invalid regex pattern in 'matches': '{pattern}' ({e})"
                                )
                        
                        # Check 'not_matches' operator
                        if "not_matches" in rules:
                            pattern = rules["not_matches"]
                            try:
                                re.compile(pattern)
                            except re.error as e:
                                errors.append(
                                    f"Role '{role}', tool '{tool_id}', output field '{field_name}': "
                                    f"Invalid regex pattern in 'not_matches': '{pattern}' ({e})"
                                )
                        
                        # Check pattern-based redaction (action: redact with matches)
                        # Note: This is for output sanitization, not validation
                        if rules.get("action") == "redact" and "matches" in rules:
                            # Pattern already checked above, but this confirms it's for sanitization
                            pass
        
        # If any errors were found, raise with all of them
        if errors:
            error_msg = "Invalid regex pattern(s) found in policy:\n" + "\n".join(f"  - {e}" for e in errors)
            raise ConfigurationError(error_msg)
    
    def _extract_tool_groups(self, policy_content: Dict[str, Any]) -> Dict[str, List[str]]:
        """Extract tool_groups from policy metadata.
        
        Args:
            policy_content: The policy content dict
            
        Returns:
            Dict mapping group names to list of tool IDs
        """
        metadata = policy_content.get("metadata", {})
        tool_groups = metadata.get("tool_groups", {})
        
        if not isinstance(tool_groups, dict):
            logger.warning("tool_groups in metadata is not a dict, ignoring")
            return {}
        
        return tool_groups
    
    def _validate_sequence_rules(
        self, 
        sequence_rules: List[Dict[str, Any]], 
        tool_groups: Dict[str, List[str]]
    ) -> List[Dict[str, Any]]:
        """Validate @group references in sequence rules without expansion.
        
        This implements lazy @group expansion: instead of materializing the
        cartesian product at load time (which can explode memory), we keep
        @group references as-is and expand them lazily at runtime during
        pattern matching.
        
        This approach scales to very large groups without memory issues:
        - Old way: 100 × 100 groups = 10,000 rules in memory
        - New way: 100 × 100 groups = 1 rule in memory
        
        Args:
            sequence_rules: List of sequence rule dicts
            tool_groups: Dict mapping group names to tool ID lists
            
        Returns:
            List of validated sequence rules (with @groups intact)
            
        Raises:
            PolicyError: If @group reference is undefined or empty
        """
        validated = []
        
        for rule in sequence_rules:
            # Get the pattern (could be under 'deny' or 'allow')
            if "deny" in rule:
                pattern = rule["deny"]
            elif "allow" in rule:
                pattern = rule["allow"]
            else:
                # No deny or allow key - keep rule as-is with warning
                logger.warning("Sequence rule missing 'deny' or 'allow' key: %s", rule)
                validated.append(rule)
                continue
            
            if not isinstance(pattern, list):
                logger.warning("Sequence pattern is not a list: %s", pattern)
                validated.append(rule)
                continue
            
            # Validate @group references (ensure they exist)
            for item in pattern:
                if isinstance(item, str) and item.startswith("@"):
                    # This is a group reference
                    group_name = item[1:]  # Remove @ prefix
                    
                    if not tool_groups:
                        raise PolicyError(
                            f"Tool groups not defined in metadata, but sequence rule references {item}"
                        )
                    
                    if group_name not in tool_groups:
                        raise PolicyError(
                            f"Unknown tool group '{item}' referenced in sequence rule. "
                            f"Available groups: {list(tool_groups.keys())}"
                        )
                    
                    group_tools = tool_groups[group_name]
                    
                    if not group_tools:
                        # Empty group - log warning but don't fail
                        # (at runtime, no tools will match this pattern element)
                        logger.warning("Tool group '@%s' is empty", group_name)
            
            # Keep the rule as-is (with @group references intact)
            validated.append(rule)
        
        return validated
    
    def _parse_data_flow(self, policy_content: Dict[str, Any]) -> None:
        """Parse data_flow rules from policy metadata.
        
        The data_flow section defines semantic labeling for data provenance:
        - labels: Maps tools/groups to the labels they produce when they run
        - blocks: Maps labels to the tools/groups they block
        
        Example policy:
            metadata:
              data_flow:
                labels:
                  "@sensitive_data": [SENSITIVE]
                  "secrets.get": [SECRET]
                blocks:
                  SENSITIVE: ["@egress_tools"]
                  SECRET: ["@egress_tools", "logging.info"]
        
        Args:
            policy_content: The policy content dict
        """
        metadata = policy_content.get("metadata", {})
        data_flow = metadata.get("data_flow", {})
        
        if not data_flow:
            logger.debug("No data_flow rules defined in policy")
            return
        
        tool_groups = self._extract_tool_groups(policy_content)
        
        # Parse 'labels' section: tool/group -> labels it produces
        labels_config = data_flow.get("labels", {})
        for tool_or_group, labels in labels_config.items():
            if not labels:
                continue
            
            # Normalize labels to a set
            if isinstance(labels, str):
                label_set = {labels}
            elif isinstance(labels, list):
                label_set = set(labels)
            else:
                logger.warning("Invalid labels format for '%s': %s", tool_or_group, labels)
                continue
            
            # Expand tool references
            tools = self._expand_tool_ref(tool_or_group, tool_groups)
            for tool in tools:
                self.tool_labels.setdefault(tool, set()).update(label_set)
        
        logger.debug("Parsed data_flow labels: %s", dict(self.tool_labels))
        
        # Parse 'blocks' section: label -> tools it blocks
        blocks_config = data_flow.get("blocks", {})
        for label, tools_or_groups in blocks_config.items():
            if not tools_or_groups:
                continue
            
            # Normalize to list
            if isinstance(tools_or_groups, str):
                tools_or_groups = [tools_or_groups]
            elif not isinstance(tools_or_groups, list):
                logger.warning("Invalid blocks format for label '%s': %s", label, tools_or_groups)
                continue
            
            # Expand tool references and build inverted index (tool -> blocking labels)
            for tool_or_group in tools_or_groups:
                tools = self._expand_tool_ref(tool_or_group, tool_groups)
                for tool in tools:
                    self.label_blocks.setdefault(tool, set()).add(label)
        
        logger.debug("Parsed data_flow blocks (tool -> blocking labels): %s", dict(self.label_blocks))
    
    def _expand_tool_ref(self, ref: str, tool_groups: Dict[str, List[str]]) -> List[str]:
        """Expand @group reference or return single tool.
        
        Args:
            ref: Tool ID or @group reference
            tool_groups: Dict mapping group names to tool ID lists
            
        Returns:
            List of tool IDs (single item if not a group)
        """
        if ref.startswith("@"):
            group_name = ref[1:]  # Remove @ prefix
            if group_name not in tool_groups:
                logger.warning("Unknown tool group '@%s' in data_flow rules", group_name)
                return []
            return tool_groups.get(group_name, [])
        return [ref]
    
    def get_labels_for_tool(self, tool_id: str) -> Set[str]:
        """Get the labels that a tool produces when it runs.
        
        These labels are added to the request's facts after the tool executes.
        
        Args:
            tool_id: The tool identifier
            
        Returns:
            Set of label strings (empty if tool doesn't produce labels)
            
        Example:
            >>> bundle.get_labels_for_tool("database.read")
            {'SENSITIVE', 'PII'}
        """
        return self.tool_labels.get(tool_id, set())
    
    def get_blocking_labels_for_tool(self, tool_id: str) -> Set[str]:
        """Get the labels that would block this tool from running.
        
        If any of these labels are present in the request's facts,
        this tool should be denied.
        
        Args:
            tool_id: The tool identifier
            
        Returns:
            Set of blocking label strings (empty if tool has no blockers)
            
        Example:
            >>> bundle.get_blocking_labels_for_tool("http.request")
            {'SENSITIVE', 'SECRET'}
        """
        return self.label_blocks.get(tool_id, set())


__all__ = ["PolicyBundle"]


