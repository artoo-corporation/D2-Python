# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""Tests for abstract sequence rules using tool groups (@group_name syntax).

Updated for lazy @group expansion: @group references are kept intact at load time
and expanded at runtime during pattern matching, preventing memory exhaustion from
large group combinations.
"""

import pytest
from d2.policy.bundle import PolicyBundle
from d2.exceptions import PolicyError


class TestToolGroupLazyExpansion:
    """Test that tool groups use lazy expansion instead of eager cartesian product."""

    def test_simple_group_validation(self):
        """Test that @group references are validated but not expanded."""
        bundle_data = {
            "metadata": {
                "tool_groups": {
                    "sensitive": ["db.read_users", "db.read_payments"],
                    "external": ["web.request", "email.send"]
                }
            },
            "policies": [
                {
                    "role": "analyst",
                    "permissions": ["db.read_users", "web.request"],
                    "sequence": [
                        {
                            "deny": ["@sensitive", "web.request"],
                            "reason": "No sensitive data to web"
                        }
                    ]
                }
            ]
        }
        
        bundle = PolicyBundle(bundle_data, mode="file")
        rules = bundle.get_sequence_rules("analyst")["rules"]
        
        # Should have 1 rule with @group references intact (lazy expansion)
        assert len(rules) == 1
        assert rules[0]["deny"] == ["@sensitive", "web.request"]
        assert rules[0]["reason"] == "No sensitive data to web"

    def test_multiple_groups_not_expanded(self):
        """Test that multiple @groups in same rule remain intact (lazy expansion)."""
        bundle_data = {
            "metadata": {
                "tool_groups": {
                    "sensitive": ["db.read_users", "db.read_payments"],
                    "external": ["web.request", "email.send"]
                }
            },
            "policies": [
                {
                    "role": "analyst",
                    "permissions": ["*"],
                    "sequence": [
                        {
                            "deny": ["@sensitive", "@external"],
                            "reason": "No sensitive to external"
                        }
                    ]
                }
            ]
        }
        
        bundle = PolicyBundle(bundle_data, mode="file")
        rules = bundle.get_sequence_rules("analyst")["rules"]
        
        # Should have 1 rule with @group references intact (lazy expansion)
        # Old behavior: 2 × 2 = 4 expanded rules
        # New behavior: 1 rule with @groups, expanded at runtime
        assert len(rules) == 1
        assert rules[0]["deny"] == ["@sensitive", "@external"]
        assert rules[0]["reason"] == "No sensitive to external"

    def test_mixed_group_and_explicit(self):
        """Test mixing @group references with explicit tool names."""
        bundle_data = {
            "metadata": {
                "tool_groups": {
                    "sensitive": ["db.read_users", "db.read_payments"]
                }
            },
            "policies": [
                {
                    "role": "analyst",
                    "permissions": ["*"],
                    "sequence": [
                        {
                            "deny": ["@sensitive", "analytics.process", "web.request"],
                            "reason": "3-hop prevention"
                        }
                    ]
                }
            ]
        }
        
        bundle = PolicyBundle(bundle_data, mode="file")
        rules = bundle.get_sequence_rules("analyst")["rules"]
        
        # Should keep @sensitive intact (lazy expansion)
        assert len(rules) == 1
        assert rules[0]["deny"] == ["@sensitive", "analytics.process", "web.request"]
        assert rules[0]["reason"] == "3-hop prevention"

    def test_transitive_pattern_with_groups(self):
        """Test 3+ hop patterns with tool groups."""
        bundle_data = {
            "metadata": {
                "tool_groups": {
                    "sensitive": ["db.read_users"],
                    "processing": ["analytics.summarize"],
                    "external": ["web.request"]
                }
            },
            "policies": [
                {
                    "role": "analyst",
                    "permissions": ["*"],
                    "sequence": [
                        {
                            "deny": ["@sensitive", "@processing", "@external"],
                            "reason": "Data laundering prevention"
                        }
                    ]
                }
            ]
        }
        
        bundle = PolicyBundle(bundle_data, mode="file")
        rules = bundle.get_sequence_rules("analyst")["rules"]
        
        # Should keep @groups intact (lazy expansion)
        assert len(rules) == 1
        assert rules[0]["deny"] == ["@sensitive", "@processing", "@external"]
        assert rules[0]["reason"] == "Data laundering prevention"

    def test_allow_rule_with_groups(self):
        """Test @group validation in allow rules."""
        bundle_data = {
            "metadata": {
                "tool_groups": {
                    "public_data": ["db.read_stats", "db.read_metrics"]
                }
            },
            "policies": [
                {
                    "role": "analyst",
                    "permissions": ["*"],
                    "sequence": [
                        {
                            "deny": ["db.*", "web.request"]
                        },
                        {
                            "allow": ["@public_data", "web.request"],
                            "reason": "Public data is safe"
                        }
                    ]
                }
            ]
        }
        
        bundle = PolicyBundle(bundle_data, mode="file")
        rules = bundle.get_sequence_rules("analyst")["rules"]
        
        # Should have 2 rules with @public_data intact (lazy expansion)
        assert len(rules) == 2
        allow_rules = [r for r in rules if "allow" in r]
        assert len(allow_rules) == 1
        assert allow_rules[0]["allow"] == ["@public_data", "web.request"]
        assert allow_rules[0]["reason"] == "Public data is safe"

    def test_undefined_group_reference(self):
        """Test that undefined @group references raise PolicyError."""
        bundle_data = {
            "metadata": {
                "tool_groups": {
                    "sensitive": ["db.read_users"]
                }
            },
            "policies": [
                {
                    "role": "analyst",
                    "permissions": ["*"],
                    "sequence": [
                        {
                            "deny": ["@sensitive", "@undefined_group", "web.request"]
                        }
                    ]
                }
            ]
        }
        
        with pytest.raises(PolicyError, match="Unknown tool group.*@undefined_group"):
            PolicyBundle(bundle_data, mode="file")

    def test_no_tool_groups_defined(self):
        """Test @group reference when no tool_groups in metadata."""
        bundle_data = {
            "metadata": {},
            "policies": [
                {
                    "role": "analyst",
                    "permissions": ["*"],
                    "sequence": [
                        {
                            "deny": ["@sensitive", "web.request"]
                        }
                    ]
                }
            ]
        }
        
        with pytest.raises(PolicyError, match="Tool groups not defined.*@sensitive"):
            PolicyBundle(bundle_data, mode="file")

    def test_empty_tool_group(self):
        """Test @group reference to empty group."""
        bundle_data = {
            "metadata": {
                "tool_groups": {
                    "empty": []
                }
            },
            "policies": [
                {
                    "role": "analyst",
                    "permissions": ["*"],
                    "sequence": [
                        {
                            "deny": ["@empty", "web.request"]
                        }
                    ]
                }
            ]
        }
        
        bundle = PolicyBundle(bundle_data, mode="file")
        rules = bundle.get_sequence_rules("analyst")["rules"]
        
        # Empty group: rule is kept (lazy expansion), but won't match anything at runtime
        assert len(rules) == 1
        assert rules[0]["deny"] == ["@empty", "web.request"]

    def test_no_group_references(self):
        """Test that rules without @groups remain unchanged."""
        bundle_data = {
            "metadata": {
                "tool_groups": {
                    "sensitive": ["db.read_users"]
                }
            },
            "policies": [
                {
                    "role": "analyst",
                    "permissions": ["*"],
                    "sequence": [
                        {
                            "deny": ["db.read_users", "web.request"],
                            "reason": "Explicit rule"
                        }
                    ]
                }
            ]
        }
        
        bundle = PolicyBundle(bundle_data, mode="file")
        rules = bundle.get_sequence_rules("analyst")["rules"]
        
        # Should remain exactly as specified (no expansion)
        assert len(rules) == 1
        assert {"deny": ["db.read_users", "web.request"], "reason": "Explicit rule"} in rules

    def test_group_with_single_tool(self):
        """Test @group containing only one tool."""
        bundle_data = {
            "metadata": {
                "tool_groups": {
                    "single": ["db.read_users"]
                }
            },
            "policies": [
                {
                    "role": "analyst",
                    "permissions": ["*"],
                    "sequence": [
                        {
                            "deny": ["@single", "web.request"]
                        }
                    ]
                }
            ]
        }
        
        bundle = PolicyBundle(bundle_data, mode="file")
        rules = bundle.get_sequence_rules("analyst")["rules"]
        
        # Should keep @single intact (lazy expansion)
        assert len(rules) == 1
        assert rules[0]["deny"] == ["@single", "web.request"]

    def test_multiple_rules_with_groups(self):
        """Test multiple sequence rules using different groups."""
        bundle_data = {
            "metadata": {
                "tool_groups": {
                    "sensitive": ["db.read_users", "db.read_payments"],
                    "external": ["web.request"],
                    "filesystem": ["file.write"]
                }
            },
            "policies": [
                {
                    "role": "analyst",
                    "permissions": ["*"],
                    "sequence": [
                        {
                            "deny": ["@sensitive", "@external"],
                            "reason": "Rule 1"
                        },
                        {
                            "deny": ["@sensitive", "@filesystem"],
                            "reason": "Rule 2"
                        }
                    ]
                }
            ]
        }
        
        bundle = PolicyBundle(bundle_data, mode="file")
        rules = bundle.get_sequence_rules("analyst")["rules"]
        
        # Should have 2 rules with @groups intact (lazy expansion)
        assert len(rules) == 2
        assert rules[0]["deny"] == ["@sensitive", "@external"]
        assert rules[1]["deny"] == ["@sensitive", "@filesystem"]

    def test_case_sensitive_group_names(self):
        """Test that @group names are case-sensitive."""
        bundle_data = {
            "metadata": {
                "tool_groups": {
                    "Sensitive": ["db.read_users"],
                    "sensitive": ["other.tool"]
                }
            },
            "policies": [
                {
                    "role": "analyst",
                    "permissions": ["*"],
                    "sequence": [
                        {
                            "deny": ["@sensitive", "web.request"]
                        }
                    ]
                }
            ]
        }
        
        bundle = PolicyBundle(bundle_data, mode="file")
        rules = bundle.get_sequence_rules("analyst")["rules"]
        
        # Should keep @sensitive intact (lazy expansion)
        assert len(rules) == 1
        assert rules[0]["deny"] == ["@sensitive", "web.request"]


class TestToolGroupRuntime:
    """Test that lazy @group expansion works correctly at runtime."""

    def test_lazy_expanded_rule_blocks_at_runtime(self):
        """Test that lazy @group expansion blocks sequences at runtime."""
        bundle_data = {
            "metadata": {
                "tool_groups": {
                    "sensitive": ["db.read_users"],
                    "external": ["web.request"]
                }
            },
            "policies": [
                {
                    "role": "analyst",
                    "permissions": ["db.read_users", "web.request"],
                    "sequence": [
                        {
                            "deny": ["@sensitive", "@external"],
                            "reason": "Prevent exfiltration"
                        }
                    ]
                }
            ]
        }
        
        bundle = PolicyBundle(bundle_data, mode="file")
        
        # Check that the lazy @group rule blocks at runtime
        call_history = ["db.read_users"]
        next_tool = "web.request"
        
        # This should find a matching deny rule (with lazy expansion)
        from d2.runtime.sequence import SequenceValidator
        tool_groups = bundle.get_tool_groups()
        validator = SequenceValidator(tool_groups=tool_groups)
        sequence_rules = bundle.get_sequence_rules("analyst")["rules"]
        error = validator.validate_sequence(
            current_history=call_history,
            next_tool_id=next_tool,
            sequence_rules=sequence_rules
        )
        
        assert error is not None
        assert "Prevent exfiltration" in str(error)

    def test_lazy_expanded_allow_overrides_deny(self):
        """Test that lazy allow rules override deny rules."""
        bundle_data = {
            "metadata": {
                "tool_groups": {
                    "sensitive": ["db.read_users", "db.read_payments"],
                    "public": ["db.read_stats"],
                    "external": ["web.request"]
                }
            },
            "policies": [
                {
                    "role": "analyst",
                    "permissions": ["*"],
                    "sequence": [
                        {
                            "deny": ["@sensitive", "@external"]
                        },
                        {
                            "deny": ["@public", "@external"]
                        },
                        {
                            "allow": ["@public", "@external"],
                            "reason": "Public data is safe"
                        }
                    ]
                }
            ]
        }
        
        bundle = PolicyBundle(bundle_data, mode="file")
        
        # db.read_users → web.request should be blocked (sensitive)
        from d2.runtime.sequence import SequenceValidator
        tool_groups = bundle.get_tool_groups()
        validator = SequenceValidator(tool_groups=tool_groups)
        sequence_rules = bundle.get_sequence_rules("analyst")["rules"]
        
        error = validator.validate_sequence(
            current_history=["db.read_users"],
            next_tool_id="web.request",
            sequence_rules=sequence_rules
        )
        assert error is not None  # Should be blocked
        
        # db.read_stats → web.request should be allowed (public override)
        error = validator.validate_sequence(
            current_history=["db.read_stats"],
            next_tool_id="web.request",
            sequence_rules=sequence_rules
        )
        assert error is None  # Should be allowed


class TestToolGroupEdgeCases:
    """Test edge cases and error conditions."""

    def test_group_name_without_at_symbol(self):
        """Test that group names without @ are treated as regular tools."""
        bundle_data = {
            "metadata": {
                "tool_groups": {
                    "sensitive": ["db.read_users"]
                }
            },
            "policies": [
                {
                    "role": "analyst",
                    "permissions": ["*"],
                    "sequence": [
                        {
                            "deny": ["sensitive", "web.request"]
                        }
                    ]
                }
            ]
        }
        
        bundle = PolicyBundle(bundle_data, mode="file")
        rules = bundle.get_sequence_rules("analyst")["rules"]
        
        # "sensitive" without @ should be treated as tool name, not expanded
        assert len(rules) == 1
        assert {"deny": ["sensitive", "web.request"]} in rules

    def test_at_symbol_in_middle_of_name(self):
        """Test that @ symbol only works at start of name."""
        bundle_data = {
            "metadata": {
                "tool_groups": {
                    "sensitive": ["db.read_users"]
                }
            },
            "policies": [
                {
                    "role": "analyst",
                    "permissions": ["*"],
                    "sequence": [
                        {
                            "deny": ["db@sensitive", "web.request"]
                        }
                    ]
                }
            ]
        }
        
        bundle = PolicyBundle(bundle_data, mode="file")
        rules = bundle.get_sequence_rules("analyst")["rules"]
        
        # "db@sensitive" should not be expanded (@ not at start)
        assert len(rules) == 1
        assert {"deny": ["db@sensitive", "web.request"]} in rules

    def test_duplicate_tools_in_expansion(self):
        """Test handling when groups have overlapping tools (lazy expansion)."""
        bundle_data = {
            "metadata": {
                "tool_groups": {
                    "group_a": ["db.read_users", "db.read_payments"],
                    "group_b": ["db.read_users"]  # Overlap with group_a
                }
            },
            "policies": [
                {
                    "role": "analyst",
                    "permissions": ["*"],
                    "sequence": [
                        {
                            "deny": ["@group_a", "web.request"]
                        },
                        {
                            "deny": ["@group_b", "web.request"]
                        }
                    ]
                }
            ]
        }
        
        bundle = PolicyBundle(bundle_data, mode="file")
        rules = bundle.get_sequence_rules("analyst")["rules"]
        
        # Should have 2 rules with @groups intact (lazy expansion)
        # Overlaps are handled naturally at runtime
        assert len(rules) == 2
        assert rules[0]["deny"] == ["@group_a", "web.request"]
        assert rules[1]["deny"] == ["@group_b", "web.request"]

    def test_very_large_group_expansion(self):
        """Test that large groups don't cause memory issues (lazy expansion)."""
        # Create groups with 50 tools each
        large_group_1 = [f"db.read_{i}" for i in range(50)]
        large_group_2 = [f"web.send_{i}" for i in range(50)]
        
        bundle_data = {
            "metadata": {
                "tool_groups": {
                    "large_source": large_group_1,
                    "large_dest": large_group_2
                }
            },
            "policies": [
                {
                    "role": "analyst",
                    "permissions": ["*"],
                    "sequence": [
                        {
                            "deny": ["@large_source", "@large_dest"]
                        }
                    ]
                }
            ]
        }
        
        bundle = PolicyBundle(bundle_data, mode="file")
        rules = bundle.get_sequence_rules("analyst")["rules"]
        
        # Old behavior: 50 × 50 = 2,500 rules in memory
        # New behavior: 1 rule with @groups (lazy expansion at runtime)
        assert len(rules) == 1
        assert rules[0]["deny"] == ["@large_source", "@large_dest"]


class TestToolGroupBackwardCompatibility:
    """Test that existing policies without @groups still work."""

    def test_policy_without_tool_groups_metadata(self):
        """Test policy without tool_groups in metadata."""
        bundle_data = {
            "metadata": {
                "name": "test-policy"
            },
            "policies": [
                {
                    "role": "analyst",
                    "permissions": ["db.read_users"],
                    "sequence": [
                        {
                            "deny": ["db.read_users", "web.request"]
                        }
                    ]
                }
            ]
        }
        
        # Should not raise error
        bundle = PolicyBundle(bundle_data, mode="file")
        rules = bundle.get_sequence_rules("analyst")["rules"]
        
        assert len(rules) == 1
        assert {"deny": ["db.read_users", "web.request"]} in rules

    def test_policy_with_empty_tool_groups(self):
        """Test policy with empty tool_groups object."""
        bundle_data = {
            "metadata": {
                "tool_groups": {}
            },
            "policies": [
                {
                    "role": "analyst",
                    "permissions": ["db.read_users"],
                    "sequence": [
                        {
                            "deny": ["db.read_users", "web.request"]
                        }
                    ]
                }
            ]
        }
        
        bundle = PolicyBundle(bundle_data, mode="file")
        rules = bundle.get_sequence_rules("analyst")["rules"]
        
        assert len(rules) == 1

