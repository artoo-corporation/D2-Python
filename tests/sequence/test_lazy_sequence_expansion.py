# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""Tests for lazy sequence expansion (prevents memory exhaustion).

This tests the refactored approach where @group references are NOT expanded
into cartesian products at policy load time, but instead are matched lazily
at runtime. This prevents memory exhaustion from large group combinations.
"""

import pytest
from d2.policy.bundle import PolicyBundle
from d2.runtime.sequence import SequenceValidator
from d2.exceptions import PolicyError


class TestLazySequenceExpansion:
    """Test that sequence rules use lazy @group expansion instead of eager cartesian product."""

    def test_large_groups_do_not_explode_memory(self):
        """Test that large group combinations don't create memory issues."""
        # This would create 100 × 100 = 10,000 rules with eager expansion
        # With lazy expansion, it's just 1 rule stored in memory
        bundle_data = {
            "metadata": {
                "name": "test",
                "tool_groups": {
                    "database": [f"db.read_{i}" for i in range(100)],
                    "external": [f"api.call_{i}" for i in range(100)]
                }
            },
            "policies": [{
                "role": "analyst",
                "sequence": [
                    {"deny": ["@database", "@external"], "reason": "No exfiltration"}
                ],
                "permissions": ["*"]
            }]
        }
        
        # Should not raise or consume excessive memory
        bundle = PolicyBundle(bundle_data, mode="file")
        
        # Verify only 1 rule stored (not 10,000)
        rules = bundle.get_sequence_rules("analyst")
        assert len(rules) == 1
        assert rules[0]["deny"] == ["@database", "@external"]

    def test_very_large_groups_still_efficient(self):
        """Test that even very large group combinations are memory efficient."""
        # This would create 200 × 200 × 200 = 8,000,000 rules with eager expansion!
        # With lazy expansion: just 1 rule
        bundle_data = {
            "metadata": {
                "name": "test",
                "tool_groups": {
                    "group_a": [f"a.tool_{i}" for i in range(200)],
                    "group_b": [f"b.tool_{i}" for i in range(200)],
                    "group_c": [f"c.tool_{i}" for i in range(200)]
                }
            },
            "policies": [{
                "role": "user",
                "sequence": [
                    {"deny": ["@group_a", "@group_b", "@group_c"]}
                ],
                "permissions": ["*"]
            }]
        }
        
        bundle = PolicyBundle(bundle_data, mode="file")
        rules = bundle.get_sequence_rules("user")
        
        # Only 1 rule stored, not 8 million!
        assert len(rules) == 1
        assert rules[0]["deny"] == ["@group_a", "@group_b", "@group_c"]

    def test_group_reference_matched_at_runtime(self):
        """Test that @group references are expanded lazily during pattern matching."""
        tool_groups = {
            "database": ["db.read_users", "db.read_orders", "db.read_payments"],
            "external": ["api.post", "email.send", "slack.message"]
        }
        
        validator = SequenceValidator(tool_groups=tool_groups)
        
        # Pattern with @group references
        pattern = ["@database", "@external"]
        
        # Should match: any database tool followed by any external tool
        history1 = ["db.read_users", "api.post"]
        assert validator._matches_pattern(history1, pattern) is True
        
        history2 = ["db.read_orders", "email.send"]
        assert validator._matches_pattern(history2, pattern) is True
        
        history3 = ["db.read_payments", "slack.message"]
        assert validator._matches_pattern(history3, pattern) is True
        
        # Should NOT match: wrong order
        history4 = ["api.post", "db.read_users"]
        assert validator._matches_pattern(history4, pattern) is False
        
        # Should NOT match: tools not in groups
        history5 = ["file.read", "api.post"]
        assert validator._matches_pattern(history5, pattern) is False

    def test_mixed_explicit_and_group_references(self):
        """Test patterns with both explicit tool IDs and @group references."""
        tool_groups = {
            "sensitive": ["db.read_users", "db.read_payments", "secrets.get_key"]
        }
        
        validator = SequenceValidator(tool_groups=tool_groups)
        
        # Mixed pattern: explicit tool + @group
        pattern = ["@sensitive", "web.http_request"]
        
        # Should match: any sensitive tool followed by explicit web request
        history1 = ["db.read_users", "web.http_request"]
        assert validator._matches_pattern(history1, pattern) is True
        
        history2 = ["secrets.get_key", "web.http_request"]
        assert validator._matches_pattern(history2, pattern) is True
        
        # Should NOT match: wrong external tool
        history3 = ["db.read_users", "email.send"]
        assert validator._matches_pattern(history3, pattern) is False

    def test_group_matching_with_gaps(self):
        """Test that @group matching works with gaps (subsequence matching)."""
        tool_groups = {
            "database": ["db.read_users", "db.read_orders"],
            "external": ["api.post", "email.send"]
        }
        
        validator = SequenceValidator(tool_groups=tool_groups)
        
        pattern = ["@database", "@external"]
        
        # Should match even with innocent tools in between (prevents evasion)
        history = [
            "db.read_users",
            "analytics.process",  # Innocent tool in between
            "ml.predict",          # Another innocent tool
            "api.post"
        ]
        assert validator._matches_pattern(history, pattern) is True

    def test_unknown_group_reference_caught_at_load_time(self):
        """Test that unknown @group references are caught when policy loads."""
        bundle_data = {
            "metadata": {
                "name": "test",
                "tool_groups": {
                    "database": ["db.read"]
                }
            },
            "policies": [{
                "role": "user",
                "sequence": [
                    {"deny": ["@database", "@nonexistent"]}  # @nonexistent not defined
                ],
                "permissions": ["*"]
            }]
        }
        
        # Should raise PolicyError at load time
        with pytest.raises(PolicyError, match="nonexistent"):
            PolicyBundle(bundle_data, mode="file")

    def test_empty_group_handled_gracefully(self):
        """Test that empty groups don't break pattern matching."""
        tool_groups = {
            "empty_group": [],
            "database": ["db.read"]
        }
        
        validator = SequenceValidator(tool_groups=tool_groups)
        
        pattern = ["@empty_group", "something"]
        
        # Should not match anything (empty group has no tools)
        history = ["db.read", "something"]
        assert validator._matches_pattern(history, pattern) is False

    def test_allow_rules_with_groups(self):
        """Test that allow rules also support @group references."""
        tool_groups = {
            "analytics": ["analytics.summarize", "analytics.aggregate"],
            "reporting": ["report.generate", "dashboard.update"]
        }
        
        validator = SequenceValidator(tool_groups=tool_groups)
        
        # Deny pattern
        deny_pattern = ["@analytics", "@reporting"]
        # Allow pattern (exception)
        allow_pattern = ["analytics.summarize", "report.generate"]
        
        # Should match deny pattern (any analytics → any reporting)
        history1 = ["analytics.aggregate", "dashboard.update"]
        assert validator._matches_pattern(history1, deny_pattern) is True
        
        # Should also match allow pattern (specific exception)
        history2 = ["analytics.summarize", "report.generate"]
        assert validator._matches_pattern(history2, allow_pattern) is True

    def test_sequence_validation_with_lazy_groups(self):
        """Integration test: full sequence validation with lazy group expansion."""
        bundle_data = {
            "metadata": {
                "name": "test",
                "tool_groups": {
                    "database": ["db.read_users", "db.read_orders"],
                    "external": ["api.post", "email.send"]
                }
            },
            "policies": [{
                "role": "analyst",
                "sequence": [
                    {"deny": ["@database", "@external"], "reason": "No exfiltration"}
                ],
                "permissions": ["*"]
            }]
        }
        
        bundle = PolicyBundle(bundle_data, mode="file")
        rules = bundle.get_sequence_rules("analyst")
        
        # Get tool_groups from bundle for validator
        tool_groups = bundle.get_tool_groups()
        validator = SequenceValidator(tool_groups=tool_groups)
        
        # Test validation with @group references
        # History has db.read_users (matches @database), next call is api.post (matches @external)
        current_history = ["db.read_users"]
        next_tool = "api.post"
        error = validator.validate_sequence(
            current_history=current_history,
            next_tool_id=next_tool,
            sequence_rules=rules
        )
        
        assert error is not None
        assert "exfiltration" in error.reason.lower()

    def test_multiple_deny_rules_with_groups(self):
        """Test multiple sequence rules with @group references."""
        bundle_data = {
            "metadata": {
                "name": "test",
                "tool_groups": {
                    "database": ["db.read_users", "db.read_payments"],
                    "filesystem": ["file.write", "file.upload"],
                    "external": ["api.post", "email.send"]
                }
            },
            "policies": [{
                "role": "user",
                "sequence": [
                    {"deny": ["@database", "@external"]},
                    {"deny": ["@database", "@filesystem"]},
                    {"deny": ["@filesystem", "@external"]}
                ],
                "permissions": ["*"]
            }]
        }
        
        bundle = PolicyBundle(bundle_data, mode="file")
        rules = bundle.get_sequence_rules("user")
        
        # Should have 3 rules (not expanded)
        assert len(rules) == 3
        assert rules[0]["deny"] == ["@database", "@external"]
        assert rules[1]["deny"] == ["@database", "@filesystem"]
        assert rules[2]["deny"] == ["@filesystem", "@external"]

    def test_nested_group_references_not_supported(self):
        """Document that we don't support group-of-groups (not needed)."""
        # This is a documentation test - we don't support:
        # @group_of_groups → [@group_a, @group_b]
        # 
        # This is intentional to keep the implementation simple.
        # Users should just reference groups directly.
        pass


class TestBackwardsCompatibility:
    """Test that explicit tool IDs (no @groups) still work."""

    def test_explicit_tool_ids_still_work(self):
        """Test that patterns with explicit tool IDs work as before."""
        bundle_data = {
            "metadata": {"name": "test"},
            "policies": [{
                "role": "user",
                "sequence": [
                    {"deny": ["db.read_users", "api.post"]}
                ],
                "permissions": ["*"]
            }]
        }
        
        bundle = PolicyBundle(bundle_data, mode="file")
        rules = bundle.get_sequence_rules("user")
        
        assert len(rules) == 1
        assert rules[0]["deny"] == ["db.read_users", "api.post"]
        
        # Test matching with explicit IDs
        validator = SequenceValidator(tool_groups={})
        history = ["db.read_users", "api.post"]
        assert validator._matches_pattern(history, ["db.read_users", "api.post"]) is True

    def test_no_groups_defined_works(self):
        """Test that policies without tool_groups still work."""
        bundle_data = {
            "metadata": {"name": "test"},  # No tool_groups
            "policies": [{
                "role": "user",
                "sequence": [
                    {"deny": ["tool.a", "tool.b"]}
                ],
                "permissions": ["*"]
            }]
        }
        
        # Should not raise
        bundle = PolicyBundle(bundle_data, mode="file")
        rules = bundle.get_sequence_rules("user")
        assert len(rules) == 1

