# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""Unit tests for sequence mode enforcement (default allow vs default deny).

This module tests the two sequence enforcement modes:
1. "allow" mode (default): Blocklist approach - deny specific patterns, allow everything else
2. "deny" mode: Allowlist approach - allow specific patterns, deny everything else (zero-trust)
"""

import pytest
from d2.exceptions import PermissionDeniedError
from d2.runtime.sequence import SequenceValidator


class TestSequenceModeLegacyBehavior:
    """Test backward compatibility - sequences without explicit mode behave as before."""

    def test_no_mode_specified_defaults_to_allow(self):
        """When no mode is specified, should default to 'allow' (current behavior)."""
        validator = SequenceValidator()
        rules = [{"deny": ["database.read", "web.request"], "reason": "Exfil"}]
        
        # Matching deny pattern should be blocked
        error = validator.validate_sequence(
            current_history=("database.read",),
            next_tool_id="web.request",
            sequence_rules=rules,
            mode=None  # No mode specified
        )
        assert error is not None
        
        # Non-matching pattern should be allowed (default allow)
        error = validator.validate_sequence(
            current_history=("analytics.process",),
            next_tool_id="file.write",
            sequence_rules=rules,
            mode=None
        )
        assert error is None

    def test_empty_rules_with_no_mode_allows_everything(self):
        """No rules + no mode = allow everything (backward compatible)."""
        validator = SequenceValidator()
        
        error = validator.validate_sequence(
            current_history=("database.read",),
            next_tool_id="web.request",
            sequence_rules=[],
            mode=None
        )
        assert error is None


class TestSequenceModeExplicitAllow:
    """Test explicit 'allow' mode (blocklist approach)."""

    def test_allow_mode_permits_non_matching_sequences(self):
        """In allow mode, sequences not matching deny rules should pass."""
        validator = SequenceValidator()
        rules = [
            {"deny": ["database.read", "web.request"], "reason": "Direct exfil"},
            {"deny": ["secrets.get", "web.request"], "reason": "Secret leak"}
        ]
        
        # Safe sequence should be allowed
        error = validator.validate_sequence(
            current_history=("analytics.process",),
            next_tool_id="database.read",
            sequence_rules=rules,
            mode="allow"
        )
        assert error is None

    def test_allow_mode_blocks_matching_deny_patterns(self):
        """In allow mode, explicit deny patterns should be blocked."""
        validator = SequenceValidator()
        rules = [{"deny": ["database.read", "web.request"], "reason": "Exfil"}]
        
        error = validator.validate_sequence(
            current_history=("database.read",),
            next_tool_id="web.request",
            sequence_rules=rules,
            mode="allow"
        )
        assert error is not None
        assert "sequence_violation" in error.reason
        assert "Exfil" in error.reason

    def test_allow_mode_with_allow_rules_overrides_deny(self):
        """In allow mode, explicit allow rules should override deny rules."""
        validator = SequenceValidator()
        rules = [
            {"deny": ["database.read", "web.request"], "reason": "Exfil"},
            {"allow": ["database.read", "web.request"], "reason": "Safe API"}
        ]
        
        # Allow rule should override deny rule
        error = validator.validate_sequence(
            current_history=("database.read",),
            next_tool_id="web.request",
            sequence_rules=rules,
            mode="allow"
        )
        assert error is None

    def test_allow_mode_empty_rules_permits_everything(self):
        """In allow mode with no rules, everything should be allowed."""
        validator = SequenceValidator()
        
        error = validator.validate_sequence(
            current_history=("database.read", "analytics.process"),
            next_tool_id="web.request",
            sequence_rules=[],
            mode="allow"
        )
        assert error is None


class TestSequenceModeDeny:
    """Test 'deny' mode (allowlist/zero-trust approach)."""

    def test_deny_mode_blocks_non_matching_sequences(self):
        """In deny mode, sequences without explicit allow rules should be denied."""
        validator = SequenceValidator()
        rules = [
            {"allow": ["database.read", "analytics.process"], "reason": "Safe pipeline"}
        ]
        
        # Non-matching sequence should be blocked (default deny)
        error = validator.validate_sequence(
            current_history=("database.read",),
            next_tool_id="web.request",
            sequence_rules=rules,
            mode="deny"
        )
        assert error is not None
        assert "sequence_violation" in error.reason
        assert "No matching allow rule" in error.reason

    def test_deny_mode_allows_matching_allow_patterns(self):
        """In deny mode, sequences matching allow rules should pass."""
        validator = SequenceValidator()
        rules = [
            {"allow": ["database.read", "analytics.process"], "reason": "Safe"}
        ]
        
        # Matching allow pattern should pass
        error = validator.validate_sequence(
            current_history=("database.read",),
            next_tool_id="analytics.process",
            sequence_rules=rules,
            mode="deny"
        )
        assert error is None

    def test_deny_mode_empty_rules_blocks_everything(self):
        """In deny mode with no rules, everything should be blocked (fail-closed)."""
        validator = SequenceValidator()
        
        error = validator.validate_sequence(
            current_history=("database.read",),
            next_tool_id="web.request",
            sequence_rules=[],
            mode="deny"
        )
        assert error is not None
        assert "No matching allow rule" in error.reason

    def test_deny_mode_first_call_also_blocked_without_allow(self):
        """In deny mode, even the first call requires an allow rule."""
        validator = SequenceValidator()
        rules = [
            {"allow": ["analytics.process", "file.write"], "reason": "Safe"}
        ]
        
        # First call without matching allow should be blocked
        error = validator.validate_sequence(
            current_history=(),
            next_tool_id="database.read",
            sequence_rules=rules,
            mode="deny"
        )
        assert error is not None

    def test_deny_mode_allows_first_call_with_allow_rule(self):
        """In deny mode, first call with allow rule should pass."""
        validator = SequenceValidator()
        rules = [
            {"allow": ["database.read"], "reason": "Initial read allowed"}
        ]
        
        # First call with allow rule should pass
        error = validator.validate_sequence(
            current_history=(),
            next_tool_id="database.read",
            sequence_rules=rules,
            mode="deny"
        )
        assert error is None

    def test_deny_mode_with_deny_rules_has_no_effect(self):
        """In deny mode, deny rules are ignored (only allow rules matter)."""
        validator = SequenceValidator()
        rules = [
            {"deny": ["database.read", "web.request"], "reason": "Ignored"},
            {"allow": ["database.read", "web.request"], "reason": "Explicit allow"}
        ]
        
        # Allow rule should work, deny rule should be ignored
        error = validator.validate_sequence(
            current_history=("database.read",),
            next_tool_id="web.request",
            sequence_rules=rules,
            mode="deny"
        )
        assert error is None

    def test_deny_mode_allows_multiple_valid_patterns(self):
        """In deny mode, multiple allow rules create multiple valid paths."""
        validator = SequenceValidator()
        rules = [
            {"allow": ["database.read", "analytics.process"], "reason": "Path 1"},
            {"allow": ["web.request", "analytics.summarize"], "reason": "Path 2"}
        ]
        
        # First path should work
        error = validator.validate_sequence(
            current_history=("database.read",),
            next_tool_id="analytics.process",
            sequence_rules=rules,
            mode="deny"
        )
        assert error is None
        
        # Second path should work
        error = validator.validate_sequence(
            current_history=("web.request",),
            next_tool_id="analytics.summarize",
            sequence_rules=rules,
            mode="deny"
        )
        assert error is None
        
        # Invalid path should be blocked
        error = validator.validate_sequence(
            current_history=("database.read",),
            next_tool_id="web.request",
            sequence_rules=rules,
            mode="deny"
        )
        assert error is not None


class TestSequenceModeWithToolGroups:
    """Test sequence modes work correctly with @group references."""

    def test_allow_mode_with_group_deny_rules(self):
        """Allow mode should block @group deny patterns."""
        validator = SequenceValidator(tool_groups={
            "sensitive": ["database.read", "secrets.get"],
            "external": ["web.request", "email.send"]
        })
        
        rules = [
            {"deny": ["@sensitive", "@external"], "reason": "Exfil"}
        ]
        
        # @group deny pattern should block
        error = validator.validate_sequence(
            current_history=("database.read",),
            next_tool_id="web.request",
            sequence_rules=rules,
            mode="allow"
        )
        assert error is not None

    def test_deny_mode_with_group_allow_rules(self):
        """Deny mode should allow @group allow patterns."""
        validator = SequenceValidator(tool_groups={
            "internal": ["database.read", "analytics.process"],
            "safe_output": ["file.write", "cache.set"]
        })
        
        rules = [
            {"allow": ["@internal", "@safe_output"], "reason": "Safe pipeline"}
        ]
        
        # @group allow pattern should pass
        error = validator.validate_sequence(
            current_history=("database.read",),
            next_tool_id="file.write",
            sequence_rules=rules,
            mode="deny"
        )
        assert error is None
        
        # Non-matching should be blocked
        error = validator.validate_sequence(
            current_history=("database.read",),
            next_tool_id="web.request",
            sequence_rules=rules,
            mode="deny"
        )
        assert error is not None


class TestSequenceModeComplexScenarios:
    """Test complex real-world scenarios for both modes."""

    def test_allow_mode_zero_trust_equivalent_via_deny_all_except(self):
        """Allow mode can simulate zero-trust by denying everything except specific patterns."""
        validator = SequenceValidator()
        
        # This is awkward in allow mode - need to enumerate all bad patterns
        # (This demonstrates why deny mode is better for zero-trust)
        rules = [
            {"deny": ["database.read", "web.request"], "reason": "Block"},
            {"deny": ["database.read", "email.send"], "reason": "Block"},
            {"deny": ["secrets.get", "web.request"], "reason": "Block"},
            # ... would need to enumerate all combinations
            {"allow": ["database.read", "analytics.process"], "reason": "Allowed path"}
        ]
        
        # Allowed path works
        error = validator.validate_sequence(
            current_history=("database.read",),
            next_tool_id="analytics.process",
            sequence_rules=rules,
            mode="allow"
        )
        assert error is None

    def test_deny_mode_regulated_industry_workflow(self):
        """Deny mode for regulated industry: only pre-approved workflows allowed."""
        validator = SequenceValidator()
        
        # Healthcare: Only specific data flows allowed
        rules = [
            {"allow": ["ehr.read_patient", "hipaa.validate", "report.generate"], 
             "reason": "Approved HIPAA workflow"},
            {"allow": ["ehr.read_patient", "analytics.anonymize", "research.submit"],
             "reason": "Approved research workflow"}
        ]
        
        # Approved workflow 1
        error = validator.validate_sequence(
            current_history=("ehr.read_patient", "hipaa.validate"),
            next_tool_id="report.generate",
            sequence_rules=rules,
            mode="deny"
        )
        assert error is None
        
        # Approved workflow 2
        error = validator.validate_sequence(
            current_history=("ehr.read_patient", "analytics.anonymize"),
            next_tool_id="research.submit",
            sequence_rules=rules,
            mode="deny"
        )
        assert error is None
        
        # Unapproved workflow (even reading patient data)
        error = validator.validate_sequence(
            current_history=("ehr.read_patient",),
            next_tool_id="email.send",  # Not in allowed patterns
            sequence_rules=rules,
            mode="deny"
        )
        assert error is not None

    def test_deny_mode_agentic_ai_sandbox(self):
        """Deny mode for AI agent: only safe tool sequences allowed."""
        validator = SequenceValidator()
        
        # AI agent can only use pre-approved sequences
        rules = [
            {"allow": ["web.search", "llm.summarize"], "reason": "Research workflow"},
            {"allow": ["database.query", "llm.analyze"], "reason": "Data analysis"},
            {"allow": ["llm.summarize", "report.save"], "reason": "Report generation"}
        ]
        
        # Agent can search and summarize
        error = validator.validate_sequence(
            current_history=("web.search",),
            next_tool_id="llm.summarize",
            sequence_rules=rules,
            mode="deny"
        )
        assert error is None
        
        # Agent cannot exfiltrate data (not in allow list)
        error = validator.validate_sequence(
            current_history=("database.query",),
            next_tool_id="web.post",  # Not allowed
            sequence_rules=rules,
            mode="deny"
        )
        assert error is not None

    def test_mode_switching_between_roles(self):
        """Different roles can use different modes (allow for trusted, deny for restricted)."""
        validator = SequenceValidator()
        
        # Trusted admin: allow mode with minimal restrictions
        admin_rules = [
            {"deny": ["database.delete_all", "web.request"], "reason": "Prevent accidents"}
        ]
        
        error = validator.validate_sequence(
            current_history=("database.read",),
            next_tool_id="email.send",
            sequence_rules=admin_rules,
            mode="allow"  # Most things allowed
        )
        assert error is None
        
        # Restricted contractor: deny mode with strict allowlist
        contractor_rules = [
            {"allow": ["analytics.read", "report.generate"], "reason": "Limited access"}
        ]
        
        error = validator.validate_sequence(
            current_history=("analytics.read",),
            next_tool_id="report.generate",
            sequence_rules=contractor_rules,
            mode="deny"  # Only specific patterns allowed
        )
        assert error is None
        
        error = validator.validate_sequence(
            current_history=("analytics.read",),
            next_tool_id="email.send",  # Not allowed
            sequence_rules=contractor_rules,
            mode="deny"
        )
        assert error is not None


class TestSequenceModeInvalidInputs:
    """Test error handling for invalid mode values."""

    def test_invalid_mode_string_defaults_to_allow(self):
        """Invalid mode string should default to 'allow' mode (safe fallback)."""
        validator = SequenceValidator()
        rules = [{"deny": ["database.read", "web.request"], "reason": "Test"}]
        
        # Invalid mode should default to allow behavior
        error = validator.validate_sequence(
            current_history=("analytics.process",),
            next_tool_id="file.write",
            sequence_rules=rules,
            mode="invalid_mode"  # Invalid
        )
        assert error is None  # Should be allowed (default allow)

    def test_mode_case_insensitive(self):
        """Mode should be case-insensitive (ALLOW, Allow, allow all work)."""
        validator = SequenceValidator()
        rules = [{"allow": ["database.read", "analytics.process"], "reason": "Safe"}]
        
        # Test uppercase (full 2-step sequence)
        error = validator.validate_sequence(
            current_history=("database.read",),
            next_tool_id="analytics.process",
            sequence_rules=rules,
            mode="DENY"
        )
        assert error is None
        
        # Test mixed case (full 2-step sequence)
        error = validator.validate_sequence(
            current_history=("database.read",),
            next_tool_id="analytics.process",
            sequence_rules=rules,
            mode="Deny"
        )
        assert error is None


class TestSequenceModeEdgeCases:
    """Test edge cases specific to mode handling."""

    def test_deny_mode_with_gaps_in_sequence(self):
        """Deny mode should still allow gaps in matching patterns (like allow mode)."""
        validator = SequenceValidator()
        rules = [
            {"allow": ["database.read", "web.request"], "reason": "Allowed"}
        ]
        
        # Pattern with gap should still match
        error = validator.validate_sequence(
            current_history=("database.read", "analytics.process"),
            next_tool_id="web.request",
            sequence_rules=rules,
            mode="deny"
        )
        assert error is None

    def test_deny_mode_three_step_pattern(self):
        """Deny mode should support multi-step patterns like allow mode."""
        validator = SequenceValidator()
        rules = [
            {"allow": ["step1", "step2", "step3"], "reason": "Multi-step workflow"}
        ]
        
        error = validator.validate_sequence(
            current_history=("step1", "step2"),
            next_tool_id="step3",
            sequence_rules=rules,
            mode="deny"
        )
        assert error is None
        
        # Missing step should block
        error = validator.validate_sequence(
            current_history=("step1",),
            next_tool_id="step3",  # Skipped step2
            sequence_rules=rules,
            mode="deny"
        )
        assert error is not None

    def test_deny_mode_single_step_allow_pattern_is_valid(self):
        """Single-step allow patterns ARE valid in deny mode (whitelist first calls)."""
        validator = SequenceValidator()
        rules = [
            {"allow": ["database.read"], "reason": "Allow first call"}
        ]
        
        # Should be allowed (single-step patterns valid in deny mode)
        error = validator.validate_sequence(
            current_history=(),
            next_tool_id="database.read",
            sequence_rules=rules,
            mode="deny"
        )
        assert error is None  # Single-step pattern matches
        
        # Different tool should be blocked
        error = validator.validate_sequence(
            current_history=(),
            next_tool_id="web.request",
            sequence_rules=rules,
            mode="deny"
        )
        assert error is not None  # Not in allow list

