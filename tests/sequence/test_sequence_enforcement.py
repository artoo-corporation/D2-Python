# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""Unit tests for sequence enforcement (call-flow authorization)."""

import pytest
from d2.context import UserContext
from d2.exceptions import PermissionDeniedError
from d2.runtime.sequence import SequenceValidator


class TestSequenceValidator:
    """Test the core sequence validation logic."""

    def test_empty_history_always_allowed(self):
        """First call in a sequence should always pass."""
        validator = SequenceValidator()
        rules = [{"deny": ["database.read", "web.request"], "reason": "Test"}]
        
        error = validator.validate_sequence(
            current_history=(),
            next_tool_id="database.read",
            sequence_rules=rules
        )
        
        assert error is None

    def test_two_step_deny_sequence(self):
        """Block exact two-step deny patterns."""
        validator = SequenceValidator()
        rules = [{"deny": ["database.read", "web.request"], "reason": "Exfiltration"}]
        
        error = validator.validate_sequence(
            current_history=("database.read",),
            next_tool_id="web.request",
            sequence_rules=rules
        )
        
        assert error is not None
        assert isinstance(error, PermissionDeniedError)
        assert "sequence_violation" in error.reason
        assert "Exfiltration" in error.reason

    def test_allowed_sequence(self):
        """Allow sequences that don't match deny patterns."""
        validator = SequenceValidator()
        rules = [{"deny": ["database.read", "web.request"], "reason": "Test"}]
        
        # Different sequence should be allowed
        error = validator.validate_sequence(
            current_history=("analytics.summarize",),
            next_tool_id="database.read",
            sequence_rules=rules
        )
        
        assert error is None

    def test_three_step_deny_sequence(self):
        """Block three-step transitive patterns."""
        validator = SequenceValidator()
        rules = [{
            "deny": ["database.read", "analytics.process", "web.request"],
            "reason": "Transitive exfiltration"
        }]
        
        # Should block the exact three-step pattern
        error = validator.validate_sequence(
            current_history=("database.read", "analytics.process"),
            next_tool_id="web.request",
            sequence_rules=rules
        )
        
        assert error is not None
        assert "Transitive exfiltration" in error.reason

    def test_multiple_rules(self):
        """Enforce all deny rules."""
        validator = SequenceValidator()
        rules = [
            {"deny": ["database.read", "web.request"], "reason": "Direct exfil"},
            {"deny": ["secrets.get", "web.request"], "reason": "Secret leak"},
        ]
        
        # First rule triggers
        error = validator.validate_sequence(
            current_history=("database.read",),
            next_tool_id="web.request",
            sequence_rules=rules
        )
        assert error is not None
        assert "Direct exfil" in error.reason
        
        # Second rule triggers
        error = validator.validate_sequence(
            current_history=("secrets.get",),
            next_tool_id="web.request",
            sequence_rules=rules
        )
        assert error is not None
        assert "Secret leak" in error.reason

    def test_pattern_matching_in_middle_of_sequence(self):
        """Deny patterns can match anywhere in the history."""
        validator = SequenceValidator()
        rules = [{"deny": ["database.read", "web.request"], "reason": "Test"}]
        
        # Pattern appears in middle of longer history
        error = validator.validate_sequence(
            current_history=("auth.login", "database.read"),
            next_tool_id="web.request",
            sequence_rules=rules
        )
        
        assert error is not None

    def test_exact_match_required(self):
        """Tool IDs must match exactly (no wildcards in this version)."""
        validator = SequenceValidator()
        rules = [{"deny": ["database.read_users", "web.request"], "reason": "Test"}]
        
        # Different tool (database.read_orders) should not match
        error = validator.validate_sequence(
            current_history=("database.read_orders",),
            next_tool_id="web.request",
            sequence_rules=rules
        )
        
        assert error is None

    def test_empty_rules_always_allow(self):
        """No rules means all sequences are allowed."""
        validator = SequenceValidator()
        
        error = validator.validate_sequence(
            current_history=("database.read", "analytics.process"),
            next_tool_id="web.request",
            sequence_rules=[]
        )
        
        assert error is None

    def test_invalid_rule_structure_skipped(self):
        """Malformed rules should be safely skipped."""
        validator = SequenceValidator()
        rules = [
            {"deny": ["database.read", "web.request"], "reason": "Valid"},
            {"invalid": "structure"},  # Malformed
            {"deny": []},  # Empty deny list
        ]
        
        # Should still enforce the valid rule
        error = validator.validate_sequence(
            current_history=("database.read",),
            next_tool_id="web.request",
            sequence_rules=rules
        )
        
        assert error is not None
        assert "Valid" in error.reason

    def test_longer_history_only_checks_relevant_window(self):
        """Should check sliding windows of history."""
        validator = SequenceValidator()
        rules = [{"deny": ["database.read", "web.request"], "reason": "Test"}]
        
        # Long history with deny pattern buried in it
        error = validator.validate_sequence(
            current_history=("auth.login", "analytics.load", "database.read"),
            next_tool_id="web.request",
            sequence_rules=rules
        )
        
        assert error is not None


class TestSequenceValidatorEdgeCases:
    """Test edge cases and error handling."""

    def test_single_step_deny_pattern(self):
        """Single-step patterns should never trigger (need at least 2)."""
        validator = SequenceValidator()
        rules = [{"deny": ["web.request"], "reason": "Test"}]
        
        error = validator.validate_sequence(
            current_history=(),
            next_tool_id="web.request",
            sequence_rules=rules
        )
        
        # Single step pattern doesn't make sense for sequences
        assert error is None

    def test_very_long_deny_pattern(self):
        """Support long multi-step patterns."""
        validator = SequenceValidator()
        rules = [{
            "deny": ["step1", "step2", "step3", "step4", "step5"],
            "reason": "Complex pattern"
        }]
        
        error = validator.validate_sequence(
            current_history=("step1", "step2", "step3", "step4"),
            next_tool_id="step5",
            sequence_rules=rules
        )
        
        assert error is not None

    def test_reason_is_optional(self):
        """Rules without reason should still work (with default message)."""
        validator = SequenceValidator()
        rules = [{"deny": ["database.read", "web.request"]}]  # No reason
        
        error = validator.validate_sequence(
            current_history=("database.read",),
            next_tool_id="web.request",
            sequence_rules=rules
        )
        
        assert error is not None
        assert "sequence_violation" in error.reason


class TestSequenceIntegrationScenarios:
    """Test real-world attack scenarios."""

    def test_direct_exfiltration_blocked(self):
        """Block database -> web pattern."""
        validator = SequenceValidator()
        rules = [{
            "deny": ["database.read_users", "web.http_request"],
            "reason": "Database access followed by external request may exfiltrate data"
        }]
        
        error = validator.validate_sequence(
            current_history=("database.read_users",),
            next_tool_id="web.http_request",
            sequence_rules=rules
        )
        
        assert error is not None
        assert "exfiltrate data" in error.reason

    def test_secrets_leak_blocked(self):
        """Block secrets -> web pattern."""
        validator = SequenceValidator()
        rules = [{
            "deny": ["secrets.get_api_key", "web.http_request"],
            "reason": "Secrets access followed by external request may leak credentials"
        }]
        
        error = validator.validate_sequence(
            current_history=("secrets.get_api_key",),
            next_tool_id="web.http_request",
            sequence_rules=rules
        )
        
        assert error is not None
        assert "leak credentials" in error.reason

    def test_safe_analytics_workflow_allowed(self):
        """Allow analytics -> database -> return (no external I/O)."""
        validator = SequenceValidator()
        rules = [{
            "deny": ["database.read_users", "web.http_request"],
            "reason": "Exfiltration"
        }]
        
        # Analytics workflow without external calls should be fine
        error = validator.validate_sequence(
            current_history=("analytics.initialize",),
            next_tool_id="database.read_users",
            sequence_rules=rules
        )
        assert error is None
        
        error = validator.validate_sequence(
            current_history=("analytics.initialize", "database.read_users"),
            next_tool_id="analytics.summarize",
            sequence_rules=rules
        )
        assert error is None

    def test_transitive_exfiltration_blocked(self):
        """Block database -> analytics -> web (three-step laundering)."""
        validator = SequenceValidator()
        rules = [{
            "deny": ["database.read_users", "analytics.process", "web.http_request"],
            "reason": "Transitive data flow to external endpoints"
        }]
        
        error = validator.validate_sequence(
            current_history=("database.read_users", "analytics.process"),
            next_tool_id="web.http_request",
            sequence_rules=rules
        )
        
        assert error is not None
        assert "Transitive" in error.reason


class TestSequenceValidatorUserIdentity:
    """Tests for user identity propagation in sequence denial errors.
    
    When a sequence violation occurs, the PermissionDeniedError should include
    the actual user's identity (from context) for proper audit logging and
    incident response. Using a generic placeholder obscures who triggered
    the denial.
    """

    def test_denial_error_includes_real_user_id_from_context(self):
        """
        GIVEN: A user with specific identity triggers a sequence violation
        WHEN: SequenceValidator returns a PermissionDeniedError
        THEN: The error should include the real user_id from context
        
        BUG: Original implementation used user_id="(sequence_context)" placeholder,
        which obscures the actual caller's identity in audit logs.
        """
        from d2.context import set_user_context, clear_user_context
        
        validator = SequenceValidator()
        rules = [{"deny": ["database.read", "web.request"], "reason": "Exfiltration"}]
        
        # GIVEN: Alice triggers a sequence violation
        with set_user_context(user_id="alice", roles=["analyst"]):
            error = validator.validate_sequence(
                current_history=("database.read",),
                next_tool_id="web.request",
                sequence_rules=rules
            )
        
        # THEN: Error should contain Alice's user_id, not a placeholder
        assert error is not None
        assert error.user_id == "alice", \
            f"Expected user_id='alice', got '{error.user_id}'. " \
            "Denial errors should include the real user for audit logging."

    def test_denial_error_includes_real_roles_from_context(self):
        """
        GIVEN: A user with specific roles triggers a sequence violation
        WHEN: SequenceValidator returns a PermissionDeniedError  
        THEN: The error should include the user's actual roles
        """
        from d2.context import set_user_context, clear_user_context
        
        validator = SequenceValidator()
        rules = [{"deny": ["secrets.read", "web.request"], "reason": "Leak"}]
        
        with set_user_context(user_id="bob", roles=["developer", "secrets-reader"]):
            error = validator.validate_sequence(
                current_history=("secrets.read",),
                next_tool_id="web.request",
                sequence_rules=rules
            )
        
        assert error is not None
        assert "developer" in error.roles or error.roles == ["developer", "secrets-reader"], \
            f"Expected roles from context, got '{error.roles}'"

    def test_denial_error_handles_missing_context_gracefully(self):
        """
        GIVEN: No user context is set (edge case / bug in calling code)
        WHEN: A sequence violation occurs
        THEN: Should still return error with sensible fallback, not crash
        """
        from d2.context import clear_user_context
        
        clear_user_context()  # Ensure no context set
        
        validator = SequenceValidator()
        rules = [{"deny": ["a", "b"], "reason": "Test"}]
        
        # Should not crash even without context
        error = validator.validate_sequence(
            current_history=("a",),
            next_tool_id="b",
            sequence_rules=rules
        )
        
        assert error is not None
        # With no context, should use some sensible fallback (not crash)
        # The specific fallback value is implementation-dependent
        assert error.user_id is not None

