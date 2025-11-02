"""
Tests for d2.context - User identity context management.

The context system manages user identity (user_id + roles) using Python's
contextvars for async-safe, thread-local behavior. Key concepts:

- UserContext: Immutable dataclass holding user_id and roles
- Context managers: set_user_context(), run_as() for scoped identity
- Context helpers: set_user(), get_current_user() for direct access
- Context boundaries: Flows within async tasks but NOT across manual threads
- Leak detection: warn_if_context_set() helps detect context leaks

Security principles:
- Immutable context prevents accidental modification
- Scoped context managers ensure proper cleanup
- Context isolation prevents cross-contamination between operations
"""
import pytest

from d2.context import set_user_context, get_current_user, clear_user_context, warn_if_context_set


def test_context_manager_properly_scopes_and_restores_identity():
    """
    GIVEN: No initial user context is set
    WHEN: We use set_user_context() as a context manager
    THEN: Context should be set within the block and restored afterward
    
    This tests the fundamental scoping behavior that ensures user identity
    is properly isolated and cleaned up.
    """
    # GIVEN: Clean initial state
    clear_user_context()
    
    # WHEN: We use the context manager to set Alice's identity
    with set_user_context("alice", ["admin"]):
        # THEN: Should see Alice within the context
        user = get_current_user()
        assert user.user_id == "alice", "Should see Alice's user ID within context"
        assert user.roles == {"admin"}, "Should see Alice's roles within context"

    # AND: Context should be restored to default after exiting
    restored_user = get_current_user()
    assert restored_user.user_id is None, "User ID should be cleared after context exit"
    assert restored_user.roles is None, "Roles should be cleared after context exit"


def test_leak_detection_identifies_lingering_context(caplog):
    """
    GIVEN: We have context leak detection available
    WHEN: We check for leaks with and without active context
    THEN: Should correctly identify when context is present vs absent
    
    This helps detect bugs where user context isn't properly cleaned up,
    which could lead to security issues or unexpected behavior.
    """
    # GIVEN: Clean state with no context
    clear_user_context()
    
    # WHEN: We check for leaks with no context set
    # THEN: Should report no leak
    no_leak_detected = warn_if_context_set()
    assert no_leak_detected is False, "Should report no leak when context is clean"

    # WHEN: We set context and check for leaks
    with set_user_context("bob", roles=["viewer"]):
        # THEN: Should detect the active context as a potential leak
        leak_detected = warn_if_context_set()
        assert leak_detected is True, "Should detect active context as potential leak"
        
        # AND: Should log a warning message about the leak
        leak_warnings = [rec for rec in caplog.records if "context leaked" in rec.message.lower()]
        assert len(leak_warnings) > 0, "Should log warning about context leak detection" 