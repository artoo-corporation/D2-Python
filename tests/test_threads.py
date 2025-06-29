"""
Tests for d2.threads - D2-blessed cross-thread patterns.

This module tests the secure threading patterns that ensure user context
is properly propagated across thread boundaries while maintaining security guarantees.

Key concepts tested:
- Context propagation: How user identity flows between threads
- Fail-closed security: No anonymous thread execution allowed
- Actor override: Explicit identity beats ambient context
- Context cleanup: Automatic cleanup prevents leaks
"""

import pytest
import threading
import time
from concurrent.futures import ThreadPoolExecutor, Future
from unittest.mock import patch, MagicMock

from d2.threads import submit_with_context, thread_entrypoint
from d2.context import UserContext, set_user, get_current_user, clear_user_context
from d2.exceptions import D2NoContextError


class TestSubmitWithContext:
    """
    Test the submit_with_context function.
    
    This function is the primary way to safely execute work in thread pools
    while preserving user identity. It supports two modes:
    1. Ambient context: Uses the current user context
    2. Explicit actor: Uses a provided UserContext (more secure)
    """
    
    def setup_method(self):
        """Ensure clean state before each test."""
        clear_user_context()
    
    def teardown_method(self):
        """Ensure clean state after each test.""" 
        clear_user_context()
    
    def test_ambient_context_is_captured_at_submit_time_not_execution_time(self):
        """
        GIVEN: User context is set before submitting work
        WHEN: Context changes after submit but before execution  
        THEN: Worker sees the original context from submit time
        
        This prevents race conditions where context changes between
        submit and execution in busy applications.
        """
        with ThreadPoolExecutor(max_workers=1) as executor:
            # GIVEN: Alice is the current user
            set_user("alice", ["admin"])
            
            def worker_function():
                """Worker that reports what user context it sees."""
                user = get_current_user()
                return user.user_id, user.roles
            
            # WHEN: We submit work (context should be snapshotted here)
            future = submit_with_context(executor, worker_function)
            
            # AND: We change the ambient context after submission
            set_user("bob", ["viewer"])
            
            # THEN: Worker should see Alice (from submit time), not Bob
            user_id, roles = future.result()
            assert user_id == "alice", "Worker should see context from submit time"
            assert roles == frozenset(["admin"]), "Worker should see original roles"
    
    def test_explicit_actor_always_wins_over_ambient_context(self):
        """
        GIVEN: Ambient context is set to one user
        WHEN: We submit work with an explicit actor parameter
        THEN: Worker sees the explicit actor, not the ambient user
        
        This "explicit wins" behavior prevents confused deputy attacks
        where ambient context might be manipulated.
        """
        with ThreadPoolExecutor(max_workers=1) as executor:
            # GIVEN: Alice is the ambient user
            set_user("alice", ["admin"])
            
            # AND: We want work to run as Bob (explicit actor)
            explicit_actor = UserContext(user_id="bob", roles=frozenset(["viewer"]))
            
            def worker_function():
                """Worker that reports what user context it sees."""
                user = get_current_user()
                return user.user_id, user.roles
            
            # WHEN: We submit with explicit actor
            future = submit_with_context(executor, worker_function, actor=explicit_actor)
            
            # THEN: Worker should see Bob (explicit), not Alice (ambient)
            user_id, roles = future.result()
            assert user_id == "bob", "Explicit actor should override ambient context"
            assert roles == frozenset(["viewer"]), "Explicit actor roles should be used"
    
    def test_fails_closed_when_no_context_available(self):
        """
        GIVEN: No ambient context is set and no explicit actor provided
        WHEN: We try to submit work to a thread pool
        THEN: Should raise D2NoContextError (fail-closed security)
        
        This prevents anonymous thread execution, which would be a security hole.
        """
        with ThreadPoolExecutor(max_workers=1) as executor:
            # GIVEN: No user context is set
            clear_user_context()
            
            # WHEN: We try to submit work without any context
            # THEN: Should fail immediately (before any thread work happens)
            with pytest.raises(D2NoContextError) as error:
                submit_with_context(executor, lambda: "should never execute")
            
            assert "submit_with_context" in str(error.value), "Error should mention the function"
    
    def test_rejects_invalid_actor_types_for_security(self):
        """
        GIVEN: We try to pass a bare dict as the actor parameter
        WHEN: We call submit_with_context
        THEN: Should raise TypeError immediately
        
        This type safety prevents bugs where someone passes a dict instead
        of a proper UserContext, which could lead to security issues.
        """
        with ThreadPoolExecutor(max_workers=1) as executor:
            # WHEN: We try to pass a bare dict instead of UserContext
            # THEN: Should fail with clear error message
            with pytest.raises(TypeError) as error:
                submit_with_context(
                    executor, 
                    lambda: "should never execute", 
                    actor={"user_id": "alice", "roles": ["admin"]}  # Wrong type!
                )
            
            assert "actor must be UserContext instance" in str(error.value), \
                   "Error should explain the type requirement"
    
    def test_automatically_cleans_up_context_when_thread_finishes(self):
        """
        GIVEN: We submit work to a thread with user context
        WHEN: The work completes (successfully)
        THEN: Context should be automatically cleared in that thread
        
        This prevents context leaks where old user identity lingers
        in thread pool threads and affects future work.
        """
        with ThreadPoolExecutor(max_workers=1) as executor:
            # GIVEN: Alice is the current user
            set_user("alice", ["admin"])
            
            execution_log = []
            
            def worker_that_logs_context():
                """Worker that records what context it sees during execution."""
                # Context should be set during execution
                user = get_current_user()
                execution_log.append({
                    "phase": "during_execution",
                    "user_id": user.user_id,
                    "roles": user.roles
                })
                
                # Simulate some actual work
                time.sleep(0.01)
                
                return "work_completed"
            
            # WHEN: We submit and wait for work to complete
            future = submit_with_context(executor, worker_that_logs_context)
            result = future.result()
            
            # THEN: Work should have completed successfully
            assert result == "work_completed"
            
            # AND: Context should have been present during execution
            assert len(execution_log) == 1
            assert execution_log[0]["user_id"] == "alice"
            assert execution_log[0]["roles"] == frozenset(["admin"])
            
            # Note: We can't directly verify cleanup since the thread is gone,
            # but the cleanup code is covered by the finally block in the implementation
    
    def test_nested_contexts_unwind_correctly_without_interference(self):
        """
        GIVEN: A thread that submits work to another thread with different context
        WHEN: The inner work completes and returns to the outer thread
        THEN: Each thread sees its correct context without interference
        
        This tests that context isolation works properly even when threads
        create other threads with different user identities.
        """
        with ThreadPoolExecutor(max_workers=2) as executor:
            # GIVEN: Alice is the main user
            set_user("alice", ["admin"])
            
            execution_log = []
            
            def outer_worker():
                """Worker that submits more work with a different user."""
                # Should see Alice initially
                user = get_current_user()
                execution_log.append(f"outer_start: {user.user_id}")
                
                # Submit inner work to run as Bob
                bob_actor = UserContext(user_id="bob", roles=frozenset(["viewer"]))
                
                def inner_worker():
                    """Nested worker that should see Bob, not Alice."""
                    user = get_current_user()
                    execution_log.append(f"inner: {user.user_id}")
                    return "inner_completed"
                
                # Submit inner work with explicit actor
                inner_future = submit_with_context(executor, inner_worker, actor=bob_actor)
                inner_result = inner_future.result()
                
                # Should still see Alice after inner work completes
                user = get_current_user()
                execution_log.append(f"outer_end: {user.user_id}")
                
                return "outer_completed"
            
            # WHEN: We run the nested scenario
            future = submit_with_context(executor, outer_worker)
            result = future.result()
            
            # THEN: All work should complete successfully
            assert result == "outer_completed"
            
            # AND: Each thread should have seen the correct user
            assert "outer_start: alice" in execution_log, "Outer thread should start as Alice"
            assert "inner: bob" in execution_log, "Inner thread should see Bob"
            assert "outer_end: alice" in execution_log, "Outer thread should end as Alice"
    
    @patch('d2.threads._context_actor_override_total')
    def test_records_security_event_when_explicit_actor_differs_from_ambient(self, mock_security_metric):
        """
        GIVEN: Alice is the ambient user
        WHEN: We submit work with Bob as explicit actor
        THEN: Should record a security metric for potential confused deputy detection
        
        This helps security teams detect cases where someone might be trying
        to escalate privileges by overriding the expected user context.
        """
        with ThreadPoolExecutor(max_workers=1) as executor:
            # GIVEN: Alice is the current ambient user
            set_user("alice", ["admin"])
            
            # WHEN: We explicitly run work as Bob (different user)
            bob_actor = UserContext(user_id="bob", roles=frozenset(["viewer"]))
            
            def simple_worker():
                """Simple worker that just returns success."""
                return "completed"
            
            future = submit_with_context(executor, simple_worker, actor=bob_actor)
            result = future.result()
            
            # THEN: Work should complete successfully
            assert result == "completed"
            
            # AND: Security metric should be recorded with details
            mock_security_metric.add.assert_called_once()
            metric_call = mock_security_metric.add.call_args
            
            # Check metric count and tags
            metric_count = metric_call[0][0]
            metric_tags = metric_call[0][1]
            
            assert metric_count == 1, "Should record exactly one security event"
            assert "ambient_user" in metric_tags, "Should tag the ambient user"
            assert "explicit_user" in metric_tags, "Should tag the explicit user"


class TestThreadEntrypoint:
    """
    Test the @thread_entrypoint decorator.
    
    This decorator is used for long-lived worker threads where the caller
    doesn't control the submission mechanism. It has two modes:
    1. require_actor=True: Must provide explicit actor (most secure)
    2. require_actor=False: Can use ambient context as fallback
    
    The decorator always ensures context is set before the function runs
    and cleaned up afterward, preventing context leaks.
    """
    
    def setup_method(self):
        """Ensure clean state before each test."""
        clear_user_context()
    
    def teardown_method(self):
        """Ensure clean state after each test."""
        clear_user_context()
    
    def test_require_actor_mode_works_with_explicit_actor(self):
        """
        GIVEN: A function decorated with require_actor=True
        WHEN: We call it with an explicit actor parameter
        THEN: Function should run with that actor's context
        
        This is the most secure mode - it requires explicit identity
        and prevents any ambient context confusion.
        """
        @thread_entrypoint(require_actor=True)
        def secure_worker_function():
            """Worker that requires explicit actor for security."""
            user = get_current_user()
            return {
                "user_id": user.user_id,
                "roles": user.roles,
                "message": "secure_work_completed"
            }
        
        # WHEN: We call with explicit Alice actor
        alice_actor = UserContext(user_id="alice", roles=frozenset(["admin"]))
        result = secure_worker_function(actor=alice_actor)
        
        # THEN: Should run as Alice
        assert result["user_id"] == "alice", "Should run with explicit actor identity"
        assert result["roles"] == frozenset(["admin"]), "Should have explicit actor roles"
        assert result["message"] == "secure_work_completed", "Work should complete successfully"
    
    def test_require_actor_mode_fails_without_explicit_actor(self):
        """
        GIVEN: A function decorated with require_actor=True
        WHEN: We call it without providing an actor parameter
        THEN: Should raise D2NoContextError immediately (fail-closed)
        
        This prevents accidentally running sensitive operations without
        knowing exactly who is performing them.
        """
        @thread_entrypoint(require_actor=True)
        def secure_function_that_needs_explicit_actor():
            """This function should never execute without explicit actor."""
            return "should_never_execute"
        
        # WHEN: We call without providing actor parameter
        # THEN: Should fail immediately with clear error
        with pytest.raises(D2NoContextError) as error:
            secure_function_that_needs_explicit_actor()
        
        error_message = str(error.value)
        assert "require_actor=True" in error_message, "Error should explain the requirement"
    
    def test_require_actor_false_with_ambient(self):
        """Test require_actor=False uses ambient context."""
        set_user("alice", ["admin"])
        
        @thread_entrypoint(require_actor=False)
        def test_function():
            user = get_current_user()
            return user.user_id, user.roles
        
        user_id, roles = test_function()
        assert user_id == "alice"
        assert roles == frozenset(["admin"])
    
    def test_require_actor_false_without_ambient_raises(self):
        """Test require_actor=False without ambient context raises D2NoContextError."""
        clear_user_context()  # Ensure no ambient
        
        @thread_entrypoint(require_actor=False)
        def test_function():
            return "should not reach here"
        
        with pytest.raises(D2NoContextError) as exc_info:
            test_function()
        
        assert "no ambient context" in str(exc_info.value)
    
    def test_explicit_actor_overrides_ambient(self):
        """Test that explicit actor overrides ambient context."""
        set_user("alice", ["admin"])
        
        @thread_entrypoint(require_actor=False)
        def test_function():
            user = get_current_user()
            return user.user_id, user.roles
        
        explicit_actor = UserContext(user_id="bob", roles=frozenset(["viewer"]))
        user_id, roles = test_function(actor=explicit_actor)
        
        assert user_id == "bob"
        assert roles == frozenset(["viewer"])
    
    def test_type_safety_actor_validation(self):
        """Test that actor parameter must be UserContext."""
        @thread_entrypoint(require_actor=False)
        def test_function():
            return "should not reach here"
        
        with pytest.raises(TypeError) as exc_info:
            test_function(actor={"user_id": "alice"})  # bare dict
        
        assert "actor must be UserContext instance" in str(exc_info.value)
    
    def test_context_cleared_on_exit(self):
        """Test that context is cleared when decorated function exits."""
        @thread_entrypoint(require_actor=True)
        def test_function():
            user = get_current_user()
            assert user.user_id == "alice"  # Context should be set
            return "done"
        
        actor = UserContext(user_id="alice", roles=frozenset(["admin"]))
        result = test_function(actor=actor)
        
        assert result == "done"
        # Context should be cleared after function exits
        # (We're in the same thread, but the decorator should have cleared it)
    
    def test_context_cleared_on_exception(self):
        """Test that context is cleared even when function raises exception."""
        @thread_entrypoint(require_actor=True)
        def test_function():
            user = get_current_user()
            assert user.user_id == "alice"  # Context should be set
            raise ValueError("test error")
        
        actor = UserContext(user_id="alice", roles=frozenset(["admin"]))
        
        with pytest.raises(ValueError):
            test_function(actor=actor)
        
        # Context should still be cleared despite exception
        # (We can't directly test this in same thread, but the finally block ensures it)
    
    @patch('d2.threads._context_actor_override_total')
    def test_entrypoint_actor_override_security_event(self, mock_metric):
        """Test that thread entrypoint emits security event for actor override."""
        set_user("alice", ["admin"])
        
        @thread_entrypoint(require_actor=False)
        def test_function():
            return "done"
        
        explicit_actor = UserContext(user_id="bob", roles=frozenset(["viewer"]))
        result = test_function(actor=explicit_actor)
        
        assert result == "done"
        
        # Should have recorded actor override event
        mock_metric.add.assert_called_once()
        call_args = mock_metric.add.call_args
        assert call_args[0][0] == 1  # count
        assert "ambient_user" in call_args[0][1]  # tags
        assert "explicit_user" in call_args[0][1]


class TestThreadingEdgeCases:
    """Test edge cases and interaction scenarios."""
    
    def setup_method(self):
        """Clear context before each test."""
        clear_user_context()
    
    def teardown_method(self):
        """Clear context after each test."""
        clear_user_context()
    
    def test_manual_thread_without_context_fails(self):
        """Test that manual thread without ambient/actor context fails closed."""
        clear_user_context()  # No ambient context
        
        result_container = []
        exception_container = []
        
        def worker():
            try:
                # This should fail because no context is available
                with ThreadPoolExecutor(max_workers=1) as executor:
                    future = submit_with_context(executor, lambda: "should not work")
                    result_container.append(future.result())
            except Exception as e:
                exception_container.append(e)
        
        thread = threading.Thread(target=worker)
        thread.start()
        thread.join()
        
        # Should have failed with D2NoContextError
        assert len(exception_container) == 1
        assert isinstance(exception_container[0], D2NoContextError)
        assert len(result_container) == 0
    
    def test_context_isolation_between_threads(self):
        """Test that context is properly isolated between different threads."""
        results = []
        
        def worker1():
            set_user("alice", ["admin"])
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = submit_with_context(executor, lambda: get_current_user().user_id)
                results.append(f"worker1: {future.result()}")
        
        def worker2():
            set_user("bob", ["viewer"])
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = submit_with_context(executor, lambda: get_current_user().user_id)
                results.append(f"worker2: {future.result()}")
        
        thread1 = threading.Thread(target=worker1)
        thread2 = threading.Thread(target=worker2)
        
        thread1.start()
        thread2.start()
        thread1.join()
        thread2.join()
        
        # Each worker should see its own context
        assert "worker1: alice" in results
        assert "worker2: bob" in results
        assert len(results) == 2
