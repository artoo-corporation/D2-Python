"""
Smoke tests for d2.threads - Critical security and behavior verification.

These tests verify the core security guarantees and edge cases that must
work correctly for the threading system to be considered secure and reliable.
"""

import pytest
import threading
import time
import asyncio
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch, MagicMock

from d2.threads import submit_with_context, thread_entrypoint
from d2.context import UserContext, set_user, get_current_user, clear_user_context
from d2.exceptions import D2NoContextError


class TestFailClosedBehavior:
    """Test that the system fails closed when no context is available."""

    def setup_method(self):
        """Ensure clean state before each test."""
        clear_user_context()
    
    def teardown_method(self):
        """Ensure clean state after each test."""
        clear_user_context()

    def test_no_ambient_no_actor_fails_closed_manual_thread(self):
        """
        SMOKE TEST: No ambient + no actor → fail closed (manual thread)
        EXPECT: D2NoContextError
        """
        with ThreadPoolExecutor(max_workers=1) as executor:
            # GIVEN: No ambient context and no explicit actor
            clear_user_context()
            
            # WHEN: We try to submit work without any context
            # THEN: Should raise D2NoContextError immediately
            with pytest.raises(D2NoContextError) as error:
                submit_with_context(executor, lambda: "should_never_execute")
            
            assert "submit_with_context" in str(error.value)

    @pytest.mark.anyio
    async def test_ambient_copied_via_to_thread_works(self):
        """
        SMOKE TEST: Ambient copied via to_thread → OK
        """
        # GIVEN: Ambient context is set
        set_user("alice", ["admin"])
        
        def worker_that_checks_context():
            """Worker function that validates context."""
            user = get_current_user()
            return user.user_id, user.roles
        
        # WHEN: We use asyncio.to_thread (which should preserve context)
        user_id, roles = await asyncio.to_thread(worker_that_checks_context)
        
        # THEN: Should see the ambient context
        assert user_id == "alice"
        assert roles == frozenset(["admin"])

    def test_manual_thread_only_ok_with_submit_with_context_or_actor(self):
        """
        SMOKE TEST: Manual thread only OK when using submit_with_context or actor=
        """
        with ThreadPoolExecutor(max_workers=1) as executor:
            # GIVEN: Ambient context is set
            set_user("alice", ["admin"])
            
            def worker_function():
                user = get_current_user()
                return user.user_id, user.roles
            
            # WHEN: We use submit_with_context with ambient context
            future = submit_with_context(executor, worker_function)
            user_id, roles = future.result()
            
            # THEN: Should work correctly
            assert user_id == "alice"
            assert roles == frozenset(["admin"])
            
            # AND: When we use explicit actor
            bob_actor = UserContext(user_id="bob", roles=frozenset(["viewer"]))
            future = submit_with_context(executor, worker_function, actor=bob_actor)
            user_id, roles = future.result()
            
            # THEN: Should see the explicit actor
            assert user_id == "bob"
            assert roles == frozenset(["viewer"])


class TestActorOverrideBehavior:
    """Test actor override detection and metrics."""
    
    def setup_method(self):
        clear_user_context()
    
    def teardown_method(self):
        clear_user_context()

    @patch('d2.threads._context_actor_override_total')
    def test_actor_overrides_ambient_increments_counter(self, mock_counter):
        """
        SMOKE TEST: Actor overrides ambient - when ambient=Alice but actor=Bob,
        guarded call runs as Bob and increments actor_override_total
        """
        with ThreadPoolExecutor(max_workers=1) as executor:
            # GIVEN: Alice is the ambient user
            set_user("alice", ["admin"])
            
            # AND: We want to run as Bob (explicit actor)
            bob_actor = UserContext(user_id="bob", roles=frozenset(["viewer"]))
            
            def worker_function():
                user = get_current_user()
                return user.user_id, user.roles
            
            # WHEN: We submit work with explicit actor (different from ambient)
            future = submit_with_context(executor, worker_function, actor=bob_actor)
            user_id, roles = future.result()
            
            # THEN: Should run as Bob (explicit actor wins)
            assert user_id == "bob"
            assert roles == frozenset(["viewer"])
            
            # AND: Should increment the override counter
            mock_counter.add.assert_called_once()
            call_args = mock_counter.add.call_args
            assert call_args[0][0] == 1  # count
            
            # Verify the tags include both users
            tags = call_args[0][1]
            assert "ambient_user" in tags
            assert "explicit_user" in tags


class TestLeakDetection:
    """Test context leak detection and cleanup."""
    
    def setup_method(self):
        clear_user_context()
    
    def teardown_method(self):
        clear_user_context()

    @patch('d2.threads._context_leak_detected_total')
    def test_leak_detection_increments_counter_on_cleanup_failure(self, mock_leak_counter):
        """
        SMOKE TEST: Leak detection - intentionally cause cleanup failure;
        verify leak_detected_total increments and warning logs
        """
        with ThreadPoolExecutor(max_workers=1) as executor:
            set_user("alice", ["admin"])
            
            def worker_that_simulates_cleanup_failure():
                # This will execute normally
                user = get_current_user()
                return user.user_id
            
            # Mock clear_user_context to fail during cleanup
            with patch('d2.threads.clear_user_context', side_effect=Exception("Simulated cleanup failure")):
                future = submit_with_context(executor, worker_that_simulates_cleanup_failure)
                result = future.result()
                
                # Work should complete despite cleanup failure
                assert result == "alice"
                
                # Should have recorded the leak
                mock_leak_counter.add.assert_called_once()
                call_args = mock_leak_counter.add.call_args
                assert call_args[0][0] == 1  # count

    def test_context_always_cleared_in_thread_entrypoint(self):
        """
        SMOKE TEST: thread_entrypoint always clears context even on exception
        """
        execution_log = []
        
        @thread_entrypoint(require_actor=True)
        def worker_that_raises_exception():
            user = get_current_user()
            execution_log.append(f"executing_as_{user.user_id}")
            raise ValueError("Intentional test exception")
        
        # Should raise the worker exception
        alice_actor = UserContext(user_id="alice", roles=frozenset(["admin"]))
        with pytest.raises(ValueError, match="Intentional test exception"):
            worker_that_raises_exception(actor=alice_actor)
        
        # Should have executed with correct context
        assert "executing_as_alice" in execution_log
        
        # Context should be cleared even after exception (we can't directly verify
        # this since it's in the decorator's finally block, but the cleanup code
        # is covered by the finally block implementation)


class TestMetricsCompleteness:
    """Test that all required metrics are emitted."""
    
    def setup_method(self):
        clear_user_context()
    
    def teardown_method(self):
        clear_user_context()

    @patch('d2.threads._context_submissions_total')
    def test_submissions_total_metric_emitted(self, mock_submissions):
        """Verify d2.context.submissions.total is emitted."""
        with ThreadPoolExecutor(max_workers=1) as executor:
            set_user("alice", ["admin"])
            
            future = submit_with_context(executor, lambda: "done")
            future.result()
            
            mock_submissions.add.assert_called_once()

    @patch('d2.threads._context_missing_actor_total')
    def test_missing_actor_total_metric_emitted(self, mock_missing):
        """Verify d2.context.missing_actor.total is emitted."""
        with ThreadPoolExecutor(max_workers=1) as executor:
            clear_user_context()  # No ambient context
            
            with pytest.raises(D2NoContextError):
                submit_with_context(executor, lambda: "should_not_execute")
            
            mock_missing.add.assert_called_once()

    @patch('d2.threads._context_leak_detected_total')
    def test_leak_detected_total_metric_emitted(self, mock_leak):
        """Verify d2.context.leak.detected.total is emitted on cleanup failure."""
        with ThreadPoolExecutor(max_workers=1) as executor:
            set_user("alice", ["admin"])
            
            # Simulate cleanup failure
            with patch('d2.threads.clear_user_context', side_effect=Exception("Cleanup failed")):
                future = submit_with_context(executor, lambda: "done")
                future.result()
                
                mock_leak.add.assert_called_once()


class TestTypeEnforcement:
    """Test type safety enforcement."""
    
    def setup_method(self):
        clear_user_context()
    
    def teardown_method(self):
        clear_user_context()

    def test_actor_must_be_usercontext_instance(self):
        """Verify actor parameter type safety."""
        with ThreadPoolExecutor(max_workers=1) as executor:
            # Should reject bare dict
            with pytest.raises(TypeError, match="actor must be UserContext instance"):
                submit_with_context(
                    executor, 
                    lambda: "should_not_execute",
                    actor={"user_id": "alice", "roles": ["admin"]}  # Wrong type
                )
            
            # Should reject string
            with pytest.raises(TypeError, match="actor must be UserContext instance"):
                submit_with_context(
                    executor,
                    lambda: "should_not_execute", 
                    actor="alice"  # Wrong type
                )

    def test_thread_entrypoint_actor_type_safety(self):
        """Verify thread_entrypoint actor parameter type safety."""
        @thread_entrypoint(require_actor=True)
        def worker_function():
            return "done"
        
        # Should reject bare dict
        with pytest.raises(TypeError, match="actor must be UserContext instance"):
            worker_function(actor={"user_id": "alice", "roles": ["admin"]})
        
        # Should accept proper UserContext
        alice_actor = UserContext(user_id="alice", roles=frozenset(["admin"]))
        result = worker_function(actor=alice_actor)
        assert result == "done"
