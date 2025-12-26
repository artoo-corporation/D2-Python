# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""
Tests for context atomicity under concurrent access.

These tests verify that context operations (record_tool_call, record_facts)
are atomic and don't lose data under concurrent access from multiple
async tasks or threads.

Key scenarios tested:
1. Multiple async tasks recording tool calls concurrently
2. Multiple async tasks recording facts concurrently  
3. Mixed tool call and fact recording
4. Thread pool workers accessing context concurrently
"""

import pytest
import asyncio
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from d2.context import (
    set_user,
    get_user_context,
    clear_user_context,
    record_tool_call,
    record_fact,
    record_facts,
    get_facts,
)


class TestRecordToolCallAtomicity:
    """Tests for record_tool_call() atomicity under concurrent access."""

    def setup_method(self):
        """Ensure clean state before each test."""
        clear_user_context()

    def teardown_method(self):
        """Ensure clean state after each test."""
        clear_user_context()

    @pytest.mark.asyncio
    async def test_concurrent_async_tasks_no_lost_tool_calls(self):
        """
        GIVEN: Multiple async tasks recording tool calls concurrently
        WHEN: Each task records multiple tool calls with yields between them
        THEN: No tool calls should be lost due to read-modify-write races
        
        This test exposes the race condition where:
        1. Task A reads call_history = ("tool_1",)
        2. Task B reads call_history = ("tool_1",)  
        3. Task A writes call_history = ("tool_1", "tool_A_2")
        4. Task B writes call_history = ("tool_1", "tool_B_2")  <- loses tool_A_2!
        """
        set_user("test_user", ["admin"])
        
        calls_per_task = 20
        num_tasks = 5
        expected_total = calls_per_task * num_tasks
        
        async def record_tools(task_id: int):
            """Record multiple tool calls with yields to allow interleaving."""
            for i in range(calls_per_task):
                record_tool_call(f"task_{task_id}_tool_{i}")
                # Yield control to allow other tasks to interleave
                await asyncio.sleep(0)
        
        # Run all tasks concurrently
        await asyncio.gather(*[record_tools(i) for i in range(num_tasks)])
        
        ctx = get_user_context()
        actual_count = len(ctx.call_history)
        
        # All tool calls should be recorded - none lost to race conditions
        assert actual_count == expected_total, (
            f"Expected {expected_total} tool calls but got {actual_count}. "
            f"Lost {expected_total - actual_count} calls due to race condition."
        )

    @pytest.mark.asyncio
    async def test_rapid_sequential_tool_calls_preserve_order(self):
        """
        GIVEN: A single async task recording tool calls rapidly
        WHEN: Tool calls are recorded in sequence without yields
        THEN: All calls should be recorded in order
        """
        set_user("test_user", ["admin"])
        
        num_calls = 100
        for i in range(num_calls):
            record_tool_call(f"tool_{i}")
        
        ctx = get_user_context()
        assert len(ctx.call_history) == num_calls
        
        # Verify order is preserved
        for i in range(num_calls):
            assert ctx.call_history[i] == f"tool_{i}", f"Order mismatch at index {i}"

    @pytest.mark.asyncio
    async def test_interleaved_tasks_all_calls_present(self):
        """
        GIVEN: Two async tasks interleaving tool call recordings
        WHEN: Tasks alternate recording with explicit yield points
        THEN: All calls from both tasks should be present (order may vary)
        """
        set_user("test_user", ["admin"])
        
        calls_a = []
        calls_b = []
        
        async def task_a():
            for i in range(10):
                tool_id = f"A_{i}"
                calls_a.append(tool_id)
                record_tool_call(tool_id)
                await asyncio.sleep(0)
        
        async def task_b():
            for i in range(10):
                tool_id = f"B_{i}"
                calls_b.append(tool_id)
                record_tool_call(tool_id)
                await asyncio.sleep(0)
        
        await asyncio.gather(task_a(), task_b())
        
        ctx = get_user_context()
        
        # All calls should be present
        for call in calls_a:
            assert call in ctx.call_history, f"Missing call from task A: {call}"
        for call in calls_b:
            assert call in ctx.call_history, f"Missing call from task B: {call}"
        
        assert len(ctx.call_history) == 20


class TestRecordFactsAtomicity:
    """Tests for record_fact() and record_facts() atomicity."""

    def setup_method(self):
        clear_user_context()

    def teardown_method(self):
        clear_user_context()

    @pytest.mark.asyncio
    async def test_concurrent_fact_recording_no_lost_facts(self):
        """
        GIVEN: Multiple async tasks recording facts concurrently
        WHEN: Each task records multiple facts with yields
        THEN: No facts should be lost due to race conditions
        """
        set_user("test_user", ["admin"])
        
        facts_per_task = 10
        num_tasks = 5
        expected_facts = set()
        
        async def record_task_facts(task_id: int):
            for i in range(facts_per_task):
                fact = f"FACT_TASK_{task_id}_{i}"
                expected_facts.add(fact)
                record_fact(fact)
                await asyncio.sleep(0)
        
        await asyncio.gather(*[record_task_facts(i) for i in range(num_tasks)])
        
        actual_facts = get_facts()
        
        # All facts should be present
        missing = expected_facts - actual_facts
        assert not missing, f"Lost facts due to race condition: {missing}"
        assert len(actual_facts) == len(expected_facts)

    @pytest.mark.asyncio
    async def test_bulk_record_facts_atomic(self):
        """
        GIVEN: A task recording multiple facts at once with record_facts()
        WHEN: Called concurrently with single fact recordings
        THEN: All facts should be captured
        """
        set_user("test_user", ["admin"])
        
        expected_facts = set()
        
        async def bulk_recorder():
            bulk = [f"BULK_{i}" for i in range(10)]
            expected_facts.update(bulk)
            record_facts(bulk)
            await asyncio.sleep(0)
        
        async def single_recorder():
            for i in range(10):
                fact = f"SINGLE_{i}"
                expected_facts.add(fact)
                record_fact(fact)
                await asyncio.sleep(0)
        
        await asyncio.gather(bulk_recorder(), single_recorder())
        
        actual_facts = get_facts()
        missing = expected_facts - actual_facts
        assert not missing, f"Lost facts: {missing}"


class TestMixedContextOperations:
    """Tests for mixed tool call and fact operations."""

    def setup_method(self):
        clear_user_context()

    def teardown_method(self):
        clear_user_context()

    @pytest.mark.asyncio
    async def test_concurrent_tool_calls_and_facts_no_interference(self):
        """
        GIVEN: Concurrent tasks recording both tool calls and facts
        WHEN: Operations are interleaved
        THEN: Neither tool calls nor facts should be lost or corrupted
        """
        set_user("test_user", ["admin"])
        
        expected_tools = []
        expected_facts = set()
        
        async def tool_recorder():
            for i in range(15):
                tool = f"tool_{i}"
                expected_tools.append(tool)
                record_tool_call(tool)
                await asyncio.sleep(0)
        
        async def fact_recorder():
            for i in range(15):
                fact = f"FACT_{i}"
                expected_facts.add(fact)
                record_fact(fact)
                await asyncio.sleep(0)
        
        await asyncio.gather(tool_recorder(), fact_recorder())
        
        ctx = get_user_context()
        
        # Check tools
        missing_tools = set(expected_tools) - set(ctx.call_history)
        assert not missing_tools, f"Lost tools: {missing_tools}"
        
        # Check facts
        missing_facts = expected_facts - ctx.facts
        assert not missing_facts, f"Lost facts: {missing_facts}"


class TestThreadedContextOperations:
    """Tests for context operations across threads."""

    def setup_method(self):
        clear_user_context()

    def teardown_method(self):
        clear_user_context()

    def test_separate_threads_have_isolated_contexts(self):
        """
        GIVEN: Multiple threads each setting their own context
        WHEN: Each thread records tool calls
        THEN: Each thread should only see its own context (isolation)
        
        Note: contextvars provides per-task isolation in async and
        per-thread isolation in sync code.
        """
        results = []
        errors = []
        
        def worker(thread_id: int):
            try:
                # Each thread gets its own context
                set_user(f"user_{thread_id}", [f"role_{thread_id}"])
                
                # Record some tools
                for i in range(5):
                    record_tool_call(f"thread_{thread_id}_tool_{i}")
                
                # Get context - should only see this thread's data
                ctx = get_user_context()
                results.append({
                    "thread_id": thread_id,
                    "user_id": ctx.user_id,
                    "call_count": len(ctx.call_history),
                    "calls": list(ctx.call_history),
                })
                
                clear_user_context()
            except Exception as e:
                errors.append((thread_id, str(e)))
        
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert not errors, f"Thread errors: {errors}"
        
        # Each thread should have seen exactly 5 tool calls (its own)
        for result in results:
            assert result["call_count"] == 5, (
                f"Thread {result['thread_id']} saw {result['call_count']} calls, expected 5"
            )
            # Verify it only saw its own tools
            expected_prefix = f"thread_{result['thread_id']}_tool_"
            for call in result["calls"]:
                assert call.startswith(expected_prefix), (
                    f"Thread {result['thread_id']} saw foreign call: {call}"
                )

    def test_thread_pool_context_isolation(self):
        """
        GIVEN: A thread pool executing tasks with different user contexts
        WHEN: Tasks run concurrently
        THEN: Each task should have isolated context
        """
        results = {}
        
        def worker(task_id: int):
            set_user(f"pool_user_{task_id}", [f"role_{task_id}"])
            time.sleep(0.01)  # Simulate work, allow interleaving
            
            record_tool_call(f"pool_tool_{task_id}")
            
            ctx = get_user_context()
            result = {
                "user_id": ctx.user_id,
                "call_history": list(ctx.call_history),
            }
            
            clear_user_context()
            return task_id, result
        
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(worker, i) for i in range(10)]
            for future in futures:
                task_id, result = future.result()
                results[task_id] = result
        
        # Each task should have seen its own context
        for task_id, result in results.items():
            assert result["user_id"] == f"pool_user_{task_id}"
            assert len(result["call_history"]) == 1
            assert result["call_history"][0] == f"pool_tool_{task_id}"


class TestStressConditions:
    """High-concurrency stress tests for context operations."""

    def setup_method(self):
        clear_user_context()

    def teardown_method(self):
        clear_user_context()

    @pytest.mark.asyncio
    async def test_high_concurrency_stress(self):
        """
        GIVEN: High number of concurrent tasks
        WHEN: All tasks record tool calls and facts simultaneously
        THEN: No data should be lost
        
        This is a stress test to catch subtle race conditions that
        might not appear under light load.
        """
        set_user("stress_test_user", ["admin"])
        
        num_tasks = 50
        ops_per_task = 20
        expected_tool_count = num_tasks * ops_per_task
        expected_fact_count = num_tasks * ops_per_task
        
        async def stress_worker(task_id: int):
            for i in range(ops_per_task):
                record_tool_call(f"stress_{task_id}_{i}")
                record_fact(f"STRESS_FACT_{task_id}_{i}")
                # Yield frequently to maximize interleaving
                if i % 2 == 0:
                    await asyncio.sleep(0)
        
        await asyncio.gather(*[stress_worker(i) for i in range(num_tasks)])
        
        ctx = get_user_context()
        
        actual_tool_count = len(ctx.call_history)
        actual_fact_count = len(ctx.facts)
        
        # Check for any data loss
        tool_loss = expected_tool_count - actual_tool_count
        fact_loss = expected_fact_count - actual_fact_count
        
        assert tool_loss == 0, (
            f"Lost {tool_loss} tool calls out of {expected_tool_count} "
            f"({100*tool_loss/expected_tool_count:.1f}% loss rate)"
        )
        assert fact_loss == 0, (
            f"Lost {fact_loss} facts out of {expected_fact_count} "
            f"({100*fact_loss/expected_fact_count:.1f}% loss rate)"
        )


