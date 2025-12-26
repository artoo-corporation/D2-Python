# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""Tests for data_flow facts system.

The data_flow system provides semantic labeling for data provenance tracking:
- Tools can "label" data when they run (e.g., database.read labels as SENSITIVE)
- Labels can "block" other tools from running (e.g., SENSITIVE blocks @egress_tools)

This prevents data exfiltration even when attackers try to pivot to different
egress channels after an initial path is blocked.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from d2.context import (
    UserContext,
    set_user,
    get_user_context,
    clear_user_context,
    record_fact,
    record_facts,
    get_facts,
    has_fact,
    has_any_fact,
)

class TestUserContextFacts:
    """Tests for facts field in UserContext."""

    def setup_method(self):
        clear_user_context()

    def teardown_method(self):
        clear_user_context()

    def test_user_context_has_facts_field(self):
        """UserContext should have a facts field that defaults to empty frozenset."""
        ctx = get_user_context()
        assert hasattr(ctx, "facts")
        assert ctx.facts == frozenset()

    def test_set_user_initializes_empty_facts(self):
        """set_user should initialize facts as empty frozenset."""
        set_user("alice", ["admin"])
        ctx = get_user_context()
        assert ctx.facts == frozenset()

    def test_record_fact_adds_single_fact(self):
        """record_fact should add a single fact to the context."""
        set_user("alice", ["admin"])
        record_fact("SENSITIVE")
        ctx = get_user_context()
        assert "SENSITIVE" in ctx.facts

    def test_record_fact_accumulates(self):
        """Multiple record_fact calls should accumulate facts."""
        set_user("alice", ["admin"])
        record_fact("SENSITIVE")
        record_fact("PII")
        record_fact("SECRET")
        ctx = get_user_context()
        assert ctx.facts == frozenset({"SENSITIVE", "PII", "SECRET"})

    def test_record_fact_is_idempotent(self):
        """Recording the same fact twice should not duplicate it."""
        set_user("alice", ["admin"])
        record_fact("SENSITIVE")
        record_fact("SENSITIVE")
        ctx = get_user_context()
        assert ctx.facts == frozenset({"SENSITIVE"})

    def test_record_facts_adds_multiple(self):
        """record_facts should add multiple facts at once."""
        set_user("alice", ["admin"])
        record_facts(["SENSITIVE", "PII", "SECRET"])
        ctx = get_user_context()
        assert ctx.facts == frozenset({"SENSITIVE", "PII", "SECRET"})

    def test_record_facts_merges_with_existing(self):
        """record_facts should merge with existing facts."""
        set_user("alice", ["admin"])
        record_fact("EXISTING")
        record_facts(["NEW1", "NEW2"])
        ctx = get_user_context()
        assert ctx.facts == frozenset({"EXISTING", "NEW1", "NEW2"})

    def test_get_facts_returns_current_facts(self):
        """get_facts should return the current accumulated facts."""
        set_user("alice", ["admin"])
        record_facts(["A", "B", "C"])
        assert get_facts() == frozenset({"A", "B", "C"})

    def test_has_fact_returns_true_when_present(self):
        """has_fact should return True when the fact exists."""
        set_user("alice", ["admin"])
        record_fact("SENSITIVE")
        assert has_fact("SENSITIVE") is True

    def test_has_fact_returns_false_when_absent(self):
        """has_fact should return False when the fact doesn't exist."""
        set_user("alice", ["admin"])
        assert has_fact("SENSITIVE") is False

    def test_has_any_fact_returns_true_when_any_present(self):
        """has_any_fact should return True if any specified fact exists."""
        set_user("alice", ["admin"])
        record_fact("PII")
        assert has_any_fact(["SENSITIVE", "PII", "SECRET"]) is True

    def test_has_any_fact_returns_false_when_none_present(self):
        """has_any_fact should return False if none of the specified facts exist."""
        set_user("alice", ["admin"])
        record_fact("OTHER")
        assert has_any_fact(["SENSITIVE", "PII", "SECRET"]) is False

    def test_facts_preserved_across_record_tool_call(self):
        """Facts should be preserved when recording tool calls."""
        from d2.context import record_tool_call
        
        set_user("alice", ["admin"])
        record_fact("SENSITIVE")
        record_tool_call("database.read")
        ctx = get_user_context()
        assert ctx.facts == frozenset({"SENSITIVE"})
        assert ctx.call_history == ("database.read",)

    def test_facts_cleared_with_context(self):
        """Facts should be cleared when context is cleared."""
        set_user("alice", ["admin"])
        record_facts(["SENSITIVE", "PII"])
        clear_user_context()
        ctx = get_user_context()
        assert ctx.facts == frozenset()

class TestPolicyBundleDataFlow:
    """Tests for data_flow parsing in PolicyBundle."""

    def test_bundle_parses_labels(self):
        """PolicyBundle should parse data_flow.labels section."""
        from d2.policy.bundle import PolicyBundle
        
        raw_bundle = {
            "metadata": {
                "name": "test-app",
                "expires": "2099-12-31T00:00:00Z",
                "data_flow": {
                    "labels": {
                        "database.read": ["SENSITIVE"],
                        "secrets.get": ["SECRET"],
                    },
                    "blocks": {
                        "SENSITIVE": ["http.request"],
                    },
                },
            },
            "policies": [
                {"role": "admin", "permissions": ["*"]},
            ],
        }
        
        bundle = PolicyBundle(raw_bundle=raw_bundle, mode="file")
        
        assert bundle.get_labels_for_tool("database.read") == {"SENSITIVE"}
        assert bundle.get_labels_for_tool("secrets.get") == {"SECRET"}
        assert bundle.get_labels_for_tool("unknown.tool") == set()

    def test_bundle_parses_blocks(self):
        """PolicyBundle should parse data_flow.blocks section."""
        from d2.policy.bundle import PolicyBundle
        
        raw_bundle = {
            "metadata": {
                "name": "test-app",
                "expires": "2099-12-31T00:00:00Z",
                "data_flow": {
                    "labels": {
                        "database.read": ["SENSITIVE"],
                    },
                    "blocks": {
                        "SENSITIVE": ["http.request", "email.send"],
                        "SECRET": ["http.request"],
                    },
                },
            },
            "policies": [
                {"role": "admin", "permissions": ["*"]},
            ],
        }
        
        bundle = PolicyBundle(raw_bundle=raw_bundle, mode="file")
        
        assert bundle.get_blocking_labels_for_tool("http.request") == {"SENSITIVE", "SECRET"}
        assert bundle.get_blocking_labels_for_tool("email.send") == {"SENSITIVE"}
        assert bundle.get_blocking_labels_for_tool("slack.post") == set()

    def test_bundle_expands_tool_groups_in_labels(self):
        """Labels should support @group expansion."""
        from d2.policy.bundle import PolicyBundle
        
        raw_bundle = {
            "metadata": {
                "name": "test-app",
                "expires": "2099-12-31T00:00:00Z",
                "tool_groups": {
                    "sensitive_data": ["database.read_users", "database.read_payments"],
                },
                "data_flow": {
                    "labels": {
                        "@sensitive_data": ["SENSITIVE", "PII"],
                    },
                    "blocks": {},
                },
            },
            "policies": [
                {"role": "admin", "permissions": ["*"]},
            ],
        }
        
        bundle = PolicyBundle(raw_bundle=raw_bundle, mode="file")
        
        assert bundle.get_labels_for_tool("database.read_users") == {"SENSITIVE", "PII"}
        assert bundle.get_labels_for_tool("database.read_payments") == {"SENSITIVE", "PII"}

    def test_bundle_expands_tool_groups_in_blocks(self):
        """Blocks should support @group expansion."""
        from d2.policy.bundle import PolicyBundle
        
        raw_bundle = {
            "metadata": {
                "name": "test-app",
                "expires": "2099-12-31T00:00:00Z",
                "tool_groups": {
                    "egress_tools": ["http.request", "email.send", "slack.post"],
                },
                "data_flow": {
                    "labels": {},
                    "blocks": {
                        "SENSITIVE": ["@egress_tools"],
                    },
                },
            },
            "policies": [
                {"role": "admin", "permissions": ["*"]},
            ],
        }
        
        bundle = PolicyBundle(raw_bundle=raw_bundle, mode="file")
        
        assert bundle.get_blocking_labels_for_tool("http.request") == {"SENSITIVE"}
        assert bundle.get_blocking_labels_for_tool("email.send") == {"SENSITIVE"}
        assert bundle.get_blocking_labels_for_tool("slack.post") == {"SENSITIVE"}

    def test_bundle_handles_missing_data_flow(self):
        """PolicyBundle should handle missing data_flow section gracefully."""
        from d2.policy.bundle import PolicyBundle
        
        raw_bundle = {
            "metadata": {
                "name": "test-app",
                "expires": "2099-12-31T00:00:00Z",
            },
            "policies": [
                {"role": "admin", "permissions": ["*"]},
            ],
        }
        
        bundle = PolicyBundle(raw_bundle=raw_bundle, mode="file")
        
        assert bundle.get_labels_for_tool("database.read") == set()
        assert bundle.get_blocking_labels_for_tool("http.request") == set()

class TestDataFlowEnforcement:
    """Tests for data_flow enforcement in the decorator."""

    @pytest.fixture
    def mock_policy_manager(self):
        """Create a mock policy manager with data_flow rules."""
        manager = MagicMock()
        manager.mode = "file"
        manager._init_complete = MagicMock()
        manager._init_complete.is_set.return_value = True
        manager._init_complete.wait = AsyncMock()
        
        # Mock bundle with data_flow rules
        bundle = MagicMock()
        bundle.all_known_tools = {"database.read", "http.request", "analytics.process"}
        bundle.tool_to_roles = {
            "database.read": {"agent"},
            "http.request": {"agent"},
            "analytics.process": {"agent"},
            "*": set(),
        }
        bundle.role_to_sequences = {}
        bundle.get_tool_groups.return_value = {}
        bundle.get_labels_for_tool = MagicMock(side_effect=lambda t: {"SENSITIVE"} if t == "database.read" else set())
        bundle.get_blocking_labels_for_tool = MagicMock(side_effect=lambda t: {"SENSITIVE"} if t == "http.request" else set())
        
        manager._get_bundle.return_value = bundle
        manager._policy_bundle = bundle
        manager.check_async = AsyncMock(return_value=True)
        manager.is_tool_in_policy_async = AsyncMock(return_value=True)
        manager.get_tool_conditions = AsyncMock(return_value=None)
        manager.get_sequence_rules = AsyncMock(return_value=(None, []))
        
        return manager

    @pytest.mark.asyncio
    async def test_tool_records_labels_after_execution(self, mock_policy_manager):
        """Tool should record its labels as facts after successful execution."""
        from d2.decorator import d2_guard
        from d2.context import set_user, clear_user_context, get_facts
        
        clear_user_context()
        set_user("agent-1", ["agent"])
        
        with patch("d2.decorator.get_policy_manager", return_value=mock_policy_manager):
            @d2_guard("database.read")
            async def read_database():
                return {"users": []}
            
            result = await read_database()
            
            # After execution, SENSITIVE should be in facts
            assert "SENSITIVE" in get_facts()
        
        clear_user_context()

    @pytest.mark.asyncio
    async def test_tool_blocked_by_existing_facts(self, mock_policy_manager):
        """Tool should be blocked if blocking labels are present in facts."""
        from d2.decorator import d2_guard
        from d2.context import set_user, clear_user_context, record_fact
        from d2.exceptions import PermissionDeniedError
        
        clear_user_context()
        set_user("agent-1", ["agent"])
        
        # Pre-set SENSITIVE fact (simulating previous tool run)
        record_fact("SENSITIVE")
        
        with patch("d2.decorator.get_policy_manager", return_value=mock_policy_manager):
            @d2_guard("http.request")
            async def send_request():
                return {"status": "sent"}
            
            with pytest.raises(PermissionDeniedError) as exc_info:
                await send_request()
            
            assert "data_flow_violation" in str(exc_info.value)
            assert "SENSITIVE" in str(exc_info.value)
        
        clear_user_context()

    @pytest.mark.asyncio
    async def test_tool_allowed_when_no_blocking_facts(self, mock_policy_manager):
        """Tool should be allowed when no blocking facts are present."""
        from d2.decorator import d2_guard
        from d2.context import set_user, clear_user_context, record_fact
        
        clear_user_context()
        set_user("agent-1", ["agent"])
        
        # Set a different fact that doesn't block http.request
        record_fact("OTHER_FACT")
        
        with patch("d2.decorator.get_policy_manager", return_value=mock_policy_manager):
            @d2_guard("http.request")
            async def send_request():
                return {"status": "sent"}
            
            result = await send_request()
            assert result == {"status": "sent"}
        
        clear_user_context()

    @pytest.mark.asyncio
    async def test_full_flow_database_to_http_blocked(self, mock_policy_manager):
        """Complete flow: database.read -> http.request should be blocked."""
        from d2.decorator import d2_guard
        from d2.context import set_user, clear_user_context, get_facts
        from d2.exceptions import PermissionDeniedError
        
        clear_user_context()
        set_user("agent-1", ["agent"])
        
        with patch("d2.decorator.get_policy_manager", return_value=mock_policy_manager):
            @d2_guard("database.read")
            async def read_database():
                return {"users": ["alice", "bob"]}
            
            @d2_guard("http.request")
            async def send_request(data):
                return {"status": "sent"}
            
            # Step 1: Read database - should succeed and add SENSITIVE fact
            data = await read_database()
            assert "SENSITIVE" in get_facts()
            
            # Step 2: Try to send via HTTP - should be blocked
            with pytest.raises(PermissionDeniedError) as exc_info:
                await send_request(data)
            
            assert "data_flow_violation" in str(exc_info.value)
        
        clear_user_context()

    @pytest.mark.asyncio
    async def test_pivot_attack_blocked(self, mock_policy_manager):
        """Pivot attack: database.read -> analytics -> http.request should be blocked."""
        from d2.decorator import d2_guard
        from d2.context import set_user, clear_user_context, get_facts
        from d2.exceptions import PermissionDeniedError
        
        clear_user_context()
        set_user("agent-1", ["agent"])
        
        with patch("d2.decorator.get_policy_manager", return_value=mock_policy_manager):
            @d2_guard("database.read")
            async def read_database():
                return {"users": ["alice", "bob"]}
            
            @d2_guard("analytics.process")
            async def process_data(data):
                return {"summary": "2 users"}
            
            @d2_guard("http.request")
            async def send_request(data):
                return {"status": "sent"}
            
            # Step 1: Read database
            data = await read_database()
            assert "SENSITIVE" in get_facts()
            
            # Step 2: Process (innocent tool, should succeed)
            summary = await process_data(data)
            # SENSITIVE fact persists
            assert "SENSITIVE" in get_facts()
            
            # Step 3: Try to exfil via HTTP - should STILL be blocked
            with pytest.raises(PermissionDeniedError):
                await send_request(summary)
        
        clear_user_context()

    @pytest.mark.asyncio
    async def test_on_deny_handler_called_for_data_flow_violation(self, mock_policy_manager):
        """on_deny handler should be called for data_flow violations."""
        from d2.decorator import d2_guard
        from d2.context import set_user, clear_user_context, record_fact
        
        clear_user_context()
        set_user("agent-1", ["agent"])
        record_fact("SENSITIVE")
        
        deny_handler_called = False
        
        def deny_handler(error):
            nonlocal deny_handler_called
            deny_handler_called = True
            return {"error": "blocked"}
        
        with patch("d2.decorator.get_policy_manager", return_value=mock_policy_manager):
            @d2_guard("http.request", on_deny=deny_handler)
            async def send_request():
                return {"status": "sent"}
            
            result = await send_request()
            assert deny_handler_called
            assert result == {"error": "blocked"}
        
        clear_user_context()

class TestDataFlowTelemetry:
    """Tests for data_flow telemetry events."""

    def setup_method(self):
        clear_user_context()

    def teardown_method(self):
        clear_user_context()

    def test_fact_recorded_metric_emitted(self):
        """OTEL metric should be emitted when facts are recorded via record_fact()."""
        from d2.telemetry.metrics import facts_recorded_total
        
        set_user("agent-1", ["agent"])
        
        # Mock the metric's add method to verify it's called
        original_add = facts_recorded_total.add
        calls = []
        
        def mock_add(value, attributes=None):
            calls.append({"value": value, "attributes": attributes})
            return original_add(value, attributes)
        
        facts_recorded_total.add = mock_add
        try:
            record_fact("SENSITIVE")
            record_fact("PII")
            
            # Verify metric was emitted for each fact
            assert len(calls) == 2
            assert calls[0]["attributes"]["fact"] == "SENSITIVE"
            assert calls[1]["attributes"]["fact"] == "PII"
        finally:
            facts_recorded_total.add = original_add

    def test_record_facts_emits_metrics_for_each(self):
        """record_facts() should emit a metric for each fact."""
        from d2.telemetry.metrics import facts_recorded_total
        
        set_user("agent-1", ["agent"])
        
        original_add = facts_recorded_total.add
        calls = []
        
        def mock_add(value, attributes=None):
            calls.append({"value": value, "attributes": attributes})
            return original_add(value, attributes)
        
        facts_recorded_total.add = mock_add
        try:
            record_facts(["SENSITIVE", "PII", "SECRET"])
            
            # Verify metric was emitted for each fact
            assert len(calls) == 3
            recorded_facts = {c["attributes"]["fact"] for c in calls}
            assert recorded_facts == {"SENSITIVE", "PII", "SECRET"}
        finally:
            facts_recorded_total.add = original_add

    @pytest.mark.asyncio
    async def test_data_flow_blocked_metric_emitted(self):
        """data_flow_blocked_total should be emitted when a tool is blocked by facts."""
        from d2.decorator import d2_guard
        from d2.telemetry.metrics import data_flow_blocked_total
        from d2.exceptions import PermissionDeniedError
        
        # Create a mock policy manager with data_flow rules
        manager = MagicMock()
        manager.mode = "file"
        manager._init_complete = MagicMock()
        manager._init_complete.is_set.return_value = True
        manager._init_complete.wait = AsyncMock()
        
        bundle = MagicMock()
        bundle.all_known_tools = {"http.request"}
        bundle.tool_to_roles = {"http.request": {"agent"}, "*": set()}
        bundle.role_to_sequences = {}
        bundle.get_tool_groups.return_value = {}
        bundle.get_labels_for_tool = MagicMock(return_value=set())
        bundle.get_blocking_labels_for_tool = MagicMock(return_value={"SENSITIVE"})
        
        manager._get_bundle.return_value = bundle
        manager._policy_bundle = bundle
        manager.check_async = AsyncMock(return_value=True)
        manager.is_tool_in_policy_async = AsyncMock(return_value=True)
        manager.get_tool_conditions = AsyncMock(return_value=None)
        manager.get_sequence_rules = AsyncMock(return_value=(None, []))
        manager._usage_reporter = None
        
        set_user("agent-1", ["agent"])
        record_fact("SENSITIVE")  # Pre-set blocking fact
        
        # Mock the blocked metric
        original_add = data_flow_blocked_total.add
        calls = []
        
        def mock_add(value, attributes=None):
            calls.append({"value": value, "attributes": attributes})
            return original_add(value, attributes)
        
        data_flow_blocked_total.add = mock_add
        
        try:
            with patch("d2.decorator.get_policy_manager", return_value=manager):
                @d2_guard("http.request")
                async def send_request():
                    return {"status": "sent"}
                
                with pytest.raises(PermissionDeniedError):
                    await send_request()
            
            # Verify data_flow_blocked_total metric was emitted
            assert len(calls) == 1
            assert calls[0]["attributes"]["tool_id"] == "http.request"
            assert "SENSITIVE" in calls[0]["attributes"]["blocking_label"]
        finally:
            data_flow_blocked_total.add = original_add

    @pytest.mark.asyncio
    async def test_cloud_event_emitted_on_labels_recorded(self):
        """UsageReporter should receive data_flow_labels_emitted event when tool emits labels."""
        from d2.decorator import d2_guard
        
        # Create a mock policy manager
        manager = MagicMock()
        manager.mode = "cloud"
        manager._init_complete = MagicMock()
        manager._init_complete.is_set.return_value = True
        manager._init_complete.wait = AsyncMock()
        
        bundle = MagicMock()
        bundle.all_known_tools = {"database.read"}
        bundle.tool_to_roles = {"database.read": {"agent"}, "*": set()}
        bundle.role_to_sequences = {}
        bundle.get_tool_groups.return_value = {}
        bundle.get_labels_for_tool = MagicMock(return_value={"SENSITIVE", "PII"})
        bundle.get_blocking_labels_for_tool = MagicMock(return_value=set())
        
        manager._get_bundle.return_value = bundle
        manager._policy_bundle = bundle
        manager.check_async = AsyncMock(return_value=True)
        manager.is_tool_in_policy_async = AsyncMock(return_value=True)
        manager.get_tool_conditions = AsyncMock(return_value=None)
        manager.get_sequence_rules = AsyncMock(return_value=(None, []))
        
        # Mock UsageReporter
        mock_reporter = MagicMock()
        track_event_calls = []
        
        def mock_track_event(event_type, event_data):
            track_event_calls.append({"event_type": event_type, "event_data": event_data})
        
        mock_reporter.track_event = mock_track_event
        manager._usage_reporter = mock_reporter
        
        set_user("agent-1", ["agent"])
        
        with patch("d2.decorator.get_policy_manager", return_value=manager):
            @d2_guard("database.read")
            async def read_database():
                return {"users": ["alice"]}
            
            await read_database()
        
        # Find the data_flow_labels_emitted event
        labels_events = [c for c in track_event_calls if c["event_type"] == "data_flow_labels_emitted"]
        assert len(labels_events) == 1
        assert labels_events[0]["event_data"]["tool_id"] == "database.read"
        assert set(labels_events[0]["event_data"]["labels"]) == {"SENSITIVE", "PII"}

    @pytest.mark.asyncio
    async def test_cloud_event_emitted_on_data_flow_violation(self):
        """UsageReporter should receive authz_decision event on data_flow violation."""
        from d2.decorator import d2_guard
        from d2.exceptions import PermissionDeniedError
        
        # Create a mock policy manager
        manager = MagicMock()
        manager.mode = "cloud"
        manager._init_complete = MagicMock()
        manager._init_complete.is_set.return_value = True
        manager._init_complete.wait = AsyncMock()
        
        bundle = MagicMock()
        bundle.all_known_tools = {"http.request"}
        bundle.tool_to_roles = {"http.request": {"agent"}, "*": set()}
        bundle.role_to_sequences = {}
        bundle.get_tool_groups.return_value = {}
        bundle.get_labels_for_tool = MagicMock(return_value=set())
        bundle.get_blocking_labels_for_tool = MagicMock(return_value={"SENSITIVE", "SECRET"})
        
        manager._get_bundle.return_value = bundle
        manager._policy_bundle = bundle
        manager.check_async = AsyncMock(return_value=True)
        manager.is_tool_in_policy_async = AsyncMock(return_value=True)
        manager.get_tool_conditions = AsyncMock(return_value=None)
        manager.get_sequence_rules = AsyncMock(return_value=(None, []))
        
        # Mock UsageReporter
        mock_reporter = MagicMock()
        track_event_calls = []
        
        def mock_track_event(event_type, event_data):
            track_event_calls.append({"event_type": event_type, "event_data": event_data})
        
        mock_reporter.track_event = mock_track_event
        manager._usage_reporter = mock_reporter
        
        set_user("agent-1", ["agent"])
        record_fact("SENSITIVE")  # Pre-set blocking fact
        
        with patch("d2.decorator.get_policy_manager", return_value=manager):
            @d2_guard("http.request")
            async def send_request():
                return {"status": "sent"}
            
            with pytest.raises(PermissionDeniedError):
                await send_request()
        
        # Find the authz_decision event with data_flow_violation reason
        authz_events = [
            c for c in track_event_calls 
            if c["event_type"] == "authz_decision" and c["event_data"].get("reason") == "data_flow_violation"
        ]
        assert len(authz_events) == 1
        event_data = authz_events[0]["event_data"]
        assert event_data["tool_id"] == "http.request"
        assert event_data["result"] == "denied"
        assert "SENSITIVE" in event_data["violated_facts"]
        assert "SENSITIVE" in event_data["blocking_labels"]