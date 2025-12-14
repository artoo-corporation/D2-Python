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
        manager.get_sequence_rules = AsyncMock(return_value=[])
        
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

    @pytest.mark.asyncio
    async def test_fact_recorded_event_emitted(self):
        """Telemetry event should be emitted when facts are recorded."""
        # This test verifies telemetry integration
        pass  # TODO: Implement when telemetry hooks are added

    @pytest.mark.asyncio
    async def test_data_flow_violation_event_emitted(self):
        """Telemetry event should be emitted on data_flow violation."""
        # This test verifies telemetry integration
        pass  # TODO: Implement when telemetry hooks are added

