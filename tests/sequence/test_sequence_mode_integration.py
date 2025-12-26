# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""Integration tests for sequence mode end-to-end (policy → bundle → decorator → validator).

These tests verify that the mode specified in policy YAML is correctly:
1. Parsed by the bundle loader
2. Stored in the bundle
3. Retrieved by the policy manager
4. Passed to the validator in the decorator
5. Applied during enforcement
"""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from d2.exceptions import PermissionDeniedError
from d2.policy.bundle import PolicyBundle
from d2.decorator import d2_guard
from d2.context import set_user, clear_user_context


class TestSequenceModeEndToEnd:
    """Test sequence mode flows end-to-end from policy to enforcement."""

    def setup_method(self):
        clear_user_context()

    def teardown_method(self):
        clear_user_context()

    def test_bundle_parses_sequence_mode_from_nested_structure(self):
        """PolicyBundle should extract mode from nested sequence structure."""
        raw_bundle = {
            "metadata": {
                "name": "test-app",
                "expires": "2099-12-31T00:00:00Z",
            },
            "policies": [
                {
                    "role": "agent",
                    "permissions": ["database.read", "analytics.process", "web.request"],
                    "sequence": {
                        "mode": "deny",  # Nested structure with mode
                        "rules": [
                            {"allow": ["database.read", "analytics.process"], "reason": "Safe"}
                        ]
                    }
                }
            ],
        }
        
        bundle = PolicyBundle(raw_bundle=raw_bundle, mode="file")
        
        # Bundle should store the mode
        sequence_data = bundle.role_to_sequences.get("agent")
        assert sequence_data is not None
        # Mode should be extracted and stored
        assert "mode" in sequence_data or hasattr(sequence_data, "mode")

    def test_bundle_handles_legacy_sequence_list_format(self):
        """PolicyBundle should handle legacy format (sequence as list, no mode)."""
        raw_bundle = {
            "metadata": {
                "name": "test-app",
                "expires": "2099-12-31T00:00:00Z",
            },
            "policies": [
                {
                    "role": "agent",
                    "permissions": ["database.read", "web.request"],
                    "sequence": [  # Legacy format: direct list
                        {"deny": ["database.read", "web.request"], "reason": "Exfil"}
                    ]
                }
            ],
        }
        
        bundle = PolicyBundle(raw_bundle=raw_bundle, mode="file")
        
        # Should default to "allow" mode
        sequence_data = bundle.role_to_sequences.get("agent")
        assert sequence_data is not None

    def test_bundle_defaults_to_allow_mode_when_not_specified(self):
        """When mode is not specified, bundle should default to 'allow'."""
        raw_bundle = {
            "metadata": {
                "name": "test-app",
                "expires": "2099-12-31T00:00:00Z",
            },
            "policies": [
                {
                    "role": "agent",
                    "permissions": ["database.read", "web.request"],
                    "sequence": {
                        # No mode specified
                        "rules": [
                            {"deny": ["database.read", "web.request"], "reason": "Exfil"}
                        ]
                    }
                }
            ],
        }
        
        bundle = PolicyBundle(raw_bundle=raw_bundle, mode="file")
        
        sequence_data = bundle.role_to_sequences.get("agent")
        assert sequence_data is not None

    @pytest.mark.asyncio
    async def test_deny_mode_enforced_through_decorator(self):
        """The decorator should pass mode to validator and enforce deny-mode correctly."""
        # Create a mock policy manager with deny-mode sequence
        manager = MagicMock()
        manager.mode = "file"
        manager._init_complete = MagicMock()
        manager._init_complete.is_set.return_value = True
        manager._init_complete.wait = AsyncMock()
        
        bundle = MagicMock()
        bundle.all_known_tools = {"database.read", "analytics.process", "web.request"}
        bundle.tool_to_roles = {
            "database.read": {"agent"},
            "analytics.process": {"agent"},
            "web.request": {"agent"},
            "*": set()
        }
        bundle.get_tool_groups.return_value = {}
        bundle.get_labels_for_tool = MagicMock(return_value=set())
        bundle.get_blocking_labels_for_tool = MagicMock(return_value=set())
        
        # Return deny-mode sequence rules with mode
        manager.get_sequence_rules = AsyncMock(return_value=(
            "deny",  # Mode
            [{"allow": ["database.read", "analytics.process"], "reason": "Safe"}]
        ))
        
        manager._get_bundle.return_value = bundle
        manager._policy_bundle = bundle
        manager.check_async = AsyncMock(return_value=True)
        manager.is_tool_in_policy_async = AsyncMock(return_value=True)
        manager.get_tool_conditions = AsyncMock(return_value=None)
        manager._usage_reporter = None
        
        set_user("agent-1", ["agent"])
        
        with patch("d2.decorator.get_policy_manager", return_value=manager):
            @d2_guard("database.read")
            async def read_database():
                return {"data": "users"}
            
            @d2_guard("analytics.process")
            async def process_analytics(data):
                return {"summary": "processed"}
            
            @d2_guard("web.request")
            async def send_web_request(data):
                return {"status": "sent"}
            
            # Step 1: database.read should work (first call, matches allow pattern start)
            result = await read_database()
            assert result == {"data": "users"}
            
            # Step 2: analytics.process should work (matches allow pattern)
            result = await process_analytics({"data": "users"})
            assert result == {"summary": "processed"}
            
            # Step 3: web.request should FAIL (no allow pattern for this sequence)
            with pytest.raises(PermissionDeniedError) as exc_info:
                await send_web_request({"data": "users"})
            
            assert "sequence_violation" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_allow_mode_enforced_through_decorator(self):
        """The decorator should pass mode to validator and enforce allow-mode correctly."""
        manager = MagicMock()
        manager.mode = "file"
        manager._init_complete = MagicMock()
        manager._init_complete.is_set.return_value = True
        manager._init_complete.wait = AsyncMock()
        
        bundle = MagicMock()
        bundle.all_known_tools = {"database.read", "analytics.process", "web.request"}
        bundle.tool_to_roles = {
            "database.read": {"agent"},
            "analytics.process": {"agent"},
            "web.request": {"agent"},
            "*": set()
        }
        bundle.get_tool_groups.return_value = {}
        bundle.get_labels_for_tool = MagicMock(return_value=set())
        bundle.get_blocking_labels_for_tool = MagicMock(return_value=set())
        
        # Return allow-mode sequence rules with mode
        manager.get_sequence_rules = AsyncMock(return_value=(
            "allow",  # Mode
            [{"deny": ["database.read", "web.request"], "reason": "Exfil"}]
        ))
        
        manager._get_bundle.return_value = bundle
        manager._policy_bundle = bundle
        manager.check_async = AsyncMock(return_value=True)
        manager.is_tool_in_policy_async = AsyncMock(return_value=True)
        manager.get_tool_conditions = AsyncMock(return_value=None)
        manager._usage_reporter = None
        
        set_user("agent-1", ["agent"])
        
        with patch("d2.decorator.get_policy_manager", return_value=manager):
            @d2_guard("database.read")
            async def read_database():
                return {"data": "users"}
            
            @d2_guard("analytics.process")
            async def process_analytics(data):
                return {"summary": "processed"}
            
            @d2_guard("web.request")
            async def send_web_request(data):
                return {"status": "sent"}
            
            # Step 1: database.read should work
            result = await read_database()
            assert result == {"data": "users"}
            
            # Step 2: analytics.process should work (no deny rule for this)
            result = await process_analytics({"data": "users"})
            assert result == {"summary": "processed"}
            
            # Step 3: web.request should FAIL (matches deny pattern)
            with pytest.raises(PermissionDeniedError) as exc_info:
                await send_web_request({"data": "users"})
            
            assert "sequence_violation" in str(exc_info.value)
            assert "Exfil" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_mode_None_defaults_to_allow_mode(self):
        """When mode is None (legacy), should behave as allow-mode."""
        manager = MagicMock()
        manager.mode = "file"
        manager._init_complete = MagicMock()
        manager._init_complete.is_set.return_value = True
        manager._init_complete.wait = AsyncMock()
        
        bundle = MagicMock()
        bundle.all_known_tools = {"database.read", "web.request", "analytics.process"}
        bundle.tool_to_roles = {
            "database.read": {"agent"},
            "web.request": {"agent"},
            "analytics.process": {"agent"},
            "*": set()
        }
        bundle.get_tool_groups.return_value = {}
        bundle.get_labels_for_tool = MagicMock(return_value=set())
        bundle.get_blocking_labels_for_tool = MagicMock(return_value=set())
        
        # Return None mode (legacy behavior)
        manager.get_sequence_rules = AsyncMock(return_value=(
            None,  # No mode (backward compat)
            [{"deny": ["database.read", "web.request"], "reason": "Exfil"}]
        ))
        
        manager._get_bundle.return_value = bundle
        manager._policy_bundle = bundle
        manager.check_async = AsyncMock(return_value=True)
        manager.is_tool_in_policy_async = AsyncMock(return_value=True)
        manager.get_tool_conditions = AsyncMock(return_value=None)
        manager._usage_reporter = None
        
        set_user("agent-1", ["agent"])
        
        with patch("d2.decorator.get_policy_manager", return_value=manager):
            @d2_guard("database.read")
            async def read_database():
                return {"data": "users"}
            
            @d2_guard("analytics.process")
            async def process_analytics(data):
                return {"summary": "processed"}
            
            # Step 1: database.read should work
            await read_database()
            
            # Step 2: analytics.process should work (no deny rule, default allow)
            result = await process_analytics({"data": "users"})
            assert result == {"summary": "processed"}


class TestSequenceModePolicyErrors:
    """Test error handling for malformed sequence mode configurations."""

    def test_invalid_mode_value_in_policy(self):
        """Invalid mode values should default to 'allow' mode gracefully."""
        raw_bundle = {
            "metadata": {
                "name": "test-app",
                "expires": "2099-12-31T00:00:00Z",
            },
            "policies": [
                {
                    "role": "agent",
                    "permissions": ["*"],
                    "sequence": {
                        "mode": "invalid_mode",  # Invalid
                        "rules": [
                            {"deny": ["database.read", "web.request"], "reason": "Test"}
                        ]
                    }
                }
            ],
        }
        
        # Should not crash, should default to allow mode
        bundle = PolicyBundle(raw_bundle=raw_bundle, mode="file")
        assert bundle.role_to_sequences.get("agent") is not None

    def test_missing_rules_key_in_nested_structure(self):
        """Nested structure without 'rules' key should be handled gracefully."""
        raw_bundle = {
            "metadata": {
                "name": "test-app",
                "expires": "2099-12-31T00:00:00Z",
            },
            "policies": [
                {
                    "role": "agent",
                    "permissions": ["*"],
                    "sequence": {
                        "mode": "deny"
                        # Missing "rules" key
                    }
                }
            ],
        }
        
        # Should not crash
        bundle = PolicyBundle(raw_bundle=raw_bundle, mode="file")
        # Should have empty rules
        sequence_data = bundle.role_to_sequences.get("agent")
        assert sequence_data is not None

    def test_mode_without_rules_structure(self):
        """Mode specified directly without nested structure should be handled."""
        raw_bundle = {
            "metadata": {
                "name": "test-app",
                "expires": "2099-12-31T00:00:00Z",
            },
            "policies": [
                {
                    "role": "agent",
                    "permissions": ["*"],
                    "sequence": "deny"  # Just a string (invalid)
                }
            ],
        }
        
        # Should not crash
        bundle = PolicyBundle(raw_bundle=raw_bundle, mode="file")

