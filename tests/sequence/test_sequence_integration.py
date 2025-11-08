# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""Integration tests for sequence enforcement with full D2 stack."""

import os
import pytest
import tempfile
import yaml
from pathlib import Path

import d2
from d2 import d2_guard, set_user, clear_user_context
from d2.exceptions import PermissionDeniedError


@pytest.fixture
def temp_policy_file():
    """Create a temporary policy file with sequence rules."""
    policy = {
        "metadata": {
            "name": "sequence-test-policy",
            "expires": "2099-12-31T23:59:59+00:00"
        },
        "policies": [
            {
                "role": "agent",
                "permissions": [
                    "database.read_users",
                    "database.read_orders",
                    "web.http_request",
                    "analytics.summarize"
                ],
                "sequence": [
                    {
                        "deny": ["database.read_users", "web.http_request"],
                        "reason": "User data exfiltration"
                    },
                    {
                        "deny": ["database.read_orders", "web.http_request"],
                        "reason": "Order data exfiltration"
                    }
                ]
            },
            {
                "role": "admin",
                "permissions": ["*"]
            }
        ]
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        yaml.dump(policy, f)
        policy_path = f.name
    
    # Set environment variable
    os.environ['D2_POLICY_FILE'] = policy_path
    
    yield policy_path
    
    # Cleanup
    if 'D2_POLICY_FILE' in os.environ:
        del os.environ['D2_POLICY_FILE']
    Path(policy_path).unlink(missing_ok=True)


@pytest.fixture
async def configured_rbac(temp_policy_file):
    """Configure RBAC with the test policy."""
    await d2.configure_rbac_async()
    yield
    await d2.shutdown_all_rbac()
    clear_user_context()


class TestSequenceIntegration:
    """End-to-end integration tests."""

    @pytest.mark.asyncio
    async def test_direct_exfiltration_blocked(self, configured_rbac):
        """Block database -> web pattern."""
        
        @d2_guard("database.read_users")
        async def read_users():
            return {"users": [{"name": "Alice"}]}
        
        @d2_guard("web.http_request")
        async def http_post(data):
            return {"status": "sent"}
        
        set_user("agent-1", roles=["agent"])
        
        # First call succeeds
        users = await read_users()
        assert users == {"users": [{"name": "Alice"}]}
        
        # Second call blocked by sequence rule
        with pytest.raises(PermissionDeniedError) as exc_info:
            await http_post(users)
        
        assert "sequence_violation" in exc_info.value.reason
        assert "User data exfiltration" in exc_info.value.reason

    @pytest.mark.asyncio
    async def test_safe_workflow_allowed(self, configured_rbac):
        """Allow analytics -> database (no external I/O)."""
        
        @d2_guard("analytics.summarize")
        async def summarize():
            return {"summary": "done"}
        
        @d2_guard("database.read_users")
        async def read_users():
            return {"users": []}
        
        set_user("agent-1", roles=["agent"])
        
        # This sequence is fine
        await summarize()
        users = await read_users()
        
        assert users == {"users": []}

    @pytest.mark.asyncio
    async def test_admin_bypasses_sequence(self, configured_rbac):
        """Admin role bypasses all sequence restrictions."""
        
        @d2_guard("database.read_users")
        async def read_users():
            return {"users": [{"name": "Bob"}]}
        
        @d2_guard("web.http_request")
        async def http_post(data):
            return {"status": "sent"}
        
        set_user("admin-1", roles=["admin"])
        
        # Admin can do DB -> Web (no sequence restriction)
        users = await read_users()
        result = await http_post(users)
        
        assert result == {"status": "sent"}

    @pytest.mark.asyncio
    async def test_multiple_sequence_rules(self, configured_rbac):
        """Enforce multiple deny patterns."""
        
        @d2_guard("database.read_users")
        async def read_users():
            return {"users": []}
        
        @d2_guard("database.read_orders")
        async def read_orders():
            return {"orders": []}
        
        @d2_guard("web.http_request")
        async def http_post(data):
            return {"status": "sent"}
        
        set_user("agent-1", roles=["agent"])
        
        # Pattern 1: database.read_users -> web blocked
        await read_users()
        with pytest.raises(PermissionDeniedError) as exc_info:
            await http_post({"data": "test"})
        assert "User data exfiltration" in exc_info.value.reason
        
        # Clear context and test pattern 2
        clear_user_context()
        set_user("agent-2", roles=["agent"])
        
        # Pattern 2: database.read_orders -> web blocked
        await read_orders()
        with pytest.raises(PermissionDeniedError) as exc_info:
            await http_post({"data": "test"})
        assert "Order data exfiltration" in exc_info.value.reason

    @pytest.mark.asyncio
    async def test_sync_functions_with_sequence(self, configured_rbac):
        """Sequence enforcement works with sync functions too."""
        
        @d2_guard("database.read_users")
        def read_users_sync():
            return {"users": [{"name": "Charlie"}]}
        
        @d2_guard("web.http_request")
        def http_post_sync(data):
            return {"status": "sent"}
        
        set_user("agent-1", roles=["agent"])
        
        # First call succeeds
        users = read_users_sync()
        assert users == {"users": [{"name": "Charlie"}]}
        
        # Second call blocked
        with pytest.raises(PermissionDeniedError) as exc_info:
            http_post_sync(users)
        
        assert "sequence_violation" in exc_info.value.reason

    @pytest.mark.asyncio
    async def test_nested_guarded_calls(self, configured_rbac):
        """Sequence tracking works through nested calls."""
        
        @d2_guard("database.read_users")
        async def read_users():
            return {"users": []}
        
        @d2_guard("analytics.summarize")
        async def process(data):
            # This internally calls another guarded function
            return {"processed": True}
        
        @d2_guard("web.http_request")
        async def send_data(data):
            return {"status": "sent"}
        
        set_user("agent-1", roles=["agent"])
        
        # Build up history: db -> analytics
        users = await read_users()
        summary = await process(users)
        
        # Now trying web should be blocked (db was called earlier)
        with pytest.raises(PermissionDeniedError):
            await send_data(summary)

    @pytest.mark.asyncio
    async def test_context_isolation(self, configured_rbac):
        """Each request has isolated call history."""
        
        @d2_guard("database.read_users")
        async def read_users():
            return {"users": []}
        
        @d2_guard("web.http_request")
        async def http_post(data):
            return {"status": "sent"}
        
        # Request 1: DB -> Web (blocked)
        set_user("agent-1", roles=["agent"])
        await read_users()
        with pytest.raises(PermissionDeniedError):
            await http_post({"data": "test"})
        
        # Clear context (simulate new request)
        clear_user_context()
        
        # Request 2: Web only (should work - fresh history)
        set_user("agent-2", roles=["agent"])
        result = await http_post({"data": "test"})
        assert result == {"status": "sent"}


