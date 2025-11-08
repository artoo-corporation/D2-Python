# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""Unit tests for multi-role policy support."""

import pytest
from d2.policy.bundle import PolicyBundle


def test_single_role_string_backwards_compatible():
    """GIVEN: Policy with single role as string (existing format)
    WHEN: PolicyBundle is created
    THEN: Role is correctly parsed
    """
    raw_bundle = {
        "metadata": {"name": "test"},
        "policies": [
            {
                "role": "analyst",
                "permissions": ["database.read", "web.request"]
            }
        ]
    }
    
    bundle = PolicyBundle(raw_bundle=raw_bundle, mode="file")
    
    assert "database.read" in bundle.tool_to_roles
    assert "analyst" in bundle.tool_to_roles["database.read"]
    assert "web.request" in bundle.tool_to_roles
    assert "analyst" in bundle.tool_to_roles["web.request"]


def test_multiple_roles_list():
    """GIVEN: Policy with multiple roles as list
    WHEN: PolicyBundle is created
    THEN: All roles are bound to the same permissions
    """
    raw_bundle = {
        "metadata": {"name": "test"},
        "policies": [
            {
                "role": ["analyst", "data_engineer", "david"],
                "permissions": ["database.read", "web.request"]
            }
        ]
    }
    
    bundle = PolicyBundle(raw_bundle=raw_bundle, mode="file")
    
    # All three roles should have access to both tools
    assert "database.read" in bundle.tool_to_roles
    assert bundle.tool_to_roles["database.read"] == {"analyst", "data_engineer", "david"}
    
    assert "web.request" in bundle.tool_to_roles
    assert bundle.tool_to_roles["web.request"] == {"analyst", "data_engineer", "david"}


def test_roles_plural_key():
    """GIVEN: Policy using 'roles' (plural) key instead of 'role'
    WHEN: PolicyBundle is created
    THEN: All roles are correctly parsed
    """
    raw_bundle = {
        "metadata": {"name": "test"},
        "policies": [
            {
                "roles": ["analyst", "qa_engineer"],
                "permissions": ["database.read"]
            }
        ]
    }
    
    bundle = PolicyBundle(raw_bundle=raw_bundle, mode="file")
    
    assert "database.read" in bundle.tool_to_roles
    assert bundle.tool_to_roles["database.read"] == {"analyst", "qa_engineer"}


def test_multi_role_with_conditions():
    """GIVEN: Multiple roles with input/output conditions
    WHEN: PolicyBundle is created
    THEN: Each role gets the same conditions
    """
    raw_bundle = {
        "metadata": {"name": "test"},
        "policies": [
            {
                "role": ["analyst", "senior_analyst"],
                "permissions": [
                    {
                        "tool": "database.read_users",
                        "allow": True,
                        "conditions": {
                            "input": {"limit": {"type": "int", "max": 100}},
                            "output": {"ssn": {"action": "filter"}}
                        }
                    }
                ]
            }
        ]
    }
    
    bundle = PolicyBundle(raw_bundle=raw_bundle, mode="file")
    
    # Both roles should have access
    assert bundle.tool_to_roles["database.read_users"] == {"analyst", "senior_analyst"}
    
    # Both roles should have the same conditions
    assert "database.read_users" in bundle.tool_conditions
    conditions_list = bundle.tool_conditions["database.read_users"]
    assert len(conditions_list) == 2  # One entry per role
    
    roles_with_conditions = {c["role"] for c in conditions_list}
    assert roles_with_conditions == {"analyst", "senior_analyst"}
    
    # Verify conditions are identical for both roles
    for cond in conditions_list:
        assert cond["conditions"]["input"]["limit"]["max"] == 100
        assert cond["conditions"]["output"]["ssn"]["action"] == "filter"


def test_multi_role_with_sequence_rules():
    """GIVEN: Multiple roles with sequence rules
    WHEN: PolicyBundle is created
    THEN: Each role gets the same sequence rules
    """
    raw_bundle = {
        "metadata": {"name": "test"},
        "policies": [
            {
                "role": ["analyst", "data_engineer"],
                "permissions": ["database.read", "web.request"],
                "sequence": [
                    {
                        "deny": ["database.read", "web.request"],
                        "reason": "Potential data exfiltration"
                    }
                ]
            }
        ]
    }
    
    bundle = PolicyBundle(raw_bundle=raw_bundle, mode="file")
    
    # Both roles should have the same sequence rules
    assert "analyst" in bundle.role_to_sequences
    assert "data_engineer" in bundle.role_to_sequences
    
    analyst_rules = bundle.role_to_sequences["analyst"]
    engineer_rules = bundle.role_to_sequences["data_engineer"]
    
    assert analyst_rules == engineer_rules
    assert len(analyst_rules) == 1
    assert analyst_rules[0]["deny"] == ["database.read", "web.request"]
    assert analyst_rules[0]["reason"] == "Potential data exfiltration"


def test_mixed_single_and_multi_role_policies():
    """GIVEN: Policy with mix of single-role and multi-role entries
    WHEN: PolicyBundle is created
    THEN: All roles are correctly parsed
    """
    raw_bundle = {
        "metadata": {"name": "test"},
        "policies": [
            {
                "role": "admin",
                "permissions": ["*"]
            },
            {
                "role": ["analyst", "intern"],
                "permissions": ["database.read"]
            },
            {
                "roles": ["contractor", "guest"],
                "permissions": ["public.api"]
            }
        ]
    }
    
    bundle = PolicyBundle(raw_bundle=raw_bundle, mode="file")
    
    # Admin has wildcard
    assert bundle.tool_to_roles["*"] == {"admin"}
    
    # Analyst and intern share database.read
    assert bundle.tool_to_roles["database.read"] == {"analyst", "intern"}
    
    # Contractor and guest share public.api
    assert bundle.tool_to_roles["public.api"] == {"contractor", "guest"}


def test_empty_role_list_skipped():
    """GIVEN: Policy with empty role list
    WHEN: PolicyBundle is created
    THEN: Policy is skipped (no errors)
    """
    raw_bundle = {
        "metadata": {"name": "test"},
        "policies": [
            {
                "role": [],
                "permissions": ["database.read"]
            },
            {
                "role": "valid_role",
                "permissions": ["web.request"]
            }
        ]
    }
    
    bundle = PolicyBundle(raw_bundle=raw_bundle, mode="file")
    
    # Empty role list policy should be skipped
    assert "database.read" not in bundle.tool_to_roles
    
    # Valid policy should work
    assert bundle.tool_to_roles["web.request"] == {"valid_role"}


def test_role_priority_prefers_role_over_roles():
    """GIVEN: Policy with both 'role' and 'roles' keys (misconfiguration)
    WHEN: PolicyBundle is created
    THEN: 'role' takes precedence (for backwards compatibility)
    """
    raw_bundle = {
        "metadata": {"name": "test"},
        "policies": [
            {
                "role": "analyst",
                "roles": ["data_engineer"],  # This should be ignored
                "permissions": ["database.read"]
            }
        ]
    }
    
    bundle = PolicyBundle(raw_bundle=raw_bundle, mode="file")
    
    # Only 'role' should be used
    assert bundle.tool_to_roles["database.read"] == {"analyst"}


def test_duplicate_roles_deduplicated():
    """GIVEN: Policy with duplicate role names in list
    WHEN: PolicyBundle is created
    THEN: Roles are deduplicated (set behavior)
    """
    raw_bundle = {
        "metadata": {"name": "test"},
        "policies": [
            {
                "role": ["analyst", "analyst", "data_engineer", "analyst"],
                "permissions": ["database.read"]
            }
        ]
    }
    
    bundle = PolicyBundle(raw_bundle=raw_bundle, mode="file")
    
    # Should only have two unique roles
    assert bundle.tool_to_roles["database.read"] == {"analyst", "data_engineer"}


def test_multi_role_json_format():
    """GIVEN: Policy in JSON format with multi-role (list of strings)
    WHEN: PolicyBundle is created
    THEN: Roles are correctly parsed (JSON native list support)
    """
    raw_bundle = {
        "metadata": {"name": "test"},
        "policies": [
            {
                "role": ["analyst", "engineer"],
                "permissions": [
                    {
                        "tool": "database.read",
                        "allow": True
                    }
                ]
            }
        ]
    }
    
    bundle = PolicyBundle(raw_bundle=raw_bundle, mode="file")
    
    assert bundle.tool_to_roles["database.read"] == {"analyst", "engineer"}


