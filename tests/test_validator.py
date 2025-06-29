"""
Tests for d2.validator - Policy bundle validation and free-tier limits.

The validator enforces free-tier limits on policy bundles to prevent abuse
and ensure fair usage. It checks multiple constraints:

Key validation rules:
- Expiration: Bundles must not be expired (based on metadata.expires)
- Tool count: Maximum 25 tools per bundle in free tier
- Bundle size: Maximum 0.5 MiB raw bundle size
- Return value: Returns tool count for successful validations

Security and business logic:
- Fail-closed: Invalid bundles are rejected completely
- Clear errors: Specific exceptions for different failure modes
- Resource limits: Prevents resource exhaustion attacks
- Time-based: Prevents use of stale/expired policies
"""
from datetime import datetime, timezone, timedelta

import pytest

from d2.validator import validate_local_bundle, BundleExpiredError, TooManyToolsError, PolicyTooLargeError


def create_test_bundle(*, expires: str, tools: list[str]):
    """
    Helper to create a test policy bundle with specified expiration and tools.
    
    Args:
        expires: ISO format expiration timestamp
        tools: List of tool IDs to include in the policy
        
    Returns:
        Policy bundle dictionary suitable for validation
    """
    return {
        "metadata": {"expires": expires},
        "policies": [
            {"role": "viewer", "permissions": tools},
        ],
    }


def test_valid_bundle_passes_all_free_tier_checks():
    """
    GIVEN: A policy bundle that meets all free-tier requirements
    WHEN: We validate it with the validator
    THEN: Should pass validation and return the tool count
    
    This tests the happy path where everything is within limits.
    """
    # GIVEN: A bundle that expires tomorrow (valid)
    tomorrow = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    bundle = create_test_bundle(expires=tomorrow, tools=["ping"])
    
    # WHEN: We validate with reasonable size (100 bytes)
    tool_count = validate_local_bundle(bundle, raw_bundle_size=100)
    
    # THEN: Should return the number of tools in the bundle
    assert tool_count == 1, "Should return count of tools in valid bundle"


def test_expired_bundle_is_rejected_with_clear_error():
    """
    GIVEN: A policy bundle that has already expired
    WHEN: We try to validate it
    THEN: Should raise BundleExpiredError
    
    This prevents use of stale policies that might have outdated permissions.
    """
    # GIVEN: A bundle that expired yesterday
    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    expired_bundle = create_test_bundle(expires=yesterday, tools=["ping"])
    
    # WHEN: We try to validate the expired bundle
    # THEN: Should raise specific expiration error
    with pytest.raises(BundleExpiredError) as error:
        validate_local_bundle(expired_bundle, raw_bundle_size=123)
    
    # Verify it's the expected error type
    assert "expired" in str(error.value).lower(), "Error should mention expiration"


def test_too_many_tools_exceeds_free_tier_limit():
    """
    GIVEN: A policy bundle with more than 25 tools (free tier limit)
    WHEN: We try to validate it
    THEN: Should raise TooManyToolsError
    
    This enforces free-tier limits to prevent resource abuse.
    """
    # GIVEN: A valid expiration time
    tomorrow = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    
    # AND: Too many tools (26 > free tier limit of 25)
    too_many_tools = [f"tool_{i}" for i in range(26)]
    oversized_bundle = create_test_bundle(expires=tomorrow, tools=too_many_tools)
    
    # WHEN: We try to validate the oversized bundle
    # THEN: Should raise tool count limit error
    with pytest.raises(TooManyToolsError) as error:
        validate_local_bundle(oversized_bundle, raw_bundle_size=456)
    
    # Verify the error mentions the limit
    assert "25" in str(error.value) or "tool" in str(error.value).lower(), \
           "Error should mention tool limit"


def test_bundle_size_limit_prevents_resource_exhaustion():
    """
    GIVEN: A policy bundle that exceeds the size limit (0.5 MiB)
    WHEN: We try to validate it
    THEN: Should raise PolicyTooLargeError
    
    This prevents memory exhaustion attacks via oversized policy bundles.
    """
    # GIVEN: A valid bundle structure
    tomorrow = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    small_bundle = create_test_bundle(expires=tomorrow, tools=["ping"])
    
    # WHEN: We report an artificially large size (0.6 MiB > 0.5 MiB limit)
    oversized_bytes = int(0.6 * 1024 * 1024)  # 0.6 MiB in bytes
    
    # THEN: Should raise size limit error
    with pytest.raises(PolicyTooLargeError) as error:
        validate_local_bundle(small_bundle, raw_bundle_size=oversized_bytes)
    
    # Verify the error mentions size
    assert "size" in str(error.value).lower() or "large" in str(error.value).lower(), \
           "Error should mention size limit" 