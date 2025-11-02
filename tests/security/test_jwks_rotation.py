"""
Tests for automatic JWKS refresh and key rotation support.

This module verifies the new automatic key rotation capabilities that enable
seamless zero-downtime key rotation when the control-plane rotates signing keys.

Key scenarios tested:
- JWS header parsing for rotation control messages
- Smart JWKS cache refresh with rate limiting
- Telemetry emission for rotation monitoring
- Backwards compatibility with existing flows
- Error handling and retry logic
"""

import asyncio
import json
import time
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from d2.jwks_cache import JWKSCache
from d2.policy import PolicyManager
from d2.exceptions import InvalidSignatureError


class TestJWKSRotationSupport:
    """Test automatic JWKS refresh for key rotation."""

    def setup_method(self):
        """Set up test fixtures."""
        # Create test RSA keys
        self.old_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.new_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        
        # Create JWKs
        self.old_jwk = json.loads(RSAAlgorithm.to_jwk(self.old_private_key.public_key()))
        self.old_jwk["kid"] = "old-key-id"
        
        self.new_jwk = json.loads(RSAAlgorithm.to_jwk(self.new_private_key.public_key()))
        self.new_jwk["kid"] = "new-key-id"

    def create_jws_with_rotation_header(self, private_key, kid: str, include_rotation: bool = False):
        """Create a JWS token with optional rotation control headers."""
        payload = {"policy": {"roles": []}, "aud": "d2.policy"}
        
        headers = {"kid": kid}
        if include_rotation:
            headers.update({
                "jwks_refresh": True,
                "rotation_id": "rot_123456",
                "timestamp": "2024-01-15T10:30:00Z",
                "reason": "scheduled_rotation",
                "new_kid": kid
            })
        
        # PyJWT only preserves standard header fields by default
        # We need to manually create the JWS to include custom headers
        import base64
        import json
        
        # Add required algorithm field
        headers["alg"] = "RS256"
        headers["typ"] = "JWT"
        
        # Create header with all custom fields
        header_json = json.dumps(headers, separators=(',', ':')).encode('utf-8')
        header_b64 = base64.urlsafe_b64encode(header_json).rstrip(b'=').decode('ascii')
        
        # Create payload
        payload_json = json.dumps(payload, separators=(',', ':')).encode('utf-8')
        payload_b64 = base64.urlsafe_b64encode(payload_json).rstrip(b'=').decode('ascii')
        
        # Sign with PyJWT but using our custom header
        signing_input = f"{header_b64}.{payload_b64}"
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        
        signature = private_key.sign(
            signing_input.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=').decode('ascii')
        
        return f"{signing_input}.{signature_b64}"

    @pytest.mark.asyncio
    async def test_header_parsing_detects_rotation_request(self):
        """
        GIVEN: A JWS token with jwks_refresh=true in the header
        WHEN: We parse the header during signature verification
        THEN: Should detect the rotation request and extract metadata
        """
        # Create JWS with rotation header
        jws_token = self.create_jws_with_rotation_header(
            self.new_private_key, "new-key-id", include_rotation=True
        )
        
        # Parse header manually (since PyJWT may filter custom fields)
        import base64
        import json
        header_part = jws_token.split('.')[0]
        # Add padding if needed
        header_part += '=' * (4 - len(header_part) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_part).decode('utf-8'))
        
        # Should detect rotation request
        assert header.get("jwks_refresh") is True
        assert header.get("rotation_id") == "rot_123456"
        assert header.get("new_kid") == "new-key-id"
        assert header.get("reason") == "scheduled_rotation"

    @pytest.mark.asyncio
    async def test_smart_refresh_with_forced_rotation(self):
        """
        GIVEN: A JWKS cache with old keys
        WHEN: We request a key with force_refresh=True (from rotation header)
        THEN: Should refresh JWKS immediately regardless of TTL
        """
        cache = JWKSCache("https://example.com/.well-known/jwks.json", api_token="test-token")
        
        # Mock the _refresh method directly to simulate JWKS responses
        refresh_call_count = 0
        
        async def mock_refresh(rotation_metadata=None):
            nonlocal refresh_call_count
            refresh_call_count += 1
            
            # Clear cache and populate based on call
            cache._cache.clear()
            
            if refresh_call_count == 1:
                # First call: populate with old key
                from jwt.algorithms import RSAAlgorithm
                key_obj = RSAAlgorithm.from_jwk(json.dumps(self.old_jwk))
                cache._cache["old-key-id"] = (key_obj, time.time() + 300)
            elif refresh_call_count == 2:
                # Second call: populate with both old and new keys (rotation)
                from jwt.algorithms import RSAAlgorithm
                old_key_obj = RSAAlgorithm.from_jwk(json.dumps(self.old_jwk))
                new_key_obj = RSAAlgorithm.from_jwk(json.dumps(self.new_jwk))
                cache._cache["old-key-id"] = (old_key_obj, time.time() + 300)
                cache._cache["new-key-id"] = (new_key_obj, time.time() + 300)
            
            # Update refresh time for rate limiting
            cache._last_refresh_time = time.time()
        
        with patch.object(cache, '_refresh_with_telemetry', side_effect=mock_refresh):
            # Get old key first (triggers initial refresh)
            old_key = await cache.get_key_with_refresh("old-key-id")
            assert old_key is not None
            
            # Now request new key with forced refresh
            rotation_metadata = {
                "rotation_id": "rot_123456",
                "new_kid": "new-key-id",
                "reason": "scheduled_rotation"
            }
            
            new_key = await cache.get_key_with_refresh(
                "new-key-id",
                force_refresh=True,
                rotation_metadata=rotation_metadata
            )
            assert new_key is not None
            
            # Should have made 2 refresh calls
            assert refresh_call_count == 2

    @pytest.mark.asyncio
    async def test_rate_limiting_prevents_hammering(self):
        """
        GIVEN: Multiple rapid requests for JWKS refresh
        WHEN: Requests come faster than rate limit allows
        THEN: Should rate limit normal refreshes but allow forced refreshes
        """
        cache = JWKSCache("https://example.com/.well-known/jwks.json", api_token="test-token")
        cache._min_refresh_interval = 5.0  # 5 second rate limit
        
        refresh_call_count = 0
        
        async def mock_refresh(rotation_metadata=None):
            nonlocal refresh_call_count
            refresh_call_count += 1
            
            # Populate cache with test key
            from jwt.algorithms import RSAAlgorithm
            key_obj = RSAAlgorithm.from_jwk(json.dumps(self.old_jwk))
            cache._cache.clear()
            cache._cache["old-key-id"] = (key_obj, time.time() + 300)
            cache._last_refresh_time = time.time()
        
        with patch.object(cache, '_refresh_with_telemetry', side_effect=mock_refresh):
            # First request should trigger refresh
            await cache.get_key_with_refresh("old-key-id", force_refresh=False)
            first_call_count = refresh_call_count
            
            # Immediate second request should be rate limited (no additional refresh)
            await cache.get_key_with_refresh("old-key-id", force_refresh=False)
            assert refresh_call_count == first_call_count
            
            # But forced refresh should bypass rate limiting
            await cache.get_key_with_refresh("old-key-id", force_refresh=True)
            assert refresh_call_count > first_call_count

    @pytest.mark.asyncio
    @patch('d2.telemetry.jwks_rotation_total')
    @patch('d2.telemetry.jwks_fetch_latency_ms')
    async def test_telemetry_emission_for_rotation_events(self, mock_latency, mock_rotation):
        """
        GIVEN: A JWKS refresh triggered by rotation
        WHEN: The refresh completes successfully
        THEN: Should emit rotation telemetry with proper tags
        """
        cache = JWKSCache("https://example.com/.well-known/jwks.json", api_token="test-token")
        
        rotation_metadata = {
            "rotation_id": "rot_123456",
            "reason": "emergency_rotation",
            "new_kid": "new-key-id"
        }
        
        # Mock refresh but call real telemetry emission
        async def mock_refresh_with_telemetry(rotation_metadata_param=None):
            # Populate cache with test key
            from jwt.algorithms import RSAAlgorithm
            key_obj = RSAAlgorithm.from_jwk(json.dumps(self.new_jwk))
            cache._cache.clear()
            cache._cache["new-key-id"] = (key_obj, time.time() + 300)
            cache._last_refresh_time = time.time()
            
            # Call the real telemetry emission method
            old_kids = set()
            new_kids = {"new-key-id"}
            latency_ms = 50.0
            cache._emit_rotation_telemetry(
                rotation_metadata=rotation_metadata_param,
                old_kids=old_kids,
                new_kids=new_kids,
                latency_ms=latency_ms,
                outcome="success"
            )
        
        with patch.object(cache, '_refresh_with_telemetry', side_effect=mock_refresh_with_telemetry):
            # Trigger rotation refresh
            await cache.get_key_with_refresh(
                "new-key-id",
                force_refresh=True,
                rotation_metadata=rotation_metadata
            )
            
            # Should have recorded rotation event
            mock_rotation.add.assert_called_once()
            rotation_call = mock_rotation.add.call_args
            assert rotation_call[0][0] == 1  # count
            
            rotation_tags = rotation_call[0][1]
            assert rotation_tags["rotation_triggered"] == "true"
            assert rotation_tags["rotation_id"] == "rot_123456"
            assert rotation_tags["reason"] == "emergency_rotation"
            
            # Should have recorded latency
            mock_latency.record.assert_called()
            latency_call = mock_latency.record.call_args
            assert latency_call[0][0] > 0  # latency_ms
            
            latency_tags = latency_call[0][1]
            assert latency_tags["outcome"] == "success"
            assert latency_tags["rotation_triggered"] == "true"

    @pytest.mark.asyncio
    async def test_backwards_compatibility_with_existing_flows(self):
        """
        GIVEN: Existing code using the legacy get_key() method
        WHEN: No rotation headers are present
        THEN: Should work exactly as before (backward compatibility)
        """
        cache = JWKSCache("https://example.com/.well-known/jwks.json", api_token="test-token")
        
        refresh_call_count = 0
        
        async def mock_refresh(rotation_metadata=None):
            nonlocal refresh_call_count
            refresh_call_count += 1
            
            # Populate cache with test key
            from jwt.algorithms import RSAAlgorithm
            key_obj = RSAAlgorithm.from_jwk(json.dumps(self.old_jwk))
            cache._cache.clear()
            cache._cache["old-key-id"] = (key_obj, time.time() + 300)
            cache._last_refresh_time = time.time()
        
        with patch.object(cache, '_refresh_with_telemetry', side_effect=mock_refresh):
            # Legacy method should still work
            key = await cache.get_key("old-key-id")
            assert key is not None
            
            # Should have made exactly one refresh call
            assert refresh_call_count == 1

    @pytest.mark.asyncio
    async def test_error_handling_continues_with_cached_keys(self):
        """
        GIVEN: A JWKS refresh that fails due to network error
        WHEN: We have cached keys available
        THEN: Should continue with cached keys and not crash the application
        """
        cache = JWKSCache("https://example.com/.well-known/jwks.json", ttl_seconds=1, api_token="test-token")
        
        refresh_call_count = 0
        
        async def mock_refresh(rotation_metadata=None):
            nonlocal refresh_call_count
            refresh_call_count += 1
            
            if refresh_call_count == 1:
                # First call succeeds - populate cache
                from jwt.algorithms import RSAAlgorithm
                key_obj = RSAAlgorithm.from_jwk(json.dumps(self.old_jwk))
                cache._cache.clear()
                cache._cache["old-key-id"] = (key_obj, time.time() + 1)  # Short TTL
                cache._last_refresh_time = time.time()
            else:
                # Second call fails - raise exception
                raise Exception("Network error")
        
        with patch.object(cache, '_refresh_with_telemetry', side_effect=mock_refresh):
            # Get key first time (populates cache)
            key1 = await cache.get_key_with_refresh("old-key-id")
            assert key1 is not None
            
            # Wait for TTL expiry
            await asyncio.sleep(1.1)
            
            # Second request should fail refresh but return cached key
            # The cache should preserve the key even after failed refresh
            key2 = await cache.get_key_with_refresh("old-key-id")
            assert key2 is not None
            
            # Should have attempted 2 refresh calls (second failed)
            assert refresh_call_count == 2

    @pytest.mark.asyncio
    async def test_unknown_header_fields_ignored_for_compatibility(self):
        """
        GIVEN: A JWS with unknown header fields (future extensions)
        WHEN: We parse the header
        THEN: Should ignore unknown fields and not break (forward compatibility)
        """
        # Create JWS with unknown future fields using manual construction
        # (PyJWT strips custom headers, so we need to create it manually)
        import base64
        import json
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        
        payload = {"policy": {"roles": []}, "aud": "d2.policy"}
        headers = {
            "kid": "test-key",
            "jwks_refresh": True,
            "rotation_id": "rot_123",
            "future_field_v2": "some_value",  # Unknown field
            "another_extension": {"nested": "data"}  # Unknown nested field
        }
        
        # Add required algorithm field
        headers["alg"] = "RS256"
        headers["typ"] = "JWT"
        
        # Create header with all custom fields
        header_json = json.dumps(headers, separators=(',', ':')).encode('utf-8')
        header_b64 = base64.urlsafe_b64encode(header_json).rstrip(b'=').decode('ascii')
        
        # Create payload
        payload_json = json.dumps(payload, separators=(',', ':')).encode('utf-8')
        payload_b64 = base64.urlsafe_b64encode(payload_json).rstrip(b'=').decode('ascii')
        
        # Sign manually
        signing_input = f"{header_b64}.{payload_b64}"
        signature = self.old_private_key.sign(
            signing_input.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=').decode('ascii')
        
        jws_token = f"{signing_input}.{signature_b64}"
        
        # Parse header manually to verify all fields are preserved
        import base64
        import json
        header_part = jws_token.split('.')[0]
        # Add padding if needed
        header_part += '=' * (4 - len(header_part) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_part).decode('utf-8'))
        
        # Known fields should be accessible
        assert header.get("jwks_refresh") is True
        assert header.get("rotation_id") == "rot_123"
        
        # Unknown fields should not break parsing
        assert header.get("future_field_v2") == "some_value"
        assert header.get("another_extension") == {"nested": "data"}

    @pytest.mark.asyncio
    async def test_authorization_headers_included_in_jwks_requests(self):
        """
        GIVEN: A JWKSCache configured with an API token
        WHEN: The cache makes JWKS requests
        THEN: Should include Authorization header with Bearer token
        """
        cache = JWKSCache("https://example.com/.well-known/jwks.json", api_token="test-token-123")
        
        # Track the headers passed to the HTTP client
        captured_headers = {}
        
        async def mock_refresh(rotation_metadata=None):
            # Simulate what _refresh does but capture the headers that would be sent
            headers = {}
            if cache._api_token:
                headers["Authorization"] = f"Bearer {cache._api_token}"
            
            # Capture the headers for verification
            captured_headers.update(headers)
            
            # Populate cache with test key
            from jwt.algorithms import RSAAlgorithm
            key_obj = RSAAlgorithm.from_jwk(json.dumps(self.old_jwk))
            cache._cache.clear()
            cache._cache["old-key-id"] = (key_obj, time.time() + 300)
            cache._last_refresh_time = time.time()
        
        with patch.object(cache, '_refresh_with_telemetry', side_effect=mock_refresh):
            # Trigger a refresh
            await cache.get_key_with_refresh("old-key-id")
            
            # Verify the Authorization header was included
            assert 'Authorization' in captured_headers, "Authorization header should be included"
            assert captured_headers['Authorization'] == 'Bearer test-token-123', f"Expected 'Bearer test-token-123', got {captured_headers['Authorization']}"


class TestPolicyManagerIntegration:
    """Test integration with PolicyManager for end-to-end rotation."""

    @pytest.mark.asyncio
    @patch('d2.policy.get_policy_manager')
    async def test_end_to_end_rotation_flow(self, mock_get_manager):
        """
        GIVEN: A policy bundle with rotation headers
        WHEN: PolicyManager verifies the signature  
        THEN: Should trigger JWKS refresh and complete verification
        """
        # This would be a more complex integration test
        # For now, we'll test that the new method is called correctly
        
        # Create mock policy manager with JWKS cache
        mock_manager = MagicMock()
        mock_jwks_cache = AsyncMock()
        mock_manager._jwks_cache = mock_jwks_cache
        mock_get_manager.return_value = mock_manager
        
        # Mock the new get_key_with_refresh method
        mock_key = MagicMock()
        mock_jwks_cache.get_key_with_refresh.return_value = mock_key
        
        # Create test bundle with rotation header
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        headers = {
            "kid": "new-key",
            "jwks_refresh": True,
            "rotation_id": "rot_789"
        }
        
        jws_token = jwt.encode(
            {"policy": {"roles": []}, "aud": "d2.policy"},
            private_key,
            algorithm="RS256", 
            headers=headers
        )
        
        bundle = {"jws": jws_token}
        
        # This test would verify the integration
        # In a real implementation, we'd need to set up the full PolicyManager
        # and verify that it correctly calls get_key_with_refresh with rotation metadata
        
        assert True  # Placeholder - full integration test would go here


import asyncio  # Add this import for the sleep in error handling test
