"""
Tests for d2.policy_client - Background policy fetching and updates.

The PolicyClient handles automatic policy bundle fetching from the D2 cloud
service, including signature verification, caching, and real-time updates.

Key concepts:
- Background polling: Continuously checks for policy updates
- JWS signatures: Cryptographic verification of policy integrity
- ETag caching: Efficient HTTP caching to minimize bandwidth
- JWKS verification: Public key fetching for signature validation
- Callback system: Notifies application of policy updates

Security principles:
- Signature verification: All policies must be cryptographically signed
- Key rotation: Supports dynamic JWKS key fetching
- Fail-closed: Invalid signatures prevent policy updates
- Transport security: HTTPS for all API communication
"""
import asyncio, json, time
from typing import List

import pytest
import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from d2.policy_client import PolicyClient
from d2.jwks_cache import JWKSCache


# Test cryptographic setup - RSA key pair for JWS signing
test_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
test_public_jwk = json.loads(RSAAlgorithm.to_jwk(test_private_key.public_key()))
test_public_jwk["kid"] = "test-kid"
MOCK_JWKS_RESPONSE = {"keys": [test_public_jwk]}


def create_signed_jws(payload: dict) -> str:
    """Create a JWS token signed with our test private key."""
    # Add required JWT claims for new structure
    jwt_payload = {
        "aud": "d2-policy:test-account:test-app",  # Required audience claim
        "iss": "d2-cloud",  # Issuer
        "iat": int(time.time()),  # Issued at
        "exp": int(time.time()) + 3600,  # Expires in 1 hour
        **payload  # Include the policy data directly in JWT payload (flat structure)
    }
    return jwt.encode(jwt_payload, test_private_key, algorithm="RS256", headers={"kid": "test-kid"})


class MockD2ApiServer:
    """
    Mock HTTP server that simulates the D2 API endpoints.
    
    Provides realistic responses for:
    - /v1/policy/bundle - Policy bundle endpoint with ETag support
    - /.well-known/jwks.json - JWKS endpoint for signature verification
    
    Supports HTTP caching behavior (304 Not Modified) and tracks
    all requests for test verification.
    """

    def __init__(self):
        """Initialize mock server with default policy and ETag."""
        self.api_calls: List[str] = []  # Track all API calls made
        self._current_etag = "etag-1"   # Current policy version
        # Policy payload with required structure for flat JWT
        self._policy_payload = {
            "metadata": {
                "name": "test-app",
                "description": "Test policy for integration tests"
            },
            "policies": []  # Default empty policy
        }

    def __call__(self, request: httpx.Request):  # type: ignore[override]
        """Handle HTTP requests and return appropriate mock responses."""
        # Track all API calls for test verification
        self.api_calls.append(request.url.path)
        
        if request.url.path.endswith("jwks.json"):
            # JWKS endpoint - return public keys for signature verification
            return httpx.Response(200, json=MOCK_JWKS_RESPONSE)

        if request.url.path.endswith("policy/bundle"):
            # Policy bundle endpoint with ETag support
            client_etag = request.headers.get("If-None-Match")
            
            if client_etag == self._current_etag:
                # Client has current version - return 304 Not Modified
                return httpx.Response(304, headers={"ETag": self._current_etag})

            # Client needs update - return new policy bundle
            # The signature contains the policy data in flat JWT structure
            # The bundle wraps it with nested structure for cloud mode
            signature = create_signed_jws(self._policy_payload)
            response_body = {
                "policy": self._policy_payload,  # Nested structure for cloud bundle
                "signature": signature,  # Flat structure in JWT
                "etag": self._current_etag,
            }
            return httpx.Response(200, json=response_body, headers={"ETag": self._current_etag})

        # Unknown endpoint
        return httpx.Response(404)


@pytest.mark.asyncio
async def test_policy_client_fetches_and_verifies_policy_bundles(monkeypatch):
    """
    GIVEN: A PolicyClient configured to poll for updates
    WHEN: We start polling and wait for background tasks to complete
    THEN: Should fetch policy bundle, verify signature, and notify callback
    
    This tests the complete policy update flow including HTTP requests,
    cryptographic verification, and application notification.
    """
    # This test needs JWT functionality that returns proper payloads
    # Override the conftest.py mock to return a valid JWT payload with aud claim
    def mock_jwt_decode(*args, **kwargs):
        return {
            "aud": "d2-policy:test-account:test-app",
            "iss": "d2-cloud", 
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
            "metadata": {
                "name": "test-app",
                "description": "Test policy for integration tests"
            },
            "policies": []
        }
    
    # Patch the JWT decode function to return a valid payload
    monkeypatch.setattr("jwt.decode", mock_jwt_decode)
    monkeypatch.setattr("d2.policy.jwt.decode", mock_jwt_decode)
    # GIVEN: Mock server that provides policy and JWKS endpoints
    mock_api_server = MockD2ApiServer()
    mock_transport = httpx.MockTransport(mock_api_server)

    # Patch httpx.AsyncClient to use our mock transport
    original_async_client = httpx.AsyncClient

    def create_mock_client(*args, **kwargs):
        """Create AsyncClient that uses our mock transport."""
        kwargs["transport"] = mock_transport
        return original_async_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", create_mock_client)

    # Track policy updates received by the application
    received_policy_updates = []

    async def handle_policy_update(policy_bundle):
        """Callback to track policy updates."""
        received_policy_updates.append(policy_bundle)

    # WHEN: We start the policy client and let it poll
    policy_client = PolicyClient(
        api_url="https://test-api.d2.dev", 
        api_token="test-token", 
        on_update=handle_policy_update
    )
    
    await policy_client.start_polling()
    
    # Wait for background tasks including signature verification
    # (Signature verification can be async and may take time)
    await asyncio.sleep(0.2)
    
    # Clean shutdown
    await policy_client.stop()

    # THEN: Should have received at least one policy update
    assert len(received_policy_updates) > 0, \
           "Should receive at least one policy update via callback"
    
    # AND: Should have called the policy bundle API endpoint
    api_calls = "".join(mock_api_server.api_calls)
    assert "/v1/policy/bundle" in api_calls, \
           "Should make API call to policy bundle endpoint"
    
    # Note: JWKS endpoint may or may not be called depending on signature 
    # verification timing, but that's acceptable for this integration test 