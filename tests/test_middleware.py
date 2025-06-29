"""
Tests for d2.middleware - ASGI middleware for HTTP header extraction.

The middleware provides utilities for extracting user identity from HTTP headers
in web applications. This is commonly used with reverse proxies or API gateways
that inject authentication headers.

Key concepts:
- ASGI scope: Standard ASGI request context containing headers
- Header extraction: Parse x-d2-user and x-d2-roles headers
- Role parsing: Split comma-separated roles into list
- Integration: Works with FastAPI, Starlette, Django, etc.

Security considerations:
- Headers should be validated by upstream auth systems
- This is for identity extraction, not authentication
- Roles are parsed as strings (case-sensitive)
"""
from d2.middleware import headers_extractor


def test_extracts_user_identity_from_http_headers():
    """
    GIVEN: An ASGI scope with D2 authentication headers
    WHEN: We extract user identity using headers_extractor
    THEN: Should parse user ID and roles correctly
    
    This tests the core functionality used by web frameworks to
    extract user context from reverse proxy headers.
    """
    # GIVEN: ASGI scope with D2 authentication headers
    asgi_scope = {
        "type": "http",
        "headers": [
            (b"x-d2-user", b"alice"),           # User identity
            (b"x-d2-roles", b"admin,developer"), # Comma-separated roles
        ],
    }
    
    # WHEN: We extract identity from the headers
    extracted_user, extracted_roles = headers_extractor(asgi_scope)
    
    # THEN: Should correctly parse user and roles
    assert extracted_user == "alice", "Should extract user ID from x-d2-user header"
    assert extracted_roles == ["admin", "developer"], \
           "Should split x-d2-roles header into list of roles" 