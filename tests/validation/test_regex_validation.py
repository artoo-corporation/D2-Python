# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""Tests for regex pattern validation at policy load time.

Security requirement: Malformed regex patterns in policies should be caught
during policy loading, NOT at runtime when a tool is called. This prevents
runtime crashes and provides clear feedback to policy authors.
"""

import pytest
from d2.exceptions import ConfigurationError
from d2.policy.bundle import PolicyBundle


class TestRegexValidationAtLoadTime:
    """Test that invalid regex patterns are caught when policies are loaded."""

    def test_invalid_regex_in_input_matches_rejected(self):
        """Test that malformed regex in input validation is caught at load time."""
        bundle_data = {
            "metadata": {"name": "test"},
            "policies": [
                {
                    "role": "analyst",
                    "permissions": [
                        {
                            "tool": "database.query",
                            "allow": True,
                            "conditions": {
                                "input": {
                                    "query": {
                                        "matches": "[unclosed("  # Invalid regex
                                    }
                                }
                            }
                        }
                    ]
                }
            ]
        }
        
        # Should raise ConfigurationError during bundle creation
        with pytest.raises(ConfigurationError, match="Invalid regex pattern"):
            PolicyBundle(bundle_data, mode="file")

    def test_invalid_regex_in_input_not_matches_rejected(self):
        """Test that malformed regex in not_matches is caught at load time."""
        bundle_data = {
            "metadata": {"name": "test"},
            "policies": [
                {
                    "role": "analyst",
                    "permissions": [
                        {
                            "tool": "web.request",
                            "allow": True,
                            "conditions": {
                                "input": {
                                    "url": {
                                        "not_matches": "(?P<invalid>"  # Invalid regex
                                    }
                                }
                            }
                        }
                    ]
                }
            ]
        }
        
        with pytest.raises(ConfigurationError, match="Invalid regex pattern"):
            PolicyBundle(bundle_data, mode="file")

    def test_invalid_regex_in_output_sanitization_rejected(self):
        """Test that malformed regex in output redact action is caught at load time."""
        bundle_data = {
            "metadata": {"name": "test"},
            "policies": [
                {
                    "role": "analyst",
                    "permissions": [
                        {
                            "tool": "database.read_users",
                            "allow": True,
                            "conditions": {
                                "output": {
                                    "email": {
                                        "action": "redact",
                                        "matches": "@[*invalid"  # Invalid regex
                                    }
                                }
                            }
                        }
                    ]
                }
            ]
        }
        
        with pytest.raises(ConfigurationError, match="Invalid regex pattern"):
            PolicyBundle(bundle_data, mode="file")

    def test_invalid_regex_in_output_validation_rejected(self):
        """Test that malformed regex in output validation is caught at load time."""
        bundle_data = {
            "metadata": {"name": "test"},
            "policies": [
                {
                    "role": "analyst",
                    "permissions": [
                        {
                            "tool": "api.call",
                            "allow": True,
                            "conditions": {
                                "output": {
                                    "status": {
                                        "matches": "^(success|error"  # Unclosed paren
                                    }
                                }
                            }
                        }
                    ]
                }
            ]
        }
        
        with pytest.raises(ConfigurationError, match="Invalid regex pattern"):
            PolicyBundle(bundle_data, mode="file")

    def test_multiple_invalid_regexes_all_reported(self):
        """Test that all invalid regex patterns are reported together."""
        bundle_data = {
            "metadata": {"name": "test"},
            "policies": [
                {
                    "role": "analyst",
                    "permissions": [
                        {
                            "tool": "database.query",
                            "allow": True,
                            "conditions": {
                                "input": {
                                    "query": {"matches": "[invalid1"},
                                    "table": {"not_matches": "(unclosed2"}
                                },
                                "output": {
                                    "result": {"matches": "*bad3"}
                                }
                            }
                        }
                    ]
                }
            ]
        }
        
        # Should raise and ideally report all bad patterns
        with pytest.raises(ConfigurationError, match="Invalid regex pattern"):
            PolicyBundle(bundle_data, mode="file")

    def test_valid_regex_patterns_accepted(self):
        """Test that valid regex patterns pass validation."""
        bundle_data = {
            "metadata": {"name": "test"},
            "policies": [
                {
                    "role": "analyst",
                    "permissions": [
                        {
                            "tool": "database.query",
                            "allow": True,
                            "conditions": {
                                "input": {
                                    "query": {
                                        "matches": "^SELECT.*FROM.*$"
                                    },
                                    "table": {
                                        "not_matches": "(DROP|DELETE|TRUNCATE)"
                                    }
                                },
                                "output": {
                                    "status": {
                                        "matches": "^(success|error)$"
                                    },
                                    "email": {
                                        "action": "redact",
                                        "matches": "@.*$"
                                    }
                                }
                            }
                        }
                    ]
                }
            ]
        }
        
        # Should not raise - all patterns are valid
        bundle = PolicyBundle(bundle_data, mode="file")
        assert bundle is not None

    def test_common_regex_mistakes_rejected(self):
        """Test that common regex mistakes are caught."""
        common_mistakes = [
            "[abc",           # Unclosed character class
            "(abc",           # Unclosed group
            "(?P<name)",      # Incomplete named group
            "*abc",           # Nothing to repeat
            "(?P<>abc)",      # Empty group name
            "(?P<123>abc)",   # Invalid group name (starts with digit)
            "(?",             # Incomplete extension
            "\\",             # Trailing backslash
        ]
        
        for bad_pattern in common_mistakes:
            bundle_data = {
                "metadata": {"name": "test"},
                "policies": [
                    {
                        "role": "user",
                        "permissions": [
                            {
                                "tool": "test.tool",
                                "allow": True,
                                "conditions": {
                                    "input": {
                                        "field": {"matches": bad_pattern}
                                    }
                                }
                            }
                        ]
                    }
                ]
            }
            
            with pytest.raises(ConfigurationError, match="Invalid regex pattern"):
                PolicyBundle(bundle_data, mode="file")

    def test_regex_validation_provides_helpful_error_message(self):
        """Test that error messages help identify the problematic pattern."""
        bundle_data = {
            "metadata": {"name": "test"},
            "policies": [
                {
                    "role": "analyst",
                    "permissions": [
                        {
                            "tool": "database.query",
                            "allow": True,
                            "conditions": {
                                "input": {
                                    "query": {"matches": "[unclosed"}
                                }
                            }
                        }
                    ]
                }
            ]
        }
        
        with pytest.raises(ConfigurationError) as exc_info:
            PolicyBundle(bundle_data, mode="file")
        
        error_msg = str(exc_info.value)
        # Should mention the pattern and the tool/field
        assert "[unclosed" in error_msg or "unclosed" in error_msg.lower()
        assert "query" in error_msg or "database.query" in error_msg

    def test_no_regex_patterns_does_not_fail(self):
        """Test that policies without regex patterns don't trigger validation."""
        bundle_data = {
            "metadata": {"name": "test"},
            "policies": [
                {
                    "role": "analyst",
                    "permissions": [
                        {
                            "tool": "database.query",
                            "allow": True,
                            "conditions": {
                                "input": {
                                    "limit": {"min": 1, "max": 100},
                                    "table": {"in": ["users", "orders"]}
                                }
                            }
                        }
                    ]
                }
            ]
        }
        
        # Should not raise - no regex patterns to validate
        bundle = PolicyBundle(bundle_data, mode="file")
        assert bundle is not None


