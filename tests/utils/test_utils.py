"""
Tests for d2.utils - Utility functions and configuration parsing.

The utils module provides helper functions for configuration, environment
variable parsing, and other common operations across the SDK.

Key concepts:
- Telemetry configuration: Parse D2_TELEMETRY environment variable
- Mode enumeration: OFF, METRICS, USAGE, ALL telemetry levels
- Flexible parsing: Support multiple formats and aliases
- Default behavior: Telemetry enabled by default (opt-out model)

Configuration philosophy:
- User-friendly: Accept many formats (0/1, yes/no, off/on, etc.)
- Explicit defaults: Clear behavior when environment is unset
- Case-insensitive: Accept upper/lower/mixed case values
"""
from d2.utils import get_telemetry_mode, TelemetryMode
import pytest


@pytest.mark.parametrize(
    "environment_value,expected_mode",
    [
        # Disabled telemetry formats
        ("", TelemetryMode.OFF),          # Empty string
        ("0", TelemetryMode.OFF),         # Numeric false  
        ("NONE", TelemetryMode.OFF),      # Explicit none
        ("off", TelemetryMode.OFF),       # Common off value
        
        # Specific telemetry modes
        ("metrics", TelemetryMode.METRICS), # Metrics only
        ("usage", TelemetryMode.USAGE),     # Usage only
        
        # Full telemetry formats  
        ("all", TelemetryMode.ALL),       # Explicit all
        ("*", TelemetryMode.ALL),         # Wildcard
        ("1", TelemetryMode.ALL),         # Numeric true
        ("TRUE", TelemetryMode.ALL),      # Boolean true (uppercase)
        ("yes", TelemetryMode.ALL),       # Affirmative
        
        # Default behavior
        (None, TelemetryMode.ALL),        # Unset environment -> default enabled
    ],
)
def test_telemetry_mode_parsing_handles_various_formats(monkeypatch, environment_value, expected_mode):
    """
    GIVEN: Various formats of the D2_TELEMETRY environment variable
    WHEN: We parse the telemetry mode configuration
    THEN: Should correctly interpret each format to the expected mode
    
    This ensures users can configure telemetry using intuitive values
    without needing to remember exact syntax.
    """
    if environment_value is None:
        # GIVEN: Environment variable is not set
        monkeypatch.delenv("D2_TELEMETRY", raising=False)
    else:
        # GIVEN: Environment variable is set to specific value
        monkeypatch.setenv("D2_TELEMETRY", environment_value)
    
    # WHEN: We parse the telemetry mode
    actual_mode = get_telemetry_mode()
    
    # THEN: Should match expected mode
    assert actual_mode == expected_mode, \
           f"Environment value '{environment_value}' should parse to {expected_mode}" 