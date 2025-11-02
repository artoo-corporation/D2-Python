"""Sanitization package - data transformation utilities.

This package provides output sanitization for transforming return values
to remove or redact sensitive data before returning to callers.
"""

from .output import OutputSanitizer, SanitizationResult, REDACTED_TOKEN

__all__ = [
    "OutputSanitizer",
    "SanitizationResult",
    "REDACTED_TOKEN",
]
