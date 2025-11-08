# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

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
