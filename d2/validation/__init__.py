# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""Validation package - input and output constraint checking.

This package provides pure validation (constraint checking) for both
input arguments and output return values. No transformation happens here.
"""

from .base import ValidationContext, ValidationResult, ValidationViolation
from .constraints import ConstraintEvaluator
from .input import InputValidator
from .output import OutputValidator

__all__ = [
    "InputValidator",
    "OutputValidator",
    "ConstraintEvaluator",
    "ValidationContext",
    "ValidationResult",
    "ValidationViolation",
]


