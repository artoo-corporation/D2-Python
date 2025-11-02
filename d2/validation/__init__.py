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


