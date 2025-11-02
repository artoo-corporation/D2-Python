"""Base dataclasses for declarative validation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Mapping, Optional


@dataclass
class ValidationViolation:
    """Represents a single rule violation for an input argument."""

    argument: str
    operator: str
    expected: Any
    actual: Any
    message: str
    code: Optional[str] = None


@dataclass
class ValidationResult:
    """Result of validating arguments against declarative rules."""

    allowed: bool
    violations: List[ValidationViolation] = field(default_factory=list)

    def merge(self, other: "ValidationResult") -> "ValidationResult":
        if other.allowed:
            return self
        self.violations.extend(other.violations)
        self.allowed = not self.violations
        return self


@dataclass
class ValidationContext:
    """Context passed to rule evaluators."""

    argument: str
    arguments: Mapping[str, Any]


__all__ = [
    "ValidationContext",
    "ValidationResult",
    "ValidationViolation",
]


