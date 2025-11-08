# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""Input validation - validates function arguments against declarative constraints.

This module provides InputValidator for checking function arguments before execution.
It uses the shared ConstraintEvaluator to validate arguments against declarative rules.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional, Sequence

from .base import ValidationContext, ValidationResult
from .constraints import ConstraintEvaluator


class InputValidator:
    """Validates function arguments against declarative policy rules.
    
    Input validation checks that function arguments satisfy specified constraints:
    - type, required, min, max, in, matches, minLength, maxLength, etc.
    - Returns ValidationResult (allowed: true/false + violations)
    - Denies (returns allowed=False) if any constraint violated
    - Executed BEFORE function runs
    
    Example:
        ```python
        validator = InputValidator()
        result = validator.validate(
            {"input": {
                "table": {"in": ["sales", "marketing"]},
                "row_limit": {"min": 1, "max": 1000}
            }},
            {"table": "sales", "row_limit": 250}
        )
        assert result.allowed is True
        ```
    """

    def __init__(self):
        self._evaluator = ConstraintEvaluator()

    def validate(self, policy_conditions: Optional[Any], arguments: Mapping[str, Any]) -> ValidationResult:
        """Validate arguments against declarative constraint rules.
        
        Args:
            policy_conditions: Policy conditions dict or list
            arguments: Function arguments to validate
            
        Returns:
            ValidationResult with allowed flag and any violations
        """
        if not policy_conditions:
            return ValidationResult(allowed=True)

        if isinstance(policy_conditions, Sequence) and not isinstance(policy_conditions, (str, bytes, bytearray)):
            aggregated = ValidationResult(allowed=True)
            for condition in policy_conditions:
                result = self.validate(condition, arguments)
                aggregated.merge(result)
            return aggregated

        # Accept either {"input": {...}} or direct mapping of argument conditions
        if "input" in policy_conditions:
            input_rules = policy_conditions["input"] or {}
        elif "output" in policy_conditions:
            # Output-only policy, no input validation needed
            return ValidationResult(allowed=True)
        else:
            input_rules = policy_conditions

        combined = ValidationResult(allowed=True)

        for argument, rules in input_rules.items():
            if not isinstance(rules, Mapping):
                continue

            context = ValidationContext(argument=argument, arguments=arguments)
            value_present = argument in arguments
            value = arguments.get(argument)

            evaluation = self._evaluator.evaluate(
                rules,
                value_present=value_present,
                value=value,
                context=context,
            )
            combined.merge(evaluation.result)

        return combined


__all__ = ["InputValidator"]


