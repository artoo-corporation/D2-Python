#!/usr/bin/env python3
"""Script to reorganize D2 validation and sanitization code."""

import os
import shutil
from pathlib import Path

# Read current output.py
with open('d2/validation/output.py', 'r') as f:
    full_content = f.read()

# ============================================================================
# Step 1: Create new d2/validation/output.py (OutputValidator only)
# ============================================================================

validation_output = '''# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""Output validation - validates return values against declarative constraints.

This module provides OutputValidator for checking function return values after execution.
It uses the shared ConstraintEvaluator to validate outputs against declarative rules.

Output validation is symmetric with input validation:
- InputValidator: checks arguments BEFORE function runs
- OutputValidator: checks return value AFTER function runs
- Both use the same constraint operators
- Both return ValidationResult
"""

from __future__ import annotations

from typing import Any, Mapping, Optional, Sequence, Tuple

from .base import ValidationContext, ValidationResult
from .constraints import ConstraintEvaluator


class OutputValidator:
    """Validate output against declarative constraints (mirrors InputValidator).
    
    Output validation checks that return values satisfy specified constraints:
    - type, required, min, max, in, matches, minLength, maxLength, etc.
    - Returns ValidationResult (allowed: true/false + violations)
    - NEVER modifies the value
    - Denies (returns allowed=False) if any constraint violated
    
    This is the symmetric counterpart to InputValidator:
    - Input: validates arguments before function execution
    - Output: validates return value after function execution
    
    Example:
        ```python
        validator = OutputValidator()
        result = validator.validate(
            {"output": {
                "status": {"required": True, "in": ["ok", "error"]},
                "count": {"type": "int", "min": 0, "max": 1000}
            }},
            {"status": "ok", "count": 42}
        )
        assert result.allowed is True
        ```
    """

    def __init__(self):
        self._evaluator = ConstraintEvaluator()

    def validate(self, policy_conditions: Optional[Any], value: Any) -> ValidationResult:
        """Validate output value against declarative constraint rules.
        
        Args:
            policy_conditions: Policy conditions dict or list
            value: The return value to validate
            
        Returns:
            ValidationResult with allowed flag and any violations
        """
        if not policy_conditions:
            return ValidationResult(allowed=True)

        if isinstance(policy_conditions, Sequence) and not isinstance(policy_conditions, (str, bytes, bytearray)):
            aggregated = ValidationResult(allowed=True)
            for condition in policy_conditions:
                result = self.validate(condition, value)
                aggregated.merge(result)
            return aggregated

        # Accept either {"output": {...}} or direct mapping of field conditions
        if isinstance(policy_conditions, Mapping):
            if "output" in policy_conditions:
                output_rules = policy_conditions["output"] or {}
            elif "input" in policy_conditions and "output" not in policy_conditions:
                # Only input rules, no output validation
                return ValidationResult(allowed=True)
            else:
                output_rules = policy_conditions
        else:
            return ValidationResult(allowed=True)

        if not isinstance(output_rules, Mapping) or not output_rules:
            return ValidationResult(allowed=True)

        combined = ValidationResult(allowed=True)

        # Validate each field that has constraint operators (no 'action' keyword)
        for field_name, rules in output_rules.items():
            # Skip global rules (not field-level constraints)
            if field_name in ("require_fields_absent", "deny_if_patterns", "max_bytes"):
                continue

            if not isinstance(rules, Mapping):
                continue

            # Skip rules that have 'action' - those are for sanitization
            if "action" in rules:
                continue

            # This is a pure validation rule (no action)
            context = ValidationContext(argument=field_name, arguments={field_name: None})
            value_present, field_value = self._resolve_field_value(value, field_name)

            evaluation = self._evaluator.evaluate(
                rules,
                value_present=value_present,
                value=field_value,
                context=context,
            )
            combined.merge(evaluation.result)

        return combined

    def _resolve_field_value(self, value: Any, field: str) -> Tuple[bool, Any]:
        """Find field value in potentially nested structure."""
        if isinstance(value, Mapping):
            # Direct key access
            if field in value:
                return True, value[field]
            
            # Support nested field syntax: "user.name"
            if "." in field:
                parts = field.split(".", 1)
                if parts[0] in value:
                    return self._resolve_field_value(value[parts[0]], parts[1])
            
            # Recurse into nested values
            for nested_value in value.values():
                present, field_value = self._resolve_field_value(nested_value, field)
                if present:
                    return present, field_value
            return False, None

        if self._is_sequence(value):
            for item in value:
                present, field_value = self._resolve_field_value(item, field)
                if present:
                    return present, field_value

        return False, None

    @staticmethod
    def _is_sequence(value: Any) -> bool:
        return isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray))


__all__ = ["OutputValidator"]
'''

# Write new validation/output.py
with open('d2/validation/output_new.py', 'w') as f:
    f.write(validation_output)

print("✓ Created d2/validation/output_new.py")

# ============================================================================
# Step 2: Extract sanitizer section to create d2/sanitization/output.py
# ============================================================================

# Find markers
sanitizer_start = full_content.find('# ==============================================================================\n# OUTPUT SANITIZATION')
legacy_start = full_content.find('# ==============================================================================\n# LEGACY UNIFIED INTERFACE')

# Extract imports and REDACTED_TOKEN from original
imports_end = full_content.find('\n\nREDACTED_TOKEN = "[REDACTED]"')
imports_section = full_content[:imports_end]

# Get just the imports we need for sanitizer
sanitizer_imports = '''# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""Output sanitization - transforms return values to remove/redact sensitive data.

This module provides OutputSanitizer for applying field actions (filter/redact/truncate/deny)
to transform sensitive data before returning it to callers.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, MutableSequence, Sequence, Tuple

from ..validation.base import ValidationContext, ValidationResult
from ..validation.constraints import ConstraintEvaluator

REDACTED_TOKEN = "[REDACTED]"
'''

# Extract sanitizer class and helpers
sanitizer_content = full_content[sanitizer_start:legacy_start].strip()

# Combine
full_sanitizer = sanitizer_imports + '\n\n' + sanitizer_content

with open('d2/sanitization/output.py', 'w') as f:
    f.write(full_sanitizer)

print("✓ Created d2/sanitization/output.py")

# ============================================================================
# Step 3: Create d2/sanitization/__init__.py
# ============================================================================

sanitization_init = '''"""Sanitization package - data transformation utilities."""

from .output import OutputSanitizer, SanitizationResult, REDACTED_TOKEN

__all__ = [
    "OutputSanitizer",
    "SanitizationResult", 
    "REDACTED_TOKEN",
]
'''

with open('d2/sanitization/__init__.py', 'w') as f:
    f.write(sanitization_init)

print("✓ Created d2/sanitization/__init__.py")

print("\n✅ File creation complete!")
print("\nNext steps:")
print("1. Move d2/validation/output_new.py to d2/validation/output.py")
print("2. Update d2/validation/__init__.py")
print("3. Update d2/runtime files")
print("4. Run tests")


