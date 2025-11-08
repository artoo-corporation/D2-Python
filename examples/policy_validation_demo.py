# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""Policy Validation Demo: Strict Validation Catches Errors Early.

This demo shows how D2's strict policy validation catches typos and errors
at load time, not at runtime. This prevents silent security bypasses where
you think a rule is protecting your app but it's actually being ignored.

Run with:
    python examples/policy_validation_demo.py
"""

import os
import tempfile
from pathlib import Path

from d2 import configure_rbac_sync
from d2.exceptions import ConfigurationError


def demo_unknown_operator():
    """Show how unknown operators are caught at policy load time."""
    print("\n" + "=" * 70)
    print("DEMO 1: Unknown Operator Detection")
    print("=" * 70)
    print("\nTrying to load a policy with a typo: 'maximum' instead of 'max'")
    
    bad_policy = """
metadata:
  name: validation-demo
  expires: "2025-12-31T23:59:59+00:00"

policies:
  - role: analyst
    permissions:
      - tool: reports.generate
        allow: true
        conditions:
          input:
            row_limit: {minimum: 1, maximum: 1000}  # Typos: should be min/max
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(bad_policy)
        temp_path = f.name
    
    try:
        os.environ["D2_POLICY_FILE"] = temp_path
        configure_rbac_sync()
        print("  Result: FAIL - Policy loaded (should have been rejected)")
    except ConfigurationError as e:
        print("  Result: SUCCESS - Policy rejected at load time")
        print(f"\n  Error message:")
        print(f"    {e}")
        print("\n  What happened:")
        print("    - D2 checked all operators against known whitelist")
        print("    - Found 'minimum' and 'maximum' which don't exist")
        print("    - Raised ConfigurationError with suggestions")
        print("\n  Why this matters:")
        print("    - Without strict validation, typos would be silently ignored")
        print("    - Your policy would have no effect, creating a security hole")
        print("    - Catching it at load time prevents production incidents")
    finally:
        os.unlink(temp_path)


def demo_case_sensitivity():
    """Show that operator names are case-sensitive."""
    print("\n" + "=" * 70)
    print("DEMO 2: Case-Sensitive Operator Names")
    print("=" * 70)
    print("\nTrying to load a policy with wrong capitalization")
    
    bad_policy = """
metadata:
  name: validation-demo
  expires: "2025-12-31T23:59:59+00:00"

policies:
  - role: analyst
    permissions:
      - tool: reports.generate
        allow: true
        conditions:
          input:
            format: {Type: string, Required: true}  # Wrong: should be lowercase
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(bad_policy)
        temp_path = f.name
    
    try:
        os.environ["D2_POLICY_FILE"] = temp_path
        configure_rbac_sync()
        print("  Result: FAIL - Policy loaded (should have been rejected)")
    except ConfigurationError as e:
        print("  Result: SUCCESS - Policy rejected at load time")
        print(f"\n  Error message:")
        print(f"    {e}")
        print("\n  Correct operators: 'type', 'required' (lowercase)")
    finally:
        os.unlink(temp_path)


def demo_common_typos():
    """Show common typos that D2 catches."""
    print("\n" + "=" * 70)
    print("DEMO 3: Common Typos D2 Catches")
    print("=" * 70)
    
    common_mistakes = [
        ("minlength", "minLength (capital L)"),
        ("maxlength", "maxLength (capital L)"),
        ("minLenght", "minLength (typo in Length)"),
        ("maxLenght", "maxLength (typo in Length)"),
    ]
    
    print("\nCommon mistakes D2 prevents:")
    for wrong, right in common_mistakes:
        print(f"  Wrong: {wrong:15} -> Right: {right}")
    
    print("\nTrying a policy with 'minlength' typo:")
    
    bad_policy = """
metadata:
  name: validation-demo
  expires: "2025-12-31T23:59:59+00:00"

policies:
  - role: analyst
    permissions:
      - tool: reports.generate
        allow: true
        conditions:
          input:
            name: {minlength: 3, maxlength: 50}  # Wrong: should be minLength/maxLength
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(bad_policy)
        temp_path = f.name
    
    try:
        os.environ["D2_POLICY_FILE"] = temp_path
        configure_rbac_sync()
        print("  Result: FAIL - Policy loaded (should have been rejected)")
    except ConfigurationError as e:
        print("  Result: SUCCESS - Policy rejected at load time")
        print(f"\n  Error details:")
        for line in str(e).split('\n')[:3]:
            print(f"    {line}")
    finally:
        os.unlink(temp_path)


def demo_invalid_regex():
    """Show how invalid regex patterns are caught at load time."""
    print("\n" + "=" * 70)
    print("DEMO 4: Invalid Regex Pattern Detection")
    print("=" * 70)
    print("\nTrying to load a policy with malformed regex")
    
    bad_policy = """
metadata:
  name: validation-demo
  expires: "2025-12-31T23:59:59+00:00"

policies:
  - role: analyst
    permissions:
      - tool: reports.generate
        allow: true
        conditions:
          input:
            email: {matches: "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-+\\.{2,}$"}  # Bad regex: unclosed [
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(bad_policy)
        temp_path = f.name
    
    try:
        os.environ["D2_POLICY_FILE"] = temp_path
        configure_rbac_sync()
        print("  Result: FAIL - Policy loaded (should have been rejected)")
    except ConfigurationError as e:
        print("  Result: SUCCESS - Policy rejected at load time")
        print(f"\n  Error message:")
        print(f"    {e}")
        print("\n  What happened:")
        print("    - D2 tried to compile the regex pattern")
        print("    - Python's re.compile() failed with syntax error")
        print("    - D2 caught this and raised ConfigurationError")
        print("\n  Why this matters:")
        print("    - Without validation, this would crash at runtime")
        print("    - Could crash during a customer request in production")
        print("    - Catching at load time lets you fix it before deploy")
    finally:
        os.unlink(temp_path)


def demo_valid_policy():
    """Show that valid policies load successfully."""
    print("\n" + "=" * 70)
    print("DEMO 5: Valid Policy Loads Successfully")
    print("=" * 70)
    print("\nLoading a policy with all correct operators and regex")
    
    good_policy = """
metadata:
  name: validation-demo
  expires: "2025-12-31T23:59:59+00:00"

policies:
  - role: analyst
    permissions:
      - tool: reports.generate
        allow: true
        conditions:
          input:
            name: {type: string, minLength: 3, maxLength: 50, required: true}
            count: {type: int, min: 1, max: 1000}
            email: {matches: "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[A-Za-z]{2,}$"}
            format: {in: [json, csv, xml]}
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(good_policy)
        temp_path = f.name
    
    try:
        os.environ["D2_POLICY_FILE"] = temp_path
        configure_rbac_sync()
        print("  Result: SUCCESS - Policy loaded")
        print("\n  All validations passed:")
        print("    - All operators recognized (type, minLength, maxLength, etc.)")
        print("    - All regex patterns compiled successfully")
        print("    - Policy is ready for use")
        print("\n  Benefits of strict validation:")
        print("    - No silent failures")
        print("    - No runtime surprises")
        print("    - Security rules work as intended")
    finally:
        os.unlink(temp_path)


def main():
    print("\n" + "=" * 70)
    print("D2 Policy Validation Demo")
    print("=" * 70)
    print("\nThis demo shows how D2 catches policy errors at load time,")
    print("preventing silent security bypasses and runtime crashes.")
    
    try:
        demo_unknown_operator()
        input("\n\nPress Enter to continue...\n")
        
        demo_case_sensitivity()
        input("\n\nPress Enter to continue...\n")
        
        demo_common_typos()
        input("\n\nPress Enter to continue...\n")
        
        demo_invalid_regex()
        input("\n\nPress Enter to continue...\n")
        
        demo_valid_policy()
        
        print("\n" + "=" * 70)
        print("Demo Complete!")
        print("=" * 70)
        print("\nKey Takeaways:")
        print("  1. D2 validates ALL operators at policy load time")
        print("  2. Typos and wrong capitalization are caught immediately")
        print("  3. Invalid regex patterns are caught before they can crash")
        print("  4. This prevents silent security bypasses in production")
        print("  5. Always run 'd2 diagnose' before deploying a policy")
        print("\n")
        
    except KeyboardInterrupt:
        print("\n\nDemo interrupted.")


if __name__ == "__main__":
    main()


