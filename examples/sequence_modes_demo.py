#!/usr/bin/env python3
# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""Demo: Sequence modes (allow vs deny) for different security requirements.

This example demonstrates:
1. ALLOW MODE (blocklist): Default behavior, deny specific patterns
2. DENY MODE (allowlist): Zero-trust, only allow specific patterns
3. When to use each mode based on security requirements
"""

import asyncio
from d2 import d2_guard, set_user_context, clear_user_context
from d2.policy_client import PolicyClient
from d2.exceptions import PermissionDeniedError


# ═══════════════════════════════════════════════════════════════════════════
# Mock Tools for Demonstration
# ═══════════════════════════════════════════════════════════════════════════

@d2_guard
async def database_read_users(limit: int = 10):
    """Read users from database."""
    return f"[DB] Read {limit} users"

@d2_guard
async def analytics_process(data: str):
    """Process data through analytics."""
    return f"[ANALYTICS] Processed: {data}"

@d2_guard
async def web_http_request(url: str):
    """Make external HTTP request."""
    return f"[WEB] Request to {url}"

@d2_guard
async def email_send(to: str, subject: str):
    """Send email."""
    return f"[EMAIL] Sent to {to}: {subject}"

@d2_guard
async def report_generate(title: str):
    """Generate report."""
    return f"[REPORT] Generated: {title}"

@d2_guard
async def file_read(path: str):
    """Read file from disk."""
    return f"[FILE] Read: {path}"


# ═══════════════════════════════════════════════════════════════════════════
# Demo 1: ALLOW MODE (Blocklist) - Senior Engineer
# ═══════════════════════════════════════════════════════════════════════════

async def demo_allow_mode():
    """
    ALLOW MODE: Trusted user with broad permissions.
    Strategy: Allow everything except known-bad patterns.
    """
    print("\n" + "="*80)
    print("DEMO 1: ALLOW MODE (Blocklist) - Senior Engineer")
    print("="*80)
    print("Policy: mode=allow, deny specific dangerous sequences")
    print("User has broad permissions, most workflows are allowed\n")
    
    # Set user context
    set_user_context(user_id="senior_eng_001", roles=["senior_engineer"])
    
    # ✅ ALLOWED: Safe internal workflow (not in deny list)
    print("✅ Test 1: Safe internal workflow")
    print("   Sequence: database.read_users → analytics.process → report.generate")
    try:
        result1 = await database_read_users(limit=100)
        print(f"   Step 1: {result1}")
        result2 = await analytics_process(result1)
        print(f"   Step 2: {result2}")
        result3 = await report_generate("User Analytics")
        print(f"   Step 3: {result3}")
        print("   ✅ SUCCESS: Internal workflow allowed (not in deny list)\n")
    except PermissionDeniedError as e:
        print(f"   ❌ DENIED: {e.reason}\n")
    
    # ❌ BLOCKED: Direct exfiltration (in deny list)
    print("❌ Test 2: Direct data exfiltration (blocked by deny rule)")
    print("   Sequence: database.read_users → web.http_request")
    try:
        clear_user_context()
        set_user_context(user_id="senior_eng_001", roles=["senior_engineer"])
        result1 = await database_read_users(limit=100)
        print(f"   Step 1: {result1}")
        result2 = await web_http_request("https://external-api.com")
        print(f"   Step 2: {result2}")
        print("   ✅ SUCCESS: Should not reach here!\n")
    except PermissionDeniedError as e:
        print(f"   ❌ BLOCKED: {e.reason}")
        print("   ✅ CORRECT: Deny rule caught exfiltration attempt\n")
    
    # ✅ ALLOWED: Data ingestion from external source (not in deny list)
    print("✅ Test 3: External data ingestion")
    print("   Sequence: web.http_request → analytics.process")
    try:
        clear_user_context()
        set_user_context(user_id="senior_eng_001", roles=["senior_engineer"])
        result1 = await web_http_request("https://data-source.com/feed")
        print(f"   Step 1: {result1}")
        result2 = await analytics_process(result1)
        print(f"   Step 2: {result2}")
        print("   ✅ SUCCESS: External ingestion allowed (reverse direction is safe)\n")
    except PermissionDeniedError as e:
        print(f"   ❌ DENIED: {e.reason}\n")
    
    clear_user_context()


# ═══════════════════════════════════════════════════════════════════════════
# Demo 2: DENY MODE (Allowlist) - Contractor
# ═══════════════════════════════════════════════════════════════════════════

async def demo_deny_mode():
    """
    DENY MODE: Restricted user with limited trust.
    Strategy: Deny everything except explicitly allowed patterns.
    """
    print("\n" + "="*80)
    print("DEMO 2: DENY MODE (Allowlist) - Contractor")
    print("="*80)
    print("Policy: mode=deny, only allow specific approved sequences")
    print("Zero-trust approach: must enumerate every allowed workflow\n")
    
    # Set user context
    set_user_context(user_id="contractor_001", roles=["contractor"])
    
    # ✅ ALLOWED: Explicitly approved workflow
    print("✅ Test 1: Approved workflow (in allow list)")
    print("   Sequence: file.read → report.generate")
    try:
        result1 = await file_read("/data/analytics.csv")
        print(f"   Step 1: {result1}")
        result2 = await report_generate("Contractor Report")
        print(f"   Step 2: {result2}")
        print("   ✅ SUCCESS: Approved sequence allowed\n")
    except PermissionDeniedError as e:
        print(f"   ❌ DENIED: {e.reason}\n")
    
    # ❌ BLOCKED: Not in allow list (even though user has permissions)
    print("❌ Test 2: Unapproved workflow (not in allow list)")
    print("   Sequence: file.read → email.send")
    try:
        clear_user_context()
        set_user_context(user_id="contractor_001", roles=["contractor"])
        result1 = await file_read("/data/analytics.csv")
        print(f"   Step 1: {result1}")
        result2 = await email_send("boss@company.com", "Data Report")
        print(f"   Step 2: {result2}")
        print("   ✅ SUCCESS: Should not reach here!\n")
    except PermissionDeniedError as e:
        print(f"   ❌ BLOCKED: {e.reason}")
        print("   ✅ CORRECT: Default deny caught unauthorized sequence\n")
    
    # ✅ ALLOWED: Another approved workflow
    print("✅ Test 3: Another approved workflow")
    print("   Sequence: report.generate → email.send")
    try:
        clear_user_context()
        set_user_context(user_id="contractor_001", roles=["contractor"])
        result1 = await report_generate("Weekly Summary")
        print(f"   Step 1: {result1}")
        result2 = await email_send("team@company.com", "Report Ready")
        print(f"   Step 2: {result2}")
        print("   ✅ SUCCESS: Approved sequence allowed\n")
    except PermissionDeniedError as e:
        print(f"   ❌ DENIED: {e.reason}\n")
    
    clear_user_context()


# ═══════════════════════════════════════════════════════════════════════════
# Demo 3: Comparison - Same Sequence, Different Modes
# ═══════════════════════════════════════════════════════════════════════════

async def demo_mode_comparison():
    """
    Show how the same sequence behaves differently under allow vs deny mode.
    """
    print("\n" + "="*80)
    print("DEMO 3: Mode Comparison - Same Sequence, Different Behavior")
    print("="*80)
    print("Sequence: analytics.process → file.read")
    print("This sequence is NOT in any deny rule and NOT in any allow rule\n")
    
    # Test with senior_engineer (allow mode)
    print("🔵 With senior_engineer (ALLOW mode):")
    set_user_context(user_id="senior_eng_001", roles=["senior_engineer"])
    try:
        result1 = await analytics_process("test data")
        print(f"   Step 1: {result1}")
        result2 = await file_read("/tmp/output.txt")
        print(f"   Step 2: {result2}")
        print("   ✅ ALLOWED: Default allow, no matching deny rule\n")
    except PermissionDeniedError as e:
        print(f"   ❌ DENIED: {e.reason}\n")
    clear_user_context()
    
    # Test with contractor (deny mode)
    print("🔴 With contractor (DENY mode):")
    set_user_context(user_id="contractor_001", roles=["contractor"])
    try:
        result1 = await analytics_process("test data")
        print(f"   Step 1: {result1}")
        result2 = await file_read("/tmp/output.txt")
        print(f"   Step 2: {result2}")
        print("   ✅ ALLOWED: Should not reach here!\n")
    except PermissionDeniedError as e:
        print(f"   ❌ DENIED: {e.reason}")
        print("   ✅ CORRECT: Default deny, no matching allow rule\n")
    clear_user_context()


# ═══════════════════════════════════════════════════════════════════════════
# Demo 4: Real-World Use Cases
# ═══════════════════════════════════════════════════════════════════════════

async def demo_real_world_use_cases():
    """
    Show real-world scenarios where each mode excels.
    """
    print("\n" + "="*80)
    print("DEMO 4: Real-World Use Cases")
    print("="*80)
    
    print("\n📊 USE ALLOW MODE WHEN:")
    print("  • Users are trusted (admins, senior engineers)")
    print("  • Workflows are dynamic and hard to enumerate")
    print("  • Organization values velocity over strict control")
    print("  • Risk tolerance is moderate")
    print("  • Example: Startup, internal tools, rapid prototyping\n")
    
    print("🔒 USE DENY MODE WHEN:")
    print("  • Users are restricted (contractors, interns, AI agents)")
    print("  • Workflows are well-defined and stable")
    print("  • Regulated industry (HIPAA, SOC2, PCI-DSS)")
    print("  • Risk tolerance is low (zero-trust, high-security)")
    print("  • Want to prevent 'unknown unknowns' (fail-closed)")
    print("  • Example: Healthcare, finance, government, AI agent sandboxes\n")
    
    print("💡 HYBRID APPROACH:")
    print("  • Use ALLOW mode for trusted roles")
    print("  • Use DENY mode for restricted roles")
    print("  • Different policies per environment (prod=deny, dev=allow)")
    print("  • Migrate from allow→deny as workflows mature\n")


# ═══════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════

async def main():
    """Run all demos."""
    print("\n" + "="*80)
    print("D2 SEQUENCE MODES DEMO")
    print("="*80)
    print("Demonstrates ALLOW (blocklist) vs DENY (allowlist) sequence modes")
    print("="*80)
    
    # Initialize policy client
    client = PolicyClient(policy_path="examples/sequence_modes_policy.yaml")
    
    await demo_allow_mode()
    await demo_deny_mode()
    await demo_mode_comparison()
    await demo_real_world_use_cases()
    
    print("\n" + "="*80)
    print("DEMO COMPLETE")
    print("="*80)
    print("Key Takeaway:")
    print("  ALLOW mode (blocklist): Easy to use, blocks known-bad patterns")
    print("  DENY mode (allowlist): Stricter security, requires pre-approved workflows")
    print("\nChoose the mode that matches your security requirements!")
    print("="*80 + "\n")


if __name__ == "__main__":
    asyncio.run(main())










