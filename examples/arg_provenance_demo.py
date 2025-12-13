# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""
Argument-Level Provenance Demo
==============================

This demonstrates D2's surgical data flow protection: blocking only when
specific arguments contain tainted values, not blanket blocking everything.

How it works:
1. D2 fingerprints leaf values in tool outputs
2. Stores fingerprints with their labels and origin
3. Before tools run, fingerprints input arguments
4. If fingerprint matches a tainted value, blocks that call

This catches the most dangerous attacks (prompt injection relay attacks)
where malicious content is passed unchanged from source to destination.

Run with:
    python examples/arg_provenance_demo.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
import asyncio

# Set up path for local development
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from d2 import (
    configure_rbac,
    d2_guard,
    set_user,
    clear_user_context,
)
from d2.exceptions import PermissionDeniedError

# Set policy file path - use arg_provenance_policy.yaml
EXAMPLES_DIR = Path(__file__).resolve().parent
POLICY_PATH = EXAMPLES_DIR / "arg_provenance_policy.yaml"
os.environ["D2_POLICY_FILE"] = str(POLICY_PATH)


# -------------------------------------------------------------------------
# Demo tools
# -------------------------------------------------------------------------

@d2_guard("database.read_users")
async def database_read_users(user_id: str):
    """Read user data from database - emits SENSITIVE label."""
    return {
        "id": user_id,
        "email": "alice@company.com",
        "ssn": "123-45-6789",
    }


@d2_guard("user.get_input")
async def user_get_input(prompt: str):
    """Get input from user - emits UNTRUSTED label."""
    return {
        "address": "attacker@evil.com",
        "command": "rm -rf /",
    }


@d2_guard("email.send")
async def email_send(to: str, body: dict):
    """Send an email."""
    return {"status": "sent", "to": to}


@d2_guard("http.post")
async def http_post(url: str, data: dict):
    """Make an HTTP POST request."""
    return {"status": "ok", "url": url}


@d2_guard("shell.run")
async def shell_run(command: str):
    """Run a shell command."""
    return {"status": "executed", "command": command}


# -------------------------------------------------------------------------
# Demo scenarios
# -------------------------------------------------------------------------

async def scenario_1_block_sensitive_data_exfil():
    """
    Scenario 1: Block exfiltration of sensitive data via arguments
    """
    print("\n" + "="*60)
    print("Scenario 1: Blocking sensitive data exfiltration")
    print("="*60)
    
    set_user("agent-1", ["agent"])
    
    # Read sensitive user data
    user_data = await database_read_users("user-123")
    print(f"[ok] Read user data: {user_data}")
    
    # Try to exfiltrate via email - BLOCKED because body contains sensitive data
    try:
        await email_send(to="admin@company.com", body=user_data)
        print("[FAIL] Should have been blocked!")
    except PermissionDeniedError as e:
        print(f"[ok] BLOCKED (body contains SENSITIVE): {e.reason}")
    
    # But sending clean data works
    result = await email_send(to="admin@company.com", body={"message": "Hello"})
    print(f"[ok] Clean email sent: {result}")
    
    clear_user_context()


async def scenario_2_block_untrusted_recipient():
    """
    Scenario 2: Block sending to untrusted addresses
    """
    print("\n" + "="*60)
    print("Scenario 2: Blocking untrusted email recipients")
    print("="*60)
    
    set_user("agent-2", ["agent"])
    
    # Get untrusted input
    user_input = await user_get_input("Enter email address")
    attacker_email = user_input["address"]
    print(f"[ok] Got user input: {attacker_email}")
    
    # Try to send to that address - BLOCKED because 'to' is UNTRUSTED
    try:
        await email_send(to=attacker_email, body={"message": "clean data"})
        print("[FAIL] Should have been blocked!")
    except PermissionDeniedError as e:
        print(f"[ok] BLOCKED (to is UNTRUSTED): {e.reason}")
    
    # But sending to a hardcoded address works
    result = await email_send(to="safe@company.com", body={"message": "clean"})
    print(f"[ok] Email to hardcoded address sent: {result}")
    
    clear_user_context()


async def scenario_3_block_command_injection():
    """
    Scenario 3: Block command injection from untrusted input
    """
    print("\n" + "="*60)
    print("Scenario 3: Blocking command injection")
    print("="*60)
    
    set_user("agent-3", ["agent"])
    
    # Get untrusted input containing malicious command
    user_input = await user_get_input("Enter command")
    malicious_cmd = user_input["command"]
    print(f"[ok] Got untrusted command: {malicious_cmd}")
    
    # Try to run it - BLOCKED because 'command' is UNTRUSTED
    try:
        await shell_run(command=malicious_cmd)
        print("[FAIL] Should have been blocked!")
    except PermissionDeniedError as e:
        print(f"[ok] BLOCKED (command is UNTRUSTED): {e.reason}")
    
    # But running a hardcoded command works
    result = await shell_run(command="ls -la")
    print(f"[ok] Hardcoded command executed: {result}")
    
    clear_user_context()


async def scenario_4_surgical_vs_blanket():
    """
    Scenario 4: Surgical vs blanket blocking comparison
    """
    print("\n" + "="*60)
    print("Scenario 4: Surgical blocking demonstration")
    print("="*60)
    
    set_user("agent-4", ["agent"])
    
    # Read sensitive data
    sensitive = await database_read_users("user-456")
    print(f"[ok] Read sensitive data: {sensitive}")
    
    # HTTP POST with tainted data - BLOCKED
    try:
        await http_post(url="https://example.com", data=sensitive)
        print("[FAIL] Should have been blocked!")
    except PermissionDeniedError as e:
        print(f"[ok] BLOCKED (data is SENSITIVE): {e.reason}")
    
    # HTTP POST with clean data - ALLOWED (surgical, not blanket)
    clean_data = {"action": "ping", "timestamp": "2024-01-01"}
    result = await http_post(url="https://example.com", data=clean_data)
    print(f"[ok] Clean HTTP POST succeeded: {result}")
    
    clear_user_context()


async def main():
    """Run all scenarios."""
    print("\n" + "#"*60)
    print("# D2 Argument-Level Provenance Demo")
    print("#"*60)
    
    # Initialize D2 with the policy file
    await configure_rbac()
    
    await scenario_1_block_sensitive_data_exfil()
    await scenario_2_block_untrusted_recipient()
    await scenario_3_block_command_injection()
    await scenario_4_surgical_vs_blanket()
    
    print("\n" + "#"*60)
    print("# Demo Complete!")
    print("# Key takeaway: D2 fingerprints values at boundaries")
    print("# and blocks only when specific arguments are tainted.")
    print("#"*60 + "\n")


if __name__ == "__main__":
    asyncio.run(main())

