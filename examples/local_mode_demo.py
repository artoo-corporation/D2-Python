# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

import asyncio
import logging
import os
import pathlib

# The SDK will read the app name from the existing ~/.config/d2/policy.yaml file
# to determine which cloud policy to fetch. No need to override D2_POLICY_FILE
# since we want to use the user's existing policy file for app name resolution.

from d2 import d2_guard, set_user, configure_rbac, clear_user_context
from d2.exceptions import PermissionDeniedError, D2Error

# Basic logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


# --- Define 4 Tools, each with a different denial strategy ---

# 1. Default: Raises PermissionDeniedError
@d2_guard("database:query")
async def query_database(query: str):
    """Requires 'database:query' permission. Will raise error on denial."""
    # Simulate I/O
    await asyncio.sleep(0.1)
    return f"Query results for: {query}"

# 2. Static Value: Returns a pre-defined string on denial
@d2_guard("weather_api", on_deny="[Weather API access is restricted]")
async def get_weather(location: str):
    """Requires 'weather_api' permission. Returns static string on denial."""
    await asyncio.sleep(0.05)
    return f"The weather in {location} is sunny."

# 3. Simple Handler: Calls a lambda function on denial
@d2_guard("notifications:send", on_deny=lambda: logging.warning("Blocked attempt to send notification."))
async def send_notification(message: str):
    """Requires 'notifications:send' permission. Logs a warning on denial."""
    logging.info(f"Notification sent: {message}")
    return "Notification sent successfully."

# 4. Contextual Handler: Calls a function with error details on denial
def detailed_denial_handler(error: PermissionDeniedError):
    """A custom handler that logs details and returns a specific dict."""
    logging.error(
        "DENIAL CONTEXT: User '%s' (roles: %s) was denied access to tool '%s'",
        error.user_id, error.roles, error.tool_id
    )
    return {"error": "ACCESS_DENIED", "tool": error.tool_id}

@d2_guard("admin:manage_users", on_deny=detailed_denial_handler)
async def manage_users(action: str):
    """Requires 'admin:manage_users' permission. Calls a detailed logger on denial."""
    return f"User action '{action}' completed successfully."


async def main():
    # Initialize the D2 SDK. If D2_TOKEN is set, it will use cloud mode
    # and fetch policy from the server. If not set, it will use local file mode.
    # The demo_policy.yaml file provides the app name for cloud policy lookup.
    await configure_rbac()

    print("\n--- Running as a 'developer' (has database:query, weather_api, notifications:send permissions) ---")
    # A real web framework would set the context in middleware; we do it inline here.
    set_user("dev-123", roles=["developer"])
    
    # Test Case 1: ALLOWED - developer has database:query permission
    print("\nAttempting query_database('SELECT * FROM users')... (should be ALLOWED)")
    try:
        result = await query_database("SELECT * FROM users")
        print(f"  -> OK. Query succeeded: {result}")
    except PermissionDeniedError as e:
        print(f"  [!] TEST FAILED: Expected query to succeed, but got: {e}")

    # Test Case 2: ALLOWED - developer has weather_api permission
    print("\nAttempting get_weather('london')... (should be ALLOWED)")
    result = await get_weather("london")
    print(f"  -> Result: {result}")
    if result and "sunny" not in result:
        print("  [!] TEST FAILED: Expected weather result.")

    # Test Case 3: ALLOWED - developer has notifications:send permission
    print("\nAttempting send_notification('hello')... (should be ALLOWED)")
    result = await send_notification("hello")
    print(f"  -> Result: {result}")
    if result != "Notification sent successfully.":
        print("  [!] TEST FAILED: Expected successful notification.")

    # Test Case 4: DENIED - developer lacks admin:manage_users permission (only admin has *)
    print("\nAttempting manage_users('create')... (should be DENIED and return dict)")
    result = await manage_users("create")
    print(f"  -> Result: {result}")
    if not isinstance(result, dict) or "error" not in result:
        print("  [!] TEST FAILED: Expected an error dictionary from the contextual handler.")
            
    print("\n\n--- Running as 'admin' (has all relevant permissions) ---")
    set_user("admin-789", roles=["admin"])
    # Admin should succeed on all calls
    print("\nAttempting manage_users('delete')... (should be ALLOWED)")
    result = await manage_users('delete')
    print(f"  -> Result: {result}")
    if "error" in str(result):
        print("  [!] TEST FAILED: Admin was denied.")

    print("\nAttempting get_weather('tokyo')... (should be ALLOWED)")
    result = await get_weather('tokyo')
    print(f"  -> Result: {result}")
    if "restricted" in str(result):
        print("  [!] TEST FAILED: Admin was denied.")

    # Clear context at end of RBAC tests
    clear_user_context()

    # ------------------------------------------------------------------
    # Run auto-thread demonstrations (sync + async hybrid scenarios)
    # ------------------------------------------------------------------
    await run_autothread_demos()


# ---------------------------------------------------------------------------
# Demo • auto-threading behaviour (v0.4+)
# ---------------------------------------------------------------------------
# These snippets show how the SDK now "just works" in sync, async and mixed
# contexts.  Run this file directly to see output, or import the individual
# demo_* functions in your own scratch pad.

import anyio
import asyncio
import d2

async def run_autothread_demos():
    """Show automatic sync-in-async off-load behaviour (v0.4+)."""

    # Use the same SDK initialisation that main() already executed.
    d2.set_user("demo-user", roles=["admin"])

    print("\n==================  AUTO-THREAD DEMOS  ==================")

    # -- Sync tool ----------------------------------------------------------
    @d2.d2_guard("demo.sync_echo")
    def sync_echo(x: str):
        import threading
        print(f"sync_echo called on thread {threading.current_thread().name}")
        return x.upper()

    # -- Nested sync -> sync (auto-thread) ----------------------------------
    @d2.d2_guard("demo.outer")
    def outer():
        return inner()

    @d2.d2_guard("demo.inner")
    def inner():
        print("inside inner()")
        return 42

    async def demo_async_call():
        print("\n--- demo_async_call (event-loop running) ---")
        res = outer()  # auto-thread kicks in
        print("outer() returned:", res)

    # 1. Pure sync call
    print("--- pure sync path ---")
    print("sync_echo =>", sync_echo("hello"))

    # 2. Nested sync call (still no loop)
    print("--- nested sync path (no loop) ---")
    print("outer =>", outer())

    # 3. Inside an event-loop → auto-thread behaviour
    await demo_async_call()

    # -- Async tools -----------------------------------------------------------
    @d2.d2_guard("demo.async_echo")
    async def async_echo(x: str):
        await asyncio.sleep(0.01)
        return x[::-1]

    @d2.d2_guard("demo.async_inner")
    async def ainner():
        await asyncio.sleep(0.01)
        return 7

    @d2.d2_guard("demo.async_outer")
    async def aouter():
        return await ainner()

    # -- Async calling Sync (auto-thread for the sync piece) -------------------
    @d2.d2_guard("demo.sync_square")
    def sync_square(n: int) -> int:
        return n * n

    @d2.d2_guard("demo.async_calls_sync")
    async def async_calls_sync(n: int) -> int:
        return sync_square(n)

    # -- Strict mode demo (raises in sync-in-async) ----------------------------
    @d2.d2_guard("demo.strict_sync", strict=True)
    def strict_sync():
        return "should not run inside event loop"

    print("\n--- async-guarded demos ---")
    print("async_echo =>", await async_echo("abc"))

    print("async nested outer =>", await aouter())

    print("async calls sync (auto-thread inside) =>", await async_calls_sync(5))

    print("--- strict=True demo (expect D2Error) ---")
    try:
        strict_sync()
        print("  [!] TEST FAILED: strict_sync() should have raised")
    except D2Error as e:
        print("  -> OK. strict mode raised:", type(e).__name__)

    print("================  END AUTO-THREAD DEMOS  ================\n")

# ---------------------------------------------------------------------------
# Entry-point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # Ensure you have run `python -m d2 init` before this script.
    asyncio.run(main()) 