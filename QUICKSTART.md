# D2 SDK: Quick Start

<div align="left">

<a href="https://github.com/artoo-corporation/D2-Python/actions/workflows/ci.yml">
  <img src="https://img.shields.io/github/actions/workflow/status/artoo-corporation/D2-Python/ci.yml?label=CI" alt="CI" />
</a>
<img src="https://img.shields.io/badge/python-3.9%E2%80%933.12-blue" alt="Python Versions" />

</div>


This is the 5-minute getting started guide. For more details, read `README.md`.

---

## Step 1: Install

```bash
#for both SDK and CLI
pip install "d2-sdk[all]"
```

## Step 2: Protect a function

```python
from d2 import d2_guard

@d2_guard("weather_api:read")
async def get_weather(city: str):
    ...
```

## Step 3: Create a local policy file

Generate a starter policy file that works in local mode (no cloud account needed). The command scans your project for any functions decorated with `@d2_guard` and adds them to the permissions list.

Haven't added the decorator yet? No problem. Run the command now, add decorators later, and run `d2 init --force` again to update the file.

```bash
# Scans current directory and creates ~/.config/d2/policy.yaml
python -m d2 init

# Specify a custom path and use JSON format
python -m d2 init --path ./src --format json
```

The command creates `~/.config/d2/policy.yaml` by default.

Here's a minimal policy file:

```yaml
metadata:
  name: your-app-name
  description: Optional description
  expires: 2025-12-31T23:59:59+00:00
policies:
  - role: admin
    permissions: ["*"]
```

### Adding input and output guardrails

You can add safety rules without changing your code. Just add the rules to your policy and D2 will enforce them automatically.

**Input validation example:**

```yaml
- role: analyst
  permissions:
    - tool: reports.generate
      allow: true
      conditions:
        input:
          table: {in: [analytics, dashboards]}
          row_limit: {max: 1000}
```

```python
@d2_guard("reports.generate")
def generate(table: str, row_limit: int):
    ...
```

With this policy, D2 blocks any calls with invalid arguments and logs `reason="input_validation"` so you know what happened.

**Output sanitization example:**

```yaml
- role: support
  permissions:
    - tool: crm.lookup_customer
      allow: true
      conditions:
        output:
          ssn: {action: filter}
          salary: {max: 100000, action: redact}
          notes: {matches: "(?i)secret", action: deny}
```

```python
@d2_guard("crm.lookup_customer")
def lookup_customer(customer_id: str):
    ...
```

The decorator automatically removes PII and masks sensitive values. If something violates the policy, D2 raises `PermissionDeniedError` with `reason="output_validation"`. Your `on_deny` handler runs if you set one up, and telemetry records the same reason code.

**Important note about typos**

D2 checks all operators and regex patterns when it loads your policy, not when your code runs. This catches problems early:

- Unknown operators cause `ConfigurationError` (common mistakes: `minimum` should be `min`, `maximum` should be `max`, `minlength` should be `minLength`)
- Invalid regex patterns cause `ConfigurationError` with details about what's wrong
- Bad policies fail at startup, not in production

All operator names are case-sensitive. If you get a `ConfigurationError`, check the error message for suggestions.

Want to see it working? Run `python examples/guardrails_demo.py`. It uses `examples/guardrails_policy.yaml`, blocks bad inputs, and shows how responses get cleaned up.

### Nested guards

Guarded functions can call other guarded functions. Each layer checks inputs and outputs using the same user context, so inner responses get cleaned before outer functions see them.

## Step 4: Initialize RBAC (one line of code)

```python
# For async services (FastAPI, Quart, etc.)
import asyncio, d2
asyncio.run(d2.configure_rbac_async())

# For sync apps (Flask, Django, scripts)
d2.configure_rbac_sync()
```

## Step 5: Set user context and clear it

### Async route (no middleware needed)

```python
from d2 import set_user, clear_context_async

@clear_context_async  # Clears context automatically after await
async def ping(request):
    set_user(request.state.user_id, ["viewer"])
    return "pong"
```

### Using context managers

```python
import d2

# Initialize once at startup (async services)
async def lifespan():
    await d2.configure_rbac_async()

# For each request
def handle_request(user_id: str, roles: list[str]):
    # Use context manager to prevent leaks
    with d2.set_user_context(user_id, roles):
        weather = get_weather("San Francisco")
        # Call other protected functions here
    # Context gets cleared automatically when block exits
```

**Security tip:** Use `with d2.set_user_context(...)` to make sure cleanup happens. If you use `d2.set_user()` instead, you must call `d2.clear_user_context()` before the function returns.

### You're ready to go

Protected functions are blocked by default until you grant access in your policy.

- Calls raise `PermissionDeniedError` when not authorized
- Edit `~/.config/d2/policy.yaml` to give permissions to roles
- Check your policy with `python -m d2 inspect`

### Sync route example

```python
from d2 import set_user, clear_context

@clear_context  # Clears context automatically after return
def handler(request):
    set_user(request.user.id, roles=request.user.roles)
    return get_weather("Berlin")
```

## Step 6: Useful CLI commands

| Command | What it does |
|---------|--------------|
| `d2 diagnose` | Check local policy limits and expiry date |
| `d2 inspect` | Show all permissions (works with local or cloud) |
| `d2 pull` | Download cloud policy bundle (needs token) |
| `d2 draft` | Upload policy draft (needs token with policy:write permission) |
| `d2 publish` | Publish signed policy bundle (needs token with policy:write permission) |

## Step 7: Environment variables reference

- `D2_TOKEN`: When set, enables cloud mode. When unset, uses local mode.
- `D2_POLICY_FILE`: Specific path to your local policy file (skips auto-discovery)
- `D2_TELEMETRY`: Control telemetry (`off`, `metrics`, `usage`, or `all`). Default is `all`.
- `D2_JWKS_URL`: Override the JWKS endpoint (rarely needed)
- `D2_STRICT_SYNC`: Set to `1` to make sync-in-async fail instead of auto-threading
- `D2_API_URL`: Base URL for the control plane (has a built-in default)
- `D2_STATE_PATH`: Path for cached bundle state (defaults to `~/.config/d2/bundles.json`)

### Cloud mode notes

- JWKS rotation happens automatically. The server tells the SDK when to refresh keys.
- Plan and app limits are shown clearly in the CLI and SDK (`D2PlanLimitError` for 402 errors, `quota_apps_exceeded` for 403 errors).
- Privacy: Any `user_id` you pass to `d2.set_user()` might be included in cloud usage events. Hash or change it if needed.
- Telemetry problems never crash your app. If the exporter isn't working, we skip it silently.

---

Need more information? Read the full `README.md` file.
