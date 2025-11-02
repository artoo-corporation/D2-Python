# D2 SDK – Quick Start

<div align="left">

<a href="https://github.com/artoo-corporation/D2-Python/actions/workflows/ci.yml">
  <img src="https://img.shields.io/github/actions/workflow/status/artoo-corporation/D2-Python/ci.yml?label=CI" alt="CI" />
</a>
<img src="https://img.shields.io/badge/python-3.9%E2%80%933.12-blue" alt="Python Versions" />

</div>


This page is the **5-minute guide**. For deeper explanations read `README.md`.

---

## 1  Install
```bash
pip install d2-sdk
# CLI helpers
pip install "d2-sdk[cli]"
```

## 2  Protect a tool
```python
from d2 import d2_guard

@d2_guard("weather_api:read")
async def get_weather(city: str): ...
```

## 3  Generate a local policy

Generate a starter policy file for **local mode**. The command scans your
project for any functions already decorated with **`@d2_guard`** and seeds the
permissions list.

*Haven’t added the decorator yet?* No problem—run it now, add decorators later,
and re-run `d2 init --force` to refresh the file.

```bash
# Scan current working directory and output YAML (~/.config/d2/policy.yaml)
python -m d2 init

# Custom path & JSON output
python -m d2 init --path ./src --format json
```
Creates `~/.config/d2/policy.yaml` by default.

Minimal schema:
```yaml
metadata:
  name: your-app-name
  description: Optional
  expires: ISO-8601
policies:
  - role: admin
    permissions: ["*"]
```

### 3.1  Add guardrails with input/output policies

Want a quick safety net without touching your code? Drop the rules into policy and D2 enforces them for you.

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

With the policy in place, D2 blocks calls that wander off the guardrails and logs `reason="input_validation"` so you know why.

Need to clean the response on the way out?

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

The decorator strips PII, masks values, and if anything still violates the policy D2 raises `PermissionDeniedError` with `reason="output_validation"`. Your `on_deny` handler runs if you configured one, and telemetry captures the same reason code for dashboards/alerts.

Want to see it live? Run `python examples/guardrails_demo.py`—it boots with `examples/guardrails_policy.yaml`, denies bad inputs, and shows how responses get scrubbed automatically.

### Nested guards
- Guarded functions can call other guarded functions. Each layer re-validates inputs and output using the same user context, so inner responses are cleaned before outer logic sees them.

## 4  Initialise RBAC (one line)

```python
# Async service (FastAPI lifespan, Quart, etc.)
import asyncio, d2
asyncio.run(d2.configure_rbac_async())

# Sync app (Flask, Django, scripts)
d2.configure_rbac_sync()
```

## 5  Inject user context & auto-clear it

### Async route (no middleware needed)
```python
from d2 import set_user, clear_context_async

@clear_context_async                 # auto-clears context after await
async def ping(request):
    set_user(request.state.user_id, ["viewer"])
    return "pong"
```
> Optional: Behind a *trusted reverse-proxy* you can install
> `d2.ASGIMiddleware` instead of manually calling `set_user()`.

```python
from d2 import ASGIMiddleware, headers_extractor

app.add_middleware(
    ASGIMiddleware,
    user_extractor=headers_extractor,  # only if headers are injected by proxy
)
```

## 4.1 Configure D2 in your app (context manager)
```python
import d2

# Initialize at startup (async services)
async def lifespan():
    await d2.configure_rbac_async()

# Per request/interaction
def handle_request(user_id: str, roles: list[str]):
    # Use context manager to avoid leaks
    with d2.set_user_context(user_id, roles):
        weather = get_weather("San Francisco")
        # ... call other guarded tools ...
    # Context auto-cleared on exit
```

> Security Note: Prefer `with d2.set_user_context(...)` to guarantee cleanup. If you use `d2.set_user()`, call `d2.clear_user_context()` before returning.

### You're all set!
Protected functions are default‑deny until granted in your policy.

- Calls raise `PermissionDeniedError` until authorized
- Edit `~/.config/d2/policy.yaml` to grant permissions to roles
- Validate with `python -m d2 inspect`

`headers_extractor` is a tiny helper that pulls the user ID and comma-separated
role list from the `X-D2-User` and `X-D2-Roles` HTTP headers.  Use it **only**
when a trusted upstream component overwrites those headers.

### Sync route
```python
from d2 import set_user, clear_context

@clear_context                       # auto-clears after return
def handler(request):
    set_user(request.user.id, roles=request.user.roles)
    return get_weather("Berlin")
```

## 6  Handy CLI commands
| command | purpose |
|---------|---------|
| `d2 diagnose` | Check local policy limits & expiry |
| `d2 inspect`  | List permissions (local or cloud) |
| `d2 pull`     | Download cloud bundle (token) |
| `d2 draft`    | Upload policy draft (token with policy:write) – note: 403 quota_apps_exceeded is non‑retryable |
| `d2 publish`  | Publish signed bundle (token with policy:write) – handles 409 ETag retry; surfaces 403 quota_apps_exceeded |

## 7  Environment Variables (recap)
- `D2_TOKEN`: if set, enables Cloud mode; unset → Local mode
- `D2_POLICY_FILE`: explicit path to local policy (overrides discovery)
- `D2_TELEMETRY`: `off|metrics|usage|all` (default `all`)
- `D2_JWKS_URL`: override JWKS endpoint (rare)
- `D2_STRICT_SYNC`: set to `1` to fail sync-in-async rather than auto-threading
- `D2_API_URL`: control-plane base URL (defaults via `DEFAULT_API_URL` in code)
- `D2_STATE_PATH`: override path for persisted bundle state (`~/.config/d2/bundles.json` by default)

Cloud mode notes:
- JWKS rotation is automatic. The server can signal refresh; SDK updates keys transparently.
- Plan/app limits are surfaced clearly in CLI and SDK (`D2PlanLimitError` for 402; `quota_apps_exceeded` for 403).
 - Privacy: Any `user_id` you pass to `d2.set_user()` may be included as-is in cloud usage events. Hash/pseudonymize if needed.
- Telemetry never breaks your app—if the exporter isn’t present, we silently no-op.

---
Need more details?  Jump to the full `README.md` . 