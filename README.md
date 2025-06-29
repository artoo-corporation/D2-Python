# D2‑Python · Detect & Deny

<div align="left">

<a href="https://github.com/artoo-corporation/D2-Python/actions/workflows/ci.yml">
  <img src="https://img.shields.io/github/actions/workflow/status/artoo-corporation/D2-Python/ci.yml?label=CI" alt="CI" />
</a>
<img src="https://img.shields.io/badge/python-3.9%E2%80%933.12-blue" alt="Python Versions" />
<img src="https://img.shields.io/badge/license-BUSL--1.1-blue" alt="License" />

</div>

D2 lets you put a fast, default‑deny RBAC guard in front of any Python function your LLM (or app) can call.

- Secure by default: if a tool isn’t explicitly allowed, it’s blocked
- Seamless DX: one decorator + a per‑request user context
- Local mode for dev; Cloud mode adds signed bundles, polling, and usage analytics
- Telemetry out of the box; no crashes on exporter failures

—

## 📦 Install & bootstrap

```bash
pip install d2-sdk[cli,all]
```

Pick the bootstrap that matches your app:

- Sync apps (CLI scripts, Flask/Django startup):

```python
from d2 import configure_rbac_sync

configure_rbac_sync()  # call once at startup
```

- Async apps (FastAPI, asyncio scripts):

```python
import d2, asyncio

async def lifespan():
    await d2.configure_rbac_async()  # call once at startup
```

Notes
- With `D2_TOKEN` unset → local‑file mode (reads a local policy file)
- With `D2_TOKEN` set → cloud mode (signed bundles + background polling)

> Note: The examples in `examples/` are interactive and use `print`/`input` for demonstration.

---

## 🔒 API stability (since 1.0)

The public API exported from `d2` is considered stable. Backward-incompatible changes will follow semantic versioning with a major version bump. Key stable symbols:
- Decorator: `d2_guard` (alias `d2`)
- RBAC bootstrap: `configure_rbac_async`, `configure_rbac_sync`, `shutdown_rbac`, `shutdown_all_rbac`, `get_policy_manager`
- Context helpers: `set_user`, `set_user_context`, `get_user_context`, `clear_user_context`, `warn_if_context_set`
- Middleware: `ASGIMiddleware`, `headers_extractor`, `clear_context`, `clear_context_async`
- Exceptions: `PermissionDeniedError`, `MissingPolicyError`, `BundleExpiredError`, `TooManyToolsError`, `PolicyTooLargeError`, `InvalidSignatureError`, `ConfigurationError`, `D2PlanLimitError`, `D2Error`

---

## 🛡️ Guard sensitive functions

Add `@d2_guard("tool-id")` to any function that should be policy-gated.

- Works on both `def` and `async def`
- If you call a sync tool from an async context, D2 auto‑threads it so you never block the event-loop (no extra code required)

```python
from d2 import d2_guard

@d2_guard("billing:read")
def read_billing():
    return {...}

@d2_guard("analytics:run")
async def run_analytics():
    return await compute()
```

---

## 👤 Set (and clear) user context per request

D2 authorizes by current user roles. Set it once per request; clear it after.

- Sync handlers (Flask/Django/etc.):

```python
from d2 import set_user, clear_context

@clear_context
def view(request):
    set_user(request.user.id, roles=request.user.roles)
    return read_billing()
```

- ASGI apps (FastAPI/Starlette):

```python
from d2 import ASGIMiddleware, headers_extractor

app.add_middleware(ASGIMiddleware, user_extractor=headers_extractor)
# Only behind a trusted proxy that injects/rewrites headers
```

What is `user_extractor`?
- It’s a function that receives the ASGI `scope` and must return a tuple `(user_id, roles)`.
- The built-in `headers_extractor` reads two headers:
  - `X-D2-User`: the user id
  - `X-D2-Roles`: a comma‑separated list of role names
Use it only when a trusted gateway (e.g., your API gateway) sets or rewrites these headers.

Custom extractor example
```python
def my_extractor(scope: dict):
    # Safer when your app already knows the user from session/JWT
    session = scope.get("session", {})
    user_id = session.get("user_id")
    roles = session.get("roles", [])
    return user_id, roles

app.add_middleware(ASGIMiddleware, user_extractor=my_extractor)
```

Tip
- If you don’t use the middleware, call `d2.clear_user_context()` at the end of each request (or use `@clear_context_async` for async handlers)

Explicit pattern without decorators
```python
from d2 import set_user, clear_user_context

def handle_request(req):
    try:
        set_user(req.user.id, roles=req.user.roles)
        return do_work()
    finally:
        clear_user_context()
```

---

## 🧩 Generate a policy and iterate locally

Create a local policy (no cloud token required):

```bash
python -m d2 init --path ./your_project
```

This scans your code for `@d2_guard` and writes a starter policy to:
- `${XDG_CONFIG_HOME:-~/.config}/d2/policy.yaml` by default

The SDK discovers the policy in this order:
1) `D2_POLICY_FILE` (explicit path)
2) `~/.config/d2/policy.yaml` (or XDG)
3) `./policy.yaml|.yml|.json` (CWD)

Example policy
```yaml
metadata:
  name: "your-app-name"
  description: "Optional human description"
  expires: "2025-12-01T00:00:00+00:00"
policies:
  - role: admin
    permissions: ["*"]
  - role: developer
    permissions:
      - "billing:read"
      - "analytics:run"
```

Try it
```python
from d2.exceptions import PermissionDeniedError

try:
    read_billing()
except PermissionDeniedError:
    ...  # map to HTTP 403, return fallback, etc.
```

---

## ☁️ Move to cloud when ready

Add your token and keep the same code:

```bash
export D2_TOKEN=d2_...
```

### Continue: Cloud mode details

```python
await d2.configure_rbac_async()  # same call as local mode
```

- The SDK polls `/v1/policy/bundle` (ETag-aware)
- Instant revocation/versioning; quotas & metrics
  - JWKS rotation is automatic: the control plane can signal a refresh via token headers and the SDK refreshes keys transparently
  - Plan/app limits surfaced clearly: `402` → `D2PlanLimitError`; `403` with `detail: quota_apps_exceeded` → upgrade or delete unused apps

Publish (signed) from CLI:
```bash
python -m d2 publish ./policy.yaml  # auto-generates key & signs
```

Key management
- Keys are registered automatically on first publish and reused thereafter.
- Revocation is managed in the dashboard.

Token types (recommended practice)
- Developer token (scope includes `policy:write`): issued from the dashboard. Use in CI/ops to upload drafts and publish policies via CLI. DO NOT ship this token with your application or devices.
- Runtime token (read‑only): also issued via the dashboard; deploy with services to fetch/verify policy bundles.

> Note: The SDK does not create tokens. It accepts tokens provisioned via the dashboard (Authorization: Bearer ...).

What does “ETag‑aware” polling mean?
- The control-plane (d2 cloud) returns an `ETag` header (a policy bundle version fingerprint).
- The SDK sends `If-None-Match: <etag>` on the next poll; the server replies `304 Not Modified` if nothing changed.
- This avoids re-downloading the same bundle and reduces load.

Failure behavior
- If the network or control-plane is unavailable, the SDK keeps using the last good bundle in memory.
- If no bundle is available or it has expired, D2 fails closed: guarded tools are denied (you’ll see `BundleExpiredError`/`MissingPolicyError` or your `on_deny` fallback).
 - Plan/app limits: publishing/drafting or runtime fetches may fail due to plan limits. Non‑retryable examples:
   - `402` → surfaced as `D2PlanLimitError` (e.g., tool or feature limit)
   - `403` with `detail: quota_apps_exceeded` → account has reached the maximum number of apps; upgrade or delete unused apps

Telemetry note
- “Auto-configured” means: if the OpenTelemetry SDK and the OTLP HTTP exporter are present, D2 turns on metrics automatically; otherwise it does nothing and your app continues normally (no crashes).
- Where metrics go: to your OTLP collector (URL via `OTEL_EXPORTER_OTLP_ENDPOINT`).
- Where usage events go: to D2 Cloud (when `D2_TOKEN` is set), for product analytics/quotas.
- D2_TELEMETRY modes:
  - `off`: no metrics, no usage events
  - `metrics`: only OTLP metrics (no usage events)
  - `usage`: only usage events to D2 Cloud (no OTLP metrics)
  - `all` (default): both; metrics still no-op if exporter libs aren’t installed

> Metrics API scopes: If you call any Cloud metrics endpoints (future feature), the token must include scope `metrics.read`. `admin` alone will not satisfy strict scope checks.

### Telemetry & privacy
- Default: `D2_TELEMETRY=all` (metrics + usage). Set `D2_TELEMETRY=off` to disable everything.
- Usage events are only sent in Cloud mode (`D2_TOKEN` set). Local mode never sends usage.
- Metrics auto-init is safe: if your app already configured an OpenTelemetry provider, D2 will not override it.
- If OTLP exporter libs are not installed, metrics are a no-op.
- ANSI ColorFormatter used by the CLI is cosmetic; the library itself does not force colored logging.
- User identifiers: Any `user_id` you pass to `d2.set_user()` may be included as-is in cloud usage events (e.g., `authz_decision`, `denied_reason`). Hash or pseudonymize if you don’t want to send real IDs.

---

## ⚙️ Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `D2_TOKEN` | unset | If set, enables Cloud mode (Bearer for API + usage ingestion). Unset → Local-file mode. |
| `D2_POLICY_FILE` | auto-discovery | Absolute/relative path to your local policy file (overrides discovery). |
| `D2_TELEMETRY` | `all` | `off` | `metrics` | `usage` | `all`: controls OTLP metrics and raw usage events. |
| `D2_JWKS_URL` | derived from API URL | Override JWKS endpoint (rare; Cloud mode usually discovers `/.well-known/jwks.json`). |
| `D2_STRICT_SYNC` | `0` | When `1` (or truthy), disables auto-threading for sync tools called inside an async loop and fails fast. |
| `D2_API_URL` | default from code (`DEFAULT_API_URL`, currently `https://d2.artoo.love`) | The base URL for the control plane. |
| `D2_STATE_PATH` | `~/.config/d2/bundles.json` | Override persisted bundle state path; set to `:memory:` to disable. |
| `D2_SILENT` | `0` | Suppress local-mode banner and expiry warnings when `1` (truthy). |

All variables listed above are implemented in the SDK as of 1.0.

---

## ❓ FAQ / Tips

- What happens if I call a sync tool inside an async context?
  - D2 auto‑threads the call and returns the real value; no extra code
  - Advanced: set `D2_STRICT_SYNC=1` or `@d2_guard(..., strict=True)` to fail‑fast for diagnostics

- Where do I put roles?
  - In your policy. A call is allowed when any user role matches a permission entry (supports `*` wildcard)

- How do I avoid context leaks?
  - Use `@clear_context` / `@clear_context_async`, or call `clear_user_context()` in `finally`
  - `d2.warn_if_context_set()` can help detect leaks in tests

- Telemetry
  - `D2_TELEMETRY=off|metrics|usage|all`

---

## 🧰 CLI commands (quick reference)

| Command | Purpose | Common flags |
|--------|---------|--------------|
| `d2 init` | Generate a starter local policy to `~/.config/d2/policy.{yaml,json}` (scans for `@d2_guard`) | `--path`, `--format`, `--force` |
| `d2 pull` | Download cloud bundle to a file (requires `D2_TOKEN`) | `--output`, `--format` |
| `d2 inspect` | Show permissions/roles (cloud or local) | `--verbose` |
| `d2 diagnose` | Validate local policy limits (tool count, expiry) |  |
| `d2 draft` | Upload a policy draft (requires token with `policy:write`) | `--version` |
| `d2 publish` | Sign & publish policy (requires token with `policy:write` + device key) | `--dry-run`, `--force` |
| `d2 revoke` | Revoke the latest policy (requires token with appropriate permission) |  |

### Publish details (attestation + preconditions)
- Authorization: `Bearer $D2_TOKEN` (token must include `policy:write`)
- Device attestation headers:
  - `X-D2-Key-Id`: device key id (auto-generated on first publish)
  - `X-D2-Signature`: base64 Ed25519 over the exact HTTP request body bytes
- Preconditions (ETag):
  - `If-Match: "<etag>"` when updating an existing policy
  - `If-None-Match: *` for first-time publish

### Draft upload
- Body: `{"version": <int>, "bundle": {...}}`
- Example: `python -m d2 draft ./policy.yaml --version 7`
 - Errors to surface without retry:
   - `403` with `detail: quota_apps_exceeded` → plan’s max apps reached (upgrade or delete apps)

### Key management (platform-owned)
- Keys are registered automatically on first publish and reused thereafter.
- Revocation is managed in the dashboard; the CLI does not expose key deletion.

### Tokens (dashboard-only)
- The SDK/CLI do not create tokens. Obtain admin/runtime tokens from the dashboard and supply via `D2_TOKEN`.

### Events ingest
- SDK sends usage events to `/v1/events/ingest` (chunked to ≤32 KiB per request).
- On `429`, the SDK respects `Retry-After` before retrying the next chunk.
- Default payload shape per event: `{event_type, payload, occurred_at}` (wrapped in `{events:[...]}`).

---

## 🧪 Development

### Running Tests

The project includes a comprehensive test suite with 79 tests covering all functionality:

```bash
# Install development dependencies
pip install -e .[dev,test]

# Run all tests
pytest

# Run tests with coverage
pytest --cov=d2 --cov-report=html

# Run specific test categories
pytest tests/test_jwks_rotation.py  # JWKS rotation tests
pytest tests/test_policy_client.py  # Policy client integration tests
pytest tests/test_decorator.py      # Decorator functionality tests
```

### Test Status
- **79 tests passing** (100% pass rate)
- **0 tests failing** 
- **0 tests skipped**
- **Fast execution**: < 5 seconds for full suite

### Key Test Areas
- **JWKS rotation and caching**: Automatic key rotation, rate limiting, error handling
- **JWT structure validation**: Audience claims, policy extraction, signature verification
- **Policy client integration**: End-to-end workflow testing with callback handling
- **Policy parsing**: Both cloud (nested) and local (flat) policy structures
- **Error handling**: Token type detection, network failures, validation errors
- **Demo integration**: Working examples for both cloud and local modes

### Development Workflow

1. **Make changes** to the codebase
2. **Run tests** to ensure no regressions: `pytest`
3. **Check linting** if available: `flake8` or similar
4. **Update documentation** if needed (README.md, EVERYTHING-python.md)
5. **Verify examples work**: `python examples/local_mode_demo.py`

---

## 📄 Licensing
Source-available under Business Source License 1.1. Internal production use permitted. No managed/hosted competing service without a commercial license. Change Date: 2029-09-08 → Change License: LGPL-3.0-or-later. See LICENSE.