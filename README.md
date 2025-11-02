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
- Small surface area: one decorator, a per-request user context, and you’re good to go
- Declarative input/output guardrails: describe argument constraints and redaction rules in policy; D2 enforces them around your tool automatically
- Telemetry with guardrails: metrics + usage events stream out automatically, and exporter hiccups never crash your app
- Local files for dev, signed bundles for prod: flip on Cloud mode for polling, JWKS rotation, and hosted analytics

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

## ✅ Policy-driven input & output guardrails (new in 1.1)

Two questions matter every time a tool is called:

1. **Did the caller send us something we’re willing to run?**
2. **Are we comfortable with the data we send back?**

D2 now lets you answer both straight from the policy file. No helper code, no wrappers, just rules.

### Input rules (keep bad calls out)

```yaml
policies:
  - role: analyst
    permissions:
      - tool: reports.generate
        allow: true
        conditions:
          input:
            table: {in: [analytics, dashboards]}
            row_limit: {min: 1, max: 1000}
            format: {matches: "^[a-z_]+$"}
```

And the guarded function might look like:

```python
@d2_guard("reports.generate")
def generate(table: str, row_limit: int):
    ...
```

D2 binds the call, checks each rule, and blocks execution if anything falls outside the policy. Violations raise `PermissionDeniedError` (or trigger your `on_deny` handler) and telemetry records `reason="input_validation"` for easy tracing.

Operators cover the basics—equals/not-equals, allow/deny lists, numeric bounds, string prefix/suffix/contains, regex checks, length checks, explicit type checks. Because policies live outside the codebase, security can tune them without waiting for a deploy.

### Output rules (validate and sanitize responses)

D2 provides two complementary capabilities for output processing:

#### 1. Output Validation (constraint checking)

Validates return values against declarative constraints—just like input validation, but for outputs. If validation fails, the entire response is denied.

```yaml
policies:
  - role: analyst
    permissions:
      - tool: analytics.get_report
        allow: true
        conditions:
          output:
            status: {required: true, in: [success, error]}
            row_count: {type: int, min: 0, max: 10000}
            format: {type: string, in: [json, csv, xml]}
```

**Key characteristics:**
- Uses constraint operators WITHOUT `action` keyword
- Denies entire response if violated (no transformation)
- Symmetric with input validation
- Think: "Is this return value structurally valid?"

#### 2. Output Sanitization (transformation)

Transforms return values to remove or redact sensitive data using field actions. This happens after validation passes.

```yaml
policies:
  - role: support
    permissions:
      - tool: crm.lookup_customer
        allow: true
        conditions:
          output:
            # Validation (pure constraints, no transformation)
            status: {required: true, in: [found, not_found]}
            
            # Sanitization (field actions, transforms data)
            ssn: {action: filter}                        # Remove field
            salary: {max: 100000, action: redact}        # Redact if > 100k
            notes: {matches: "(?i)secret", action: deny} # Deny if pattern found
            items: {maxLength: 100, action: truncate}    # Trim to 100 items
            
            # Global sanitization rules
            max_bytes: 65536
            require_fields_absent: [internal_flag]
```

Paired with a tool such as:

```python
@d2_guard("crm.lookup_customer")
def lookup_customer(customer_id: str):
    ...
```

**Processing order:**
1. **Validate**: Check constraints without `action` (deny if violated)
2. **Sanitize**: Apply field actions (transform or deny)
3. Return cleaned value to caller

**Field-level actions:**

- `action: filter` — drop the field entirely
- `action: redact` — replace value with `[REDACTED]` (or pattern-substitute if `matches` specified)
- `action: deny` — block entire response if field triggers
- `action: truncate` — trim field value (requires `maxLength`)

Actions can be **conditional** (only trigger on constraint violation):
```yaml
salary: {max: 100000, action: redact}  # Only redact if > 100k
score: {type: int, max: 100, action: filter}  # Only remove if invalid or > 100
```

**Constraint operators (work on both input and output):**

- `type`, `min`, `max`, `gt`, `lt` — numeric/type validation
- `minLength`, `maxLength` — length checks
- `in`, `not_in` — allow/deny lists
- `matches`, `contains`, `startsWith`, `endsWith` — string pattern checks
- `eq`, `ne`, `required` — equality/presence checks

**Global sanitization rules:**

- `deny_if_patterns` — block if sanitized output still matches forbidden patterns
- `require_fields_absent` — block if forbidden fields exist anywhere
- `max_bytes` — enforce size limit on serialized output

**Key differences:**

| Aspect | Validation | Sanitization |
|--------|-----------|--------------|
| **Keyword** | No `action` | Requires `action` |
| **Effect** | Deny if violated | Transform (or deny if `action: deny`) |
| **Value** | Never modified | Always transformed when triggered |
| **Use case** | "Is this structurally valid?" | "Remove sensitive data" |

Stack them however you like. If no rule fires, we return the original value untouched. If a validation or deny rule triggers, D2 raises `PermissionDeniedError` (or calls your `on_deny` handler) with `reason="output_validation"` or `reason="output_sanitization"` for easy auditing. Telemetry records the same reason codes for downstream monitoring.

#### Nested guards

- Guarded functions can safely call other guarded functions. Each layer re-runs input checks and output sanitation using the same user context, so inner responses are cleaned before outer guards inspect or return them.

Run `python examples/guardrails_demo.py` to watch both guardrail types block bad inputs and sanitize outputs using the sample policy in `examples/guardrails_policy.yaml`.

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

## 📊 Telemetry & analytics

D2 pushes useful telemetry without demanding extra wiring:

- **Metrics** land in your OTLP collector (respecting `OTEL_EXPORTER_OTLP_ENDPOINT`). Latency, decision counts, JWKS rotation, polling health—it’s all there.
- **Usage events** go to the D2 Cloud ingest endpoint whenever `D2_TOKEN` is set. Every event is tagged with tool id, policy etag, service name, and the exact denial reason if there was one.
- **D2_TELEMETRY modes**
  - `off` – nothing leaves the process
  - `metrics` – OTLP only
  - `usage` – cloud events only
  - `all` (default) – both; metrics still no-op if the exporter libs aren’t installed
- Exporter failures never bubble up—worst case we drop the event and keep your app running.

> If/when metrics APIs arrive in the control plane, tokens will need the `metrics.read` scope alongside `admin`.

### Telemetry & privacy
- Local mode is completely offline. Usage events only flow in Cloud mode.
- Already configured an OpenTelemetry provider? D2 leaves it alone.
- User identifiers you pass into `set_user()` appear as-is in denial events. Hash or pseudonymise if that matters for your compliance story.
- ANSI colour in the CLI is just cosmetic; the library logs plain text.

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
