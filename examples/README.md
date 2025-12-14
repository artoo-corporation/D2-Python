# D2 Python Examples

This directory contains comprehensive, runnable examples demonstrating all D2 features.

## Examples Overview

### 1. policy_validation_demo.py (NEW)

**Demonstrates:** Strict policy validation that catches typos and errors at load time.

**Features shown:**
- Unknown operator detection (e.g., `minimum` vs `min`)
- Case-sensitivity enforcement (`Type` vs `type`)
- Common typo detection (`minlength` vs `minLength`)
- Invalid regex pattern validation
- ConfigurationError messages with suggestions

**Run:**
```bash
python examples/policy_validation_demo.py
```

**Key benefit:** Prevents silent security bypasses where typos in policies would be ignored.

---

### 2. guardrails_demo.py (EXPANDED)

**Demonstrates:** Declarative input/output guardrails with validation and sanitization.

**New features added:**
- Policy validation explanation
- Enhanced sanitization telemetry details
- Field-level tracking (fields_modified, actions_applied, field_count)

**Features shown:**
- Input validation with all constraint operators
- Output validation (structural checks)
- Output sanitization (PII removal, redaction, filtering)
- Pattern-based redaction
- Global sanitization rules (max_bytes, require_fields_absent, deny_if_patterns)
- Field-level vs response-level denials

**Run:**
```bash
python examples/guardrails_demo.py
```

**Policy:** `guardrails_policy.yaml`

---

### 3. sequence_demo.py (EXPANDED)

**Demonstrates:** Sequence enforcement to prevent confused deputy attacks.

**New features added:**
- Tool groups with lazy expansion (Scenario 12)
- Memory efficiency explanation
- @group reference demonstration

**Features shown:**
- Direct exfiltration blocking (DB → Web)
- Transitive attack prevention (DB → Analytics → Web)
- Multi-channel coverage (Web, Email, S3, Files)
- Agent isolation (independent call histories)
- Admin bypass (wildcard roles)
- **Tool groups:** `@sensitive_data`, `@external_io`, `@internal_processing`
- **Lazy expansion:** 5×5=25 patterns from 1 rule, no memory explosion

**Run:**
```bash
python examples/sequence_demo.py
```

**Policy:** `sequence_demo_policy.yaml` (now uses @group references)

**Scenarios:**
- Part 1: Baseline (2 scenarios) - Safe workflows
- Part 2: Basic Attacks (3 scenarios) - 2-hop exfiltration
- Part 3: Advanced Attacks (4 scenarios) - Multi-hop laundering
- Part 4: Edge Cases (2 scenarios) - Agent isolation, admin bypass
- Part 5: Tool Groups (1 scenario) - Memory efficiency

---

### 4. data_flow_demo.py (NEW - v1.2+)

**Demonstrates:** Semantic data flow tracking with facts (labels) that block egress tools.

**Features shown:**
- **Fact labeling:** Tools emit semantic labels after execution
- **Blanket blocking:** One fact blocks all tools in a group
- **Pivot attack prevention:** Attacker can't switch to email/slack/webhook
- **Multi-label accumulation:** Facts compound during request
- **Programmatic API:** `record_fact()`, `get_facts()`, `has_fact()`, `has_any_fact()`

**Use cases:**
- Compliance (PCI, GDPR, HIPAA) - label data types, block external APIs
- LLM output tainting (CaMeL-style) - prevent prompt injection → code execution
- Multi-agent isolation - block privileged tools after untrusted input

**Run:**
```bash
python examples/data_flow_demo.py
```

**Policy:** `data_flow_policy.yaml`

**Key difference from sequences:**
- Sequences block specific tool patterns (`A → B`)
- Data flow blocks **all** tools with matching label ("once sensitive, block all egress")

---

### 5. defense_in_depth_demo.py

**Demonstrates:** Complete security stack (RBAC + Sequence + Data Flow + Guardrails).

**Features shown:**
- All four layers working together
- Defense in depth approach
- Comprehensive protection
- Conditional authorization based on guardrails

**Run:**
```bash
python examples/defense_in_depth_demo.py
```

**Policy:** `defense_in_depth_policy.json`

---

### 7. multi_role_demo.py

**Demonstrates:** Multi-role policies for reduced duplication.

**Features shown:**
- Single policy block for multiple roles
- DRY principle for role tiers
- Syntax options (`role: [...]` vs `roles: [...]`)

**Run:**
```bash
python examples/multi_role_demo.py
```

**Policy:** `multi_role_policy.yaml`

---

### 8. local_mode_demo.py

**Demonstrates:** Basic RBAC with local file mode.

**Features shown:**
- Different denial strategies (raise, static value, handler, contextual handler)
- Auto-threading (sync in async)
- Role-based permissions

**Run:**
```bash
python examples/local_mode_demo.py
```

**Policy:** `local_mode_demo_policy.yaml`

---

## What's New (Recent Enhancements)

### Data Flow Tracking (v1.2+)
- **Semantic labeling:** Tools emit facts (labels) after execution
- **Blanket blocking:** One fact can block all tools in a group
- **Pivot attack prevention:** No need to enumerate every egress path
- **Programmatic API:** `record_fact()`, `get_facts()`, `has_fact()`, `has_any_fact()`
- **Compliance ready:** Label data as PCI, GDPR, HIPAA and automatically block external APIs

### New Constraint Operators (v1.2+)
- **`not_matches`:** Regex pattern that must NOT match (e.g., block SSNs, passwords)
- **`max_bytes`:** Limit payload size in bytes (UTF-8 aware, distinct from `maxLength`)
- **`not_contains`:** String must not contain substring (e.g., block path traversal)

### Policy Validation (v1.3)
- **Strict operator validation:** Unknown operators cause `ConfigurationError` at load time
- **Regex validation:** Malformed patterns caught before they can crash at runtime
- **Common typo detection:** Helpful error messages suggest corrections
- **Case-sensitivity enforcement:** Prevents silent failures from capitalization mistakes

### Enhanced Telemetry (v1.3)
- **Detailed sanitization tracking:** Know exactly which fields were modified
- **Field-level metadata:** `fields_modified`, `actions_applied`, `field_count`
- **Compliance ready:** Audit logs show specific data transformations

### Tool Groups with Lazy Expansion (v1.2)
- **Memory efficient:** 50×50×50 patterns without Cartesian product explosion
- **Runtime matching:** O(1) set membership checks instead of materializing all combinations
- **Maintainable:** Update groups in one place, rules automatically apply
- **Flexible:** Mix @group references with explicit tool IDs

---

## Running the Examples

All examples are interactive and self-contained. They use local policy files (no cloud token required).

**Prerequisites:**
```bash
pip install d2-sdk[cli]
```

**Quick start:**
```bash
# See policy validation in action
python examples/policy_validation_demo.py

# See input/output guardrails
python examples/guardrails_demo.py

# See sequence enforcement + tool groups
python examples/sequence_demo.py
```

---

## Policy Files

| Policy File | Used By | Key Features |
|-------------|---------|--------------|
| `data_flow_policy.yaml` | data_flow_demo.py | Fact labeling, blanket blocking, pivot prevention |
| `guardrails_policy.yaml` | guardrails_demo.py | Input validation, output sanitization, pattern redaction |
| `sequence_demo_policy.yaml` | sequence_demo.py | Tool groups (@sensitive_data, @external_io), lazy expansion |
| `defense_in_depth_policy.json` | defense_in_depth_demo.py | All layers combined (RBAC + Sequence + Data Flow + Guardrails) |
| `multi_role_policy.yaml` | multi_role_demo.py | Multi-role syntax |
| `local_mode_demo_policy.yaml` | local_mode_demo.py | Basic RBAC |

---

## Learning Path

1. **Start with `local_mode_demo.py`** - Understand basic RBAC
2. **Then `guardrails_demo.py`** - Learn input/output guardrails
3. **Then `sequence_demo.py`** - See temporal authorization
4. **Then `data_flow_demo.py`** - Understand semantic data tracking
5. **Then `policy_validation_demo.py`** - Understand policy validation
6. **Finally `defense_in_depth_demo.py`** - See everything together

---

## Testing Your Own Policies

Use the CLI to validate policies before deploying:

```bash
# Validate local policy
d2 diagnose

# Inspect permissions for a role
d2 inspect

# Check for common issues
d2 diagnose --verbose
```

---

## Common Use Cases Demonstrated

### Preventing Data Exfiltration
- **Direct:** `database.read_users` → `web.http_request` (sequence_demo.py)
- **Transitive:** `database.read_users` → `analytics.summarize` → `web.http_request` (sequence_demo.py)
- **Local:** `database.read_users` → `file.write` (sequence_demo.py)
- **Blanket:** Once SENSITIVE fact is set, ALL egress blocked (data_flow_demo.py)

### Data Flow Tracking
- **Compliance:** Label PCI/GDPR data, auto-block external APIs (data_flow_demo.py)
- **LLM safety:** Block code execution after LLM output (data_flow_demo.py)
- **Pivot prevention:** One label blocks all egress, no enumeration needed (data_flow_demo.py)

### Input Validation
- Argument constraints (guardrails_demo.py)
- Type checking (guardrails_demo.py)
- Range limits (guardrails_demo.py)
- Regex patterns (guardrails_demo.py)
- Allow/deny lists (guardrails_demo.py)

### Output Sanitization
- PII removal (ssn, salary) (guardrails_demo.py)
- Pattern redaction (SECRET) (guardrails_demo.py)
- Size limits (truncate, max_bytes) (guardrails_demo.py)
- Field denial (guardrails_demo.py)

### Scalability
- Tool groups for large policies (sequence_demo.py)
- Lazy expansion to prevent memory explosion (sequence_demo.py)
- Multi-role for reduced duplication (multi_role_demo.py)

---

## Troubleshooting

**Policy won't load?**
- Check for typos in operator names (use `policy_validation_demo.py`)
- Verify regex patterns are valid
- Run `d2 diagnose` for detailed errors

**Sequence enforcement not working?**
- Verify tool_groups are defined in metadata
- Check that @group references match group names exactly
- Ensure tools are listed in permissions

**Sanitization not applying?**
- Check that fields exist in the actual return value
- Verify action syntax (must have `action: filter/redact/deny/truncate`)
- Distinguish between validation (no action) and sanitization (has action)

---

## More Information

- **Full documentation:** See `EVERYTHING-python.md` in repo root
- **Quick start:** See `QUICKSTART.md` in repo root
- **API reference:** See `README.md` in repo root
- **Trail of Bits research:** https://blog.trailofbits.com/2025/07/31/hijacking-multi-agent-systems-in-your-pajamas/


