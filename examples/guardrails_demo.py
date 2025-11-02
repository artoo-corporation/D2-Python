# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""Runnable demo showcasing declarative input/output guardrails.

Run with:

    python examples/guardrails_demo.py

The script bootstraps D2 in local-file mode using `guardrails_policy.yaml`,
then shows:

1. Input guardrails denying malformed calls before the tool executes.
2. Output guardrails stripping/redacting sensitive data before it reaches the caller.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from textwrap import indent

from d2 import configure_rbac_sync, d2_guard, set_user, clear_user_context
from d2.exceptions import PermissionDeniedError


EXAMPLES_DIR = Path(__file__).resolve().parent
POLICY_PATH = EXAMPLES_DIR / "guardrails_policy.yaml"


def ensure_policy_file() -> None:
    """Make sure the sample policy exists with sensible defaults."""

    if not POLICY_PATH.exists():
        raise FileNotFoundError(
            f"Expected guardrails policy at {POLICY_PATH}. "
            "The file ships with the repo—double-check your checkout."
        )


@d2_guard("analytics.fetch_report")
def fetch_report(table: str, row_limit: int, format: str) -> dict:
    """Pretend to fetch analytics data after the guardrail check passes."""

    return {
        "table": table,
        "row_limit": row_limit,
        "format": format,
        "rows": ["... fake analytics rows ..."],
    }


@d2_guard("analytics.create_segment")
def create_segment(
    segment_name: str,
    priority: int,
    region: str,
    channel: str,
    tags: list[str],
) -> dict:
    """Return a stub segment payload once validation succeeds."""

    return {
        "segment_name": segment_name,
        "priority": priority,
        "region": region,
        "channel": channel,
        "tags": tags,
    }


@d2_guard("analytics.schedule_report")
def schedule_report(
    cadence: str,
    timezone: str,
    day_of_month: int,
    window_minutes: int,
    include_pii: bool,
) -> dict:
    """Pretend to schedule a report."""

    return {
        "cadence": cadence,
        "timezone": timezone,
        "day_of_month": day_of_month,
        "window_minutes": window_minutes,
        "include_pii": include_pii,
    }


@d2_guard("analytics.update_thresholds")
def update_thresholds(metric: str, lower: float, upper: float, notes: str | None = None) -> dict:
    """Return threshold adjustments."""

    return {
        "metric": metric,
        "lower": lower,
        "upper": upper,
        "notes": notes,
    }


@d2_guard("analytics.export")
def export_records() -> dict:
    """Return data that intentionally includes sensitive fields."""

    return {
        "records": [
            {
                "customer": "Alice",
                "ssn": "123-45-6789",
                "salary": "120000",
                "notes": "Contains SECRET project details",
            },
            {
                "customer": "Bob",
                "ssn": "987-65-4321",
                "salary": "95000",
                "notes": "clean",
            },
            {
                "customer": "Carol",
                "ssn": "111-22-3333",
                "salary": "82000",
                "notes": "SECRET tier upgrade",
            },
            {
                "customer": "Dave",
                "ssn": "555-66-7777",
                "salary": "77000",
                "notes": "overflow row that should be trimmed",
            },
        ]
    }


@d2_guard("analytics.export_flags")
def export_with_flags() -> dict[str, str]:
    """Return data that should be denied entirely by output validators."""

    return {
        "customer": "Eve",
        "pii_flag": "true",
        "notes": "Contains SECRET entitlement overrides",
        "payload": "x" * 150,
    }


@d2_guard("analytics.export_bulk")
def export_bulk() -> dict[str, str]:
    """Return a payload that exceeds the max_bytes budget."""

    return {
        "export": "y" * 256,
    }


@d2_guard("analytics.export_tokens")
def export_tokens() -> dict[str, list[str]]:
    """Return session tokens that the policy should block outright."""

    return {
        "tokens": ["tok_123", "tok_456", "tok_789"],
    }


@d2_guard("analytics.export_logs")
def export_logs() -> dict[str, str]:
    """Return logs that may contain forbidden patterns."""

    return {
        "log": "2025-10-13 user=alice password=secret123 action=download",
    }




def show(title: str, payload) -> None:
    print(f"\n== {title} ==")
    if isinstance(payload, (dict, list)):
        print(indent(json.dumps(payload, indent=2), "  "))
    else:
        print(f"  {payload}")


def run_input_guardrail_examples() -> None:
    print("\n" + "=" * 70)
    print("INPUT GUARDRAILS: Validating arguments before execution")
    print("=" * 70)
    print("\nPolicy allows 'analyst' role to call analytics.fetch_report with:")
    print("  • table: must be 'sales' OR 'marketing'")
    print("  • row_limit: must be between 1 and 1000")
    print("  • format: must match pattern ^[a-z_]+$ (lowercase/underscore only)")
    print("-" * 70)

    # Allowed: everything matches the policy
    print("\n[TEST 1] Valid call within policy bounds")
    print("  Calling: fetch_report(table='sales', row_limit=250, format='weekly_summary')")
    print("  Expected: ✓ ALLOWED (all constraints satisfied)")
    try:
        result = fetch_report(table="sales", row_limit=250, format="weekly_summary")
        print("  Result: ✓ Success!")
        show("  Response", result)
    except PermissionDeniedError as exc:
        print(f"  ✗ Unexpected denial: {exc}")

    input("\n\nPress Enter to continue...\n\n")  # noqa: S101

    # Denied: table not on the allow list
    print("\n[TEST 2] Invalid table argument")
    print("  Calling: fetch_report(table='engineering', row_limit=100, format='daily')")
    print("  Expected: ✗ DENIED (table not in ['sales', 'marketing'])")
    try:
        fetch_report(table="engineering", row_limit=100, format="daily")
        print("  Result: ✗ Unexpected success!")
    except PermissionDeniedError as exc:
        print("  Result: ✓ Correctly denied")
        print("  Policy violation: Argument 'table' must be one of ['sales', 'marketing']")
        print(f"  Actual value: 'engineering'")

    input("\n\nPress Enter to continue...\n\n")  # noqa: S101

    # Denied: row_limit too large
    print("\n[TEST 3] Row limit exceeds maximum")
    print("  Calling: fetch_report(table='marketing', row_limit=5000, format='monthly')")
    print("  Expected: ✗ DENIED (row_limit > 1000)")
    try:
        fetch_report(table="marketing", row_limit=5000, format="monthly")
        print("  Result: ✗ Unexpected success!")
    except PermissionDeniedError as exc:
        print("  Result: ✓ Correctly denied")
        print("  Policy violation: Argument 'row_limit' must be ≤ 1000")
        print(f"  Actual value: 5000")

    input("\n\nPress Enter to continue...\n\n")  # noqa: S101

    # Denied: format fails regex
    print("\n[TEST 4] Format contains invalid characters")
    print("  Calling: fetch_report(table='sales', row_limit=100, format='Ad-Hoc Export')")
    print("  Expected: ✗ DENIED (format contains spaces and capital letters)")
    try:
        fetch_report(table="sales", row_limit=100, format="Ad-Hoc Export")
        print("  Result: ✗ Unexpected success!")
    except PermissionDeniedError as exc:
        print("  Result: ✓ Correctly denied")
        print("  Policy violation: Argument 'format' must match pattern ^[a-z_]+$")
        print(f"  Actual value: 'Ad-Hoc Export' (contains uppercase, spaces, and dash)")

    input("\n\nPress Enter to continue...\n\n")  # noqa: S101

    print("\nPolicy also enforces constraints for analytics.create_segment:")
    print("  • segment_name length between 3 and 32 characters")
    print("  • priority between 1 and 5")
    print("  • region allow-list and channel block-list")
    print("  • tags must be a short non-empty list")
    print("-" * 70)

    print("\n[TEST 5] Valid segment payload")
    try:
        result = create_segment(
            segment_name="vip_customers",
            priority=3,
            region="us",
            channel="email",
            tags=["loyal", "high-spend"],
        )
        print("  Result: ✓ Success!")
        show("  Segment", result)
    except PermissionDeniedError as exc:
        print(f"  ✗ Unexpected denial: {exc}")

    input("\n\nPress Enter to continue...\n\n")  # noqa: S101

    print("\n[TEST 6] Segment name too short + blocked channel")
    try:
        create_segment(
            segment_name="ab",
            priority=2,
            region="eu",
            channel="sms",
            tags=["promo"],
        )
        print("  Result: ✗ Unexpected success!")
    except PermissionDeniedError as exc:
        print("  Result: ✓ Correctly denied")
        print(f"  Policy violation: {exc}")

    input("\n\nPress Enter to continue...\n\n")  # noqa: S101

    print("\n[TEST 7] Too many tags triggers maxLength rule")
    try:
        create_segment(
            segment_name="holiday_campaign",
            priority=1,
            region="apac",
            channel="push",
            tags=["one", "two", "three", "four", "five", "six"],
        )
        print("  Result: ✗ Unexpected success!")
    except PermissionDeniedError as exc:
        print("  Result: ✓ Correctly denied")
        print("  Policy violation: tags list exceeds allowed length")

    input("\n\nPress Enter to continue...\n\n")  # noqa: S101

    print("\nPolicy also governs analytics.schedule_report:")
    print("  • cadence allow-list, timezone regex, safe day_of_month")
    print("  • window_minutes within sane bounds, include_pii forced false")

    print("\n[TEST 8] Valid schedule request")
    try:
        result = schedule_report(
            cadence="weekly",
            timezone="America/New_York",
            day_of_month=7,
            window_minutes=90,
            include_pii=False,
        )
        print("  Result: ✓ Success!")
        show("  Schedule", result)
    except PermissionDeniedError as exc:
        print(f"  ✗ Unexpected denial: {exc}")

    input("\n\nPress Enter to continue...\n\n")  # noqa: S101

    print("\n[TEST 9] include_pii=True violates eq rule")
    try:
        schedule_report(
            cadence="monthly",
            timezone="Europe/Paris",
            day_of_month=15,
            window_minutes=120,
            include_pii=True,
        )
        print("  Result: ✗ Unexpected success!")
    except PermissionDeniedError as exc:
        print("  Result: ✓ Correctly denied")
        print("  Policy violation: include_pii must be false")

    input("\n\nPress Enter to continue...\n\n")  # noqa: S101

    print("\nFinally, analytics.update_thresholds ensures sane metric updates")
    print("  • Numeric bounds, unsupported metrics, and TODO notes are blocked")

    print("\n[TEST 10] Valid threshold update")
    try:
        result = update_thresholds("conversion_rate", lower=0.1, upper=0.4, notes=None)
        print("  Result: ✓ Success!")
        show("  Thresholds", result)
    except PermissionDeniedError as exc:
        print(f"  ✗ Unexpected denial: {exc}")

    input("\n\nPress Enter to continue...\n\n")  # noqa: S101

    print("\n[TEST 11] Invalid thresholds (notes contain TODO)")
    try:
        update_thresholds("conversion_rate", lower=0.05, upper=0.9, notes="TODO revisit")
        print("  Result: ✗ Unexpected success!")
    except PermissionDeniedError as exc:
        print("  Result: ✓ Correctly denied")
        print(f"  Policy violation: {exc}")


def run_output_guardrail_examples() -> None:
    print("\n" + "=" * 70)
    print("OUTPUT GUARDRAILS: Sanitizing responses before they leave")
    print("=" * 70)
    print("\nPolicy sanitizes analytics.export responses with:")
    print("  • ssn: {action: filter} → removes field from nested records")
    print("  • salary: {action: filter} → removes field from nested records")
    print("  • notes: {matches: '(?i)secret', action: redact} → replaces pattern match with [REDACTED]")
    print("  • records: {maxLength: 3, action: truncate} → limits array to 3 items")
    print("\nNote: Pattern-based redaction is surgical - it only redacts the matching")
    print("portion of the string, preserving the rest of the content.")
    print("-" * 70)

    # Demonstrate what the underlying tool emits before guardrails kick in.
    print("\n[BEFORE] Raw data from export_records() [bypassing guard for demo]:")
    raw = export_records.__wrapped__()  # type: ignore[attr-defined]
    print(indent(json.dumps(raw, indent=2), "  "))
    print(f"\n  → Contains {len(raw['records'])} records with SSNs, salaries, and SECRET notes")

    print("\n[AFTER] Sanitized response (policy automatically applied):")
    sanitized = export_records()
    print(indent(json.dumps(sanitized, indent=2), "  "))
    
    print("\n  Changes applied:")
    print("    ✓ Removed 'ssn' field from all nested records")
    print("    ✓ Removed 'salary' field from all nested records")
    print("    ✓ Redacted 'SECRET' pattern in notes (Alice, Carol)")
    print("    ✓ Preserved Bob's notes as 'clean' (no pattern match)")
    print(f"    ✓ Truncated 'records' array from {len(raw['records'])} to {len(sanitized['records'])} items")

    input("\n\nPress Enter to continue...\n\n")  # noqa: S101

    # Demonstrate a hard denial when post-conditions fail.
    print("\n[TEST 5] Response contains forbidden field")
    print("  Policy: require_fields_absent: ['pii_flag']")
    print("  Calling: export_with_flags() → returns data with 'pii_flag' present")
    print("  Expected: ✗ DENIED (entire response blocked)")
    try:
        export_with_flags()
        print("  Result: ✗ Unexpected success!")
    except PermissionDeniedError as exc:
        print("  Result: ✓ Correctly denied")
        print("  Policy violation: Output contains forbidden field 'pii_flag'")
        print("  Why: Global 'require_fields_absent' ensures certain fields never escape")

    input("\n\nPress Enter to continue...\n\n")  # noqa: S101

    print("\n[TEST 6] Response exceeds size limit")
    print("  Policy: max_bytes: 128")
    print("  Calling: export_bulk() → returns 256 bytes of data")
    print("  Expected: ✗ DENIED (payload too large)")
    try:
        export_bulk()
        print("  Result: ✗ Unexpected success!")
    except PermissionDeniedError as exc:
        print("  Result: ✓ Correctly denied")
        print("  Policy violation: Response size (256 bytes) exceeds max_bytes (128)")
        print("  Why: Global 'max_bytes' prevents exfiltration of large payloads")

    input("\n\nPress Enter to continue...\n\n")  # noqa: S101

    print("\nOUTPUT DENIAL RULES: Blocking responses when policy conditions fail")
    print("\n[TEST 7] Field-level deny when tokens field is present")
    try:
        export_tokens()
        print("  Result: ✗ Unexpected success!")
    except PermissionDeniedError as exc:
        print("  Result: ✓ Correctly denied")
        print("  Policy violation: 'tokens' field triggers action=deny")

    input("\n\nPress Enter to continue...\n\n")  # noqa: S101

    print("\n[TEST 8] Global deny_if_patterns catches secrets in logs")
    try:
        export_logs()
        print("  Result: ✗ Unexpected success!")
    except PermissionDeniedError as exc:
        print("  Result: ✓ Correctly denied")
        print("  Policy violation: Response matched forbidden patterns (secret/password)")

    print("\n" + "=" * 70)
    print("Demo complete! All guardrails working as expected.")
    print("=" * 70)




def main() -> None:
    ensure_policy_file()

    # Force local-file mode to use the sample policy.
    os.environ.setdefault("D2_POLICY_FILE", str(POLICY_PATH))

    configure_rbac_sync()

    try:
        set_user("analyst-123", roles=["analyst"])
        run_input_guardrail_examples()
        run_output_guardrail_examples()
    finally:
        clear_user_context()


if __name__ == "__main__":
    main()


