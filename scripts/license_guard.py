#!/usr/bin/env python3
import sys, pathlib, re
root = pathlib.Path(__file__).resolve().parents[1]

# Check LICENSE contains BSL 1.1
lic = (root / "LICENSE").read_text(encoding="utf-8", errors="ignore")
if "Business Source License 1.1" not in lic:
    print("LICENSE guard: Business Source License 1.1 not found", file=sys.stderr)
    sys.exit(1)

# Check pyproject classifiers do not include Apache/MIT/GPL before change date
pj = (root / "pyproject.toml").read_text(encoding="utf-8", errors="ignore")
bad = ["Apache Software License", "MIT License", "GNU General Public License"]
if any(b in pj for b in bad):
    print("LICENSE guard: Found disallowed OSI classifier pre-Change Date", file=sys.stderr)
    sys.exit(1)

print("license_guard: OK")
