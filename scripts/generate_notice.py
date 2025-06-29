#!/usr/bin/env python3

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HEADER_PATH = ROOT / "NOTICE.header"
THIRD_PARTY_PATH = ROOT / "NOTICE.third_party"
NOTICE_OUT = ROOT / "NOTICE"
TPN_OUT = ROOT / "THIRD_PARTY_NOTICES.md"

NOTICE_INTRO = (
    "\n\nThird-Party Notices\n\n"
    "This distribution includes open-source components that remain under their\n"
    "respective licenses. A short summary table is available in `THIRD_PARTY_NOTICES.md`.\n"
    "The full license texts for bundled dependencies are reproduced below.\n\n"
)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _write(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def _sanitize_no_local_paths(content: str) -> str:
    # Hard block common absolute path patterns (macOS/Linux/Windows)
    forbidden_patterns = [
        r"/Users/[^\s]+",
        r"/home/[^\s]+",
        r"[A-Za-z]:\\\\Users\\\\[^\s]+",
    ]
    for pat in forbidden_patterns:
        if re.search(pat, content):
            # Remove entire lines that contain local absolute paths
            content = "\n".join(
                line for line in content.splitlines() if not re.search(pat, line)
            ) + "\n"
    return content


def build_notice() -> str:
    header = _read(HEADER_PATH)
    third_party = _read(THIRD_PARTY_PATH)

    # Compose final NOTICE content
    content = header.rstrip() + "\n" + NOTICE_INTRO + third_party
    content = _sanitize_no_local_paths(content)
    return content


def parse_third_party_blocks(text: str) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in text.splitlines():
        if line.strip() == "---":
            if current:
                entries.append(current)
                current = {}
            continue
        if line.startswith("Package:"):
            current["Package"] = line.split(":", 1)[1].strip()
        elif line.startswith("Version:"):
            current["Version"] = line.split(":", 1)[1].strip()
        elif line.startswith("License:"):
            current["License"] = line.split(":", 1)[1].strip()
    if current:
        entries.append(current)
    return entries


TPN_HEADER = """# Third-Party Notices

This product bundles open-source software (“OSS”) components that remain under
their respective licenses. The following list is sourced from `NOTICE.third_party`.

> NOTE: This file is provided for attribution purposes only and does not grant
> any rights to the proprietary portions of the D2 SDK.

| Package | Version | License |
|---------|---------|---------|
"""


def build_third_party_notices_md() -> str:
    blocks = _read(THIRD_PARTY_PATH)
    rows = parse_third_party_blocks(blocks)
    table_lines = [f"| {r.get('Package','')} | {r.get('Version','')} | {r.get('License','')} |" for r in rows]
    return TPN_HEADER + "\n".join(table_lines) + "\n"


def main() -> None:
    notice_content = build_notice()
    _write(NOTICE_OUT, notice_content)

    tpn_md = build_third_party_notices_md()
    _write(TPN_OUT, tpn_md)

    # Final sanity check: ensure NOTICE has no local absolute paths
    if "/Users/" in notice_content or "\\Users\\" in notice_content:
        raise SystemExit("Generated NOTICE still contains a local path; aborting.")


if __name__ == "__main__":
    main() 