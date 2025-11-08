# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

from pathlib import Path

from d2.__main__ import _discover_tool_ids, _discover_tools, _validate_condition_arguments


def _write(p: Path, content: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)


def test_discover_tool_ids_functions_and_methods(tmp_path: Path):
    # Simple function with explicit ID
    _write(
        tmp_path / "pkg" / "mod.py",
        """
from d2 import d2_guard

@d2_guard("explicit.id")
def top_level():
    pass

class MyClass:
    @d2_guard
    def my_method(self):
        pass

class Outer:
    class Inner:
        @d2_guard
        def deep(self):
            pass
""".lstrip(),
    )

    # Attribute and alias forms in another module
    _write(
        tmp_path / "pkg" / "other.py",
        """
import d2
from d2 import d2 as d2_alias

@d2.d2_guard("attr.id")
def using_attr():
    pass

@d2_alias("alias.id")
def using_alias():
    pass
""".lstrip(),
    )

    found = _discover_tool_ids(tmp_path)

    # Explicit IDs are included as-is
    assert "explicit.id" in found
    assert "attr.id" in found
    assert "alias.id" in found

    # Implicit IDs include module and class stacks
    assert "pkg.mod.MyClass.my_method" in found
    assert "pkg.mod.Outer.Inner.deep" in found

    # Non-decorated functions should not be present
    assert "pkg.mod.top_level" not in found  # explicit took precedence 


def test_discover_tools_includes_parameters(tmp_path: Path):
    _write(
        tmp_path / "pkg" / "mod.py",
        """
from d2 import d2_guard

@d2_guard
def top_level(table, row_limit=100, *, format="json", **extra):
    pass
""".lstrip(),
    )

    mapping = _discover_tools(tmp_path)
    tool_id = "pkg.mod.top_level"
    assert tool_id in mapping
    params = mapping[tool_id]
    # self/cls removed, var keywords retained
    assert "table" in params
    assert "row_limit" in params
    assert "format" in params
    assert "**extra" in params


def test_validate_condition_arguments_detects_unknown_keys(tmp_path: Path):
    policy = {
        "policies": [
            {
                "role": "analyst",
                "permissions": [
                    {
                        "tool": "reports.generate",
                        "conditions": {
                            "input": {
                                "table": {"eq": "users"},
                                "row_limit": {"max": 1000},
                            }
                        },
                    }
                ],
            }
        ]
    }

    signatures = {"reports.generate": ["table", "row_limit"]}
    assert _validate_condition_arguments(policy, signatures) == []

    bad_policy = {
        "policies": [
            {
                "role": "analyst",
                "permissions": [
                    {
                        "tool": "reports.generate",
                        "conditions": {
                            "input": {
                                "row_lmit": {"max": 1000},
                            }
                        },
                    }
                ],
            }
        ]
    }

    warnings = _validate_condition_arguments(bad_policy, signatures)
    assert warnings
    assert "row_lmit" in warnings[0]


def test_discover_tools_scans_examples_directory(tmp_path: Path):
    examples_root = tmp_path / "examples"
    _write(
        examples_root / "demo.py",
        """
from d2 import d2_guard

@d2_guard("examples.tool")
def demo():
    pass
""".lstrip(),
    )

    found = _discover_tool_ids(examples_root)
    assert "examples.tool" in found