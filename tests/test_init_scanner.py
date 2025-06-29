from pathlib import Path

from d2.__main__ import _discover_tool_ids


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