# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""Utilities for discovering @d2-guarded tools and validating policy conditions."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence, Set


DEFAULT_SKIP_DIRS: Set[str] = {
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".git",
    "site-packages",
    "dist-packages",
    "node_modules",
    "build",
    "dist",
    "tests",
}


def discover_tools(project_root: Path, *, skip_dirs: Optional[Set[str]] = None) -> Dict[str, list[str]]:
    """Recursively scan *project_root* for ``@d2_guard`` decorators."""

    skip_dirs = skip_dirs or DEFAULT_SKIP_DIRS
    tools: Dict[str, list[str]] = {}

    allowed_names: set[str] = {"d2_guard", "d2"}

    def _is_d2_decorator(dec: ast.AST) -> bool:
        if isinstance(dec, ast.Name) and dec.id in allowed_names:
            return True
        if isinstance(dec, ast.Call):
            func = dec.func
            if isinstance(func, ast.Name) and func.id in allowed_names:
                return True
            if isinstance(func, ast.Attribute) and func.attr in {"d2_guard", "d2"}:
                return True
        if isinstance(dec, ast.Attribute) and dec.attr in {"d2_guard", "d2"}:
            return True
        return False

    def _extract_params(node: ast.AST) -> list[str]:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return []

        args = node.args
        params: list[str] = []

        for arg in getattr(args, "posonlyargs", []):
            params.append(arg.arg)
        for arg in args.args:
            params.append(arg.arg)
        if args.vararg is not None:
            params.append(f"*{args.vararg.arg}")
        for arg in args.kwonlyargs:
            params.append(arg.arg)
        if args.kwarg is not None:
            params.append(f"**{args.kwarg.arg}")

        return [p for p in params if p not in {"self", "cls"}]

    class _Visitor(ast.NodeVisitor):
        def __init__(self, module_name: str):
            self.module_name = module_name
            self.class_stack: list[str] = []

        def visit_ClassDef(self, node: ast.ClassDef):  # type: ignore[override]
            self.class_stack.append(node.name)
            for child in node.body:
                self.visit(child)
            self.class_stack.pop()

        def _collect(self, node: ast.AST):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if not getattr(node, "decorator_list", None):
                    return
                for dec in node.decorator_list:
                    if not _is_d2_decorator(dec):
                        continue
                    explicit_id: Optional[str] = None
                    params = _extract_params(node)
                    if isinstance(dec, ast.Call) and dec.args:
                        arg0 = dec.args[0]
                        if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                            explicit_id = arg0.value
                    if explicit_id:
                        # Merge parameters from multiple definitions (union of all params)
                        if explicit_id in tools:
                            # Keep the longer parameter list
                            if len(params) > len(tools[explicit_id]):
                                tools[explicit_id] = params
                        else:
                            tools[explicit_id] = params
                    else:
                        qual = ".".join(self.class_stack + [node.name]) if self.class_stack else node.name
                        full_id = f"{self.module_name}.{qual}"
                        if full_id in tools:
                            if len(params) > len(tools[full_id]):
                                tools[full_id] = params
                        else:
                            tools[full_id] = params

        def visit_FunctionDef(self, node: ast.FunctionDef):  # type: ignore[override]
            self._collect(node)
            for child in node.body:
                self.visit(child)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):  # type: ignore[override]
            self._collect(node)
            for child in node.body:
                self.visit(child)

    for file_path in project_root.rglob("*.py"):
        if any(part in skip_dirs for part in file_path.parts):
            continue

        try:
            source = file_path.read_text()
        except (OSError, UnicodeDecodeError):
            continue

        if ("@d2_guard" not in source) and ("@d2" not in source) and ("d2_guard(" not in source):
            continue

        try:
            tree = ast.parse(source, filename=str(file_path))
        except SyntaxError:
            continue

        rel_module = (
            file_path.relative_to(project_root)
            .with_suffix("")
            .as_posix()
            .replace("/", ".")
        )

        for top in getattr(tree, "body", []):
            if isinstance(top, ast.ImportFrom) and top.module == "d2":
                for alias in top.names:
                    if alias.name in {"d2", "d2_guard"}:
                        allowed_names.add(alias.asname or alias.name)

        _Visitor(rel_module).visit(tree)

    return tools


def discover_tool_ids(project_root: Path, *, skip_dirs: Optional[Set[str]] = None) -> Set[str]:
    return set(discover_tools(project_root, skip_dirs=skip_dirs).keys())


def collect_condition_argument_names(conditions: Any) -> Set[str]:
    """Collect parameter names from input conditions only (not output).
    
    Output conditions are for sanitization/validation of return values,
    not function parameters, so they shouldn't be validated against the
    function signature.
    """
    keys: Set[str] = set()

    if isinstance(conditions, Mapping):
        # Only check "input" section - "output" is for return value processing
        input_rules = conditions.get("input")
        if isinstance(input_rules, Mapping):
            keys.update(str(k) for k in input_rules.keys())
    elif isinstance(conditions, Sequence) and not isinstance(conditions, (str, bytes, bytearray)):
        for item in conditions:
            keys.update(collect_condition_argument_names(item))

    return keys


def validate_condition_arguments(bundle: Dict[str, Any], tool_signatures: Dict[str, list[str]]) -> list[str]:
    messages: list[str] = []

    if not bundle:
        return messages

    tools_with_kwargs = {
        tool
        for tool, params in tool_signatures.items()
        if any(name.startswith("**") or name == "kwargs" for name in params)
    }

    for policy in bundle.get("policies", []):
        role = policy.get("role", "<unknown>")
        for perm in policy.get("permissions", []):
            if not isinstance(perm, Mapping):
                continue
            tool_id = perm.get("tool")
            if not tool_id or tool_id == "*":
                continue
            conditions = perm.get("conditions")
            if not conditions:
                continue
            keys = collect_condition_argument_names(conditions)
            if not keys:
                continue

            signature = tool_signatures.get(tool_id)
            if signature is None:
                messages.append(
                    f"Role '{role}' sets conditions for tool '{tool_id}', but no decorated function was found in the project scan."
                )
                continue

            if tool_id in tools_with_kwargs:
                continue

            allowed = set(signature)
            invalid = keys - allowed
            if invalid:
                messages.append(
                    f"Role '{role}' conditions for tool '{tool_id}' reference unknown parameter(s): {sorted(invalid)}"
                )

    return messages


__all__ = [
    "DEFAULT_SKIP_DIRS",
    "collect_condition_argument_names",
    "discover_tool_ids",
    "discover_tools",
    "validate_condition_arguments",
]

