# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

import argparse
import asyncio
import os
import sys
import logging
import ast
import re as _re
import httpx

from pathlib import Path
from typing import Dict, Any, Set, Optional
from datetime import datetime, timedelta, timezone
import base64 as _b64
from nacl.signing import SigningKey
import time
import uuid


from .utils import ColorFormatter, DEFAULT_API_URL, HTTP_TIMEOUT_SECONDS
from .exceptions import PolicyError, ConfigurationError
from .policy_file import FilePolicyLoader
from .validator import resolve_limits
from ._crypto import get_or_create_key
from .utils import require_app_name
from .cache import CacheManager

logger = logging.getLogger("d2.cli")

import json
try:
    import yaml  # type: ignore
except ImportError:
    logger.error("PyYAML is required for YAML output. Install with: pip install \"d2[cli]\"")
    sys.exit(1)

from urllib import parse as _urlp


# ---------------------------------------------------------------------------
# Helper: discover tool IDs in the project source tree
# ---------------------------------------------------------------------------

DEFAULT_SKIP_DIRS = {
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
    "examples",
}


def _discover_tool_ids(project_root: Path, *, skip_dirs: Optional[Set[str]] = None) -> Set[str]:
    """Recursively scan for functions/methods decorated with @d2_guard (or @d2).
    - Detect methods inside classes and nested classes; generate a qualified
      name like ``module.Class.method`` for implicit IDs (matching runtime).
    - Recognize decorator aliases/attribute forms: ``@d2_guard``, ``@d2``,
      ``@d2.d2_guard``.
    - Broaden the prefilter to reduce false negatives.
    """

    skip_dirs = skip_dirs or DEFAULT_SKIP_DIRS
    tool_ids: Set[str] = set()

    # Will be populated per-module from top-level imports
    allowed_names: set[str] = {"d2_guard", "d2"}

    def _is_d2_decorator(dec: ast.AST) -> bool:
        # Name: d2_guard or d2
        if isinstance(dec, ast.Name) and dec.id in allowed_names:
            return True
        # Call to a name
        if isinstance(dec, ast.Call):
            func = dec.func
            if isinstance(func, ast.Name) and func.id in allowed_names:
                return True
            if isinstance(func, ast.Attribute) and func.attr in {"d2_guard", "d2"}:
                return True
        # Attribute decorator (e.g., sdk.d2_guard)
        if isinstance(dec, ast.Attribute) and dec.attr in {"d2_guard", "d2"}:
            return True
        return False

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
                    # explicit id: first arg is a string literal
                    explicit_id: Optional[str] = None
                    if isinstance(dec, ast.Call) and dec.args:
                        arg0 = dec.args[0]
                        if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                            explicit_id = arg0.value
                    if explicit_id:
                        tool_ids.add(explicit_id)
                    else:
                        qual = ".".join(self.class_stack + [node.name]) if self.class_stack else node.name
                        tool_ids.add(f"{self.module_name}.{qual}")

        def visit_FunctionDef(self, node: ast.FunctionDef):  # type: ignore[override]
            self._collect(node)
            # Recurse into nested defs/classes if any
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

        # Broadened prefilter: look for common decorator tokens
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

        # Discover alias names: from d2 import d2 as X, or d2_guard as Y
        for top in getattr(tree, "body", []):
            if isinstance(top, ast.ImportFrom) and top.module == "d2":
                for alias in top.names:
                    if alias.name in {"d2", "d2_guard"}:
                        allowed_names.add(alias.asname or alias.name)

        _Visitor(rel_module).visit(tree)

    return tool_ids

# Get a logger instance

# Default local policy file path. The loader will also check other locations.
# Use the canonical policy file location that d2 switch and other commands use
xdg_config_home = Path(os.environ.get("XDG_CONFIG_HOME", "~/.config")).expanduser()
DEFAULT_POLICY_PATH = Path(os.getenv("D2_POLICY_FILE", xdg_config_home / "d2" / "policy.yaml"))

DEFAULT_POLICY_CONTENT = """
# This is a default D2 policy file.
#
# It defines a simple RBAC policy with three roles:
# - 'admin': Can do anything.
# - 'developer': Can access a 'weather_api' and read billing data.
# - 'viewer': Can only access a basic 'ping' tool.
#
# You can use these permissions in your code with the @d2_guard decorator:
# @d2_guard("weather_api")

version: 1
policies:
  - role: admin
    permissions:
      - "*"

  - role: developer
    permissions:
      - "weather_api"
      - "billing:read"

  - role: viewer
    permissions:
      - "ping"
""".lstrip()


def _find_default_policy_file() -> Path:
    """Return the canonical local policy file path, preferring env override,
    otherwise ~/.config/d2/policy.{yaml,yml,json}. Raises FileNotFoundError if none exist.
    Raises ConfigurationError if multiple policy files exist.
    """
    from .exceptions import ConfigurationError
    
    xdg_config_home = Path(os.environ.get("XDG_CONFIG_HOME", "~/.config")).expanduser()
    env_path = os.getenv("D2_POLICY_FILE")
    candidates = []
    if env_path:
        candidates.append(Path(env_path))
    else:
        # Only check standard locations if no env override
        candidates.extend([
            xdg_config_home / "d2" / "policy.yaml",
            xdg_config_home / "d2" / "policy.yml", 
            xdg_config_home / "d2" / "policy.json",
        ])
    
    existing_files = []
    for candidate in candidates:
        try:
            if candidate.exists():
                existing_files.append(candidate)
        except Exception:
            continue
    
    if not existing_files:
        # If env provided but not found, point user at it first
        if env_path:
            raise FileNotFoundError(f"Policy file not found at {env_path}. Set D2_POLICY_FILE to a valid path or run `d2 init`.")
        # Otherwise list what we looked for
        searched = ", ".join(str(p) for p in candidates)
        raise FileNotFoundError(f"No policy file found. Looked for: {searched}. Run `d2 init`.")
    
    if len(existing_files) > 1 and not env_path:
        # Multiple policy files exist - this is problematic and must be resolved
        pretty_files = "\n   • " + "\n   • ".join(str(f) for f in existing_files)
        raise ConfigurationError(
            f"❌ Multiple policy files detected:{pretty_files}\n"
            "❌ Only ONE policy file should exist to avoid conflicts.\n"
            "   Run 'd2 init --force' to clean up and create a single policy file."
        )
    
    return existing_files[0]


def _extract_policy_content(policy_data: Dict[str, Any], stage: str) -> Dict[str, Any]:
    """Extract the editable policy content from API response."""
    jws = policy_data.get("jws")
    bundle = policy_data.get("bundle")
    
    if jws:
        # Published policy - decode JWS to get bundle content
        try:
            import base64
            import json
            
            # Split JWS: header.payload.signature
            parts = jws.split(".")
            if len(parts) != 3:
                raise ValueError("Invalid JWS format")
                
            # Decode payload (base64url)
            payload_b64 = parts[1]
            # Add padding if needed
            padding = 4 - len(payload_b64) % 4
            if padding != 4:
                payload_b64 += "=" * padding
                
            payload_bytes = base64.urlsafe_b64decode(payload_b64)
            jwt_payload = json.loads(payload_bytes)
            
            # Extract policy from flat JWT structure (metadata and policies directly in payload)
            if "metadata" not in jwt_payload or "policies" not in jwt_payload:
                raise ValueError("JWT payload missing required 'metadata' or 'policies' fields")
            
            # Reconstruct policy bundle from flat JWT payload
            policy_data = {
                "metadata": jwt_payload["metadata"],
                "policies": jwt_payload["policies"]
            }
                
            return policy_data
            
        except Exception as e:
            raise ValueError(f"Failed to decode JWS policy bundle: {e}")
    elif bundle:
        # Draft policy - use the raw bundle content directly
        if not isinstance(bundle, dict):
            raise ValueError("Bundle field must be a dictionary")
            
        # Validate that we have the expected policy structure
        if 'metadata' not in bundle and 'policies' not in bundle:
            raise ValueError("Bundle missing required 'metadata' or 'policies' fields")
            
        return bundle
    else:
        # Fallback: try to extract from response (backwards compatibility)
        # Extract the policy content (excluding API metadata like version, etag, jws, bundle)
        api_metadata_fields = {'version', 'etag', 'jws', 'bundle'}
        bundle_content = {k: v for k, v in policy_data.items() 
                        if k not in api_metadata_fields}
        
        # Check if we have the expected policy structure
        if not bundle_content:
            raise ValueError("No policy content found - neither JWS nor bundle field present")
            
        # Validate that we have at least metadata and policies
        if 'metadata' not in bundle_content and 'policies' not in bundle_content:
            raise ValueError("Policy content missing required 'metadata' or 'policies' fields")
            
        return bundle_content


async def _fetch_cloud_policy(api_url: str, token: str, *, app_name_override: Optional[str] = None, stage: str = "bundle") -> Dict[str, Any]:
    """Fetches the policy bundle from the D2 cloud."""
    # Always use the bundle endpoint; pass stage as a query parameter (published|draft|auto)
    if stage not in ("bundle", "published", "auto", "draft"):
        raise ValueError(f"Invalid stage: {stage}")
    endpoint = "/v1/policy/bundle"
        
    bundle_url = f"{api_url.rstrip('/')}{endpoint}"
    
    # Add query parameters
    params = {}
    if app_name_override:
        params["app_name"] = app_name_override
        
    # Add stage parameter for bundle endpoint
    if stage in ("published", "auto", "draft"):
        params["stage"] = stage
    # stage="bundle" leaves stage unspecified to let server default apply
        
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Request-Id": str(uuid.uuid4())
    }
    
    async with httpx.AsyncClient() as client:
        try:
            logger.info(f"Fetching policy from {bundle_url}...")
            response = await client.get(bundle_url, headers=headers, params=params, timeout=HTTP_TIMEOUT_SECONDS)
            response.raise_for_status()
            logger.info("Fetch successful.")
            
            # Add ETag from headers to response data
            data = response.json()
            if "etag" in response.headers:
                data["etag"] = response.headers["etag"]
            return data
            
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                if app_name_override:
                    raise Exception(f"No {stage} policy found for app '{app_name_override}'. Run 'd2 init' to create one or check the app name.")
                else:
                    raise Exception(f"No {stage} policy found. Run 'd2 init' to create one.")
            elif e.response.status_code == 401:
                raise Exception("Invalid or expired token. Check your D2_TOKEN.")
            elif e.response.status_code == 403:
                raise Exception("Access denied. Check your token permissions.")
            else:
                raise Exception(f"HTTP {e.response.status_code}: {e.response.text}")
        except httpx.RequestError as e:
            raise Exception(f"Network error: {e}")


def _init_global_config(args):
    """Creates the default global policy file in ~/.config/d2/."""
    # First, check if the D2_POLICY_FILE env var is set, as it will always take precedence.
    if "D2_POLICY_FILE" in os.environ:
        path = Path(os.environ["D2_POLICY_FILE"])
        if path.exists():
            logger.warning(f"⚠️  D2_POLICY_FILE is set and points to an existing file: {path}")
            logger.warning("   The SDK will use this file and ignore the global policy file.")
            logger.warning("   To avoid confusion, consider unsetting this environment variable for local testing.")

    output_format = args.format

    # ------------------------------------------------------------------
    # Scan project for @d2_guard usages
    # ------------------------------------------------------------------
    project_root = Path(args.path).resolve()
    if not project_root.exists():
        logger.error("Provided --path %s does not exist.", project_root)
        sys.exit(1)

    discovered_tools = sorted(_discover_tool_ids(project_root))
    if discovered_tools:
        logger.info("🔍 Found %d tool(s) guarded by @d2_guard in %s", len(discovered_tools), project_root)
        if len(discovered_tools) > 25:
            logger.warning("Policy will exceed the free 25-tool cap (%d detected). Local mode will refuse to load; consider upgrading.", len(discovered_tools))
    else:
        logger.info("No @d2_guard usage found in %s. Generating sample policy instead.", project_root)

    xdg_config_home = Path(os.environ.get("XDG_CONFIG_HOME", "~/.config")).expanduser()
    config_dir = xdg_config_home / "d2"
    config_dir.mkdir(parents=True, exist_ok=True)
    existing_candidates = list(config_dir.glob("policy.*"))
    target_file = config_dir / f"policy.{output_format}"

    if existing_candidates and not args.force:
        if len(existing_candidates) == 1 and existing_candidates[0] == target_file:
            # Same format file already exists
            logger.warning("Policy file already exists: %s", existing_candidates[0])
            try:
                overwrite = input("   Overwrite existing file? [y/N]: ").lower().strip()
                if overwrite != 'y':
                    logger.info("Aborted.")
                    return
            except KeyboardInterrupt:
                print()
                logger.info("Aborted.")
                return
        else:
            # Multiple files or different format - this is problematic
            pretty = "\n   • " + "\n   • ".join(str(p) for p in existing_candidates)
            logger.warning("❌ Multiple policy files detected:%s", pretty)
            logger.warning("❌ Only ONE policy file should exist to avoid confusion.")
            try:
                overwrite = input("   🧹 Delete ALL existing files and create %s? [y/N]: " % target_file.name).lower().strip()
                if overwrite != 'y':
                    logger.info("Aborted. Please manually remove duplicate policy files first.")
                    return
            except KeyboardInterrupt:
                print()
                logger.info("Aborted.")
                return

    # Remove all existing policy.* files to maintain single source of truth
    for f in existing_candidates:
        try:
            f.unlink()
            logger.info("🗑️  Removed: %s", f)
        except Exception as e:
            logger.warning("Failed to remove %s: %s", f, e)

    config_file = target_file

    # Generate the policy with a 7-day expiry
    expiry_date = datetime.now(timezone.utc) + timedelta(days=7)
    
    policies_section = [
        {"role": "admin", "permissions": ["*"]},
    ]

    if discovered_tools:
        policies_section.append({"role": "<FILL_ME_IN>", "permissions": discovered_tools})
    else:
        # Fallback sample as before
        policies_section.append({
            "role": "developer",
            "permissions": [
                "database:query",
                "weather_api",
                "notifications:send",
            ]
        })

    policy_data = {
        "metadata": {
            "name": "<FILL_ME_IN>",
            "description": "Describe this policy bundle",
            "expires": expiry_date.isoformat(),
        },
        "policies": policies_section,
    }

    if output_format == 'yaml':
        with config_file.open('w') as f:
            # Write a helpful, static header comment first.
            f.write("# D2 policy generated by `d2 init`\n")
            f.write("# This file is used when the D2_TOKEN environment variable is NOT set.\n")
            f.write("# Free-tier local policies expire automatically after 7 days. Run `d2 init --force` to refresh it.\n\n")

            if discovered_tools:
                f.write("# Detected tools: \n")
                for t in discovered_tools:
                    f.write(f"#   - {t}\n")
                f.write("#\n# Hint: Replace '<FILL_ME_IN>' with your role names and adjust permissions as needed.\n\n")
            
            # Dump YAML with minimal quoting – only when necessary for correctness.
            class _SmartDumper(yaml.SafeDumper):
                pass

            _BOOL_NULL = {"y","yes","n","no","on","off","true","false","null","~"}
            _LEADING_SPECIAL = set("*&?:-#{}[],>|%@`")
            _num_re = _re.compile(r"^[+-]?\d+(?:\.\d+)?$")
            _date_re = _re.compile(r"^\d{4}-\d{2}-\d{2}$")

            def _repr_str(dumper, data: str):
                s = data
                needs_quote = (
                    s == "*" or
                    s.lower() in _BOOL_NULL or
                    (s and s[0] in _LEADING_SPECIAL) or
                    _num_re.match(s) is not None or
                    _date_re.match(s) is not None
                )
                style = '"' if needs_quote else None
                return dumper.represent_scalar('tag:yaml.org,2002:str', s, style=style)

            _SmartDumper.add_representer(str, _repr_str)

            yaml.dump(policy_data, f, sort_keys=False, indent=4, Dumper=_SmartDumper)

    elif output_format == 'json':
        with config_file.open('w') as f:
            # For JSON, we can just dump the data.
            json.dump(policy_data, f, indent=2)

    logger.info(f"✅ Created default policy file at: {config_file}")
    logger.info("   To get started, see the docs: https://artoo.love/d2/docs")

async def _pull_policy(args):
    """Handler for the 'pull' command."""

    token = os.getenv("D2_TOKEN")
    if not token:
        # No cloud token – inform the user where the local policy lives (if any).
        logger.info("D2_TOKEN not set – operating in local-file mode.")
        try:
            loader = FilePolicyLoader()
            logger.info("Your local policy file is located at: %s", loader.policy_path)
            logger.info("Edit that file directly or run `d2 diagnose` for a quick check.")
        except ConfigurationError:
            logger.info("No local policy file found. Run `python -m d2 init` to create one.")
        return

    api_url = DEFAULT_API_URL
    
    # Determine app_name: command-line flag takes precedence over local policy file
    app_name = getattr(args, 'app_name', None)
    if app_name:
        logger.info("Using app_name from --app-name flag: %s", app_name)
    else:
        try:
            from .utils import require_app_name
            app_name = require_app_name()
            logger.info("Using app_name from local policy: %s", app_name)
        except Exception:
            logger.info("No local policy file found or no app_name specified")
    
    # Get stage from args (defaults to "published")
    stage = getattr(args, 'stage', 'published')
    logger.info("Fetching %s policy", stage)
    
    try:
        # If user asked for published but we got 404, try auto (which falls back to draft)
        if stage == "published":
            try:
                policy_data = await _fetch_cloud_policy(api_url, token, app_name_override=app_name, stage=stage)
                actual_stage = "published"
            except Exception as e:
                error_str = str(e).lower()
                if ("404" in error_str or "not found" in error_str or f"no {stage} policy found" in error_str):
                    logger.warning("No published policy found, trying auto (published or draft)...")
                    policy_data = await _fetch_cloud_policy(api_url, token, app_name_override=app_name, stage="auto")
                    # Determine what we actually got by checking if JWS is present (signed = published)
                    actual_stage = "published" if policy_data.get("jws") else "draft"
                    logger.info("✅ Found %s policy instead", actual_stage)
                else:
                    raise e
        else:
            # For draft or any other stage, just request it directly
            policy_data = await _fetch_cloud_policy(api_url, token, app_name_override=app_name, stage=stage)
            actual_stage = stage
    except Exception as e:
        logger.error("Failed to fetch policy: %s", e)
        return

    # Extract just the editable policy content (not API metadata like version/etag/jws)
    bundle_content = _extract_policy_content(policy_data, actual_stage)

    target_path = Path(args.output) if args.output else DEFAULT_POLICY_PATH

    out_format = args.format or ("json" if target_path.suffix == ".json" else "yaml")

    target_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Check for conflicting policy files before writing (unless specific output provided)
    if not args.output:
        config_dir = target_path.parent
        existing_candidates = [f for f in config_dir.glob("policy.*") if f != target_path and f.exists()]
        if existing_candidates:
            logger.warning("⚠️  Multiple policy files detected:")
            logger.warning("   • %s (target)", target_path)
            for f in existing_candidates:
                logger.warning("   • %s", f)
            logger.warning("⚠️  Run 'd2 init --force' to clean up and create a single policy file.")

    with open(target_path, "w") as f:
        if out_format == "json":
            json.dump(bundle_content, f, indent=2)
        else:
            yaml.dump(bundle_content, f, sort_keys=False, indent=2)

    # Show what we actually got
    version = policy_data.get("version", "unknown")
    
    # Update cache with fetched policy data
    try:
        from .cache import CacheManager
        cache = CacheManager(token, app_name)
        etag = policy_data.get("etag") or ""
        jws = policy_data.get("jws") or ""
        version = policy_data.get("version", 0)
        if etag:
            cache.save_bundle(jws, etag, version)
            logger.debug("Updated cache for app '%s' (ETag: %s, version: %s)", app_name, etag[:12] + "..." if len(etag) > 12 else etag, version)
        
        # Note: We don't save context here because _fetch_cloud_policy doesn't return
        # response headers (like X-D2-Account-Id). Context will be saved properly
        # when the runtime CloudPolicyLoader is used, which has access to full response.
    except Exception as e:
        logger.debug("Failed to update cache: %s", e)
    
    logger.info(f"✅ Cloud policy successfully pulled to {target_path} ({actual_stage} version {version})")


async def _inspect_policy(args):
    """Handler for the 'inspect' command – works for both cloud and local."""

    token = os.getenv("D2_TOKEN")

    if token:
        mode = "cloud"
        api_url = DEFAULT_API_URL
        # Use app_name override if provided, otherwise try to get from local policy
        app_name = getattr(args, 'name', None)
        if not app_name:
            try:
                from .utils import require_app_name
                app_name = require_app_name()
                logger.info("Using app_name from local policy: %s", app_name)
            except Exception:
                logger.info("No local policy file found or no app_name specified")
        
        try:
            api_response = await _fetch_cloud_policy(api_url, token, app_name_override=app_name, stage="bundle")
            # Extract the actual policy content from the API response
            policy_data = _extract_policy_content(api_response, "bundle")
        except Exception as e:
            logger.error("Failed to fetch policy: %s", e)
            return
        source_msg = "D2 cloud policy"
    else:
        mode = "file"
        logger.info("D2_TOKEN not set – inspecting local policy file instead.")
        try:
            loader = FilePolicyLoader()
            policy_data = await loader.load_policy()
            source_msg = f"local policy ({loader.policy_path})"
        except ConfigurationError as e:
            logger.error("❌ %s", e)
            logger.info("Run `python -m d2 init` to create a policy file or set D2_TOKEN for cloud mode.")
            return
        except PolicyError as e:
            logger.error("❌ Local policy invalid: %s", e)
            logger.info("Run `d2 diagnose` for detailed validation errors.")
            return

    policies = policy_data.get("policies", [])

    if not policies:
        logger.warning("%s is empty or contains no permissions.", source_msg.capitalize())
        return

    if args.verbose:
        # Use print here for clean YAML output without logging format
        print("---")
        print(f"{source_msg.capitalize()} – Roles & Permissions:")
        print(yaml.dump(policies, indent=2, sort_keys=False))
    else:
        all_permissions: Set[str] = set()
        for policy in policies:
            all_permissions.update(policy.get("permissions", []))

        # Clean list output
        print(f"Permissions available in {source_msg}:")
        print("---------------------------------------")
        if not all_permissions:
            print("(No permissions found)")
            return

        for perm in sorted(all_permissions):
            print(f"  - {perm}")

        print("---------------------------------------")
        print("`d2 inspect --verbose` for full details.")

async def _diagnose_policy(_args):
    """Offline linter for the policy file – works in both local and cloud mode."""

    try:
        loader = FilePolicyLoader()
        if os.getenv("D2_TOKEN"):
            logger.info("Cloud token detected – diagnostics will apply cloud quotas, but analysing local file contents.")
    except ConfigurationError as e:
        logger.error("❌ %s", e)
        logger.info("Run `python -m d2 init` to generate a starter policy file.")
        return

    try:
        bundle = await loader.load_policy()
    except PolicyError as e:
        logger.error("❌ Policy validation failed: %s", e)
        logger.info("See the error above for the quickest fix or visit https://artoo.love/d2/pricing to upgrade.")
        return

    # At this point the bundle is valid – show helpful stats.

    defined_tools = set()
    for policy in bundle.get("policies", []):
        defined_tools.update(policy.get("permissions", []))
    defined_tools.discard("*")
    tool_count = len(defined_tools)

    # --------------------------------------------------
    # Cloud quota context – if token present, show plan & limits
    # --------------------------------------------------
    token = os.getenv("D2_TOKEN")
    # Local import to avoid circulars and keep startup fast
    limits = resolve_limits(token) if token else None
    plan_name = limits.get("plan") if limits else None
    cloud_limits = {"max_tools": limits.get("max_tools")} if limits else None

    expiry_str = bundle.get("metadata", {}).get("expires")
    hours_left_msg = "unknown"
    if expiry_str:
        try:
            expiry_date = datetime.fromisoformat(expiry_str)
            if expiry_date.tzinfo is None:
                expiry_date = expiry_date.replace(tzinfo=timezone.utc)
            delta = expiry_date - datetime.now(timezone.utc)
            hours_left = int(delta.total_seconds() // 3600)
            hours_left_msg = f"{hours_left} h" if hours_left >= 0 else "expired"
        except Exception:
            pass

    # --------------------------------------------
    # Extra lint: metadata.name placeholder / empty
    # --------------------------------------------
    meta_name = bundle.get("metadata", {}).get("name", "")
    placeholder = (not meta_name) or str(meta_name).startswith("<") or "FILL_ME_IN" in str(meta_name)

    # --------------------------------------------
    # Extra lint: permissions that are not strings
    # --------------------------------------------
    bad_perms = []
    for pol in bundle.get("policies", []):
        role = pol.get("role", "<unknown>")
        for perm in pol.get("permissions", []):
            if not isinstance(perm, str):
                bad_perms.append((role, perm, type(perm).__name__))
            elif perm.lower() in {"yes", "no", "on", "off", "true", "false"}:
                bad_perms.append((role, perm, "bool-like"))

    ok = True
    if placeholder:
        ok = False
        logger.error("❌ metadata.name is missing or still a placeholder (<FILL_ME_IN>).")

    if bad_perms:
        ok = False
        for role, perm, typ in bad_perms:
            logger.error("❌ Permission %s in role %s should be a string (got %s). Quote it in YAML.", perm, role, typ)

    if not ok:
        logger.error("Fix the above issues before running `d2 draft` or `d2 publish`.")
        return

    logger.info("✅ Policy looks good – here’s the summary:")
    if plan_name:
        max_tools_cloud = cloud_limits.get("max_tools")
        logger.info("   • Cloud plan : %s (tool cap %s)", plan_name, max_tools_cloud or "∞")
        logger.info("   • Tools defined: %d / %s", tool_count, max_tools_cloud or "∞")
    else:
        logger.info("   • Tools defined: %d / 25", tool_count)

    logger.info("   • Expires in : %s", hours_left_msg)

    # Gentle upsell if near limits
    if tool_count >= 25:
        logger.warning("You have hit the free-tier tool cap (25). Future tools will fail. Consider upgrading.")
    elif tool_count >= 22:
        logger.warning("You’re within 3 tools of the free-tier cap. Plan for an upgrade soon.")

    if hours_left_msg != "unknown":
        try:
            hours_left_int = int(hours_left_msg.split()[0])
            # Only warn for local-mode usage; in cloud mode the control-plane auto-refreshes on access.
            if not token:
                if hours_left_int <= 24:
                    logger.warning("⏰ Policy expires in <24 h – calls will hard-fail afterwards. Run `d2 init --force` or upgrade.")
                elif hours_left_int <= 72:
                    logger.warning("Policy expires in <3 days. Consider refreshing or upgrading.")
            else:
                logger.info("Local policy expiry in %s – informational only; cloud mode auto-refreshes on access.", hours_left_msg)
        except ValueError:
            pass

    logger.info("Run `d2 pull` (cloud) or `d2 init --force` (local) to refresh/extend your policy.")


async def _publish_policy(args):
    """CLI handler for `d2 publish`."""

    token = os.getenv("D2_TOKEN")
    if not token:
        logger.error("D2_TOKEN environment variable required for cloud publish.")
        return

    api_url = DEFAULT_API_URL

    # Determine bundle file path – prefer D2_POLICY_FILE, then ~/.config/d2/policy.{yaml,yml,json}
    try:
        file_path = _find_default_policy_file()
    except FileNotFoundError as e:
        logger.error(str(e))
        return

    raw_bytes = file_path.read_bytes()

    # Production safety guard
    import sys as _sys
    if api_url.endswith("artoo.com") and not args.prod:
        logger.error("Refusing to publish to production API without --prod flag.")
        raise SystemExit(1)


    async with httpx.AsyncClient(base_url=api_url, headers={"Authorization": f"Bearer {token}"}) as client:
            priv_path, key_id = await get_or_create_key(client)
            sign_key = SigningKey(priv_path.read_bytes())
            sig = sign_key.sign(raw_bytes).signature
            signature_b64 = _b64.b64encode(sig).decode()

            headers = {}
            if signature_b64:
                headers["X-D2-Signature"] = signature_b64
                headers["X-D2-Key-Id"] = key_id
            # Explicit content type for raw bytes body
            headers["Content-Type"] = "application/octet-stream"

            # Try first with If-Match: * for first publish, then retry with exact ETag on 409
            app_name = require_app_name()
            url = f"/v1/policy/publish?app_name={_urlp.quote(app_name)}"
        
            # First attempt with wildcard (first publish)
            headers["If-Match"] = "*"
            logger.info("Uploading policy… (precondition: %s)", headers.get("If-Match"))
            resp = await client.post(url, content=raw_bytes, headers=headers)
        
            # Handle 409 ETag mismatch with automatic retry
            if resp.status_code == 409:
                logger.warning("Policy already exists, fetching current ETag for retry...")
                try:
                    # Fetch current bundle to get ETag
                    bundle_resp = await client.get(f"/v1/policy/bundle?app_name={_urlp.quote(app_name)}&stage=published")
                    if bundle_resp.status_code == 200:
                        current_etag = bundle_resp.headers.get("etag")
                        if current_etag:
                            headers["If-Match"] = current_etag
                            logger.info("Retrying with current ETag: %s", current_etag)
                            resp = await client.post(url, content=raw_bytes, headers=headers)
                        else:
                            logger.error("Failed to get ETag from current bundle")
                    else:
                        logger.error("Failed to fetch current bundle for ETag (status %s)", bundle_resp.status_code)
                except Exception as e:
                    logger.error("Failed to fetch current ETag: %s", e)
        
            if resp.status_code in (200, 201):
                try:
                    body = resp.json()
                    logger.info("✅ Published policy version %s (ETag %s)", body.get("version"), body.get("etag"))
                    # No local ETag cache persistence anymore
                except json.JSONDecodeError:
                    logger.info("✅ Policy published (status %s)", resp.status_code)
            else:
                # Branch on common error statuses with actionable messages
                msg = None
                try:
                    payload = resp.json()
                except Exception:
                    payload = {}
                if resp.status_code == 409:
                    msg = payload.get("error") or "etag_mismatch"
                    logger.error("Publish failed (409): %s. Current policy was modified during publish attempt.", msg)
                elif resp.status_code == 400:
                    err = payload.get("error") or "invalid_request"
                    detail = payload.get("detail") or payload.get("message") or ""
                    
                    # New strict validation errors for drafts/publish
                    if isinstance(detail, str) and detail.startswith("policy_validation_failed"):
                        msg = detail.replace("policy_validation_failed: ", "").strip()
                        logger.error("Publish validation failed: %s", msg or detail)
                        raise SystemExit(1)

                    if err == "invalid_signature":
                        logger.error("Publish failed: invalid_signature. Ensure X-D2-Signature signs the exact HTTP body and Key-Id is correct.")
                    elif err == "no_deny_rules":
                        logger.error("Publish failed: no_deny_rules. Backend rejects bundles that allow everything; add explicit denies.")
                    elif err == "no_changes" or "already published" in detail.lower() or "no difference" in detail.lower():
                        logger.warning("⚠️  Policy not published: %s", detail or "No changes detected from current published version")
                        logger.info("The draft content is identical to the current published policy. Make changes to your policy file before publishing.")
                    else:
                        full_error = f"{err}: {detail}" if detail else err
                        logger.error("Publish failed (400): %s", full_error)
                        # Log raw response for debugging unclear errors
                        if err == "invalid_request" and not detail:
                            try:
                                logger.debug("Raw server response: %s", resp.text)
                            except Exception:
                                pass
                elif resp.status_code == 403:
                    # Explicit app quota handling
                    detail = payload.get("detail") or payload.get("error") or "forbidden"
                    message = payload.get("message") or ""
                    if detail == "quota_apps_exceeded":
                        logger.error("Publish failed: quota_apps_exceeded. %s", message or "Your plan's max apps limit has been reached. Upgrade or delete unused apps.")
                    elif (payload.get("error") or "") == "key_revoked":
                        logger.error("Publish failed: key_revoked. Register a new key and retry.")
                    else:
                        logger.error("Forbidden (403): %s", message or detail)
                elif resp.status_code == 404:
                    err = payload.get("error") or "not_found"
                    if err == "key_not_found":
                        logger.error("Publish failed: key_not_found. Upload public key via `d2 publish` (auto) or API, then retry.")
                    else:
                        logger.error("Not found (404): %s", err)
                else:
                    logger.error("Failed (%s): %s", resp.status_code, resp.text)
                    raise SystemExit(1)




async def _show_status(args):
    """CLI handler for `d2 status` - show token context and cache state."""
    token = os.getenv("D2_TOKEN")
    if not token:
        logger.error("D2_TOKEN not set - no cache context available.")
        return

    
    
    # Get current app from policy file
    try:
        app_name = require_app_name()
        logger.info("Current app  : %s (from policy file)", app_name)
        cache = CacheManager(token, app_name)
        
        # Show bundle state for this app
        etag = cache.get_cached_etag()
        version = cache.get_cached_version()
        bundle_age = cache.get_cache_age()
        
        if etag and bundle_age is not None:
            logger.info("Bundle ETag  : %s...%s (cached, age %d s)", etag[:8], etag[-8:], int(bundle_age))
            if version is not None:
                logger.info("Bundle Version: %s", version)
            else:
                logger.info("Bundle Version: not cached (run d2 pull to refresh)")
        else:
            logger.info("Bundle ETag  : not cached for this app")
            logger.info("Bundle Version: not cached")
        
        # Polling status display removed for developer CLI output
            
    except Exception as e:
        logger.error("Cannot determine current app: %s", e)
        logger.info("Edit your policy file to set metadata.name")


async def _switch_app(args):
    """CLI handler for `d2 switch` - fetch app policy and update local file."""
    new_app_name = args.app_name.strip()
    
    if not new_app_name:
        logger.error("App name cannot be empty")
        return
        
    # Validate app name format (basic validation)
    if not new_app_name.replace("-", "").replace("_", "").replace(".", "").isalnum():
        logger.error("App name should contain only letters, numbers, hyphens, underscores, and dots")
        return
    
    token = os.getenv("D2_TOKEN")
    if not token:
        logger.error("D2_TOKEN environment variable required for switching apps.")
        return
        
    if not token.startswith("d2_"):
        logger.error("Invalid token format. D2 tokens must start with 'd2_'.")
        return
    
    try:
        from pathlib import Path
        import yaml
        
        # Get policy file path
        xdg_config_home = Path(os.environ.get("XDG_CONFIG_HOME", "~/.config")).expanduser()
        policy_path = Path(os.getenv("D2_POLICY_FILE", xdg_config_home / "d2" / "policy.yaml"))
        
        # Check current app name to detect changes
        current_app = "<not set>"
        if policy_path.exists():
            try:
                current_data = yaml.safe_load(policy_path.read_text())
                if isinstance(current_data, dict):
                    current_app = current_data.get("metadata", {}).get("name", "<not set>")
            except Exception:
                pass  # Will create fresh policy file
        
        if current_app == new_app_name:
            logger.info("Already on app: %s", new_app_name)
            return
            
        # Fetch published policy from cloud
        api_url = os.getenv("D2_API_URL", DEFAULT_API_URL).rstrip("/")
        
        logger.info("Fetching published policy for app: %s", new_app_name)
        
        try:
            # Use auto to get published or fall back to draft automatically
            policy_data = await _fetch_cloud_policy(api_url, token, app_name_override=new_app_name, stage="auto")
            # Determine what we actually got by checking if JWS is present (signed = published)
            actual_stage = "published" if policy_data.get("jws") else "draft"
            if actual_stage == "draft":
                logger.info("Using draft policy (no published version exists)")
        except Exception as e:
            logger.error("Failed to fetch policy for app '%s': %s", new_app_name, e)
            logger.info("Run `d2 init` to create a new policy, or check that the app exists")
            return
        
        # Extract editable policy content
        try:
            bundle_content = _extract_policy_content(policy_data, actual_stage)
        except Exception as e:
            logger.error("Failed to extract policy content: %s", e)
            return
        
        # Ensure policy directory exists
        policy_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Check for conflicting policy files before writing
        config_dir = policy_path.parent
        existing_candidates = [f for f in config_dir.glob("policy.*") if f != policy_path and f.exists()]
        if existing_candidates:
            logger.warning("⚠️  Multiple policy files detected:")
            logger.warning("   • %s (target)", policy_path)
            for f in existing_candidates:
                logger.warning("   • %s", f)
            logger.warning("⚠️  Run 'd2 init --force' to clean up and create a single policy file.")
        
        # Write bundle content to local policy file
        try:
            policy_path.write_text(yaml.dump(bundle_content, default_flow_style=False, sort_keys=False))
            version = policy_data.get("version", "unknown")
            
            logger.info("✅ Switched from '%s' to '%s'", current_app, new_app_name)
            logger.info("Local policy file updated with %s version %s", actual_stage, version)
            
            # Update cache context
            from .cache import CacheManager
            cache = CacheManager(token, new_app_name)
            # Save the fetched bundle to cache
            etag = policy_data.get("etag") or "unknown"
            jws = policy_data.get("jws") or ""
            version = policy_data.get("version", 0)
            cache.save_bundle(jws, etag, version)
            
            logger.info("Policy cache updated for app '%s'", new_app_name)
                    
        except Exception as e:
            logger.error("Failed to update policy file: %s", e)
            return
            
    except ImportError:
        logger.error("PyYAML required for policy file operations. Install with: pip install PyYAML")
    except Exception as e:
        logger.error("Failed to switch app: %s", e)





async def _upload_draft(args):
    """CLI handler for `d2 draft` (upload policy draft)."""
    token = os.getenv("D2_TOKEN")
    if not token:
        logger.error("D2_TOKEN environment variable required for cloud draft upload.")
        return

    api_url = DEFAULT_API_URL

    # Determine draft file path – prefer D2_POLICY_FILE, then ~/.config/d2/policy.{yaml,yml,json}
    try:
        file_path = _find_default_policy_file()
    except FileNotFoundError as e:
        logger.error(str(e))
        return

    raw = file_path.read_bytes()
    # Parse as YAML or JSON
    if file_path.suffix in (".yaml", ".yml"):
        try:
            bundle = yaml.safe_load(raw)
        except Exception as e:
            logger.error("Failed to parse YAML: %s", e)
            return
    else:
        try:
            bundle = json.loads(raw)
        except Exception as e:
            logger.error("Failed to parse JSON: %s", e)
            return

    # ------------------------------------------------------------------
    # Basic validation – ensure mandatory metadata.name is present so the
    # back-end doesn’t create orphaned drafts lacking an app identifier.
    # ------------------------------------------------------------------
    meta_name = (
        isinstance(bundle, dict)
        and isinstance(bundle.get("metadata", {}), dict)
        and bundle.get("metadata", {}).get("name")
    )
    if (
        not meta_name
        or not str(meta_name).strip()
        or str(meta_name).strip().startswith("<")
        or "FILL_ME_IN" in str(meta_name)
    ):
        logger.error("Draft upload aborted: metadata.name is required in the policy file.")
        return

    payload = {"bundle": bundle}  # Server assigns version

    async with httpx.AsyncClient(base_url=api_url, headers={"Authorization": f"Bearer {token}"}) as client:
        resp = await client.put("/v1/policy/draft", json=payload)
        if resp.status_code in (200, 201):
            version = None
            try:
                data = resp.json()
                version = data.get("version")
                if version is None and isinstance(data.get("draft"), dict):
                    version = data["draft"].get("version")
            except Exception:
                version = None
            if version is not None:
                logger.info("✅ Draft uploaded (version=%s)", version)
            else:
                logger.info("✅ Draft uploaded")
        elif resp.status_code == 403:
            # App quota exceeded or permission issues – non-retryable guidance for quota case
            try:
                payload = resp.json()
            except Exception:
                payload = {}
            detail = payload.get("detail") or payload.get("error") or "forbidden"
            message = payload.get("message") or ""
            if detail == "quota_apps_exceeded":
                logger.error(
                    "Draft upload failed: quota_apps_exceeded. %s",
                    message or "Your plan's max apps limit has been reached. Upgrade or delete unused apps.",
                )
                raise SystemExit(1)
            logger.error("Draft upload failed (403): %s", message or detail)
            raise SystemExit(1)
        elif resp.status_code == 400:
            # Strict validation errors (server-side)
            try:
                payload = resp.json()
            except Exception:
                payload = {}
            detail = payload.get("detail") or payload.get("message") or "invalid_request"
            if isinstance(detail, str) and detail.startswith("policy_validation_failed"):
                msg = detail.replace("policy_validation_failed: ", "").strip()
                logger.error("Draft validation failed: %s", msg or detail)
            else:
                logger.error("Draft upload failed (400): %s", detail)
            raise SystemExit(1)
        else:
            try:
                detail = resp.json().get("error")
            except Exception:
                detail = resp.text
            logger.error("Draft upload failed (%s): %s", resp.status_code, detail)
            raise SystemExit(1)


# Note: Key revocation is platform-managed; the SDK does not expose deletion.


def main():
    # Configure logging for the CLI
    handler = logging.StreamHandler()
    handler.setFormatter(ColorFormatter())
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.addHandler(handler)
    root_logger.setLevel(logging.INFO)

    # Run garbage collection on startup (non-blocking)
    try:
        from .cache import gc_old_caches
        gc_result = gc_old_caches(dry_run=False)
        if gc_result["cleaned_count"] > 0:
            freed_mb = gc_result["freed_bytes"] / (1024 * 1024)
            logger.info("Cleaned %d unused policy caches (%.1f MiB)", 
                       gc_result["cleaned_count"], freed_mb)
    except Exception:
        pass  # Ignore GC errors, don't block CLI

    parser = argparse.ArgumentParser(
        prog="python -m d2",
        description="D2 SDK Command-Line Interface. Manages local and cloud policies.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # `d2 init`
    parser_init = subparsers.add_parser(
        "init",
        help="Generate a policy file (local mode). Auto-scans your project for @d2_guard tools and writes ~/.config/d2/policy.yaml by default.",
        description="Generate a starter policy bundle for *local-file* mode. The command scans your code-base for @d2_guard-decorated functions and pre-populates the permissions list so you only have to fill in role names."
    )
    parser_init.add_argument("--force", action="store_true", help="Overwrite the policy file if it already exists.")
    parser_init.add_argument(
        "-p",
        "--path",
        default=".",
        help="Project directory to scan for @d2_guard usages when generating the policy (default: current dir).",
    )
    parser_init.add_argument(
        "--format",
        choices=["yaml", "json"],
        default="yaml",
        help="Output format for the policy file (default: yaml)."
    )
    parser_init.set_defaults(func=_init_global_config)

    # `d2 pull`
    parser_pull = subparsers.add_parser(
        "pull",
        help="Download the cloud policy to a file (requires D2_TOKEN). If no token is set, just prints the path of your local policy.",
        description="Download the policy bundle from the D2 cloud and write it to a file. In cloud mode this lets you inspect or version-control the bundle. When the D2_TOKEN env-var is absent the command behaves gracefully and simply tells you where your current local policy lives."
    )
    parser_pull.add_argument("-o", "--output", help="Output file path (default: ./policy.yaml)")
    parser_pull.add_argument("--format", choices=["yaml", "json"], default="yaml", help="Force output format when downloading cloud policy (default: yaml)")
    parser_pull.add_argument("--app-name", help="Specify which app's policy to fetch (overrides local policy file)")
    parser_pull.add_argument("--stage", choices=["published", "draft"], default="published", help="Which version to fetch: published (stable) or draft (work-in-progress)")
    parser_pull.set_defaults(func=_pull_policy)

    # `d2 inspect`
    parser_inspect = subparsers.add_parser(
        "inspect",
        help="List permissions and roles (works for both cloud and local mode).",
        description="Inspect the policy bundle. With D2_TOKEN set, fetches the cloud policy; otherwise reads your local policy file. Shows permissions or, with --verbose, the full role→permission mapping."
    )
    parser_inspect.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed output including roles and permissions in YAML format.",
    )
    parser_inspect.set_defaults(func=_inspect_policy)

    # `d2 diagnose`
    parser_diag = subparsers.add_parser(
        "diagnose",
        help="Validate local policy bundle against cloud quotas (when token present) or free-tier limits.",
        description="Run validation checks against your local policy file. With D2_TOKEN set, applies cloud quotas and shows plan info. Without token, applies free-tier constraints (25 tools, 7-day expiry). Outputs actionable guidance and upgrade suggestions."
    )
    parser_diag.set_defaults(func=_diagnose_policy)

    # ------------------------------------------------------------------
    # `d2 publish` – zero-touch signed bundle upload
    # ------------------------------------------------------------------

    parser_publish = subparsers.add_parser(
        "publish",
        help="Publish the current policy bundle (requires token with `policy:write`)."
    )
    # No optional flags; publish always signs and uploads
    parser_publish.set_defaults(func=_publish_policy)

    # `d2 draft` – upload a draft (requires token with `policy:write` scope)
    parser_draft = subparsers.add_parser(
        "draft",
        help="Upload a policy draft (requires token with `policy:write`).",
        description="Upload a policy draft. Cloud increments the version automatically."
    )
    # No file override; always reads from canonical location (can be overridden via D2_POLICY_FILE env)
    parser_draft.set_defaults(func=_upload_draft)

    # revoke command removed – policy revocation is admin-only via dashboard/API

    # `d2 status` – show token context and cache state
    parser_status = subparsers.add_parser(
        "status",
        help="Show information about cached policy.",
        description="Display information about currently cached policy."
    )
    parser_status.set_defaults(func=_show_status)

    # `d2 license-info` – show license summary
    def _license_info(_args=None):
        print(
            "D2 is source-available under BSL 1.1 (Change Date 2029-09-08 → LGPL-3.0-or-later).\n"
            "Internal production use allowed; managed-service offerings prohibited without commercial terms.\n"
            "See LICENSE."
        )

    parser_license = subparsers.add_parser(
        "license-info",
        help="Show license summary.",
        description="Display licensing information for D2."
    )
    parser_license.set_defaults(func=_license_info)

    # `d2 switch` – change current app in policy file
    parser_switch = subparsers.add_parser(
        "switch",
        help="Switch to a different app.",
        description="Update metadata.name in your policy file to switch between apps."
    )
    parser_switch.add_argument("app_name", help="App name to switch to")
    parser_switch.set_defaults(func=_switch_app, is_async=True)

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    
    # Adjust log level for verbosity
    if "verbose" in args and args.verbose:
        root_logger.setLevel(logging.DEBUG)

    if hasattr(args, "func"):
        if asyncio.iscoroutinefunction(args.func):
            asyncio.run(args.func(args))
        else:
            args.func(args)
    else:
        parser.print_help(sys.stderr)


if __name__ == "__main__":
    main() 