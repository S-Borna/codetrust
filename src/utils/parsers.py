"""Import extraction, requirements parsing, and Dockerfile parsing utilities."""

import json
import re
import sys

import structlog

logger = structlog.get_logger()

# Python standard library modules (3.10+)
_PYTHON_STDLIB: frozenset[str] = frozenset(sys.stdlib_module_names)

# Node.js built-in modules
_NODE_BUILTINS: frozenset[str] = frozenset({
    "assert", "buffer", "child_process", "cluster", "console", "constants",
    "crypto", "dgram", "dns", "domain", "events", "fs", "http", "http2",
    "https", "inspector", "module", "net", "os", "path", "perf_hooks",
    "process", "punycode", "querystring", "readline", "repl", "stream",
    "string_decoder", "sys", "timers", "tls", "tty", "url", "util", "v8",
    "vm", "wasi", "worker_threads", "zlib",
    "node:assert", "node:buffer", "node:child_process", "node:cluster",
    "node:console", "node:crypto", "node:dgram", "node:dns", "node:events",
    "node:fs", "node:http", "node:http2", "node:https", "node:inspector",
    "node:module", "node:net", "node:os", "node:path", "node:perf_hooks",
    "node:process", "node:querystring", "node:readline", "node:repl",
    "node:stream", "node:string_decoder", "node:sys", "node:timers",
    "node:tls", "node:tty", "node:url", "node:util", "node:v8", "node:vm",
    "node:wasi", "node:worker_threads", "node:zlib",
})

# Known import-to-package mapping (Python)
PYTHON_IMPORT_TO_PACKAGE: dict[str, str] = {
    "PIL": "Pillow",
    "cv2": "opencv-python",
    "sklearn": "scikit-learn",
    "yaml": "PyYAML",
    "bs4": "beautifulsoup4",
    "gi": "PyGObject",
    "attr": "attrs",
    "dateutil": "python-dateutil",
    "dotenv": "python-dotenv",
    "jose": "python-jose",
    "jwt": "PyJWT",
    "magic": "python-magic",
    "serial": "pyserial",
    "usb": "pyusb",
    "wx": "wxPython",
}

# Regex patterns for Python imports
_PY_IMPORT_RE = re.compile(r"^\s*import\s+([\w.]+)")
_PY_FROM_IMPORT_RE = re.compile(r"^\s*from\s+([\w.]+)\s+import\s+")

# Regex patterns for JS/TS imports
_JS_IMPORT_FROM_RE = re.compile(
    r"""(?:import\s+(?:[\w{},\s*]+\s+from\s+)?['"]([^'"]+)['"])"""
)
_JS_REQUIRE_RE = re.compile(r"""require\s*\(\s*['"]([^'"]+)['"]\s*\)""")
_JS_DYNAMIC_IMPORT_RE = re.compile(r"""import\s*\(\s*['"]([^'"]+)['"]\s*\)""")

# Requirements.txt line pattern
_REQ_LINE_RE = re.compile(
    r"^([A-Za-z0-9][\w.-]*(?:\[[^\]]+\])?)\s*([<>=!~]+.*)?"
)

# Version specifier extraction
_VERSION_SPEC_RE = re.compile(r"([<>=!~]+)\s*([\w.*]+)")


def extract_python_imports(code: str) -> list[str]:
    """Extract top-level package names from Python code.

    Handles:
      import foo              -> "foo"
      import foo.bar          -> "foo"
      from foo import bar     -> "foo"
      from foo.bar import baz -> "foo"
      from . import something -> skip (relative import)

    Normalizes via PYTHON_IMPORT_TO_PACKAGE mapping.
    Skips stdlib modules.
    """
    packages: set[str] = set()

    for line in code.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        top_level = _extract_python_import_line(stripped)
        if top_level is not None:
            packages.add(top_level)

    return sorted(packages)


def _extract_python_import_line(line: str) -> str | None:
    """Extract top-level package from a single Python import line."""
    # from .foo import bar -> skip relative
    if re.match(r"^\s*from\s+\.+", line):
        return None

    match = _PY_FROM_IMPORT_RE.match(line)
    if match:
        module = match.group(1).split(".")[0]
        return _normalize_python_package(module)

    match = _PY_IMPORT_RE.match(line)
    if match:
        module = match.group(1).split(".")[0]
        return _normalize_python_package(module)

    return None


def _normalize_python_package(module: str) -> str | None:
    """Normalize a Python module name, skip stdlib."""
    if module in _PYTHON_STDLIB:
        return None
    return PYTHON_IMPORT_TO_PACKAGE.get(module, module)


def extract_js_imports(code: str) -> list[str]:
    """Extract package names from JavaScript/TypeScript code.

    Handles:
      import x from 'foo'      -> "foo"
      import { x } from 'foo'  -> "foo"
      const x = require('foo') -> "foo"
      import('foo')            -> "foo"
      from '@scope/pkg'        -> "@scope/pkg"

    Skips: relative imports (./ ../), node builtins.
    """
    packages: set[str] = set()

    for line in code.splitlines():
        for pattern in (_JS_IMPORT_FROM_RE, _JS_REQUIRE_RE, _JS_DYNAMIC_IMPORT_RE):
            for match in pattern.finditer(line):
                pkg = _normalize_js_package(match.group(1))
                if pkg is not None:
                    packages.add(pkg)

    return sorted(packages)


def _normalize_js_package(specifier: str) -> str | None:
    """Normalize a JS import specifier, skip relative and builtins."""
    if specifier.startswith(".") or specifier.startswith("/"):
        return None
    if specifier in _NODE_BUILTINS:
        return None

    # Scoped packages: @scope/name -> @scope/name
    if specifier.startswith("@"):
        parts = specifier.split("/")
        if len(parts) >= 2:
            return f"{parts[0]}/{parts[1]}"
        return None

    # Non-scoped: take root package name
    return specifier.split("/")[0]


def parse_requirements_txt(content: str) -> dict[str, str]:
    """Parse requirements.txt to {package: version_spec}.

    Handles: ==, >=, ~=, !=, extras like [dev], comments, -r includes.
    Skips: git+ URLs, file:// URLs, blank lines.
    """
    result: dict[str, str] = {}

    for line in content.splitlines():
        line = line.strip()

        # Skip empty, comments, -r includes, URLs
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        if line.startswith("git+") or line.startswith("file://"):
            continue
        if line.startswith("http://") or line.startswith("https://"):
            continue

        parsed = _parse_requirement_line(line)
        if parsed is not None:
            name, version = parsed
            result[name] = version

    return result


def _parse_requirement_line(line: str) -> tuple[str, str] | None:
    """Parse a single requirements.txt line into (name, version_spec)."""
    # Remove inline comments
    if " #" in line:
        line = line[: line.index(" #")]

    match = _REQ_LINE_RE.match(line.strip())
    if not match:
        return None

    name = match.group(1)
    # Strip extras: package[dev] -> package
    if "[" in name:
        name = name[: name.index("[")]

    version_spec = match.group(2) or ""
    # Extract just the version number from ==1.0.0
    if version_spec:
        version_match = _VERSION_SPEC_RE.match(version_spec)
        if version_match:
            version_spec = version_match.group(2)

    return name.lower(), version_spec


def parse_package_json_deps(content: str) -> dict[str, str]:
    """Parse package.json dependencies + devDependencies."""
    result: dict[str, str] = {}
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, TypeError):
        return result

    for key in ("dependencies", "devDependencies"):
        deps = data.get(key, {})
        if isinstance(deps, dict):
            for name, version in deps.items():
                # Strip ^ ~ >= etc. for the version
                clean_version = re.sub(r"^[\^~>=<]+", "", str(version))
                result[name] = clean_version

    return result


def parse_dockerfile_from(content: str) -> list[tuple[str, str]]:
    """Extract (image, tag) tuples from Dockerfile.

    Handles:
      FROM python:3.12-slim            -> ("python", "3.12-slim")
      FROM python:3.12-slim AS builder -> ("python", "3.12-slim")
      FROM --platform=linux/amd64 node -> ("node", "latest")
      ARG BASE=python:3.12             -> tries to resolve
    """
    results: list[tuple[str, str]] = []
    args: dict[str, str] = {}

    for line in content.splitlines():
        stripped = line.strip()

        # Collect ARG definitions for substitution
        arg_match = re.match(r"^ARG\s+(\w+)=(.+)", stripped, re.IGNORECASE)
        if arg_match:
            args[arg_match.group(1)] = arg_match.group(2).strip()
            continue

        if not re.match(r"^FROM\s", stripped, re.IGNORECASE):
            continue

        parsed = _parse_from_line(stripped, args)
        if parsed is not None:
            results.append(parsed)

    return results


def _parse_from_line(
    line: str, args: dict[str, str]
) -> tuple[str, str] | None:
    """Parse a single FROM line into (image, tag)."""
    # Remove FROM keyword
    rest = re.sub(r"^FROM\s+", "", line, flags=re.IGNORECASE).strip()

    # Remove --platform=... flag
    rest = re.sub(r"--platform=\S+\s*", "", rest).strip()

    # Remove AS alias
    rest = re.split(r"\s+AS\s+", rest, flags=re.IGNORECASE)[0].strip()

    if not rest or rest.lower() == "scratch":
        return None

    # Substitute ARG variables: $VAR or ${VAR}
    for var_name, var_value in args.items():
        rest = rest.replace(f"${{{var_name}}}", var_value)
        rest = rest.replace(f"${var_name}", var_value)

    # Split image:tag
    if ":" in rest:
        image, tag = rest.split(":", 1)
    else:
        image, tag = rest, "latest"

    return image.strip(), tag.strip()
