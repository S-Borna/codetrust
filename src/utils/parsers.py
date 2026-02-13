"""Import extraction, requirements parsing, and Dockerfile parsing utilities."""

import json
import re
import sys

import structlog

logger = structlog.get_logger()

# Python standard library modules (3.10+)
_PYTHON_STDLIB: frozenset[str] = frozenset(sys.stdlib_module_names)

# Go standard library packages (common top-level)
_GO_STDLIB: frozenset[str] = frozenset({
    "archive", "bufio", "builtin", "bytes", "compress", "container",
    "context", "crypto", "database", "debug", "embed", "encoding",
    "errors", "expvar", "flag", "fmt", "go", "hash", "html", "image",
    "index", "internal", "io", "log", "maps", "math", "mime", "net",
    "os", "path", "plugin", "reflect", "regexp", "runtime", "slices",
    "sort", "strconv", "strings", "sync", "syscall", "testing", "text",
    "time", "unicode", "unsafe",
})

# Rust standard/core crates to skip
_RUST_STD_CRATES: frozenset[str] = frozenset({
    "std", "core", "alloc", "proc_macro", "test",
    "self", "super", "crate",
})

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

    # Path aliases: @/ ~/ #/ are project-local aliases (Next.js, Vite, etc.)
    if specifier.startswith("@/") or specifier.startswith("~/") or specifier.startswith("#/"):
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


def _substitute_args(text: str, args: dict[str, str]) -> str:
    """Replace $VAR and ${VAR} placeholders with ARG values."""
    result = text
    for var_name, var_value in args.items():
        result = result.replace(f"${{{var_name}}}", var_value)
        result = result.replace(f"${var_name}", var_value)
    return result


def _split_image_tag(text: str) -> tuple[str, str]:
    """Split an image reference into (image, tag)."""
    if ":" in text:
        image, tag = text.split(":", 1)
    else:
        image, tag = text, "latest"
    return image.strip(), tag.strip()


def _parse_from_line(
    line: str, args: dict[str, str]
) -> tuple[str, str] | None:
    """Parse a single FROM line into (image, tag)."""
    rest = re.sub(r"^FROM\s+", "", line, flags=re.IGNORECASE).strip()
    rest = re.sub(r"--platform=\S+\s*", "", rest).strip()
    rest = re.split(r"\s+AS\s+", rest, flags=re.IGNORECASE)[0].strip()

    if not rest or rest.lower() == "scratch":
        return None

    rest = _substitute_args(rest, args)
    return _split_image_tag(rest)


# --- Go import extraction ---

# Single import: import "github.com/gin-gonic/gin"
_GO_SINGLE_IMPORT_RE = re.compile(r'^\s*import\s+"([^"]+)"')

# Import block: import ( ... )
_GO_IMPORT_BLOCK_RE = re.compile(
    r'import\s*\((.*?)\)', re.DOTALL
)

# Individual import inside block: "github.com/gin-gonic/gin"
_GO_BLOCK_ITEM_RE = re.compile(r'"([^"]+)"')


def extract_go_imports(code: str) -> list[str]:
    """Extract third-party module paths from Go code.

    Handles:
      import "github.com/gin-gonic/gin"     -> "github.com/gin-gonic/gin"
      import ( "fmt" ; "github.com/..." )    -> skip "fmt", keep third-party

    Skips: Go standard library packages.
    """
    modules: set[str] = set()

    # Single imports
    for line in code.splitlines():
        match = _GO_SINGLE_IMPORT_RE.match(line)
        if match:
            normalized = _normalize_go_import(match.group(1))
            if normalized is not None:
                modules.add(normalized)

    # Import blocks
    for block_match in _GO_IMPORT_BLOCK_RE.finditer(code):
        block_content = block_match.group(1)
        for item_match in _GO_BLOCK_ITEM_RE.finditer(block_content):
            normalized = _normalize_go_import(item_match.group(1))
            if normalized is not None:
                modules.add(normalized)

    return sorted(modules)


def _normalize_go_import(import_path: str) -> str | None:
    """Normalize a Go import path, skip stdlib."""
    top_level = import_path.split("/")[0]

    # Standard library: no dots in top-level (e.g. "fmt", "net", "os")
    if top_level in _GO_STDLIB:
        return None

    # Third-party modules always have a domain with a dot
    if "." not in top_level:
        return None

    return import_path


# --- Rust import extraction ---

# use serde::Deserialize;
_RUST_USE_RE = re.compile(r'^\s*(?:pub\s+)?use\s+(\w+)')

# extern crate serde;
_RUST_EXTERN_CRATE_RE = re.compile(r'^\s*extern\s+crate\s+(\w+)')


def extract_rust_imports(code: str) -> list[str]:
    """Extract third-party crate names from Rust code.

    Handles:
      use serde::Deserialize;       -> "serde"
      use serde_json::Value;        -> "serde_json"
      extern crate rand;            -> "rand"
      pub use tokio::runtime;       -> "tokio"

    Skips: std, core, alloc, self, super, crate.
    Normalizes underscores to hyphens for crates.io lookup.
    """
    crates: set[str] = set()

    for line in code.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue

        crate_name = _extract_rust_crate(stripped)
        if crate_name is not None:
            crates.add(crate_name)

    return sorted(crates)


def _extract_rust_crate(line: str) -> str | None:
    """Extract crate name from a single Rust line."""
    match = _RUST_USE_RE.match(line)
    if match:
        crate = match.group(1)
        return _normalize_rust_crate(crate)

    match = _RUST_EXTERN_CRATE_RE.match(line)
    if match:
        crate = match.group(1)
        return _normalize_rust_crate(crate)

    return None


def _normalize_rust_crate(crate: str) -> str | None:
    """Normalize a Rust crate name, skip std crates."""
    if crate in _RUST_STD_CRATES:
        return None

    # crates.io uses hyphens, Rust code uses underscores
    return crate.replace("_", "-")


# --- go.mod parsing ---


def parse_go_mod(content: str) -> dict[str, str]:
    """Parse go.mod require blocks to {module: version}.

    Handles:
      require github.com/gin-gonic/gin v1.9.1      -> single require
      require ( ... )                                -> block require

    Skips: replace, exclude, indirect requirements.
    """
    result: dict[str, str] = {}

    # Single-line requires
    for match in re.finditer(
        r'^\s*require\s+([\w./-]+)\s+(v[\w.+-]+)',
        content,
        re.MULTILINE,
    ):
        result[match.group(1)] = match.group(2)

    # Block requires
    for block_match in re.finditer(
        r'require\s*\((.*?)\)', content, re.DOTALL
    ):
        block = block_match.group(1)
        for line in block.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("//"):
                continue
            # Skip indirect dependencies
            if "// indirect" in stripped:
                continue
            parts = stripped.split()
            if len(parts) >= 2:
                result[parts[0]] = parts[1]

    return result


# --- Cargo.toml parsing ---


def parse_cargo_toml(content: str) -> dict[str, str]:
    """Parse Cargo.toml [dependencies] to {crate: version}.

    Handles:
      serde = "1.0"                          -> simple version
      serde = { version = "1.0", ... }       -> table with version
      tokio = { version = "1", features = [...] }

    Only parses [dependencies] and [dev-dependencies] sections.
    """
    result: dict[str, str] = {}
    current_section: str = ""

    dep_sections = {"[dependencies]", "[dev-dependencies]", "[build-dependencies]"}

    for line in content.splitlines():
        stripped = line.strip()

        # Track which section we're in
        if stripped.startswith("["):
            current_section = stripped.split("]")[0] + "]"
            # Also handle [dependencies.serde] style
            continue

        if current_section not in dep_sections and not current_section.startswith(
            "[dependencies."
        ):
            continue

        if not stripped or stripped.startswith("#"):
            continue

        parsed = _parse_cargo_dep_line(stripped, current_section)
        if parsed is not None:
            name, version = parsed
            result[name] = version

    return result


def _parse_cargo_dep_line(
    line: str, section: str
) -> tuple[str, str] | None:
    """Parse a single Cargo.toml dependency line."""
    # Handle dotted section: [dependencies.serde]
    if section.startswith("[dependencies."):
        crate_name = section.split(".", 1)[1].rstrip("]")
        version_match = re.match(r'version\s*=\s*"([^"]+)"', line)
        if version_match:
            return crate_name, version_match.group(1)
        return None

    if "=" not in line:
        return None

    name, _, value = line.partition("=")
    name = name.strip()
    value = value.strip()

    if not name or not value:
        return None

    # Simple: serde = "1.0"
    if value.startswith('"'):
        version = value.strip('"')
        return name, version

    # Table: serde = { version = "1.0", ... }
    version_match = re.search(r'version\s*=\s*"([^"]+)"', value)
    if version_match:
        return name, version_match.group(1)

    return name, ""
