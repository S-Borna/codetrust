# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
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

# Ruby standard library modules to skip
_RUBY_STDLIB: frozenset[str] = frozenset({
    "abbrev", "base64", "benchmark", "bigdecimal", "cgi", "cmath",
    "coverage", "csv", "date", "dbm", "debug", "delegate", "digest",
    "drb", "english", "erb", "etc", "expect", "fcntl", "fiber",
    "fiddle", "fileutils", "find", "forwardable", "gdbm", "getoptlong",
    "io", "ipaddr", "irb", "json", "logger", "matrix", "minitest",
    "monitor", "mutex_m", "net", "nkf", "objspace", "observer",
    "open-uri", "open3", "openssl", "optparse", "ostruct", "pathname",
    "pp", "prettyprint", "prime", "pstore", "psych", "pty", "racc",
    "rake", "rdoc", "readline", "reline", "resolv", "rinda", "ripper",
    "rss", "ruby2_keywords", "securerandom", "set", "shellwords",
    "singleton", "socket", "stringio", "strscan", "syslog", "tempfile",
    "test", "time", "timeout", "tmpdir", "tracer", "tsort", "un",
    "unicode_normalize", "uri", "weakref", "webrick", "win32ole",
    "yaml", "zlib",
    # Core modules always available
    "kernel", "comparable", "enumerable", "errno", "file", "dir",
    "process", "signal", "thread", "mutex",
})

# PHP built-in extensions/namespaces to skip
_PHP_BUILTINS: frozenset[str] = frozenset({
    "php", "array", "string", "math", "date", "file", "dir",
    "json", "xml", "dom", "simplexml", "xmlreader", "xmlwriter",
    "curl", "ftp", "http", "socket", "stream",
    "pdo", "mysqli", "sqlite3", "pgsql", "oci8",
    "session", "cookie", "filter", "hash", "openssl", "mcrypt",
    "mbstring", "iconv", "intl", "gettext",
    "pcre", "posix", "spl", "reflection", "classobj",
    "gd", "imagick", "exif", "fileinfo", "finfo",
    "zlib", "bz2", "zip", "phar", "rar",
    "ctype", "tokenizer", "readline",
    "shmop", "sem", "sysvsem", "sysvshm", "sysvmsg",
    "pcntl", "proc",
    "apcu", "opcache",
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

# --- Ruby import patterns ---
_RUBY_REQUIRE_RE = re.compile(r"""^\s*require\s+['"]([^'"]+)['"]""")
_RUBY_REQUIRE_RELATIVE_RE = re.compile(r"""^\s*require_relative\s+['"]""")

# --- PHP import patterns ---
_PHP_USE_RE = re.compile(r"^\s*use\s+([\w\\]+)")
_PHP_REQUIRE_RE = re.compile(
    r"""^\s*(?:require|include|require_once|include_once)\s+['"]([^'"]+)['"]"""
)


def extract_python_imports(code: str) -> list[str]:
    """Extract top-level package names from Python code.

    Handles:
      import foo              -> "foo"
      import foo.bar          -> "foo"
      from foo import bar     -> "foo"
      from foo.bar import baz -> "foo"
      from . import something -> skip (relative import)

    Normalizes via PYTHON_IMPORT_TO_PACKAGE mapping.
    Skips stdlib modules, TYPE_CHECKING-only imports, and docstring examples.
    """
    packages: set[str] = set()
    in_type_checking = False
    in_docstring = False
    type_checking_indent = 0

    for line in code.splitlines():
        stripped = line.strip()

        # Track docstrings — skip imports inside them
        if '"""' in stripped or "'''" in stripped:
            quote = '"""' if '"""' in stripped else "'''"
            count = stripped.count(quote)
            if count == 1:
                in_docstring = not in_docstring
            continue
        if in_docstring:
            continue

        if not stripped or stripped.startswith("#"):
            continue

        # Track TYPE_CHECKING blocks — skip imports inside them
        if stripped == "if TYPE_CHECKING:":
            in_type_checking = True
            type_checking_indent = len(line) - len(line.lstrip())
            continue
        if in_type_checking:
            current_indent = len(line) - len(line.lstrip())
            if stripped and current_indent <= type_checking_indent:
                in_type_checking = False
            else:
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
    """Normalize a Python module name, skip stdlib and type stubs."""
    if module in _PYTHON_STDLIB:
        return None
    if module.startswith("_"):
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


# --- Java import extraction ---

# Java standard library prefixes to skip
_JAVA_STDLIB_PREFIXES: tuple[str, ...] = ("java.", "javax.", "sun.", "jdk.")

_JAVA_IMPORT_RE = re.compile(
    r"^\s*import\s+(?:static\s+)?(\w+(?:\.\w+)*)\.\w+\s*;"
)


def extract_java_imports(code: str) -> list[str]:
    """Extract third-party Java package names from import statements.

    Examples (Java syntax)::

        "import com.google.gson.Gson;"       => "com.google.gson"
        "import static org.junit.Assert.*;"   => "org.junit"

    Skips java.*, javax.*, sun.*, jdk.* standard library imports.
    """
    packages: set[str] = set()

    for line in code.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
            continue

        match = _JAVA_IMPORT_RE.match(stripped)
        if match:
            pkg = match.group(1)
            if not any(pkg.startswith(prefix) for prefix in _JAVA_STDLIB_PREFIXES):
                packages.add(pkg)

    return sorted(packages)


# --- C# using extraction ---

_CSHARP_STD_PREFIXES: tuple[str, ...] = ("System", "Microsoft", "Windows")

_CSHARP_USING_RE = re.compile(
    r"^\s*using\s+(?:static\s+)?(\w+(?:\.\w+)*)\s*;"
)


def extract_csharp_imports(code: str) -> list[str]:
    """Extract third-party C# namespace references from using directives.

    Examples (C# syntax)::

        "using Newtonsoft.Json;"              => "Newtonsoft.Json"
        "using static Serilog.Log;"           => "Serilog"

    Skips System.*, Microsoft.*, Windows.* standard namespaces.
    """
    namespaces: set[str] = set()

    for line in code.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue

        match = _CSHARP_USING_RE.match(stripped)
        if match:
            ns = match.group(1)
            top_level = ns.split(".")[0]
            if top_level not in _CSHARP_STD_PREFIXES:
                namespaces.add(ns)

    return sorted(namespaces)


# --- C/C++ include extraction ---

_CPP_STD_HEADERS: frozenset[str] = frozenset({
    "iostream", "string", "vector", "map", "set", "algorithm", "cstdio",
    "cstring", "cstdlib", "cmath", "cassert", "ctime", "climits",
    "cfloat", "fstream", "sstream", "iomanip", "memory", "functional",
    "numeric", "iterator", "utility", "tuple", "array", "deque",
    "list", "queue", "stack", "bitset", "complex", "valarray",
    "regex", "atomic", "thread", "mutex", "condition_variable",
    "chrono", "random", "ratio", "type_traits", "typeinfo",
    "stdexcept", "exception", "new", "limits", "locale",
    "initializer_list", "optional", "variant", "any", "filesystem",
    "span", "ranges", "concepts", "coroutine", "format",
    "stdio.h", "stdlib.h", "string.h", "math.h", "assert.h",
    "ctype.h", "errno.h", "float.h", "limits.h", "locale.h",
    "signal.h", "stdarg.h", "stddef.h", "time.h", "unistd.h",
    "pthread.h",
})

_CPP_INCLUDE_RE = re.compile(r'^\s*#\s*include\s+[<"]([^>"]+)[>"]')


def extract_cpp_includes(code: str) -> list[str]:
    """Extract non-standard C/C++ include headers.

    Examples (C++ syntax)::

        "#include <boost/asio.hpp>"   => "boost/asio.hpp"
        "#include 'mylib.h'"          => "mylib.h"

    Skips C/C++ standard library headers and sys/* headers.
    """
    headers: set[str] = set()

    for line in code.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        match = _CPP_INCLUDE_RE.match(stripped)
        if match:
            header = match.group(1)
            if header not in _CPP_STD_HEADERS and not header.startswith("sys/"):
                headers.add(header)

    return sorted(headers)


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


# --- Ruby import extraction ---


def extract_ruby_imports(code: str) -> list[str]:
    """Extract third-party gem names from Ruby code.

    Handles:
      require 'rails'             -> "rails"
      require "nokogiri"          -> "nokogiri"
      require 'net/http'          -> skip (stdlib)
      require_relative './helper' -> skip (relative)

    Skips: Ruby standard library modules.
    """
    gems: set[str] = set()

    for line in code.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # Skip require_relative (always local)
        if _RUBY_REQUIRE_RELATIVE_RE.match(stripped):
            continue

        match = _RUBY_REQUIRE_RE.match(stripped)
        if match:
            name = match.group(1)
            normalized = _normalize_ruby_require(name)
            if normalized is not None:
                gems.add(normalized)

    return sorted(gems)


def _normalize_ruby_require(name: str) -> str | None:
    """Normalize a Ruby require name, skip stdlib and sub-paths.

    Maps 'some_gem/submodule' -> 'some_gem' (top-level gem name).
    Converts underscores to hyphens for common gems.
    """
    # Get top-level module name (before any /)
    top_level = name.split("/")[0]

    # Skip standard library
    if top_level.lower() in _RUBY_STDLIB:
        return None

    # Skip relative paths
    if top_level.startswith("."):
        return None

    return top_level


# --- PHP import extraction ---


def extract_php_imports(code: str) -> list[str]:
    """Extract third-party package namespaces from PHP code.

    Handles:
      use Illuminate\\Support\\Facades\\DB;   -> "illuminate/support"
      use GuzzleHttp\\Client;                 -> "guzzlehttp/client"
      require 'vendor/autoload.php';          -> skip (autoloader)

    Skips: PHP built-in extensions and vendor autoload.
    """
    packages: set[str] = set()

    for line in code.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
            continue

        match = _PHP_USE_RE.match(stripped)
        if match:
            namespace = match.group(1)
            normalized = _normalize_php_namespace(namespace)
            if normalized is not None:
                packages.add(normalized)

    return sorted(packages)


def _normalize_php_namespace(namespace: str) -> str | None:
    """Normalize a PHP namespace to a Composer package name.

    Converts 'Illuminate\\Support\\Facades\\DB' -> 'illuminate/support'.
    Uses first two segments of the namespace as vendor/package.
    """
    parts = namespace.replace("\\", "/").split("/")

    if len(parts) < 2:
        # Single segment — check if it's a built-in
        if parts[0].lower() in _PHP_BUILTINS:
            return None
        return parts[0].lower()

    vendor = parts[0].lower()
    package = parts[1].lower()

    # Skip built-in extensions
    if vendor in _PHP_BUILTINS:
        return None

    return f"{vendor}/{package}"


# --- Gemfile parsing ---


def parse_gemfile(content: str) -> dict[str, str]:
    """Parse a Ruby Gemfile to {gem_name: version}.

    Handles:
      gem 'rails', '~> 7.0'        -> {"rails": "~> 7.0"}
      gem "nokogiri"                -> {"nokogiri": ""}
      gem 'pg', '>= 1.1'           -> {"pg": ">= 1.1"}

    Skips: source, group blocks (but captures gems inside them), comments.
    """
    result: dict[str, str] = {}
    gem_re = re.compile(
        r"""^\s*gem\s+['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]*)['"]\s*)?"""
    )

    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        match = gem_re.match(stripped)
        if match:
            name = match.group(1)
            version = match.group(2) or ""
            result[name] = version

    return result


# --- composer.json parsing ---


def parse_composer_json(content: str) -> dict[str, str]:
    """Parse a PHP composer.json to {package: version}.

    Handles the "require" and "require-dev" sections:
      {"require": {"laravel/framework": "^10.0"}}

    Skips: php version requirements, ext-* extensions.
    """
    result: dict[str, str] = {}

    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        logger.warning("composer_json_parse_error")
        return result

    for section in ("require", "require-dev"):
        deps = data.get(section, {})
        if not isinstance(deps, dict):
            continue
        for pkg, version in deps.items():
            # Skip PHP version and extension requirements
            if pkg == "php" or pkg.startswith("ext-") or pkg.startswith("lib-"):
                continue
            if isinstance(version, str):
                result[pkg] = version

    return result


# --- pom.xml parsing (Maven) ---


def parse_pom_xml(content: str) -> dict[str, str]:
    """Parse a Maven pom.xml to {groupId:artifactId: version}.

    Uses regex to avoid xml.etree import overhead. Handles:
      <dependency>
        <groupId>com.google.guava</groupId>
        <artifactId>guava</artifactId>
        <version>33.0.0-jre</version>
      </dependency>
    """
    result: dict[str, str] = {}

    dep_re = re.compile(
        r"<dependency>\s*"
        r"<groupId>([^<]+)</groupId>\s*"
        r"<artifactId>([^<]+)</artifactId>\s*"
        r"(?:<version>([^<]*)</version>)?\s*",
        re.DOTALL,
    )

    for match in dep_re.finditer(content):
        group_id = match.group(1).strip()
        artifact_id = match.group(2).strip()
        version = (match.group(3) or "").strip()
        key = f"{group_id}:{artifact_id}"
        result[key] = version

    return result


# --- .csproj parsing (NuGet) ---


def parse_csproj(content: str) -> dict[str, str]:
    """Parse a .NET .csproj file to {package: version}.

    Handles:
      <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
      <PackageReference Include="Serilog" />
    """
    result: dict[str, str] = {}

    pkg_re = re.compile(
        r'<PackageReference\s+Include="([^"]+)"\s*'
        r'(?:Version="([^"]*)")?\s*/?>'
    )

    for match in pkg_re.finditer(content):
        name = match.group(1).strip()
        version = (match.group(2) or "").strip()
        result[name] = version

    return result
