"""Import verification: extract imports from source files and verify against registries.

Bridges static analysis with live registry checks. Designed for CLI and CI use
where imports should be verified automatically during scan.
"""

import asyncio
import os
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

import httpx
import structlog

from src.models.enums import Language, VerifyStatus
from src.models.responses import PackageResult
from src.services.cache import CacheService
from src.services.registry import RegistryService
from src.utils.parsers import (
    PYTHON_IMPORT_TO_PACKAGE,
    extract_js_imports,
    extract_python_imports,
)

logger = structlog.get_logger()

# Reverse map: package name -> import name(s)
_PACKAGE_TO_IMPORT: dict[str, str] = {v: k for k, v in PYTHON_IMPORT_TO_PACKAGE.items()}

# Import line patterns
_PY_IMPORT_RE = re.compile(r"^\s*import\s+([\w.]+)")
_PY_FROM_IMPORT_RE = re.compile(r"^\s*from\s+([\w.]+)\s+import\s+")

# Registry verification timeout (seconds)
_VERIFY_TIMEOUT: float = 15.0


def _find_import_line(code: str, package: str) -> int:
    """Find the line where a package is first imported.

    Handles PYTHON_IMPORT_TO_PACKAGE reverse mapping, e.g.
    package='opencv-python' will find 'import cv2'.
    """
    # Check if this package is imported under a different name
    import_names = {package}
    reverse = _PACKAGE_TO_IMPORT.get(package)
    if reverse:
        import_names.add(reverse)

    for line_num, line in enumerate(code.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        for name in import_names:
            if re.match(rf"^\s*import\s+{re.escape(name)}\b", line):
                return line_num
            if re.match(rf"^\s*from\s+{re.escape(name)}\b", line):
                return line_num
    return 1


def _collect_python_imports(
    files: list[tuple[str, str]],
) -> dict[str, list[tuple[str, int]]]:
    """Extract Python imports from files, grouped by package name.

    Args:
        files: List of (filepath, code) tuples.

    Returns:
        Dict mapping package_name -> [(filepath, line_number), ...]
    """
    package_map: dict[str, list[tuple[str, int]]] = {}

    for filepath, code in files:
        imports = extract_python_imports(code)
        for pkg in imports:
            line = _find_import_line(code, pkg)
            package_map.setdefault(pkg, []).append((filepath, line))

    return package_map


def _collect_js_imports(
    files: list[tuple[str, str]],
) -> dict[str, list[tuple[str, int]]]:
    """Extract JS/TS imports from files, grouped by package name.

    Args:
        files: List of (filepath, code) tuples.

    Returns:
        Dict mapping package_name -> [(filepath, line_number), ...]
    """
    package_map: dict[str, list[tuple[str, int]]] = {}

    for filepath, code in files:
        imports = extract_js_imports(code)
        for pkg in imports:
            # Find the line where this import appears
            line = 1
            for line_num, src_line in enumerate(code.splitlines(), 1):
                if pkg in src_line:
                    line = line_num
                    break
            package_map.setdefault(pkg, []).append((filepath, line))

    return package_map


async def _verify_packages(
    language: Language,
    packages: list[str],
) -> list[PackageResult]:
    """Verify packages against registries without Redis cache.

    Creates a lightweight RegistryService with no-op cache for CLI use.
    """
    # CacheService degrades gracefully without Redis connection
    cache = CacheService("redis://localhost:6379")

    async with httpx.AsyncClient(timeout=_VERIFY_TIMEOUT) as client:
        registry = RegistryService(cache, client)
        return await registry.verify_packages(language, packages)


def _results_to_findings(
    results: list[PackageResult],
    package_map: dict[str, list[tuple[str, int]]],
    language: str,
) -> list[dict[str, str | int]]:
    """Convert PackageResult objects to CLI-style finding dicts."""
    findings: list[dict[str, str | int]] = []

    for result in results:
        if result.status == VerifyStatus.NOT_FOUND:
            suggestion_text = ""
            if result.suggestion:
                suggestion_text = f" Did you mean '{result.suggestion}'?"
            for filepath, line in package_map.get(result.package, []):
                findings.append({
                    "rule_id": "import_not_found",
                    "severity": "BLOCK",
                    "message": (
                        f"Package '{result.package}' not found on "
                        f"{result.registry.value} — possible AI hallucination."
                        f"{suggestion_text}"
                    ),
                    "file": filepath,
                    "line": line,
                })

        elif result.status == VerifyStatus.DEPRECATED:
            for filepath, line in package_map.get(result.package, []):
                findings.append({
                    "rule_id": "import_deprecated",
                    "severity": "WARN",
                    "message": (
                        f"Package '{result.package}' is deprecated on "
                        f"{result.registry.value}."
                    ),
                    "file": filepath,
                    "line": line,
                })

        elif result.status == VerifyStatus.VERSION_MISMATCH:
            for filepath, line in package_map.get(result.package, []):
                findings.append({
                    "rule_id": "import_version_mismatch",
                    "severity": "WARN",
                    "message": (
                        f"Package '{result.package}': {result.message}"
                    ),
                    "file": filepath,
                    "line": line,
                })

    return findings


async def async_verify_file_imports(
    py_files: list[tuple[str, str]] | None = None,
    js_files: list[tuple[str, str]] | None = None,
) -> list[dict[str, str | int]]:
    """Verify imports from source files against live registries.

    Args:
        py_files: List of (filepath, code) tuples for Python files.
        js_files: List of (filepath, code) tuples for JS/TS files.

    Returns:
        List of finding dicts for unverified imports.
    """
    all_findings: list[dict[str, str | int]] = []

    # Python imports
    if py_files:
        python_map = _collect_python_imports(py_files)
        if python_map:
            try:
                results = await _verify_packages(
                    Language.PYTHON, list(python_map.keys()),
                )
                all_findings.extend(
                    _results_to_findings(results, python_map, "Python"),
                )
            except Exception as exc:
                logger.warning("import_verify_python_error", error=str(exc))

    # JS/TS imports
    if js_files:
        js_map = _collect_js_imports(js_files)
        if js_map:
            try:
                results = await _verify_packages(
                    Language.JAVASCRIPT, list(js_map.keys()),
                )
                all_findings.extend(
                    _results_to_findings(results, js_map, "JavaScript"),
                )
            except Exception as exc:
                logger.warning("import_verify_js_error", error=str(exc))

    return all_findings


def verify_file_imports_sync(
    py_files: list[tuple[str, str]] | None = None,
    js_files: list[tuple[str, str]] | None = None,
) -> list[dict[str, str | int]]:
    """Synchronous wrapper for import verification.

    Safe to call from CLI context. Uses asyncio.run() internally.
    """
    try:
        return asyncio.run(async_verify_file_imports(py_files, js_files))
    except Exception as exc:
        logger.warning("import_verify_error", error=str(exc))
        return []


def collect_source_files(
    targets: list[str],
) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """Walk targets and collect Python and JS/TS source files.

    Skips test files, binary files, and excluded directories.

    Returns:
        (py_files, js_files) — each a list of (filepath, code) tuples.
    """
    skip_dirs = {
        ".git", ".venv", "venv", "node_modules", "__pycache__",
        "dist", "build", ".next", ".open-next", ".turbo",
        ".nuxt", ".output", ".svelte-kit", ".vercel", ".wrangler",
        "coverage", "out", ".cache", "test", "__tests__",
    }
    py_exts = {".py"}
    js_exts = {".js", ".ts", ".jsx", ".tsx"}

    py_files: list[tuple[str, str]] = []
    js_files: list[tuple[str, str]] = []

    from pathlib import Path

    for target in targets:
        target_path = Path(target)

        if target_path.is_file():
            _add_source_file(target_path, py_files, js_files, py_exts, js_exts)
        elif target_path.is_dir():
            for root, dirs, files in os.walk(target_path):
                dirs[:] = [d for d in dirs if d not in skip_dirs]
                for fname in files:
                    fpath = Path(os.path.join(root, fname))
                    _add_source_file(fpath, py_files, js_files, py_exts, js_exts)

    return py_files, js_files


def _add_source_file(
    fpath: "Path",
    py_files: list[tuple[str, str]],
    js_files: list[tuple[str, str]],
    py_exts: set[str],
    js_exts: set[str],
) -> None:
    """Classify and read a single source file."""
    ext = fpath.suffix.lower()
    basename = fpath.name.lower()

    # Skip test files
    if (
        basename.startswith("test_")
        or basename.startswith("conftest")
        or ".test." in basename
        or ".spec." in basename
    ):
        return

    if ext not in py_exts and ext not in js_exts:
        return

    try:
        code = fpath.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return

    if ext in py_exts:
        py_files.append((str(fpath), code))
    elif ext in js_exts:
        js_files.append((str(fpath), code))
