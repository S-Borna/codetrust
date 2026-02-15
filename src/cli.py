"""
CodeTrust CLI — install, scan, and enforce from any project.

Usage:
    codetrust init          Install enforcement layers into current project
    codetrust scan <file>   Scan a file for anti-patterns
    codetrust scan .        Scan all source files in current directory
    codetrust status        Check if CodeTrust is installed in current project
    codetrust doctor        Verify all enforcement layers are working
"""

from __future__ import annotations

import argparse
import importlib.resources
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore[no-redef]

# --- Rules imported from backend (single source of truth) ---
# This eliminates rule drift between CLI, backend, and extension.
# All rule definitions live in src/rules/anti_patterns.py.
from src.rules.anti_patterns import (
    ANTI_PATTERNS,
    DEVOPS_EXTENSIONS,
    DEVOPS_FILENAMES,
    SQL_EXTENSIONS,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from src.gateway.policies import GovernanceConfig


logger = structlog.get_logger()


def _build_cli_rules() -> dict[str, list[tuple[str, str, str]]]:
    """Build CLI rule lists from the authoritative backend ANTI_PATTERNS.

    Returns categorized (id, pattern, message) tuples grouped by severity
    and file_types for the CLI's file-type routing logic.
    Rules with special_handler are skipped here — they are implemented
    directly in scan_file() as multi-line / file-level checks.
    """
    cats: dict[str, list[tuple[str, str, str]]] = {
        "generic_block": [], "generic_warn": [], "generic_info": [],
        "sql_block": [], "sql_warn": [], "sql_info": [],
        "docker_block": [], "docker_warn": [],
        "ci_warn": [],
        "devops_block": [], "devops_warn": [], "devops_info": [],
        "react_block": [], "react_warn": [],
        "k8s_block": [], "k8s_warn": [], "k8s_info": [],
    }

    for rule in ANTI_PATTERNS:
        if rule.get("special_handler"):
            continue  # CLI does regex-only; skip rules needing Python handlers

        severity = str(rule["severity"])  # Severity enum -> str
        file_types = rule.get("file_types")
        entry = (rule["id"], rule["pattern"], rule["message"])

        if file_types:
            ft_set = set(file_types)
            # SQL rules
            if ft_set & SQL_EXTENSIONS:
                cats[f"sql_{severity.lower()}"].append(entry)
            # React/JSX rules
            elif rule["id"].startswith("react_"):
                cats.get(f"react_{severity.lower()}", cats["react_warn"]).append(entry)
            # Kubernetes rules
            elif rule["id"].startswith("k8s_"):
                cats.get(f"k8s_{severity.lower()}", cats["k8s_warn"]).append(entry)
            # Dockerfile rules
            elif ft_set & {".dockerfile"}:
                cats.get(f"docker_{severity.lower()}", cats["docker_warn"]).append(entry)
            # CI rules (yml/yaml files prefixed ci_)
            elif rule["id"].startswith("ci_"):
                cats.get(f"ci_{severity.lower()}", cats["ci_warn"]).append(entry)
            # DevOps/infra rules (yml, yaml, toml, json, tf, hcl)
            else:
                cats.get(f"devops_{severity.lower()}", cats["devops_warn"]).append(entry)
        else:
            # Generic rules (no file_types restriction)
            cats.get(f"generic_{severity.lower()}", cats["generic_warn"]).append(entry)

    return cats


_CLI_RULES = _build_cli_rules()

# Named lists used by scan_file() for file-type routing
BLOCK_RULES = _CLI_RULES["generic_block"]
WARN_RULES = _CLI_RULES["generic_warn"]
INFO_RULES = _CLI_RULES["generic_info"]
SQL_BLOCK_RULES = _CLI_RULES["sql_block"]
SQL_WARN_RULES = _CLI_RULES["sql_warn"]
SQL_INFO_RULES = _CLI_RULES["sql_info"]
DOCKER_BLOCK_RULES = _CLI_RULES["docker_block"]
DOCKER_WARN_RULES = _CLI_RULES["docker_warn"]
CI_WARN_RULES = _CLI_RULES["ci_warn"]
DEVOPS_BLOCK_RULES = _CLI_RULES["devops_block"]
DEVOPS_WARN_RULES = _CLI_RULES["devops_warn"]
DEVOPS_INFO_RULES = _CLI_RULES["devops_info"]
REACT_BLOCK_RULES = _CLI_RULES["react_block"]
REACT_WARN_RULES = _CLI_RULES["react_warn"]
K8S_BLOCK_RULES = _CLI_RULES["k8s_block"]
K8S_WARN_RULES = _CLI_RULES["k8s_warn"]
K8S_INFO_RULES = _CLI_RULES.get("k8s_info", [])

SOURCE_EXTS = {".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java", ".sh",
               ".sql", ".yml", ".yaml", ".toml"}
DEVOPS_EXTS = DEVOPS_EXTENSIONS
SQL_EXTS = SQL_EXTENSIONS
DOCKER_EXTS = set()  # Dockerfiles matched by name, not extension
DOCKER_NAMES = {"dockerfile"}
CI_DIRS = {".github"}  # CI files live under .github/workflows/
DEVOPS_NAMES = DEVOPS_FILENAMES

# --- Colors ---

RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
BLUE = "\033[0;34m"
BOLD = "\033[1m"
NC = "\033[0m"


def color(text: str, c: str) -> str:
    """Wrap text in ANSI color if stdout is a terminal."""
    if sys.stdout.isatty():
        return f"{c}{text}{NC}"
    return text


_SEVERITY_ORDER: dict[str, int] = {"BLOCK": 0, "WARN": 1, "INFO": 2}

PR_RISK_MAX_SCORE = 100
PR_RISK_HIGH_THRESHOLD = 60
PR_RISK_MED_THRESHOLD = 25

PR_RISK_RULES: list[tuple[str, int, tuple[str, ...]]] = [
    ("Auth / identity", 25, ("auth", "oidc", "sso", "jwt", "oauth")),
    ("Tenancy / multi-tenant", 25, ("tenant", "tenancy", "org", "organization")),
    ("Billing / payments", 20, ("billing", "stripe", "invoice", "subscription")),
    ("Data model / migrations", 20, ("alembic/versions/", "migrations/", "schema", "models/")),
    ("API surface", 15, ("src/api.py", "openapi", "routes", "controllers")),
    ("Gateway / enforcement", 15, ("gateway/", "policies", "governance")),
    ("Secrets / config", 15, (".env", "config", "settings", "secrets")),
    ("CI/CD / deployment", 10, (".github/workflows/", "dockerfile", "docker-compose", "helm/", "deploy/")),
    ("Security", 10, ("security", "crypto", "encryption", "rbac", "acl")),
    ("Compliance", 10, ("gdpr", "compliance", "retention", "pii", "privacy")),
]

TREND_FILE_REL = ".codetrust/trend.jsonl"

_ENDPOINT_RE = re.compile(r"['\"](/(?:v\d+|api)[^'\"\s]{1,120})['\"]")


def _extract_touched_endpoints(diff_text: str) -> list[str]:
    """Extract API endpoint-looking strings from added lines in a unified diff."""
    endpoints: list[str] = []
    seen: set[str] = set()
    for ln in diff_text.splitlines():
        if not ln.startswith("+") or ln.startswith("+++"):
            continue
        for m in _ENDPOINT_RE.finditer(ln):
            ep = m.group(1)
            if not ep or len(ep) < 3:
                continue
            if ep in seen:
                continue
            seen.add(ep)
            endpoints.append(ep)
            if len(endpoints) >= 20:
                return endpoints
    return endpoints


def _normalize_path_for_git(path: str, *, cwd: Path) -> str:
    """Normalize a filepath for git operations and stable output.

    - Converts absolute paths under cwd to relative paths.
    - Strips leading './'.
    - Uses POSIX separators for git compatibility.
    """
    try:
        p = Path(path)
        if p.is_absolute():
            try:
                rel = p.relative_to(cwd.resolve())
                path = str(rel)
            except Exception:
                path = str(p)
        norm = Path(path).as_posix()
        if norm.startswith("./"):
            norm = norm[2:]
        return norm
    except Exception:
        return path


def _dedupe_findings(findings: list[dict[str, str | int]]) -> list[dict[str, str | int]]:
    """Remove duplicate findings while preserving first-seen order."""
    seen: set[tuple[str, int, str, str, str]] = set()
    out: list[dict[str, str | int]] = []
    for f in findings:
        file = str(f.get("file", ""))
        line = int(f.get("line", 0) or 0)
        rule_id = str(f.get("rule_id", ""))
        severity = str(f.get("severity", "INFO"))
        message = str(f.get("message", ""))
        key = (file, line, rule_id, severity, message)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def _sort_findings(findings: list[dict[str, str | int]]) -> list[dict[str, str | int]]:
    """Sort findings deterministically for stable diffs and CI output."""
    def _k(f: dict[str, str | int]) -> tuple[int, str, int, str, str]:
        sev = str(f.get("severity", "INFO"))
        sev_rank = _SEVERITY_ORDER.get(sev, 9)
        file = str(f.get("file", ""))
        line = int(f.get("line", 0) or 0)
        rule_id = str(f.get("rule_id", ""))
        msg = str(f.get("message", ""))
        return (sev_rank, file, line, rule_id, msg)

    return sorted(findings, key=_k)


_HUNK_RE = re.compile(r"^@@\s+-\d+(?:,\d+)?\s+\+(\d+)(?:,(\d+))?\s+@@", re.MULTILINE)


def _parse_unified0_changed_ranges(diff_text: str) -> list[tuple[int, int]]:
    """Parse `git diff --unified=0` and return changed line ranges on the + side."""
    ranges: list[tuple[int, int]] = []
    for m in _HUNK_RE.finditer(diff_text):
        start = int(m.group(1))
        length_str = m.group(2)
        length = int(length_str) if length_str is not None else 1
        if length <= 0:
            continue
        ranges.append((start, start + length - 1))
    return ranges


def _get_git_changed_files(*, cwd: Path) -> tuple[list[str], bool]:
    """Return (changed_files, staged) using git diff.

    Prefers staged changes when present; otherwise uses working-tree diff vs HEAD.
    """
    try:
        staged = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMRT"],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
        )
        staged_files = [ln.strip() for ln in staged.stdout.splitlines() if ln.strip()]
        if staged_files:
            return staged_files, True

        wt = subprocess.run(
            ["git", "diff", "HEAD", "--name-only", "--diff-filter=ACMRT"],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
        )
        wt_files = [ln.strip() for ln in wt.stdout.splitlines() if ln.strip()]
        return wt_files, False
    except (OSError, ValueError):
        return ([], False)


def _get_git_numstat(*, cwd: Path, staged: bool) -> dict[str, tuple[int, int]]:
    """Return git numstat mapping: file -> (added_lines, deleted_lines)."""
    base_cmd = ["git", "diff", "--numstat"]
    if staged:
        base_cmd.append("--cached")
    else:
        base_cmd.append("HEAD")
    try:
        res = subprocess.run(
            base_cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
        )
        out: dict[str, tuple[int, int]] = {}
        for ln in res.stdout.splitlines():
            parts = ln.split("\t")
            if len(parts) < 3:
                continue
            a, d, p = parts[0], parts[1], parts[2]
            try:
                added = int(a) if a.isdigit() else 0
                deleted = int(d) if d.isdigit() else 0
            except ValueError:
                added, deleted = 0, 0
            out[p.strip()] = (added, deleted)
        return out
    except (OSError, ValueError):
        return {}


def _get_git_file_diff(*, cwd: Path, staged: bool, path: str) -> str:
    """Get unified=0 diff for a single file (best-effort)."""
    rel = _normalize_path_for_git(path, cwd=cwd)
    base_cmd = ["git", "diff", "--unified=0", "--no-color"]
    if staged:
        base_cmd.append("--cached")
    else:
        base_cmd.append("HEAD")
    base_cmd.extend(["--", rel])
    try:
        res = subprocess.run(
            base_cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
        )
        return res.stdout
    except (OSError, ValueError):
        return ""


def _compute_pr_risk(
    *,
    project_dir: Path,
    changed_files: list[str],
    staged: bool,
) -> dict[str, object]:
    """Compute a PR risk score from changed files, diff stats, and diff content."""
    norm_files = [_normalize_path_for_git(f, cwd=project_dir) for f in changed_files]

    signals: list[dict[str, object]] = []
    total = 0
    touched_endpoints: list[str] = []
    lowered = [f.lower() for f in norm_files]

    for label, points, needles in PR_RISK_RULES:
        hit_files: list[str] = []
        for f in lowered:
            if any(n in f for n in needles):
                hit_files.append(f)
        if hit_files:
            total += points
            signals.append({
                "label": label,
                "points": points,
                "matched": sorted(set(hit_files))[:10],
            })

    # Stats signals (file count + line changes)
    file_count = len(set(norm_files))
    if file_count >= 50:
        total += 15
        signals.append({"label": "Many files changed", "points": 15, "matched": [str(file_count)]})
    elif file_count >= 20:
        total += 10
        signals.append({"label": "Many files changed", "points": 10, "matched": [str(file_count)]})
    elif file_count >= 10:
        total += 5
        signals.append({"label": "Many files changed", "points": 5, "matched": [str(file_count)]})

    numstat = _get_git_numstat(cwd=project_dir, staged=staged)
    total_changed_lines = 0
    for f in norm_files:
        a, d = numstat.get(f, (0, 0))
        total_changed_lines += int(a) + int(d)

    if total_changed_lines >= 800:
        total += 20
        signals.append({"label": "Large diff", "points": 20, "matched": [str(total_changed_lines)]})
    elif total_changed_lines >= 300:
        total += 10
        signals.append({"label": "Large diff", "points": 10, "matched": [str(total_changed_lines)]})
    elif total_changed_lines >= 100:
        total += 5
        signals.append({"label": "Large diff", "points": 5, "matched": [str(total_changed_lines)]})

    # Diff-content signals (keyword-based, best-effort)
    diff_rules: list[tuple[str, int, tuple[str, ...]]] = [
        ("Authorization changes", 20, ("authorization", "x-api-key", "bearer")),
        ("Tenant boundary changes", 15, ("tenant", "org_id", "organization_id")),
        ("Schema / migration changes", 20, ("alter table", "create table", "drop table", "alembic")),
        ("Sensitive data handling", 15, ("pii", "ssn", "credit card", "gdpr", "retention")),
        ("CI/CD changes", 10, (".github/workflows", "timeout-minutes", "uses:")),
    ]

    for rel in norm_files:
        diff_text = _get_git_file_diff(cwd=project_dir, staged=staged, path=rel)
        if not diff_text:
            continue
        touched_endpoints.extend(_extract_touched_endpoints(diff_text))
        low = diff_text.lower()
        for label, points, needles in diff_rules:
            if any(n in low for n in needles):
                total += points
                signals.append({"label": label, "points": points, "matched": [rel]})

    if touched_endpoints:
        unique_eps: list[str] = []
        seen_ep: set[str] = set()
        for ep in touched_endpoints:
            if ep in seen_ep:
                continue
            seen_ep.add(ep)
            unique_eps.append(ep)
        touched_endpoints = unique_eps[:25]
        total += 20
        signals.append({
            "label": "API endpoints touched",
            "points": 20,
            "matched": touched_endpoints[:10],
        })

    score = min(PR_RISK_MAX_SCORE, total)
    if score >= PR_RISK_HIGH_THRESHOLD:
        level = "HIGH"
    elif score >= PR_RISK_MED_THRESHOLD:
        level = "MED"
    else:
        level = "LOW"

    signals_sorted = sorted(signals, key=lambda s: int(s.get("points", 0) or 0), reverse=True)
    return {
        "score": score,
        "level": level,
        "signals": signals_sorted,
        "changed_files": sorted(set(norm_files)),
        "changed_files_count": file_count,
        "changed_lines": total_changed_lines,
        "touched_endpoints": touched_endpoints,
        "touched_endpoints_count": len(touched_endpoints),
    }


def _is_line_in_ranges(line: int, ranges: Iterable[tuple[int, int]]) -> bool:
    return any(start <= line <= end for start, end in ranges)


def _get_git_changed_ranges(
    *,
    cwd: Path,
    files: list[str],
) -> dict[str, list[tuple[int, int]]]:
    """Get changed line ranges for files using git diff.

    Prefer staged changes when present; otherwise use working-tree diff vs HEAD.
    Returns a map from normalized relative file path -> list of (start,end).
    """
    try:
        staged = subprocess.run(
            ["git", "diff", "--cached", "--name-only"],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
        )
        has_staged = bool(staged.stdout.strip())
    except (OSError, ValueError) as exc:
        logger.debug("git_diff_name_only_failed", error=str(exc))
        return {}

    result: dict[str, list[tuple[int, int]]] = {}
    for fp in files:
        rel = _normalize_path_for_git(fp, cwd=cwd)
        if not rel:
            continue
        base_cmd = ["git", "diff", "--unified=0"]
        if has_staged:
            base_cmd.append("--cached")
        else:
            base_cmd.append("HEAD")
        base_cmd.extend(["--", rel])

        try:
            diff = subprocess.run(
                base_cmd,
                cwd=cwd,
                capture_output=True,
                text=True,
                check=False,
            )
            ranges = _parse_unified0_changed_ranges(diff.stdout)
            if ranges:
                result[rel] = ranges
        except (OSError, ValueError) as exc:
            logger.debug("git_diff_unified0_failed", path=rel, error=str(exc))
            continue

    return result


def _filter_findings_to_changed_lines(
    *,
    cwd: Path,
    findings: list[dict[str, str | int]],
) -> list[dict[str, str | int]]:
    """Keep only findings that fall on changed lines for their file."""
    files = [str(f.get("file", "")) for f in findings if f.get("file")]
    if not files:
        return []
    changed = _get_git_changed_ranges(cwd=cwd, files=files)
    if not changed:
        return []

    kept: list[dict[str, str | int]] = []
    for f in findings:
        raw_file = str(f.get("file", ""))
        rel = _normalize_path_for_git(raw_file, cwd=cwd)
        ranges = changed.get(rel)
        if not ranges:
            continue
        line = int(f.get("line", 0) or 0)
        if line <= 0:
            continue
        if _is_line_in_ranges(line, ranges):
            # Normalize file path for stable output
            f = {**f, "file": rel}
            kept.append(f)
    return kept


# --- Project config loader ---


def _load_project_config() -> dict:
    """Load CodeTrust config from pyproject.toml [tool.codetrust] or .codetrust.toml.

    Search order:
      1. .codetrust.toml in current directory
      2. pyproject.toml [tool.codetrust] section
    Returns empty dict if no config found.
    """
    cwd = Path.cwd()

    # 1. .codetrust.toml
    ct_toml = cwd / ".codetrust.toml"
    if ct_toml.is_file():
        with open(ct_toml, "rb") as f:
            data = tomllib.load(f)
        if isinstance(data, dict) and isinstance(data.get("codetrust"), dict):
            return data.get("codetrust", {})
        return data

    # 2. pyproject.toml [tool.codetrust]
    pyproject = cwd / "pyproject.toml"
    if pyproject.is_file():
        with open(pyproject, "rb") as f:
            data = tomllib.load(f)
        return data.get("tool", {}).get("codetrust", {})

    return {}


def _read_text_if_exists(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def _read_json_if_exists(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _autofix_print_debug_python(code: str) -> tuple[str, bool]:
    """Deterministic autofix: replace leading print(...) with logging.info(...).

    Also ensures `import logging` exists.
    """
    lines = code.splitlines(keepends=True)

    changed = False
    out_lines: list[str] = []
    print_re = re.compile(r"^(\s*)print\s*\(")
    for line in lines:
        m = print_re.match(line)
        if m:
            indent = m.group(1)
            out_lines.append(indent + "logging.info(" + line[m.end():])
            changed = True
        else:
            out_lines.append(line)

    new_code = "".join(out_lines)

    if "import logging" in new_code:
        return new_code, changed

    if not changed:
        return new_code, False

    # Insert import logging after shebang/encoding/docstring when possible.
    insert_at = 0
    if out_lines and out_lines[0].startswith("#!"):
        insert_at = 1
    if len(out_lines) > insert_at and "coding" in out_lines[insert_at]:
        insert_at += 1

    # Handle module docstring.
    if len(out_lines) > insert_at and out_lines[insert_at].lstrip().startswith(('"""', "'''")):
        delim = '"""' if '"""' in out_lines[insert_at] else "'''"
        i = insert_at
        # If docstring ends on same line, move one line down; else scan until closing.
        if out_lines[i].count(delim) >= 2:
            insert_at = i + 1
        else:
            i += 1
            while i < len(out_lines):
                if delim in out_lines[i]:
                    insert_at = i + 1
                    break
                i += 1

    out_lines.insert(insert_at, "import logging\n")
    return "".join(out_lines), True


def cmd_fix(args: argparse.Namespace) -> int:
    """Apply safe deterministic autofix recipes to files."""
    targets = getattr(args, "targets", []) or ["."]
    apply = bool(getattr(args, "apply", False))

    project_dir = Path.cwd()

    def _is_excluded_for_fix(path: Path) -> bool:
        try:
            rel = str(path.resolve().relative_to(project_dir.resolve())).replace("\\", "/")
        except Exception:
            rel = str(path).replace("\\", "/")

        parts = {p for p in Path(rel).parts if p}
        if parts & {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build"}:
            return True

        exclude_paths = PROJECT_CONFIG.get("exclude_paths", [])
        if isinstance(exclude_paths, list):
            for pat in exclude_paths:
                if isinstance(pat, str) and pat and pat in rel:
                    return True
        return False

    files: list[Path] = []
    for t in targets:
        p = Path(t)
        if p.is_file():
            files.append(p)
        elif p.is_dir():
            for fp in sorted(p.rglob("*.py")):
                if _is_excluded_for_fix(fp):
                    continue
                files.append(fp)

    if not files:
        print("No files to fix.")
        return 0

    changed_files = 0
    changed_lines = 0
    for fp in files:
        try:
            code = fp.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            logger.debug("fix_read_failed", path=str(fp), error=str(exc))
            continue
        new_code, changed = _autofix_print_debug_python(code)
        if not changed:
            continue

        changed_files += 1
        changed_lines += sum(
            1
            for a, b in zip(code.splitlines(), new_code.splitlines(), strict=False)
            if a != b
        )

        if apply:
            fp.write_text(new_code, encoding="utf-8")

    if apply:
        print(f"Applied fixes to {changed_files} file(s).")
    else:
        print(f"Fix preview: {changed_files} file(s) would change. Re-run with --apply to write.")
    return 0


def _detect_verify_gates(project_dir: Path) -> list[str]:
    """Best-effort detection of common repo verification gates.

    Used only for human-facing hints (must never affect machine outputs).
    """
    gates: list[str] = []

    package_json = project_dir / "package.json"
    if package_json.is_file():
        data = _read_json_if_exists(package_json)
        scripts = data.get("scripts") if isinstance(data, dict) else None
        if isinstance(scripts, dict):
            if "verify" in scripts:
                gates.append("npm run verify")
            else:
                for k in ("lint", "test", "typecheck", "build"):
                    if k in scripts:
                        gates.append(f"npm run {k}")

    pyproject = project_dir / "pyproject.toml"
    if pyproject.is_file():
        try:
            raw = pyproject.read_text(encoding="utf-8", errors="ignore")
            data = tomllib.loads(raw)
            tool = data.get("tool", {}) if isinstance(data, dict) else {}
            if isinstance(tool, dict):
                if "ruff" in tool:
                    gates.append("ruff check")
                if "pytest" in tool:
                    gates.append("pytest")
        except (OSError, ValueError, TypeError):
            # Best-effort detection only — ignore unreadable/invalid TOML.
            data = {}

    # Loose detection for common config files
    if ((project_dir / "pytest.ini").is_file() or (project_dir / "tox.ini").is_file()) and "pytest" not in gates:
        gates.append("pytest")
    if ((project_dir / ".ruff.toml").is_file() or (project_dir / "ruff.toml").is_file()) and "ruff check" not in gates:
        gates.append("ruff check")
    if (project_dir / "tsconfig.json").is_file():
        gates.append("tsc")

    # Deduplicate while preserving order
    seen: set[str] = set()
    out: list[str] = []
    for g in gates:
        if g in seen:
            continue
        seen.add(g)
        out.append(g)
    return out


def _has_eslint(project_dir: Path) -> bool:
    package_json = project_dir / "package.json"
    if package_json.is_file():
        data = _read_json_if_exists(package_json)
        if isinstance(data, dict):
            deps = data.get("dependencies", {})
            dev = data.get("devDependencies", {})
            if isinstance(deps, dict) and "eslint" in deps:
                return True
            if isinstance(dev, dict) and "eslint" in dev:
                return True
            if "eslintConfig" in data:
                return True
    for name in (
        ".eslintrc",
        ".eslintrc.json",
        ".eslintrc.js",
        ".eslintrc.cjs",
        ".eslintrc.yaml",
        ".eslintrc.yml",
    ):
        if (project_dir / name).is_file():
            return True
    return False


def _has_ruff(project_dir: Path) -> bool:
    pyproject = project_dir / "pyproject.toml"
    if pyproject.is_file():
        raw = _read_text_if_exists(pyproject)
        if "[tool.ruff" in raw:
            return True
    return (project_dir / ".ruff.toml").is_file() or (project_dir / "ruff.toml").is_file()


def _suppress_lint_covered_findings(
    *,
    project_dir: Path,
    findings: list[dict[str, str | int]],
) -> tuple[list[dict[str, str | int]], int]:
    """Optionally suppress findings that are commonly covered by linters.

    Returns: (kept_findings, suppressed_count)
    """
    has_eslint = _has_eslint(project_dir)
    has_ruff = _has_ruff(project_dir)
    if not has_eslint and not has_ruff:
        return findings, 0

    suppressed = 0
    kept: list[dict[str, str | int]] = []
    for f in findings:
        file = str(f.get("file", ""))
        rule_id = str(f.get("rule_id", ""))
        ext = Path(file).suffix.lower()

        if has_eslint and ext in {".js", ".ts", ".jsx", ".tsx"} and rule_id == "console_log":
            suppressed += 1
            continue
        if has_ruff and ext == ".py" and rule_id == "print_debug":
            suppressed += 1
            continue

        kept.append(f)

    return kept, suppressed


# Loaded once at import time — available globally
PROJECT_CONFIG = _load_project_config()


# --- Scan engine ---


def scan_file(filepath: str) -> list[dict[str, str | int]]:
    """Scan a single file for anti-patterns, routing rules by file type."""
    findings: list[dict[str, str | int]] = []

    # Config-based path exclusions
    exclude_paths = PROJECT_CONFIG.get("exclude_paths", [])
    for pat in exclude_paths:
        if pat in filepath:
            return findings

    try:
        with open(filepath, "rb") as bf:
            chunk = bf.read(8192)
            if b"\x00" in chunk:
                return findings  # Binary file — skip
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            code = f.read()
    except OSError:
        return findings

    return scan_text(code, filepath)


def scan_text(code: str, filepath: str) -> list[dict[str, str | int]]:
    """Scan in-memory code using the same routing logic as scan_file."""
    findings: list[dict[str, str | int]] = []

    # Config-based path exclusions
    exclude_paths = PROJECT_CONFIG.get("exclude_paths", [])
    for pat in exclude_paths:
        if pat in filepath:
            return findings

    lines = code.splitlines(keepends=True)

    basename = os.path.basename(filepath).lower()
    ext = Path(filepath).suffix.lower()

    if basename.startswith("test_") or basename.startswith("conftest") or ".test." in basename or ".spec." in basename:
        return findings  # Skip test files

    # CLI entry points use print() for user output — not debug prints
    is_cli_entrypoint = basename in {"cli.py", "scan_runner.py", "scan.py"}

    is_dockerfile = basename.startswith("dockerfile")
    is_ci = ".github" in filepath and ext in {".yml", ".yaml"}
    is_devops = ext in DEVOPS_EXTS or basename in DEVOPS_NAMES
    is_react = ext in {".jsx", ".tsx"}
    is_k8s = ext in {".yml", ".yaml"} and not is_ci

    # Choose rule sets based on file type
    if ext in SQL_EXTS:
        block_rules = SQL_BLOCK_RULES
        warn_rules = SQL_WARN_RULES
        info_rules = SQL_INFO_RULES
    elif is_dockerfile:
        block_rules = BLOCK_RULES + DOCKER_BLOCK_RULES + DEVOPS_BLOCK_RULES
        warn_rules = WARN_RULES + DOCKER_WARN_RULES + DEVOPS_WARN_RULES
        info_rules = INFO_RULES
    elif is_react:
        block_rules = BLOCK_RULES + REACT_BLOCK_RULES
        warn_rules = WARN_RULES + REACT_WARN_RULES
        info_rules = INFO_RULES
    elif is_ci:
        block_rules = BLOCK_RULES + DEVOPS_BLOCK_RULES + K8S_BLOCK_RULES
        warn_rules = WARN_RULES + CI_WARN_RULES + DEVOPS_WARN_RULES + K8S_WARN_RULES
        info_rules = INFO_RULES + DEVOPS_INFO_RULES + K8S_INFO_RULES
    elif is_k8s:
        block_rules = BLOCK_RULES + DEVOPS_BLOCK_RULES + K8S_BLOCK_RULES
        warn_rules = WARN_RULES + DEVOPS_WARN_RULES + K8S_WARN_RULES
        info_rules = INFO_RULES + DEVOPS_INFO_RULES + K8S_INFO_RULES
    elif is_devops:
        block_rules = BLOCK_RULES + DEVOPS_BLOCK_RULES
        warn_rules = WARN_RULES + DEVOPS_WARN_RULES
        info_rules = INFO_RULES + DEVOPS_INFO_RULES
    else:
        block_rules = BLOCK_RULES
        warn_rules = WARN_RULES
        info_rules = INFO_RULES

    for line_num, line in enumerate(lines, 1):
        # Check suppress_lint BEFORE noqa skip (noqa itself is a suppress_lint finding)
        if "noqa" in line or "type: ignore" in line or "eslint-disable" in line:
            for rule_id, pattern, message in warn_rules:
                if rule_id == "suppress_lint" and re.search(pattern, line):
                    findings.append({
                        "rule_id": rule_id,
                        "severity": "WARN",
                        "message": message,
                        "file": filepath,
                        "line": line_num,
                    })
            if "noqa" in line:
                continue
        for rule_id, pattern, message in block_rules:
            if re.search(pattern, line):
                findings.append({
                    "rule_id": rule_id,
                    "severity": "BLOCK",
                    "message": message,
                    "file": filepath,
                    "line": line_num,
                })
        for rule_id, pattern, message in warn_rules:
            if is_cli_entrypoint and rule_id == "print_debug":
                continue  # print() is correct for CLI user output
            if re.search(pattern, line):
                findings.append({
                    "rule_id": rule_id,
                    "severity": "WARN",
                    "message": message,
                    "file": filepath,
                    "line": line_num,
                })
        for rule_id, pattern, message in info_rules:
            if re.search(pattern, line):
                findings.append({
                    "rule_id": rule_id,
                    "severity": "INFO",
                    "message": message,
                    "file": filepath,
                    "line": line_num,
                })

    # File-level checks for Dockerfiles
    if is_dockerfile:
        content = "".join(lines)
        if not re.search(r"^\s*USER\s+\S+", content, re.MULTILINE):
            findings.append({
                "rule_id": "docker_root_user",
                "severity": "WARN",
                "message": "Dockerfile has no USER instruction — runs as root.",
                "file": filepath,
                "line": 1,
            })
        if not re.search(r"^\s*WORKDIR\s+", content, re.MULTILINE):
            findings.append({
                "rule_id": "docker_no_workdir",
                "severity": "INFO",
                "message": "Dockerfile has no WORKDIR — set explicit working directory.",
                "file": filepath,
                "line": 1,
            })
        if re.search(r"^\s*CMD\s", content, re.MULTILINE) and not re.search(r"^\s*HEALTHCHECK\s", content, re.MULTILINE):
            findings.append({
                "rule_id": "dockerfile_no_healthcheck",
                "severity": "INFO",
                "message": "Dockerfile has CMD but no HEALTHCHECK. Add HEALTHCHECK for container orchestration.",
                "file": filepath,
                "line": 1,
            })

    # ── Special handler: except_swallow ──
    # except followed by pass/... on next non-blank line = silently swallowed
    _check_except_swallow(lines, filepath, findings)

    # ── Special handler: sleep_no_context ──
    # sleep() without a comment on the preceding line
    _check_sleep_no_context(lines, filepath, findings)

    # ── Special handler: function_length ──
    # Python functions > 40 lines
    if ext == ".py":
        _check_function_length(lines, filepath, findings)

    # ── Special handler: connection_no_timeout ──
    _check_connection_timeout(lines, filepath, findings)

    # ── Special handler: compose_no_healthcheck ──
    if is_devops and ext in {".yml", ".yaml"} and "compose" in basename:
        _check_compose_healthcheck(lines, filepath, findings)

    # ── Special handler: ci_no_timeout ──
    if is_ci:
        _check_ci_no_timeout(lines, filepath, findings)

    # ── Apply project config: ignore_rules / severity_overrides ──
    ignore_rules: set[str] = set(PROJECT_CONFIG.get("ignore_rules", []))
    severity_overrides: dict[str, str] = PROJECT_CONFIG.get("severity_overrides", {})
    if ignore_rules or severity_overrides:
        filtered: list[dict[str, str | int]] = []
        for f in findings:
            rid = str(f.get("rule_id", ""))
            if rid in ignore_rules:
                continue
            if rid in severity_overrides:
                f = {**f, "severity": severity_overrides[rid].upper()}
            filtered.append(f)
        findings = filtered

    return findings


def _scan_text_at_git_ref(
    *,
    cwd: Path,
    ref: str,
    rel_path: str,
) -> list[dict[str, str | int]]:
    """Scan file content at a git ref (best-effort)."""
    try:
        out = subprocess.run(
            ["git", "show", f"{ref}:{rel_path}"],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
        )
        if out.returncode != 0:
            return []
        return scan_text(out.stdout, rel_path)
    except Exception:
        return []


def _finding_key_cli(f: dict[str, str | int]) -> tuple[str, str, int, str, str]:
    """Stable identity key for diffing findings across refs."""
    return (
        str(f.get("rule_id", "")),
        str(f.get("file", "")),
        int(f.get("line", 0) or 0),
        str(f.get("severity", "")),
        str(f.get("message", "")),
    )


def _diff_new_findings_cli(
    *,
    head: list[dict[str, str | int]],
    baseline: list[dict[str, str | int]],
) -> list[dict[str, str | int]]:
    """Return only findings that exist in head but not baseline."""
    baseline_keys = {_finding_key_cli(f) for f in baseline}
    return [f for f in head if _finding_key_cli(f) not in baseline_keys]


def _severity_meets_threshold(severity: str, threshold: str) -> bool:
    order = {"INFO": 1, "WARN": 2, "BLOCK": 3}
    return order.get(severity, 0) >= order.get(threshold, 3)


def _scan_code_text(code: str, filename: str) -> list[dict[str, str | int]]:
    """Scan in-memory code using the same routing as scan_file()."""
    tmp_path = Path(filename)
    basename = tmp_path.name.lower()
    if basename.startswith("test_") or basename.startswith("conftest") or ".test." in basename or ".spec." in basename:
        return []

    # Preserve path-based routing (e.g., .github, dockerfile naming) by writing
    # to a temp directory that mirrors the original relative path.
    import tempfile as _tempfile

    with _tempfile.TemporaryDirectory() as tmp_dir:
        tmp_file = Path(tmp_dir) / tmp_path
        tmp_file.parent.mkdir(parents=True, exist_ok=True)
        tmp_file.write_text(code, encoding="utf-8", errors="ignore")
        return scan_file(str(tmp_file))


def _git_show_head(project_dir: Path, relpath: str) -> str | None:
    """Return file content at HEAD for relpath, or None if missing."""
    rel = _normalize_path_for_git(relpath, cwd=project_dir)
    try:
        res = subprocess.run(
            ["git", "show", f"HEAD:{rel}"],
            cwd=project_dir,
            capture_output=True,
            text=True,
            check=False,
        )
        if res.returncode != 0:
            return None
        return res.stdout
    except (OSError, ValueError):
        return None


def _compute_trust_diff(*, project_dir: Path, changed_files: list[str], staged: bool) -> dict[str, object]:
    """Compute a trust/drift diff between HEAD and current changes."""
    norm_files = [_normalize_path_for_git(f, cwd=project_dir) for f in changed_files]
    norm_files = [f for f in norm_files if Path(f).suffix.lower() in SOURCE_EXTS]
    norm_files = sorted(set(norm_files))

    head_findings: list[dict[str, str | int]] = []
    cur_findings: list[dict[str, str | int]] = []

    for rel in norm_files:
        head_text = _git_show_head(project_dir, rel)
        if head_text is not None:
            head_findings.extend(_scan_code_text(head_text, rel))
        abs_path = project_dir / rel
        if abs_path.is_file():
            cur_findings.extend(scan_file(str(abs_path)))

    head_findings = _sort_findings(_dedupe_findings(head_findings))
    cur_findings = _sort_findings(_dedupe_findings(cur_findings))

    head_drift = _calculate_drift_score(head_findings)
    cur_drift = _calculate_drift_score(cur_findings)

    def _counts(findings: list[dict[str, str | int]]) -> dict[str, int]:
        return {
            "total": len(findings),
            "blocks": sum(1 for f in findings if f.get("severity") == "BLOCK"),
            "warnings": sum(1 for f in findings if f.get("severity") == "WARN"),
            "infos": sum(1 for f in findings if f.get("severity") == "INFO"),
        }

    head_counts = _counts(head_findings)
    cur_counts = _counts(cur_findings)

    return {
        "scope": "staged" if staged else "working_tree",
        "files": norm_files,
        "head": {"drift": head_drift, "counts": head_counts},
        "current": {"drift": cur_drift, "counts": cur_counts},
        "delta": {
            "drift_score": int(cur_drift.get("score", 0)) - int(head_drift.get("score", 0)),
            "total_findings": cur_counts["total"] - head_counts["total"],
            "blocks": cur_counts["blocks"] - head_counts["blocks"],
            "warnings": cur_counts["warnings"] - head_counts["warnings"],
            "infos": cur_counts["infos"] - head_counts["infos"],
        },
    }


def cmd_trust_diff(args: argparse.Namespace) -> int:
    """Compare trust/drift between HEAD and current changes."""
    project_dir = Path.cwd()
    changed_files, staged = _get_git_changed_files(cwd=project_dir)
    report = _compute_trust_diff(project_dir=project_dir, changed_files=changed_files, staged=staged)

    if getattr(args, "json", False):
        print(json.dumps(report, indent=2, default=str))
        return 0

    delta = report.get("delta", {})
    head = report.get("head", {})
    cur = report.get("current", {})
    head_drift = head.get("drift", {}) if isinstance(head, dict) else {}
    cur_drift = cur.get("drift", {}) if isinstance(cur, dict) else {}
    print(f"\n{color('📈 CodeTrust Trust Diff', BOLD)}")
    print(f"   Scope: {report.get('scope', '-')}")
    print(f"   Files compared: {len(report.get('files', []) if isinstance(report.get('files', []), list) else [])}")
    print(f"   Drift score: {head_drift.get('score', 0)}/100 → {cur_drift.get('score', 0)}/100 (Δ {delta.get('drift_score', 0)})\n")
    print(f"   Findings Δ: total {delta.get('total_findings', 0)}, blocks {delta.get('blocks', 0)}, warns {delta.get('warnings', 0)}, infos {delta.get('infos', 0)}")
    return 0


# --- Trend command ---


def _git_rev_parse(project_dir: Path, ref: str) -> str:
    try:
        res = subprocess.run(
            ["git", "rev-parse", ref],
            cwd=project_dir,
            capture_output=True,
            text=True,
            check=False,
        )
        return res.stdout.strip() if res.returncode == 0 else ""
    except (OSError, ValueError):
        return ""


def _trend_path(project_dir: Path) -> Path:
    return project_dir / TREND_FILE_REL


def _trend_read(project_dir: Path) -> list[dict[str, object]]:
    path = _trend_path(project_dir)
    if not path.is_file():
        return []
    entries: list[dict[str, object]] = []
    invalid_json_lines = 0
    for ln in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            obj = json.loads(ln)
            if isinstance(obj, dict):
                entries.append(obj)
        except json.JSONDecodeError:
            invalid_json_lines += 1
            continue
    if invalid_json_lines:
        logger.debug(
            "trend_read_skipped_invalid_json",
            path=str(path),
            count=invalid_json_lines,
        )
    return entries


def _trend_write(project_dir: Path, entry: dict[str, object]) -> None:
    path = _trend_path(project_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, sort_keys=True, default=str) + "\n")


def _trend_snapshot(project_dir: Path, targets: list[str]) -> dict[str, object]:
    all_findings: list[dict[str, str | int]] = []
    files_scanned = 0
    for t in targets:
        all_findings.extend(scan_path(t))
        if Path(t).is_file():
            files_scanned += 1
        elif Path(t).is_dir():
            for _root, _dirs, files in os.walk(t):
                files_scanned += sum(1 for fn in files if Path(fn).suffix in SOURCE_EXTS)

    all_findings = _sort_findings(_dedupe_findings(all_findings))
    drift = _calculate_drift_score(all_findings)
    blocks = sum(1 for f in all_findings if f.get("severity") == "BLOCK")
    warns = sum(1 for f in all_findings if f.get("severity") == "WARN")
    infos = sum(1 for f in all_findings if f.get("severity") == "INFO")
    verdict = "BLOCK" if blocks else ("WARN" if warns else "PASS")

    import datetime as _dt

    utc_tz = _dt.UTC

    return {
        "ts": _dt.datetime.now(utc_tz).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "git_sha": _git_rev_parse(project_dir, "HEAD"),
        "targets": targets,
        "verdict": verdict,
        "files_scanned": files_scanned,
        "total_findings": len(all_findings),
        "blocks": blocks,
        "warnings": warns,
        "infos": infos,
        "drift_score": drift,
    }


def cmd_trend(args: argparse.Namespace) -> int:
    project_dir = Path.cwd()
    sub = str(getattr(args, "subcommand", "show"))
    limit = int(getattr(args, "limit", 20) or 20)
    if limit < 1:
        limit = 1

    if sub == "record":
        targets = list(getattr(args, "targets", []) or ["."])
        entry = _trend_snapshot(project_dir, targets)
        _trend_write(project_dir, entry)
        if getattr(args, "json", False):
            print(json.dumps(entry, indent=2, default=str))
            return 0
        print(f"\n{color('📌 CodeTrust Trend — Recorded', BOLD)}")
        print(f"   {entry['ts']} | {entry['verdict']} | drift {entry['drift_score'].get('score', 0)}/100")
        print(f"   Findings: {entry['total_findings']} (BLOCK {entry['blocks']}, WARN {entry['warnings']}, INFO {entry['infos']})")
        print(f"   Stored: {TREND_FILE_REL}\n")
        return 0

    # show (default)
    entries = _trend_read(project_dir)
    entries = entries[-limit:]
    if getattr(args, "json", False):
        print(json.dumps({"entries": entries}, indent=2, default=str))
        return 0

    print(f"\n{color('📈 CodeTrust Trend', BOLD)}")
    if not entries:
        print("   No trend data yet. Run: codetrust trend record\n")
        return 0

    for e in entries:
        ts = str(e.get("ts", ""))
        verdict = str(e.get("verdict", ""))
        drift = e.get("drift_score", {})
        score = drift.get("score", 0) if isinstance(drift, dict) else 0
        total = int(e.get("total_findings", 0) or 0)
        blocks = int(e.get("blocks", 0) or 0)
        warns = int(e.get("warnings", 0) or 0)
        print(f"   {ts} | {verdict} | drift {score}/100 | {total} findings (B{blocks} W{warns})")
    print()
    return 0


# ── Special handler implementations ──────────────────────────────


def _check_except_swallow(
    lines: list[str], filepath: str, findings: list[dict],
) -> None:
    """Flag except blocks that swallow errors with pass/..."""
    for i, line in enumerate(lines):
        if not re.match(r"^\s*except[\s:]", line):
            continue
        # Look at the next non-blank line(s) for pass or ...
        for j in range(i + 1, min(i + 3, len(lines))):
            nxt = lines[j].strip()
            if not nxt:
                continue
            if nxt in ("pass", "..."):
                findings.append({
                    "rule_id": "except_swallow",
                    "severity": "BLOCK",
                    "message": "Exception caught and silently swallowed (pass/...). Handle the error or re-raise.",
                    "file": filepath,
                    "line": i + 1,
                })
            break  # only check the first non-blank line after except


def _check_sleep_no_context(
    lines: list[str], filepath: str, findings: list[dict],
) -> None:
    """Flag sleep() calls without a preceding comment explaining why."""
    sleep_re = re.compile(r"(?:time\.)?sleep\s*\(")
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if sleep_re.search(line):
            # Check if the preceding line is a comment
            prev = lines[i - 1].strip() if i > 0 else ""
            if not prev.startswith("#"):
                findings.append({
                    "rule_id": "sleep_no_context",
                    "severity": "INFO",
                    "message": "sleep() without explanation. Why is a delay needed? Document or fix root cause.",
                    "file": filepath,
                    "line": i + 1,
                })


def _check_function_length(
    lines: list[str], filepath: str, findings: list[dict],
) -> None:
    """Flag Python functions longer than 40 lines."""
    func_re = re.compile(r"^(\s*)(async\s+)?def\s+(\w+)")
    func_starts: list[tuple[int, int, str]] = []  # (line_num, indent, name)

    for i, line in enumerate(lines):
        m = func_re.match(line)
        if m:
            indent = len(m.group(1))
            name = m.group(3)
            func_starts.append((i, indent, name))

    for idx, (start, indent, name) in enumerate(func_starts):
        # Function body ends at next def at same/lower indent or EOF
        end = len(lines)
        for nxt_start, nxt_indent, _ in func_starts[idx + 1:]:
            if nxt_indent <= indent:
                end = nxt_start
                break
        # Count non-blank, non-comment lines in body
        body_lines = 0
        for j in range(start + 1, end):
            stripped = lines[j].strip()
            if stripped and not stripped.startswith("#"):
                body_lines += 1
        if body_lines > 40:
            findings.append({
                "rule_id": "long_function",
                "severity": "INFO",
                "message": f"Function '{name}' is {body_lines} lines (max 40).",
                "file": filepath,
                "line": start + 1,
            })


def _check_connection_timeout(
    lines: list[str], filepath: str, findings: list[dict],
) -> None:
    """Flag network/DB connections without explicit timeout."""
    conn_re = re.compile(
        r"(?:from_url|AsyncClient|Client|create_async_engine|create_engine)\s*\(",
    )
    for i, line in enumerate(lines):
        if conn_re.search(line):
            # Check current + next 2 lines for 'timeout'
            context = "".join(lines[i:i + 3])
            if "timeout" not in context.lower():
                findings.append({
                    "rule_id": "connection_no_timeout",
                    "severity": "WARN",
                    "message": "Network/DB connection without explicit timeout. Add connect_timeout or socket_timeout.",
                    "file": filepath,
                    "line": i + 1,
                })


def _check_compose_healthcheck(
    lines: list[str], filepath: str, findings: list[dict],
) -> None:
    """Flag Docker Compose services without healthcheck."""
    content = "".join(lines)
    # Find services with 'image:' but no 'healthcheck:' at same indent
    service_re = re.compile(r"^\s{2}(\w[\w-]*):\s*$", re.MULTILINE)
    for m in service_re.finditer(content):
        svc_name = m.group(1)
        svc_start = m.end()
        # Find next service or EOF
        nxt = service_re.search(content, svc_start)
        svc_block = content[svc_start:nxt.start() if nxt else len(content)]
        if "image:" in svc_block and "healthcheck:" not in svc_block:
            line_num = content[:m.start()].count("\n") + 1
            findings.append({
                "rule_id": "compose_no_healthcheck",
                "severity": "INFO",
                "message": f"Service '{svc_name}' has no healthcheck. Add healthcheck for reliable orchestration.",
                "file": filepath,
                "line": line_num,
            })


def _check_ci_no_timeout(
    lines: list[str], filepath: str, findings: list[dict],
) -> None:
    """Flag CI jobs (runs-on:) without timeout-minutes."""
    content = "".join(lines)
    # Find jobs with runs-on but no timeout-minutes
    runs_on_re = re.compile(r"^\s+runs-on:\s", re.MULTILINE)
    for m in runs_on_re.finditer(content):
        # Look backward for job name and forward for timeout-minutes
        before = content[:m.start()]
        # Find the job block — look for next runs-on or EOF
        nxt = runs_on_re.search(content, m.end())
        job_block = content[m.start():nxt.start() if nxt else len(content)]
        if "timeout-minutes:" not in job_block:
            # Also check a few lines above (job-level timeout)
            prev_block = before[max(0, len(before) - 200):]
            if "timeout-minutes:" not in prev_block:
                line_num = before.count("\n") + 1
                findings.append({
                    "rule_id": "ci_no_timeout",
                    "severity": "INFO",
                    "message": "CI job has no timeout-minutes. Add timeout to prevent hung pipelines.",
                    "file": filepath,
                    "line": line_num,
                })


def scan_path(target: str) -> list[dict[str, str | int]]:
    """Scan a file or directory."""
    findings: list[dict[str, str | int]] = []
    target_path = Path(target)

    if target_path.is_file():
        return scan_file(str(target_path))

    if target_path.is_dir():
        skip_dirs = {
            ".git", ".venv", "venv", "node_modules", "__pycache__",
            "dist", "build", ".next", ".open-next", ".turbo",
            ".nuxt", ".output", ".svelte-kit", ".vercel", ".wrangler",
            "coverage", "out", ".cache", "test", "__tests__",
        }
        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for filename in files:
                filepath = os.path.join(root, filename)
                if Path(filepath).suffix in SOURCE_EXTS:
                    findings.extend(scan_file(filepath))

    return findings


# --- Templates (loaded from src/templates/) ---


def _load_template(name: str) -> str:
    """Load a template file from the templates package."""
    ref = importlib.resources.files("src.templates").joinpath(name)
    return ref.read_text(encoding="utf-8")


def _confirm(prompt: str) -> bool:
    """Ask for confirmation on stdin when interactive."""
    if not sys.stdin.isatty():
        return False
    ans = input(f"{prompt} [y/N]: ").strip().lower()
    return ans in {"y", "yes"}


def _write_text_file_safe(
    path: Path,
    content: str,
    *,
    yes: bool,
) -> bool:
    """Write a text file, never overwriting without explicit confirmation.

    Returns True if written/updated, False otherwise.
    """
    if path.exists():
        existing = path.read_text(encoding="utf-8", errors="ignore")
        if existing == content:
            return False
        if not yes and not _confirm(f"Update existing {path}?"):
            return False
        shutil.copy2(path, path.with_suffix(path.suffix + ".bak"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return True


def _read_json(path: Path) -> dict:
    """Read a JSON file into a dict. Returns empty dict on parse error."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _write_json_file_safe(path: Path, obj: dict, *, yes: bool) -> bool:
    """Write JSON file safely with no overwrite without confirmation."""
    content = json.dumps(obj, indent=2, sort_keys=True) + "\n"
    return _write_text_file_safe(path, content, yes=yes)


def _detect_stack(project_dir: Path) -> str:
    """Best-effort repo stack detection."""
    if (project_dir / "next.config.js").is_file() or (project_dir / "next.config.mjs").is_file():
        return "nextjs"
    if (project_dir / "package.json").is_file():
        return "node"
    if (project_dir / "pyproject.toml").is_file() or (project_dir / "requirements.txt").is_file():
        return "python"
    if (project_dir / "go.mod").is_file():
        return "go"
    return "generic"


def _stack_settings_presets(stack: str) -> dict[str, object]:
    """Return stack-specific VS Code settings presets for CodeTrust."""
    if stack == "python":
        return {
            "codetrust.enabledLanguages": ["python"],
        }
    if stack == "go":
        return {
            "codetrust.enabledLanguages": ["go"],
        }
    if stack in {"node", "nextjs"}:
        return {
            "codetrust.enabledLanguages": ["javascript", "typescript"],
        }
    return {}


POLICY_PROFILE_CHOICES: tuple[str, ...] = ("startup", "team", "enterprise")
POLICY_DEFAULT_PROFILE = "team"

POLICY_DEFAULT_EXCLUDE_PATHS: list[str] = [
    "migrations/",
    "vendor/",
    "node_modules/",
]

PYPROJECT_POLICY_BEGIN = "# BEGIN CODETRUST POLICY (generated)"
PYPROJECT_POLICY_END = "# END CODETRUST POLICY"


def _toml_escape_string(value: str) -> str:
    """Escape a string for TOML basic string contexts."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _toml_string_array(values: list[str]) -> str:
    """Render a TOML array of basic strings."""
    escaped = [f'"{_toml_escape_string(v)}"' for v in values]
    return "[" + ", ".join(escaped) + "]"


def _governance_config_for_profile(profile: str) -> GovernanceConfig:
    """Create a GovernanceConfig preset for the given profile."""
    from src.gateway.policies import GovernanceConfig, GovernanceMode

    cfg = GovernanceConfig()
    if profile == "startup":
        cfg.mode = GovernanceMode.AUDIT
        cfg.block_sudo = False
    elif profile == "team":
        cfg.mode = GovernanceMode.ENFORCE
        cfg.block_sudo = False
    elif profile == "enterprise":
        cfg.mode = GovernanceMode.ENFORCE
        cfg.block_sudo = True
    else:
        raise ValueError(f"Unknown profile: {profile}")

    return cfg


def _render_governance_sections(*, root: str, cfg: GovernanceConfig) -> str:
    """Render governance TOML sections under the given root table.

    root examples:
      - codetrust
      - tool.codetrust
    """
    lines: list[str] = []

    lines.extend([
        f"[{root}.governance]",
        f"enabled = {str(bool(cfg.enabled)).lower()}",
        f'mode = "{cfg.mode.value}"',
        "",
        f"[{root}.governance.terminal]",
        f"block_heredoc = {str(bool(cfg.block_heredoc)).lower()}",
        f"block_eval = {str(bool(cfg.block_eval)).lower()}",
        f"block_sudo = {str(bool(cfg.block_sudo)).lower()}",
        f"block_rm_rf = {str(bool(cfg.block_rm_rf)).lower()}",
        f"block_curl_pipe_sh = {str(bool(cfg.block_curl_pipe_sh)).lower()}",
        f"block_git_push = {str(bool(cfg.block_git_push)).lower()}",
        f"block_chmod_777 = {str(bool(cfg.block_chmod_777)).lower()}",
        "",
        f"[{root}.governance.files]",
        f"protected_paths = {_toml_string_array(list(cfg.protected_paths))}",
        f"scan_before_write = {str(bool(cfg.scan_before_write)).lower()}",
        "",
        f"[{root}.governance.packages]",
        f"verify_before_install = {str(bool(cfg.verify_before_install)).lower()}",
        f"block_suspicious_packages = {str(bool(cfg.block_suspicious_packages)).lower()}",
        "",
        f"[{root}.governance.audit]",
        f"enabled = {str(bool(cfg.audit_enabled)).lower()}",
        f'path = "{_toml_escape_string(cfg.audit_path)}"',
        f"retention_days = {int(cfg.retention_days)}",
        "",
        f"[{root}.governance.webhooks]",
        f'url = "{_toml_escape_string(cfg.webhook_url)}"',
        f'provider = "{_toml_escape_string(cfg.webhook_provider)}"',
        f"on_block = {str(bool(cfg.webhook_on_block)).lower()}",
        f"on_warn = {str(bool(cfg.webhook_on_warn)).lower()}",
    ])

    disabled_rules = sorted(cfg.disabled_rules)
    if disabled_rules:
        lines.append("")
        lines.append(f"disabled_rules = {_toml_string_array(disabled_rules)}")

    return "\n".join(lines) + "\n"


def _render_codetrust_toml_for_profile(profile: str) -> str:
    """Render full .codetrust.toml content for the chosen policy profile."""
    cfg = _governance_config_for_profile(profile)
    header = (
        "# CodeTrust Governance Configuration\n"
        f"# Generated by: codetrust policy wizard --profile {profile}\n\n"
        "[codetrust]\n"
        f"exclude_paths = {_toml_string_array(POLICY_DEFAULT_EXCLUDE_PATHS)}\n"
        "ignore_rules = []\n\n"
    )
    return header + _render_governance_sections(root="codetrust", cfg=cfg)


def _render_pyproject_codetrust_for_profile(profile: str) -> str:
    """Render [tool.codetrust] TOML content for pyproject.toml."""
    cfg = _governance_config_for_profile(profile)
    header = (
        "[tool.codetrust]\n"
        f"exclude_paths = {_toml_string_array(POLICY_DEFAULT_EXCLUDE_PATHS)}\n"
        "ignore_rules = []\n\n"
    )
    return header + _render_governance_sections(root="tool.codetrust", cfg=cfg)


def _upsert_marked_block(
    text: str,
    *,
    begin_marker: str,
    end_marker: str,
    inner_block: str,
) -> tuple[str, bool]:
    """Insert or replace a marker-delimited block in a text file."""
    if begin_marker in text and end_marker in text:
        pre, rest = text.split(begin_marker, 1)
        _old, post = rest.split(end_marker, 1)
        new = pre.rstrip("\n") + "\n" + begin_marker + "\n" + inner_block.rstrip("\n") + "\n" + end_marker + "\n" + post.lstrip("\n")
        return (new, new != text)

    if begin_marker in text or end_marker in text:
        # Partial markers — don't guess; avoid corrupting TOML.
        return (text, False)

    appended = text.rstrip("\n") + "\n\n" + begin_marker + "\n" + inner_block.rstrip("\n") + "\n" + end_marker + "\n"
    return (appended, True)


def cmd_policy(args: argparse.Namespace) -> int:
    """Policy wizard for generating governance config presets."""
    project_dir = Path.cwd()

    sub = str(getattr(args, "subcommand", ""))
    if sub != "wizard":
        print("Run: codetrust policy wizard")
        return 1

    yes = bool(getattr(args, "yes", False))
    profile = str(getattr(args, "profile", POLICY_DEFAULT_PROFILE))
    if profile not in POLICY_PROFILE_CHOICES:
        print(f"Invalid --profile. Choose one of: {', '.join(POLICY_PROFILE_CHOICES)}")
        return 2

    print(f"\n{color('🧭 CodeTrust Policy Wizard', BOLD)}\n")
    print(f"  Profile: {profile}")

    # 1) .codetrust.toml
    ct_toml_path = project_dir / ".codetrust.toml"
    ct_content = _render_codetrust_toml_for_profile(profile)
    wrote_ct = _write_text_file_safe(ct_toml_path, ct_content, yes=yes)
    print(f"  {color('✅', GREEN) if wrote_ct else color('↪', BLUE)} {ct_toml_path}")

    # 2) Schema autocomplete helpers (.taplo.toml + .codetrust.schema.json)
    taplo_path = project_dir / ".taplo.toml"
    wrote_taplo = _write_text_file_safe(taplo_path, _load_template("taplo.toml"), yes=yes)
    print(f"  {color('✅', GREEN) if wrote_taplo else color('↪', BLUE)} {taplo_path}")

    schema_path = project_dir / ".codetrust.schema.json"
    wrote_schema = _write_text_file_safe(schema_path, _load_template("codetrust.schema.json"), yes=yes)
    print(f"  {color('✅', GREEN) if wrote_schema else color('↪', BLUE)} {schema_path}")

    # 3) Optional pyproject.toml sync
    py_mode = str(getattr(args, "pyproject", "auto"))
    if py_mode not in {"auto", "skip", "force"}:
        py_mode = "auto"

    pyproject = project_dir / "pyproject.toml"
    if py_mode != "skip" and pyproject.is_file():
        existing = pyproject.read_text(encoding="utf-8", errors="ignore")
        has_tool_section = "[tool.codetrust]" in existing or "[tool.codetrust." in existing

        if has_tool_section and PYPROJECT_POLICY_BEGIN not in existing and py_mode != "force":
            print(f"  {color('↪', BLUE)} {pyproject} (existing [tool.codetrust] found; skipping sync)")
        else:
            inner = _render_pyproject_codetrust_for_profile(profile)
            updated, changed = _upsert_marked_block(
                existing,
                begin_marker=PYPROJECT_POLICY_BEGIN,
                end_marker=PYPROJECT_POLICY_END,
                inner_block=inner,
            )
            if changed:
                wrote_py = _write_text_file_safe(pyproject, updated, yes=yes)
                print(f"  {color('✅', GREEN) if wrote_py else color('↪', BLUE)} {pyproject} ({'synced' if wrote_py else 'no change'})")
            else:
                print(f"  {color('↪', BLUE)} {pyproject} (no change)")

    print("\nDone.\n")
    return 0


def cmd_add(args: argparse.Namespace) -> int:
    """Add CodeTrust bootstrap files to the current repo (VS Code/DevContainer/docs)."""
    project_dir = Path.cwd()
    yes = bool(getattr(args, "yes", False))

    print(f"\n{color('🧩 CodeTrust — Adding repo bootstrap files', BOLD)}\n")

    # 1) .vscode/extensions.json
    vscode_dir = project_dir / ".vscode"
    ext_file = vscode_dir / "extensions.json"
    ext_data: dict = _read_json(ext_file) if ext_file.exists() else {}
    recs = ext_data.get("recommendations")
    if not isinstance(recs, list):
        recs = []
    if "SaidBorna.codetrust" not in recs:
        recs.append("SaidBorna.codetrust")
    ext_data["recommendations"] = recs
    if "unwantedRecommendations" not in ext_data:
        ext_data["unwantedRecommendations"] = []
    wrote_ext = _write_json_file_safe(ext_file, ext_data, yes=yes)
    print(f"  {color('✅', GREEN) if wrote_ext else color('↪', BLUE)} {ext_file}")

    # 2) .vscode/settings.json (only add missing keys; never override)
    if args.settings:
        settings_file = vscode_dir / "settings.json"
        settings: dict = _read_json(settings_file) if settings_file.exists() else {}
        if not isinstance(settings, dict):
            settings = {}
        defaults: dict[str, object] = {
            "codetrust.scanOnSave": True,
            "codetrust.scanType": "static",
            "codetrust.severityThreshold": "INFO",
            "codetrust.verifyImportsOnSave": False,
            "codetrust.governance.enabled": True,
            "codetrust.governance.mode": "enforce",
        }

        stack_arg = str(getattr(args, "stack", "auto"))
        stack = _detect_stack(project_dir) if stack_arg == "auto" else stack_arg
        defaults.update(_stack_settings_presets(stack))
        for k, v in defaults.items():
            if k not in settings:
                settings[k] = v
        wrote_settings = _write_json_file_safe(settings_file, settings, yes=yes)
        print(f"  {color('✅', GREEN) if wrote_settings else color('↪', BLUE)} {settings_file}")

    # 3) .devcontainer/devcontainer.json
    if args.devcontainer:
        dc_file = project_dir / ".devcontainer" / "devcontainer.json"
        dc: dict = _read_json(dc_file) if dc_file.exists() else {}
        if not isinstance(dc, dict):
            dc = {}
        custom = dc.get("customizations")
        if not isinstance(custom, dict):
            custom = {}
        vscode_custom = custom.get("vscode")
        if not isinstance(vscode_custom, dict):
            vscode_custom = {}
        exts = vscode_custom.get("extensions")
        if not isinstance(exts, list):
            exts = []
        if "SaidBorna.codetrust" not in exts:
            exts.append("SaidBorna.codetrust")
        vscode_custom["extensions"] = exts
        custom["vscode"] = vscode_custom
        dc["customizations"] = custom
        if "name" not in dc:
            dc["name"] = "CodeTrust DevContainer"
        wrote_dc = _write_json_file_safe(dc_file, dc, yes=yes)
        print(f"  {color('✅', GREEN) if wrote_dc else color('↪', BLUE)} {dc_file}")

    # 4) CONTRIBUTING.md snippet
    if args.contributing:
        contrib_file = project_dir / "CONTRIBUTING.md"
        if contrib_file.exists():
            text = contrib_file.read_text(encoding="utf-8", errors="ignore")
            marker = "## CodeTrust"
            if marker not in text:
                snippet = (
                    "\n\n## CodeTrust\n\n"
                    "This repo uses CodeTrust as a quality gate for AI-assisted development.\n\n"
                    "- Local: run `codetrust scan .` before opening a PR\n"
                    "- Pre-commit: commits may be blocked until BLOCK findings are resolved\n"
                    "- CI: PRs can fail the CodeTrust Quality Gate (SARIF uploaded to Security)\n"
                )
                wrote = _write_text_file_safe(contrib_file, text + snippet, yes=yes)
                print(f"  {color('✅', GREEN) if wrote else color('↪', BLUE)} {contrib_file}")
            else:
                print(f"  {color('↪', BLUE)} {contrib_file} (already has CodeTrust section)")
        else:
            print(f"  {color('⚠️', YELLOW)}  CONTRIBUTING.md not found — skipping")

    print("\nDone.\n")
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    """Install CodeTrust enforcement layers into current project."""
    project_dir = Path.cwd()
    installed: list[str] = []

    print(f"\n{color('🛡️  CodeTrust — Installing enforcement layers', BOLD)}\n")

    # 1. CLAUDE.md
    claude_md = project_dir / "CLAUDE.md"
    if claude_md.exists() and not args.force:
        print(f"  {color('⚠️', YELLOW)}  CLAUDE.md exists (use --force to overwrite)")
    else:
        if claude_md.exists():
            shutil.copy2(claude_md, claude_md.with_suffix(".md.bak"))
        claude_md.write_text(_load_template("CLAUDE.md"))
        installed.append("CLAUDE.md")
        print(f"  {color('✅', GREEN)} CLAUDE.md installed")

    # 2. .cursorrules
    cursorrules = project_dir / ".cursorrules"
    cursorrules.write_text(_load_template("cursorrules"))
    installed.append(".cursorrules")
    print(f"  {color('✅', GREEN)} .cursorrules installed")

    # 3. Pre-commit hook
    git_dir = project_dir / ".git"
    if git_dir.is_dir():
        # Create hooks/ in project root (version-controlled)
        hooks_dir = project_dir / "hooks"
        hooks_dir.mkdir(exist_ok=True)
        hook_file = hooks_dir / "pre-commit"
        hook_file.write_text(_load_template("pre-commit"))
        hook_file.chmod(0o755)

        # Set core.hooksPath
        subprocess.run(
            ["git", "config", "core.hooksPath", "hooks"],
            cwd=project_dir,
            capture_output=True,
        )

        # Also install in .git/hooks as fallback
        git_hook = git_dir / "hooks" / "pre-commit"
        git_hook.parent.mkdir(exist_ok=True)
        git_hook.write_text(_load_template("pre-commit"))
        git_hook.chmod(0o755)

        installed.append("pre-commit hook (core.hooksPath)")
        print(f"  {color('✅', GREEN)} Pre-commit hook installed via core.hooksPath")
    else:
        print(f"  {color('⚠️', YELLOW)}  Not a git repo — skipping hooks")

    # 4. GitHub Action
    workflows_dir = project_dir / ".github" / "workflows"
    workflows_dir.mkdir(parents=True, exist_ok=True)
    action_file = workflows_dir / "codetrust-scan.yml"
    if action_file.exists() and not args.force:
        print(f"  {color('⚠️', YELLOW)}  GitHub Action exists (use --force to overwrite)")
    else:
        action_file.write_text(_load_template("codetrust-scan.yml"))
        installed.append("GitHub Action")
        print(f"  {color('✅', GREEN)} GitHub Action installed")

    # 5. .gitignore additions
    gitignore = project_dir / ".gitignore"
    patterns_to_add = ["codetrust-report.md", ".codetrust/"]
    if gitignore.exists():
        existing = gitignore.read_text()
        new_patterns = [p for p in patterns_to_add if p not in existing]
        if new_patterns:
            with open(gitignore, "a") as f:
                f.write("\n# CodeTrust\n")
                for p in new_patterns:
                    f.write(f"{p}\n")

    # 6. Governance config (.codetrust.toml)
    governance_toml = project_dir / ".codetrust.toml"
    if governance_toml.exists() and not args.force:
        print(f"  {color('⚠️', YELLOW)}  .codetrust.toml exists (use --force to overwrite)")
    else:
        if governance_toml.exists():
            shutil.copy2(governance_toml, governance_toml.with_suffix(".toml.bak"))
        governance_toml.write_text(_load_template("codetrust.toml"))
        installed.append(".codetrust.toml")
        print(f"  {color('✅', GREEN)} Governance config (.codetrust.toml) installed")

    # 7. Audit directory
    audit_dir = project_dir / ".codetrust"
    audit_dir.mkdir(exist_ok=True)
    installed.append(".codetrust/ audit directory")
    print(f"  {color('✅', GREEN)} Audit directory created")

    # Summary
    print(f"\n{'━' * 48}")
    print(f"\n  {color('✅ CodeTrust installed!', GREEN)}\n")
    print("  Enforcement stack:")
    print(f"    Layer 1: CLAUDE.md / .cursorrules  {color('(advisory)', BLUE)}")
    print(f"    Layer 2: VS Code extension         {color('(passive)', BLUE)}")
    print(f"    Layer 3: Pre-commit hook            {color('(blocking)', GREEN)}")
    print(f"    Layer 4: GitHub Action              {color('(absolute)', RED)}")
    print(f"    Layer 5: Gateway governance         {color('(interceptor)', RED)}")
    print()
    print("  Governance:")
    print(f"    Config:    .codetrust.toml   {color('(edit to customize)', BLUE)}")
    print("    Audit log: .codetrust/audit.jsonl")
    print("    Mode:      enforce (block violations)")
    print()
    print("  Next steps:")
    print("    1. Push to GitHub")
    print("    2. Settings → Branches → Require 'CodeTrust Quality Gate' to pass")
    print("    3. Install VS Code extension: code --install-extension SaidBorna.codetrust")
    print("    4. Add gateway to Claude/Cursor config (see: codetrust governance --setup)")
    print()

    return 0


# --- Scan command ---


def _calculate_drift_score(findings: list[dict]) -> dict:
    """Calculate AI Drift Score from CLI scan findings."""
    weights = {"BLOCK": 10, "WARN": 3, "INFO": 1}
    total_weight = sum(weights.get(f.get("severity", "INFO"), 1) for f in findings)
    score = max(0, 100 - total_weight)
    if score >= 90:
        grade = "A"
    elif score >= 70:
        grade = "B"
    elif score >= 50:
        grade = "C"
    elif score >= 30:
        grade = "D"
    else:
        grade = "F"
    return {"score": score, "grade": grade}


_SARIF_SEVERITY: dict[str, str] = {"BLOCK": "error", "WARN": "warning", "INFO": "note"}


def _findings_to_sarif(findings: list[dict]) -> dict:
    """Convert CLI findings to a SARIF v2.1.0 document."""
    seen_rules: set[str] = set()
    rules: list[dict] = []
    results: list[dict] = []

    for f in findings:
        rid = str(f.get("rule_id", "unknown"))
        sev = str(f.get("severity", "INFO"))
        level = _SARIF_SEVERITY.get(sev, "note")
        if rid not in seen_rules:
            seen_rules.add(rid)
            rules.append({
                "id": rid,
                "shortDescription": {"text": str(f.get("message", ""))},
                "defaultConfiguration": {"level": level},
            })
        results.append({
            "ruleId": rid,
            "level": level,
            "message": {"text": str(f.get("message", ""))},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": str(f.get("file", "unknown"))},
                    "region": {"startLine": max(int(f.get("line", 1)), 1), "startColumn": 1},
                },
            }],
        })

    return {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "CodeTrust",
                    "version": "2.1.0",
                    "informationUri": "https://codetrust.dev",
                    "rules": rules,
                },
            },
            "results": results,
        }],
    }


def cmd_scan(args: argparse.Namespace) -> int:
    """Scan files for anti-patterns."""
    targets = args.targets
    if not targets:
        targets = ["."]

    all_findings: list[dict[str, str | int]] = []
    files_scanned = 0

    # Machine-readable modes must not mix output (pre-commit, CI, tooling).
    machine_output = bool(getattr(args, "json", False)) or (
        bool(getattr(args, "sarif", False)) and not bool(getattr(args, "sarif_file", ""))
    )

    baseline_ref = str(getattr(args, "baseline", "") or "").strip()
    baseline_mode = bool(baseline_ref)

    if baseline_mode:
        cwd = Path.cwd()
        try:
            diff = subprocess.run(
                ["git", "diff", "--name-only", "--diff-filter=ACM", baseline_ref, "--"],
                cwd=cwd,
                capture_output=True,
                text=True,
                check=False,
            )
            changed_files = [ln.strip() for ln in diff.stdout.splitlines() if ln.strip()]
        except Exception:
            changed_files = []

        # Limit to supported source files and to explicit targets if provided.
        allowed: set[str] = set()
        for t in targets:
            p = Path(t)
            if p.is_file():
                allowed.add(_normalize_path_for_git(str(p), cwd=cwd) or str(p))

        scan_files = []
        for rel in changed_files:
            if Path(rel).suffix.lower() not in SOURCE_EXTS:
                continue
            if allowed and rel not in allowed:
                continue
            if not Path(rel).exists():
                continue
            scan_files.append(rel)

        baseline_findings: list[dict[str, str | int]] = []
        head_findings: list[dict[str, str | int]] = []

        for rel in scan_files:
            head_findings.extend(scan_file(rel))
            baseline_findings.extend(_scan_text_at_git_ref(cwd=cwd, ref=baseline_ref, rel_path=rel))
        files_scanned = len(scan_files)

        # If requested, filter to changed lines *against the baseline ref*.
        if getattr(args, "changed_only", False) and head_findings:
            try:
                changed_ranges: dict[str, list[tuple[int, int]]] = {}
                for rel in {str(f.get("file", "")) for f in head_findings if f.get("file")}:
                    base_cmd = ["git", "diff", "--unified=0", baseline_ref, "--", rel]
                    d = subprocess.run(
                        base_cmd,
                        cwd=cwd,
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    ranges = _parse_unified0_changed_ranges(d.stdout)
                    if ranges:
                        changed_ranges[rel] = ranges

                kept: list[dict[str, str | int]] = []
                for f in head_findings:
                    rel = _normalize_path_for_git(str(f.get("file", "")), cwd=cwd)
                    ranges = changed_ranges.get(rel)
                    if not ranges:
                        continue
                    line = int(f.get("line", 0) or 0)
                    if line <= 0:
                        continue
                    if _is_line_in_ranges(line, ranges):
                        kept.append({**f, "file": rel})
                head_findings = kept
            except Exception as exc:
                if not machine_output:
                    print(
                        color(
                            f"  ⚠️  Could not compute changed-line ranges vs baseline ({baseline_ref}): {exc}",
                            YELLOW,
                        )
                    )

        new_findings = _diff_new_findings_cli(head=head_findings, baseline=baseline_findings)
        all_findings = new_findings

    else:
        for target in targets:
            findings = scan_path(target)
            all_findings.extend(findings)
            if Path(target).is_file():
                files_scanned += 1
            elif Path(target).is_dir():
                skip_dirs = {
                    ".git", ".venv", "venv", "node_modules", "__pycache__",
                    "dist", "build", ".next", ".open-next", ".turbo",
                    ".nuxt", ".output", ".svelte-kit", ".vercel", ".wrangler",
                    "coverage", "out", ".cache",
                }
                for _root, dirs, files in os.walk(target):
                    dirs[:] = [d for d in dirs if d not in skip_dirs]
                    files_scanned += sum(1 for f in files if Path(f).suffix in SOURCE_EXTS)

    # --- Live import verification against registries ---
    if not getattr(args, "no_verify_imports", False):
        try:
            from src.services.import_verifier import (
                collect_source_files,
                verify_file_imports_sync,
            )

            py_files, js_files = collect_source_files(targets)
            if py_files or js_files:
                import_count = len(py_files) + len(js_files)
                if not machine_output:
                    print(
                        f"  {color('🔍 Verifying imports against registries...', BLUE)}"
                        f" ({import_count} file(s))"
                    )
                import_findings = verify_file_imports_sync(py_files, js_files)
                if import_findings:
                    all_findings.extend(import_findings)
                    if not machine_output:
                        print(
                            f"  {color(f'   Found {len(import_findings)} unverified import(s)', RED)}\n"
                        )
                else:
                    if not machine_output:
                        print(
                            f"  {color('   All imports verified ✓', GREEN)}\n"
                        )
        except Exception:
            pass  # Import verification is best-effort; don't break scan

    cwd = Path.cwd()

    if (not baseline_mode) and getattr(args, "changed_only", False):
        all_findings = _filter_findings_to_changed_lines(cwd=cwd, findings=all_findings)

    suppressed_count = 0
    if getattr(args, "suppress_lint_noise", False):
        all_findings, suppressed_count = _suppress_lint_covered_findings(
            project_dir=cwd,
            findings=all_findings,
        )

    if getattr(args, "dedupe", False):
        all_findings = _dedupe_findings(all_findings)

    all_findings = _sort_findings(all_findings)

    blocks = [f for f in all_findings if f.get("severity") == "BLOCK"]
    warns = [f for f in all_findings if f.get("severity") == "WARN"]
    infos = [f for f in all_findings if f.get("severity") == "INFO"]
    drift = _calculate_drift_score(all_findings)

    verdict = "BLOCK" if blocks else ("WARN" if warns else "PASS")

    if baseline_mode:
        threshold = str(getattr(args, "fail_on_new", "BLOCK"))
        has_new_threshold = any(
            _severity_meets_threshold(str(f.get("severity", "INFO")), threshold)
            for f in all_findings
        )
        if has_new_threshold:
            verdict = "BLOCK" if threshold == "BLOCK" else ("WARN" if threshold == "WARN" else verdict)

    result = {
        "verdict": verdict,
        "files_scanned": files_scanned,
        "total_findings": len(all_findings),
        "blocks": len(blocks),
        "warnings": len(warns),
        "infos": len(infos),
        "drift_score": drift,
        "baseline": baseline_ref if baseline_mode else "",
        "fail_on_new": str(getattr(args, "fail_on_new", "")) if baseline_mode else "",
        "findings": all_findings,
    }

    # Human output (do not mix with machine-readable modes)
    if not machine_output:
        gates = _detect_verify_gates(cwd)
        if gates:
            gates_str = ", ".join(gates[:4]) + ("" if len(gates) <= 4 else ", …")
            print(color(f"  🔒 Repo gates detected: {gates_str}", BLUE))
            print(color("  Tip: run these gates before merging to reduce CI churn\n", BLUE))

        if suppressed_count:
            print(color(f"  🧹 Suppressed {suppressed_count} linter-covered finding(s) (opt-in)", BLUE))
            print()

        print(f"\n{color('🛡️  CodeTrust Scan', BOLD)}")
        print(f"   Files: {files_scanned} | Findings: {len(all_findings)}")
        print(f"   AI Drift Score: {drift['score']}/100 ({drift['grade']})\n")

        if blocks:
            print(color("  🚫 BLOCK — must fix:", RED))
            for f in blocks:
                print(f"     {f['file']}:{f['line']} [{f['rule_id']}] {f['message']}")
            print()

        if warns:
            print(color("  ⚠️  WARN — should fix:", YELLOW))
            for f in warns[:20]:
                print(f"     {f['file']}:{f['line']} [{f['rule_id']}] {f['message']}")
            if len(warns) > 20:
                print(f"     ... and {len(warns) - 20} more")
            print()

        if infos:
            print(color("  i  INFO:", BLUE))
            for f in infos[:10]:
                print(f"     {f['file']}:{f['line']} [{f['rule_id']}] {f['message']}")
            if len(infos) > 10:
                print(f"     ... and {len(infos) - 10} more")
            print()

        if not blocks and not warns and not infos:
            print(color("  ✅ PASS — no issues found\n", GREEN))

    # JSON output (pure JSON on stdout)
    if getattr(args, "json", False):
        print(json.dumps(result, indent=2, default=str))

    # SARIF output
    if getattr(args, "sarif", False) or getattr(args, "sarif_file", ""):
        sarif_doc = _findings_to_sarif(all_findings)
        sarif_json = json.dumps(sarif_doc, indent=2, default=str)
        if getattr(args, "sarif_file", ""):
            Path(args.sarif_file).write_text(sarif_json, encoding="utf-8")
            if not machine_output:
                print(f"  SARIF written to {args.sarif_file}")
        else:
            # Pure SARIF to stdout (do not mix with JSON)
            if not getattr(args, "json", False):
                print(sarif_json)

    def _should_fail(v: str, fail_on: str) -> bool:
        if fail_on == "never":
            return False
        if fail_on == "block":
            return v == "BLOCK"
        return fail_on == "warn" and v in ("BLOCK", "WARN")

    if baseline_mode:
        threshold = str(getattr(args, "fail_on_new", "BLOCK"))
        fail = any(
            _severity_meets_threshold(str(f.get("severity", "INFO")), threshold)
            for f in all_findings
        )
        return 1 if fail else 0

    fail_on = str(getattr(args, "fail_on", "block"))
    return 1 if _should_fail(verdict, fail_on) else 0


# --- Status command ---


def cmd_status(_args: argparse.Namespace) -> int:
    """Check which enforcement layers are installed."""
    project_dir = Path.cwd()

    print(f"\n{color('🛡️  CodeTrust Status', BOLD)}\n")

    checks = [
        ("CLAUDE.md", (project_dir / "CLAUDE.md").exists()),
        (".cursorrules", (project_dir / ".cursorrules").exists()),
        (
            "Pre-commit hook",
            (project_dir / "hooks" / "pre-commit").exists()
            or (project_dir / ".git" / "hooks" / "pre-commit").exists(),
        ),
        (
            "GitHub Action",
            (project_dir / ".github" / "workflows" / "codetrust-scan.yml").exists(),
        ),
    ]

    # Check core.hooksPath
    hooks_path_set = False
    try:
        result = subprocess.run(
            ["git", "config", "core.hooksPath"],
            capture_output=True,
            text=True,
            cwd=project_dir,
        )
        hooks_path_set = result.returncode == 0 and result.stdout.strip() == "hooks"
    except FileNotFoundError:
        hooks_path_set = False  # git not found

    all_ok = True
    for name, installed in checks:
        icon = color("✅", GREEN) if installed else color("❌", RED)
        print(f"  {icon} {name}")
        if not installed:
            all_ok = False

    icon = color("✅", GREEN) if hooks_path_set else color("❌", RED)
    print(f"  {icon} core.hooksPath = hooks")
    if not hooks_path_set:
        all_ok = False

    print()
    if all_ok:
        print(color("  All enforcement layers active.\n", GREEN))
    else:
        print(f"  Run {color('codetrust init', BOLD)} to install missing layers.\n")

    return 0 if all_ok else 1


# --- Doctor command ---


def _doctor_fix(*, project_dir: Path, yes: bool) -> list[str]:
    """Install missing enforcement layers.

    Returns a list of actions performed.
    """
    actions: list[str] = []

    # 1) Ensure hooks/pre-commit exists
    hooks_dir = project_dir / "hooks"
    hooks_dir.mkdir(exist_ok=True)

    hook_file = hooks_dir / "pre-commit"
    hook_content = _load_template("pre-commit")
    wrote_hook = _write_text_file_safe(hook_file, hook_content, yes=yes)
    if wrote_hook:
        actions.append("Installed hooks/pre-commit")
    try:
        hook_file.chmod(0o755)
    except OSError:
        actions.append("Warning: could not chmod hooks/pre-commit")

    # Legacy hook fallback
    git_dir = project_dir / ".git"
    if git_dir.is_dir():
        legacy_hook = git_dir / "hooks" / "pre-commit"
        wrote_legacy = _write_text_file_safe(legacy_hook, hook_content, yes=yes)
        if wrote_legacy:
            actions.append("Installed .git/hooks/pre-commit (legacy fallback)")
        try:
            legacy_hook.chmod(0o755)
        except OSError:
            actions.append("Warning: could not chmod .git/hooks/pre-commit")

        # Activate version-controlled hooks
        try:
            subprocess.run(
                ["git", "config", "core.hooksPath", "hooks"],
                cwd=project_dir,
                capture_output=True,
                text=True,
                check=False,
            )
            actions.append("Set git core.hooksPath=hooks")
        except Exception as exc:
            actions.append(f"Warning: could not set core.hooksPath ({exc})")

    # 2) Ensure governance config
    ct_toml = project_dir / ".codetrust.toml"
    wrote_toml = _write_text_file_safe(ct_toml, _load_template("codetrust.toml"), yes=yes)
    if wrote_toml:
        actions.append("Installed .codetrust.toml")

    # 3) Ensure GitHub Action workflow
    wf = project_dir / ".github" / "workflows" / "codetrust-scan.yml"
    wf.parent.mkdir(parents=True, exist_ok=True)
    wrote_wf = _write_text_file_safe(wf, _load_template("codetrust-scan.yml"), yes=yes)
    if wrote_wf:
        actions.append("Installed .github/workflows/codetrust-scan.yml")

    # 4) Ensure .cursorrules
    cursorrules = project_dir / ".cursorrules"
    wrote_cursor = _write_text_file_safe(cursorrules, _load_template("cursorrules"), yes=yes)
    if wrote_cursor:
        actions.append("Installed .cursorrules")

    # 5) Ensure CLAUDE.md (only if missing)
    claude_md = project_dir / "CLAUDE.md"
    if not claude_md.exists():
        wrote_claude = _write_text_file_safe(claude_md, _load_template("CLAUDE.md"), yes=yes)
        if wrote_claude:
            actions.append("Installed CLAUDE.md")

    # 6) Ensure .gitignore contains CodeTrust patterns
    gitignore = project_dir / ".gitignore"
    patterns_to_add = ["codetrust-report.md", ".codetrust/"]
    try:
        existing = gitignore.read_text(encoding="utf-8", errors="ignore") if gitignore.exists() else ""
        missing = [p for p in patterns_to_add if p not in existing]
        if missing:
            if not gitignore.exists():
                gitignore.write_text("\n".join(missing) + "\n", encoding="utf-8")
            else:
                with open(gitignore, "a", encoding="utf-8") as f:
                    f.write("\n# CodeTrust\n")
                    for p in missing:
                        f.write(f"{p}\n")
            actions.append("Updated .gitignore (CodeTrust patterns)")
    except OSError:
        actions.append("Warning: could not update .gitignore")

    return actions


def cmd_doctor(args: argparse.Namespace) -> int:
    """Run diagnostic checks on CodeTrust installation."""
    print(f"\n{color('🛡️  CodeTrust Doctor', BOLD)}\n")

    issues: list[str] = []
    project_dir = Path.cwd()

    # 1. Check git
    if not (project_dir / ".git").is_dir():
        issues.append("Not a git repository")

    # 1b. Check git hook activation (core.hooksPath)
    hooks_path = ""
    try:
        result = subprocess.run(
            ["git", "config", "core.hooksPath"],
            capture_output=True,
            text=True,
            cwd=project_dir,
        )
        hooks_path = result.stdout.strip() if result.returncode == 0 else ""
    except FileNotFoundError:
        hooks_path = ""

    hooks_path_set = hooks_path == "hooks"
    if hooks_path_set:
        print(f"  {color('✅', GREEN)} core.hooksPath = hooks")
    else:
        print(f"  {color('⚠️', YELLOW)}  core.hooksPath not set to hooks")
        print(f"     Fix: {color('git config core.hooksPath hooks', BOLD)}")

    # 2. Check CLAUDE.md has enforcement section
    claude_md = project_dir / "CLAUDE.md"
    if claude_md.exists():
        content = claude_md.read_text()
        if "codetrust" not in content.lower():
            issues.append("CLAUDE.md exists but doesn't mention CodeTrust")
            print(f"  {color('⚠️', YELLOW)}  CLAUDE.md missing CodeTrust rules")
        else:
            print(f"  {color('✅', GREEN)} CLAUDE.md has CodeTrust enforcement")
    else:
        issues.append("CLAUDE.md not found")
        print(f"  {color('❌', RED)} CLAUDE.md not found")

    # 3. Check hook is executable
    hook = project_dir / "hooks" / "pre-commit"
    if hook.exists():
        if os.access(hook, os.X_OK):
            print(f"  {color('✅', GREEN)} Pre-commit hook is executable")
        else:
            issues.append("Pre-commit hook not executable")
            print(f"  {color('❌', RED)} Pre-commit hook not executable")
    else:
        issues.append("Pre-commit hook not found")
        print(f"  {color('❌', RED)} Pre-commit hook not found")

    legacy_hook = project_dir / ".git" / "hooks" / "pre-commit"
    if legacy_hook.exists() and not hooks_path_set:
        print(f"  {color('⚠️', YELLOW)}  Legacy hook detected (.git/hooks/pre-commit)")
        print(f"     Recommendation: {color('git config core.hooksPath hooks', BOLD)} (version-controlled hooks)")
    if hook.exists() and not hooks_path_set:
        issues.append("core.hooksPath not set to hooks (hook may not run)")

    # 4. Test hook works
    if hook.exists() and os.access(hook, os.X_OK):
        result = subprocess.run(
            [sys.executable, str(hook)],
            capture_output=True,
            text=True,
            cwd=project_dir,
        )
        if result.returncode == 0:
            print(f"  {color('✅', GREEN)} Pre-commit hook runs successfully")
        else:
            print(f"  {color('⚠️', YELLOW)}  Pre-commit hook returned exit code {result.returncode}")

    # 5. Check GitHub Action
    action = project_dir / ".github" / "workflows" / "codetrust-scan.yml"
    if action.exists():
        print(f"  {color('✅', GREEN)} GitHub Action workflow exists")
    else:
        issues.append("GitHub Action not found")
        print(f"  {color('❌', RED)} GitHub Action not found")

    print()
    if not issues:
        print(color("  All checks passed. CodeTrust is fully operational.\n", GREEN))
        return 0

    if getattr(args, "fix", False):
        yes = bool(getattr(args, "yes", False))
        actions = _doctor_fix(project_dir=project_dir, yes=yes)
        if actions:
            print(color("  Applied fixes:", GREEN))
            for a in actions:
                print(f"    - {a}")
            print()
        else:
            print(color("  No safe fixes applied.", YELLOW))
            print()

        print(color("  Re-checking...\n", BLUE))
        return cmd_doctor(argparse.Namespace(fix=False, yes=False))

    print(f"  {len(issues)} issue(s) found. Run {color('codetrust doctor --fix', BOLD)} to install missing layers.\n")
    return 1


# --- PR risk command ---


def cmd_pr_risk(args: argparse.Namespace) -> int:
    """Estimate PR risk based on changed files (git diff)."""
    project_dir = Path.cwd()
    changed_files, staged = _get_git_changed_files(cwd=project_dir)
    risk = _compute_pr_risk(project_dir=project_dir, changed_files=changed_files, staged=staged)

    if getattr(args, "json", False):
        payload = {**risk, "staged": staged}
        print(json.dumps(payload, indent=2, default=str))
        return 0

    print(f"\n{color('📡 CodeTrust PR Risk Radar', BOLD)}")
    scope = "staged changes" if staged else "working tree vs HEAD"
    print(f"   Scope: {scope}")
    print(f"   Changed files: {int(risk.get('changed_files_count', 0) or 0)}")
    print(f"   Changed lines: {int(risk.get('changed_lines', 0) or 0)}")
    print(f"   Risk: {risk['level']} ({risk['score']}/{PR_RISK_MAX_SCORE})\n")

    eps = risk.get("touched_endpoints", [])
    if isinstance(eps, list) and eps:
        print(color("  Touched endpoints:", BLUE))
        for ep in eps[:8]:
            print(f"    - {ep}")
        if len(eps) > 8:
            print(f"    ... and {len(eps) - 8} more")
        print()

    signals = risk.get("signals", [])
    if isinstance(signals, list) and signals:
        print(color("  Top signals:", BLUE))
        for s in signals[:6]:
            label = str(s.get("label", ""))
            points = int(s.get("points", 0) or 0)
            print(f"    - +{points}: {label}")
        print()
    else:
        print(color("  No high-risk touchpoints detected from file paths.", GREEN))
        print()

    return 0


# --- Governance command ---


def cmd_governance(args: argparse.Namespace) -> int:
    """Manage AI governance policies."""
    from src.gateway.policies import PolicyEngine

    project_dir = Path.cwd()
    engine = PolicyEngine.from_workspace(str(project_dir))

    if args.setup:
        print(f"\n{color('🛡️  CodeTrust Gateway — MCP Setup', BOLD)}\n")
        print("  Add to your AI client's MCP configuration:\n")
        print(f"  {color('Claude Desktop', BOLD)} (~/.claude/claude_desktop_config.json):\n")
        print('  {')
        print('    "mcpServers": {')
        print('      "codetrust-gateway": {')
        print('        "command": "python",')
        print('        "args": ["-m", "src.gateway.server"],')
        print(f'        "cwd": "{project_dir}"')
        print('      }')
        print('    }')
        print('  }\n')
        print(f"  {color('Cursor', BOLD)} (.cursorrules already installed):\n")
        print("  The gateway works alongside .cursorrules enforcement.")
        print("  For full interception, add the MCP server config above.\n")
        print(f"  {color('Configuration', BOLD)}:\n")
        print("    Config file:  .codetrust.toml")
        print("    Audit log:    .codetrust/audit.jsonl")
        print("    Env override: CODETRUST_GOVERNANCE_MODE=enforce|audit|off\n")
        return 0

    if args.mode:
        toml_path = project_dir / ".codetrust.toml"
        if toml_path.is_file():
            content = toml_path.read_text()
            import re as _re
            content = _re.sub(
                r'mode\s*=\s*"[^"]*"',
                f'mode = "{args.mode}"',
                content,
            )
            toml_path.write_text(content)
            print(f"  {color('✅', GREEN)} Governance mode set to: {args.mode}")
        else:
            print(f"  {color('❌', RED)} No .codetrust.toml found. Run: codetrust init")
            return 1
        return 0

    # Default: show status
    config = engine.config
    policies = engine.get_policies()
    enabled = sum(1 for p in policies if p.enabled)
    disabled = sum(1 for p in policies if not p.enabled)

    print(f"\n{color('🛡️  CodeTrust Governance Status', BOLD)}\n")
    print(f"  Mode:     {color(config.mode.value.upper(), GREEN if config.mode.value == 'enforce' else YELLOW)}")
    print(f"  Enabled:  {config.enabled}")
    print(f"  Policies: {enabled} active, {disabled} disabled")
    print(f"  Audit:    {config.audit_path}")
    print()

    print(f"  {color('Terminal Policies:', BOLD)}")
    terminal_flags = {
        "Heredoc":       config.block_heredoc,
        "Eval":          config.block_eval,
        "Sudo su":       config.block_sudo,
        "rm -rf /":      config.block_rm_rf,
        "curl|sh":       config.block_curl_pipe_sh,
        "git push":      config.block_git_push,
        "chmod 777":     config.block_chmod_777,
    }
    for name, enabled_flag in terminal_flags.items():
        icon = color("✅", GREEN) if enabled_flag else color("⚪", BLUE)
        print(f"    {icon} {name}")

    print()
    if config.protected_paths:
        print(f"  {color('Protected Files:', BOLD)}")
        for p in config.protected_paths:
            print(f"    🔒 {p}")
        print()

    return 0


# --- Audit command ---


def cmd_audit(args: argparse.Namespace) -> int:
    """Query the governance audit log."""
    import time as _time

    from src.gateway.audit import AuditLogger
    from src.gateway.policies import PolicyEngine

    project_dir = Path.cwd()
    engine = PolicyEngine.from_workspace(str(project_dir))
    audit = AuditLogger(
        project_dir / engine.config.audit_path,
        enabled=engine.config.audit_enabled,
    )

    if getattr(args, "purge", False):
        retention = engine.config.retention_days
        purged = audit.purge(older_than_days=retention)
        remaining = audit.entry_count()
        print(f"Purged {purged} entries older than {retention} days. {remaining} entries remaining.")
        return 0

    if args.stats:
        stats = audit.get_stats()
        print(f"\n{color('📊 Audit Statistics', BOLD)}\n")
        if stats["total"] == 0:
            print("  No audit entries found.\n")
            return 0
        print(f"  Total actions: {stats['total']}")
        for verdict, count in stats.get("by_verdict", {}).items():
            v_color = RED if verdict == "BLOCK" else (YELLOW if verdict == "WARN" else GREEN)
            print(f"  {color(verdict, v_color)}: {count}")
        if stats.get("top_rules"):
            print(f"\n  {color('Top Triggered Rules:', BOLD)}")
            for rule in stats["top_rules"][:5]:
                print(f"    {rule['rule_id']}: {rule['count']}x")
        print()
        return 0

    # Show recent entries
    since = _time.time() - (args.hours * 3600)
    entries = audit.get_entries(
        since=since,
        verdict=args.verdict,
        limit=50,
    )

    # SIEM export path
    fmt = getattr(args, "format", "table")
    if fmt != "table":
        from src.gateway.siem import SiemFormat, export_entries, export_to_file

        siem_fmt = SiemFormat(fmt)
        if args.export:
            count = export_to_file(entries, siem_fmt, args.export)
            print(f"Exported {count} entries to {args.export} ({fmt})")
            return 0
        for line in export_entries(entries, siem_fmt):
            print(line)
        return 0

    print(f"\n{color(f'📋 Audit Log — Last {args.hours} Hours', BOLD)}\n")

    if not entries:
        print("  No entries found.\n")
        return 0

    for entry in entries:
        ts = _time.strftime("%H:%M:%S", _time.localtime(entry.timestamp))
        v_color = RED if entry.verdict == "BLOCK" else (YELLOW if entry.verdict == "WARN" else GREEN)
        verdict_str = color(entry.verdict.ljust(5), v_color)
        action = entry.original_action[:70]
        if len(entry.original_action) > 70:
            action += "..."
        rule = entry.rule_id or "-"
        print(f"  {ts}  {verdict_str}  {rule.ljust(28)}  {action}")

    print(f"\n  Showing {len(entries)} entries.\n")
    return 0


# --- Main ---


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="codetrust",
        description="CodeTrust — AI code verification. Install, scan, enforce.",
    )
    subparsers = parser.add_subparsers(dest="command")

    # init
    init_parser = subparsers.add_parser("init", help="Install enforcement layers")
    init_parser.add_argument("--force", action="store_true", help="Overwrite existing files")

    # add
    add_parser = subparsers.add_parser(
        "add",
        help="Add CodeTrust repo bootstrap files (.vscode/.devcontainer/CONTRIBUTING)",
    )
    add_parser.add_argument(
        "--settings",
        action="store_true",
        help="Also write .vscode/settings.json defaults (only missing keys)",
    )
    add_parser.add_argument(
        "--stack",
        choices=["auto", "nextjs", "node", "python", "go", "generic"],
        default="auto",
        help="Stack presets to apply when writing settings.json (default: auto-detect)",
    )
    add_parser.add_argument(
        "--devcontainer",
        action="store_true",
        help="Also write/merge .devcontainer/devcontainer.json",
    )
    add_parser.add_argument(
        "--contributing",
        action="store_true",
        help="Also append a CodeTrust section to CONTRIBUTING.md (if present)",
    )
    add_parser.add_argument(
        "--yes",
        action="store_true",
        help="Overwrite/merge without prompting",
    )

    # scan
    scan_parser = subparsers.add_parser("scan", help="Scan files for anti-patterns")
    scan_parser.add_argument("targets", nargs="*", default=["."], help="Files or directories")
    scan_parser.add_argument("--json", action="store_true", help="Output as JSON")
    scan_parser.add_argument("--sarif", action="store_true", help="Output as SARIF v2.1.0")
    scan_parser.add_argument("--sarif-file", type=str, default="", help="Write SARIF to file")
    scan_parser.add_argument(
        "--fail-on",
        dest="fail_on",
        choices=["never", "warn", "block"],
        default="block",
        help="Exit non-zero when verdict meets threshold (default: block)",
    )
    scan_parser.add_argument(
        "--no-verify-imports",
        action="store_true",
        help="Skip live registry verification of imports",
    )
    scan_parser.add_argument(
        "--changed-only",
        action="store_true",
        help="Only report findings that fall on changed lines (uses git diff)",
    )
    scan_parser.add_argument(
        "--baseline",
        type=str,
        default="",
        help="Baseline git ref (e.g. origin/main). When set, gates on new findings vs baseline and scans only files changed against that ref.",
    )
    scan_parser.add_argument(
        "--fail-on-new",
        dest="fail_on_new",
        choices=["INFO", "WARN", "BLOCK"],
        default="BLOCK",
        help="Exit non-zero if NEW findings include this severity or higher (requires --baseline). Default: BLOCK.",
    )
    scan_parser.add_argument(
        "--dedupe",
        action="store_true",
        help="Dedupe identical findings for noise control",
    )
    scan_parser.add_argument(
        "--suppress-lint-noise",
        dest="suppress_lint_noise",
        action="store_true",
        help="Suppress findings commonly covered by existing linters (opt-in)",
    )

    # fix
    fix_parser = subparsers.add_parser("fix", help="Apply safe deterministic autofix recipes")
    fix_parser.add_argument("targets", nargs="*", default=["."], help="Files or directories")
    fix_parser.add_argument(
        "--apply",
        action="store_true",
        help="Write changes to disk (default: preview only)",
    )

    # status
    subparsers.add_parser("status", help="Check installed enforcement layers")

    # doctor
    doctor_parser = subparsers.add_parser("doctor", help="Diagnose CodeTrust installation")
    doctor_parser.add_argument(
        "--fix",
        action="store_true",
        help="Install missing enforcement layers (safe; no overwrite without confirmation)",
    )
    doctor_parser.add_argument(
        "--yes",
        action="store_true",
        help="Apply fixes without prompting (when safe)",
    )

    # pr-risk
    pr_parser = subparsers.add_parser("pr-risk", help="Estimate PR risk based on changed files")
    pr_parser.add_argument("--json", action="store_true", help="Output as JSON")

    # trust-diff
    td_parser = subparsers.add_parser("trust-diff", help="Compare trust/drift between HEAD and current changes")
    td_parser.add_argument("--json", action="store_true", help="Output as JSON")

    # trend
    trend_parser = subparsers.add_parser("trend", help="Record/show drift trend snapshots")
    trend_sub = trend_parser.add_subparsers(dest="subcommand")

    trend_show = trend_sub.add_parser("show", help="Show last snapshots")
    trend_show.add_argument("--limit", type=int, default=20, help="How many entries to show")
    trend_show.add_argument("--json", action="store_true", help="Output as JSON")

    trend_record = trend_sub.add_parser("record", help="Record a snapshot")
    trend_record.add_argument("targets", nargs="*", default=["."], help="Files or directories")
    trend_record.add_argument("--json", action="store_true", help="Output as JSON")

    # governance
    gov_parser = subparsers.add_parser("governance", help="Manage AI governance policies")
    gov_parser.add_argument("--setup", action="store_true", help="Show MCP gateway setup instructions")
    gov_parser.add_argument("--status", action="store_true", help="Show current governance status")
    gov_parser.add_argument("--mode", choices=["enforce", "audit", "off"], help="Set governance mode")

    # policy
    policy_parser = subparsers.add_parser("policy", help="Policy wizard for governance config")
    policy_sub = policy_parser.add_subparsers(dest="subcommand")
    policy_wizard = policy_sub.add_parser("wizard", help="Generate policy presets + config autocomplete")
    policy_wizard.add_argument(
        "--profile",
        choices=list(POLICY_PROFILE_CHOICES),
        default=POLICY_DEFAULT_PROFILE,
        help="Policy preset: startup|team|enterprise (default: team)",
    )
    policy_wizard.add_argument(
        "--pyproject",
        choices=["auto", "skip", "force"],
        default="auto",
        help="Sync into pyproject.toml [tool.codetrust]: auto|skip|force (default: auto)",
    )
    policy_wizard.add_argument(
        "--yes",
        action="store_true",
        help="Overwrite/update without prompting",
    )

    # audit
    audit_parser = subparsers.add_parser("audit", help="Query governance audit log")
    audit_parser.add_argument("--hours", type=int, default=24, help="Hours to look back (default: 24)")
    audit_parser.add_argument("--verdict", choices=["ALLOW", "WARN", "BLOCK"], help="Filter by verdict")
    audit_parser.add_argument("--stats", action="store_true", help="Show aggregate statistics")
    audit_parser.add_argument(
        "--format",
        choices=["table", "cef", "leef", "syslog", "json"],
        default="table",
        help="Output format: table (default), cef, leef, syslog, json",
    )
    audit_parser.add_argument(
        "--export",
        type=str,
        default="",
        help="Export audit entries to file in the chosen --format",
    )
    audit_parser.add_argument(
        "--purge",
        action="store_true",
        help="Purge entries older than retention_days (default: 90 days)",
    )

    args = parser.parse_args()

    if args.command == "init":
        return cmd_init(args)
    if args.command == "add":
        # default to full bootstrap when no specific targets requested
        if not args.devcontainer and not args.contributing:
            args.devcontainer = True
            args.contributing = True
        if not args.settings:
            args.settings = True
        return cmd_add(args)
    if args.command == "scan":
        return cmd_scan(args)
    if args.command == "fix":
        return cmd_fix(args)
    if args.command == "status":
        return cmd_status(args)
    if args.command == "doctor":
        return cmd_doctor(args)
    if args.command == "pr-risk":
        return cmd_pr_risk(args)
    if args.command == "trust-diff":
        return cmd_trust_diff(args)
    if args.command == "trend":
        return cmd_trend(args)
    if args.command == "governance":
        return cmd_governance(args)
    if args.command == "policy":
        return cmd_policy(args)
    if args.command == "audit":
        return cmd_audit(args)

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
