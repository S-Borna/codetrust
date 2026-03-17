# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
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
import ast
import importlib.resources
import json
import os
import re
import shutil
import subprocess
import sys
import time
import tomllib
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

from src.rules.anti_patterns import (
    ANTI_PATTERNS,
    DEVOPS_EXTENSIONS,
    DEVOPS_FILENAMES,
    SQL_EXTENSIONS,
)
from src.services.rule_catalog import RULE_CATALOG

if TYPE_CHECKING:
    from collections.abc import Iterable

    from src.gateway.audit import AuditEntry, AuditLogger
    from src.gateway.policies import GovernanceConfig, PolicyEngine


logger = structlog.get_logger()


def _echo(
    *args: object,
    sep: str = " ",
    end: str = "\n",
    file: object | None = None,
    flush: bool = False,
) -> None:
    """Write CLI output to stdout (or specified stream).

    Centralised output function for the CLI. Accepts the same
    arguments as the built-in ``print`` while keeping lint clean
    and allowing future output-format hooks (JSON, quiet mode, etc.).
    """
    target = file if file is not None else sys.stdout
    target.write(sep.join(str(a) for a in args) + end)
    if flush:
        target.flush()

_SECONDS_PER_HOUR: int = 3_600
_PREV_BLOCK_LOOKBACK: int = 200


def _init_cli_rule_categories() -> dict[str, list[tuple[str, str, str]]]:
    """Create empty category buckets for CLI rule routing."""
    return {
        "generic_block": [], "generic_warn": [], "generic_info": [],
        "sql_block": [], "sql_warn": [], "sql_info": [],
        "docker_block": [], "docker_warn": [],
        "ci_block": [], "ci_warn": [], "ci_info": [],
        "devops_block": [], "devops_warn": [], "devops_info": [],
        "react_block": [], "react_warn": [],
        "k8s_block": [], "k8s_warn": [], "k8s_info": [],
        "ruby_block": [], "ruby_warn": [], "ruby_info": [],
        "php_block": [], "php_warn": [], "php_info": [],
        "ps_block": [], "ps_warn": [], "ps_info": [],
        "nginx_block": [], "nginx_warn": [], "nginx_info": [],
        "bicep_block": [], "bicep_warn": [], "bicep_info": [],
        "redis_block": [], "redis_warn": [], "redis_info": [],
        "systemd_block": [], "systemd_warn": [], "systemd_info": [],
    }


def _classify_rule_entry(
    cats: dict[str, list[tuple[str, str, str]]],
    rule: dict[str, object],
    entry: tuple[str, str, str],
    severity: str,
) -> None:
    """Place a single rule entry into the correct category bucket."""
    file_types = rule.get("file_types")
    sev_lower = severity.lower()
    if file_types:
        ft_set = set(str(t) for t in file_types)  # type safety: file_types is object
        rule_id = str(rule["id"])
        if ft_set & SQL_EXTENSIONS:
            cats[f"sql_{sev_lower}"].append(entry)
        elif rule_id.startswith("react_"):
            cats.get(f"react_{sev_lower}", cats["react_warn"]).append(entry)
        elif rule_id.startswith("k8s_"):
            cats.get(f"k8s_{sev_lower}", cats["k8s_warn"]).append(entry)
        elif ft_set & {".dockerfile"}:
            cats.get(f"docker_{sev_lower}", cats["docker_warn"]).append(entry)
        elif rule_id.startswith("ci_"):
            cats.get(f"ci_{sev_lower}", cats["ci_warn"]).append(entry)
        elif ft_set == {".rb"}:
            cats.get(f"ruby_{sev_lower}", cats["ruby_warn"]).append(entry)
        elif ft_set == {".php"}:
            cats.get(f"php_{sev_lower}", cats["php_warn"]).append(entry)
        elif ft_set & {".ps1", ".psm1"}:
            cats.get(f"ps_{sev_lower}", cats["ps_warn"]).append(entry)
        elif rule_id.startswith("redis_"):
            cats.get(f"redis_{sev_lower}", cats["redis_warn"]).append(entry)
        elif rule_id.startswith("systemd_"):
            cats.get(f"systemd_{sev_lower}", cats["systemd_warn"]).append(entry)
        elif ft_set == {".conf"}:
            cats.get(f"nginx_{sev_lower}", cats["nginx_warn"]).append(entry)
        elif ft_set == {".bicep"}:
            cats.get(f"bicep_{sev_lower}", cats["bicep_warn"]).append(entry)
        else:
            cats.get(f"devops_{sev_lower}", cats["devops_warn"]).append(entry)
    else:
        cats.get(f"generic_{sev_lower}", cats["generic_warn"]).append(entry)


def _build_cli_rules() -> dict[str, list[tuple[str, str, str]]]:
    """Build CLI rule lists from the authoritative backend ANTI_PATTERNS.

    Returns categorized (id, pattern, message) tuples grouped by severity
    and file_types for the CLI's file-type routing logic.
    Rules with special_handler are skipped here — they are implemented
    directly in scan_file() as multi-line / file-level checks.
    """
    cats = _init_cli_rule_categories()

    for rule in ANTI_PATTERNS:
        if rule.get("special_handler"):
            continue  # CLI does regex-only; skip rules needing Python handlers

        severity = str(rule["severity"])  # Severity enum -> str
        entry = (rule["id"], rule["pattern"], rule["message"])
        _classify_rule_entry(cats, rule, entry, severity)

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
CI_BLOCK_RULES = _CLI_RULES["ci_block"]
CI_WARN_RULES = _CLI_RULES["ci_warn"]
CI_INFO_RULES = _CLI_RULES.get("ci_info", [])
DEVOPS_BLOCK_RULES = _CLI_RULES["devops_block"]
DEVOPS_WARN_RULES = _CLI_RULES["devops_warn"]
DEVOPS_INFO_RULES = _CLI_RULES["devops_info"]
REACT_BLOCK_RULES = _CLI_RULES["react_block"]
REACT_WARN_RULES = _CLI_RULES["react_warn"]
K8S_BLOCK_RULES = _CLI_RULES["k8s_block"]
K8S_WARN_RULES = _CLI_RULES["k8s_warn"]
K8S_INFO_RULES = _CLI_RULES.get("k8s_info", [])
RUBY_BLOCK_RULES = _CLI_RULES["ruby_block"]
RUBY_WARN_RULES = _CLI_RULES["ruby_warn"]
PHP_BLOCK_RULES = _CLI_RULES["php_block"]
PHP_WARN_RULES = _CLI_RULES["php_warn"]
PS_BLOCK_RULES = _CLI_RULES["ps_block"]
PS_WARN_RULES = _CLI_RULES["ps_warn"]
PS_INFO_RULES = _CLI_RULES["ps_info"]
NGINX_BLOCK_RULES = _CLI_RULES["nginx_block"]
NGINX_WARN_RULES = _CLI_RULES["nginx_warn"]
NGINX_INFO_RULES = _CLI_RULES["nginx_info"]
BICEP_BLOCK_RULES = _CLI_RULES["bicep_block"]
BICEP_WARN_RULES = _CLI_RULES["bicep_warn"]
REDIS_BLOCK_RULES = _CLI_RULES["redis_block"]
REDIS_WARN_RULES = _CLI_RULES["redis_warn"]
SYSTEMD_WARN_RULES = _CLI_RULES["systemd_warn"]
SYSTEMD_INFO_RULES = _CLI_RULES["systemd_info"]

SOURCE_EXTS = {
    ".py", ".js", ".ts", ".tsx", ".jsx",
    ".go", ".rs", ".java", ".cs",
    ".rb", ".php",
    ".sh", ".ps1", ".psm1", ".psd1",
    ".sql",
    ".yml", ".yaml", ".toml",
    ".tf", ".tfvars", ".hcl",
    ".cpp", ".c", ".h",
    ".html", ".htm",
    ".conf", ".bicep",
    ".service", ".timer", ".ini", ".cfg",
}
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

_SCAN_SKIP_DIRS: frozenset[str] = frozenset({
    ".git", ".venv", "venv", "node_modules", "__pycache__",
    "dist", "build", ".next", ".open-next", ".turbo",
    ".nuxt", ".output", ".svelte-kit", ".vercel", ".wrangler",
    "coverage", "out", ".cache",
})
_SCAN_MAX_WARN_DISPLAY: int = 20
_SCAN_MAX_INFO_DISPLAY: int = 10
_SCAN_MAX_GATES_DISPLAY: int = 4
_SCAN_MAX_RULES_TELEMETRY: int = 50
_SCAN_MAX_FINDINGS_TELEMETRY: int = 50
_AUDIT_ENTRY_LIMIT: int = 50
_AUDIT_TOP_RULES_DISPLAY: int = 5

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


PR_RISK_FILE_COUNT_LARGE = 50
PR_RISK_FILE_COUNT_MED = 20
PR_RISK_FILE_COUNT_SMALL = 10
PR_RISK_DIFF_LARGE = 800
PR_RISK_DIFF_MED = 300
PR_RISK_DIFF_SMALL = 100
PR_RISK_ENDPOINT_LIMIT = 25
PR_RISK_ENDPOINT_DISPLAY = 10

PR_RISK_DIFF_RULES: list[tuple[str, int, tuple[str, ...]]] = [
    ("Authorization changes", 20, ("authorization", "x-api-key", "bearer")),
    ("Tenant boundary changes", 15, ("tenant", "org_id", "organization_id")),
    ("Schema / migration changes", 20, ("alter table", "create table", "drop table", "alembic")),
    ("Sensitive data handling", 15, ("pii", "ssn", "credit card", "gdpr", "retention")),
    ("CI/CD changes", 10, (".github/workflows", "timeout-minutes", "uses:")),
]


def _pr_risk_file_path_signals(
    lowered: list[str],
    signals: list[dict[str, object]],
) -> int:
    """Score risk from file-path keyword matches. Returns points added."""
    total = 0
    for label, points, needles in PR_RISK_RULES:
        hit_files: list[str] = [
            f for f in lowered if any(n in f for n in needles)
        ]
        if hit_files:
            total += points
            signals.append({
                "label": label,
                "points": points,
                "matched": sorted(set(hit_files))[:10],
            })
    return total


def _pr_risk_volume_signal(
    count: int,
    label: str,
    thresholds: list[tuple[int, int]],
    signals: list[dict[str, object]],
) -> int:
    """Score risk from a volume metric (file count or line count)."""
    for threshold, points in thresholds:
        if count >= threshold:
            signals.append({"label": label, "points": points, "matched": [str(count)]})
            return points
    return 0


def _pr_risk_diff_content_signals(
    norm_files: list[str],
    project_dir: Path,
    staged: bool,
    signals: list[dict[str, object]],
) -> tuple[int, list[str]]:
    """Score risk from diff content keywords. Returns (points, endpoints)."""
    total = 0
    touched_endpoints: list[str] = []
    for rel in norm_files:
        diff_text = _get_git_file_diff(cwd=project_dir, staged=staged, path=rel)
        if not diff_text:
            continue
        touched_endpoints.extend(_extract_touched_endpoints(diff_text))
        low = diff_text.lower()
        for label, points, needles in PR_RISK_DIFF_RULES:
            if any(n in low for n in needles):
                total += points
                signals.append({"label": label, "points": points, "matched": [rel]})
    return total, touched_endpoints


def _pr_risk_endpoint_signal(
    touched_endpoints: list[str],
    signals: list[dict[str, object]],
) -> tuple[int, list[str]]:
    """Score risk from touched API endpoints. Returns (points, deduped list)."""
    if not touched_endpoints:
        return 0, []
    seen_ep: set[str] = set()
    unique_eps: list[str] = []
    for ep in touched_endpoints:
        if ep not in seen_ep:
            seen_ep.add(ep)
            unique_eps.append(ep)
    deduped = unique_eps[:PR_RISK_ENDPOINT_LIMIT]
    signals.append({
        "label": "API endpoints touched",
        "points": 20,
        "matched": deduped[:PR_RISK_ENDPOINT_DISPLAY],
    })
    return 20, deduped


_PR_RISK_FILE_THRESHOLDS: list[tuple[int, int]] = [
    (PR_RISK_FILE_COUNT_LARGE, 15), (PR_RISK_FILE_COUNT_MED, 10), (PR_RISK_FILE_COUNT_SMALL, 5),
]
_PR_RISK_DIFF_THRESHOLDS: list[tuple[int, int]] = [
    (PR_RISK_DIFF_LARGE, 20), (PR_RISK_DIFF_MED, 10), (PR_RISK_DIFF_SMALL, 5),
]


def _compute_pr_risk(
    *,
    project_dir: Path,
    changed_files: list[str],
    staged: bool,
) -> dict[str, object]:
    """Compute a PR risk score from changed files, diff stats, and diff content."""
    norm_files = [_normalize_path_for_git(f, cwd=project_dir) for f in changed_files]
    signals: list[dict[str, object]] = []
    lowered = [f.lower() for f in norm_files]

    total = _pr_risk_file_path_signals(lowered, signals)
    file_count = len(set(norm_files))
    total += _pr_risk_volume_signal(file_count, "Many files changed", _PR_RISK_FILE_THRESHOLDS, signals)

    numstat = _get_git_numstat(cwd=project_dir, staged=staged)
    total_changed_lines = sum(int(a) + int(d) for f in norm_files for a, d in [numstat.get(f, (0, 0))])
    total += _pr_risk_volume_signal(total_changed_lines, "Large diff", _PR_RISK_DIFF_THRESHOLDS, signals)

    diff_pts, touched_endpoints = _pr_risk_diff_content_signals(norm_files, project_dir, staged, signals)
    total += diff_pts
    ep_pts, touched_endpoints = _pr_risk_endpoint_signal(touched_endpoints, signals)
    total += ep_pts

    score = min(PR_RISK_MAX_SCORE, total)
    if score >= PR_RISK_HIGH_THRESHOLD:
        level = "HIGH"
    elif score >= PR_RISK_MED_THRESHOLD:
        level = "MED"
    else:
        level = "LOW"
    signals_sorted = sorted(signals, key=lambda s: int(s.get("points", 0) or 0), reverse=True)
    return {
        "score": score, "level": level, "signals": signals_sorted,
        "changed_files": sorted(set(norm_files)), "changed_files_count": file_count,
        "changed_lines": total_changed_lines, "touched_endpoints": touched_endpoints,
        "touched_endpoints_count": len(touched_endpoints),
    }


def _is_line_in_ranges(line: int, ranges: Iterable[tuple[int, int]]) -> bool:
    return any(start <= line <= end for start, end in ranges)


def _git_diff_file_ranges(
    rel: str,
    has_staged: bool,
    cwd: Path,
) -> list[tuple[int, int]]:
    """Run git diff --unified=0 on a single file and parse changed ranges."""
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
        return _parse_unified0_changed_ranges(diff.stdout)
    except (OSError, ValueError) as exc:
        logger.debug("git_diff_unified0_failed", path=rel, error=str(exc))
        return []


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
        ranges = _git_diff_file_ranges(rel, has_staged, cwd)
        if ranges:
            result[rel] = ranges

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


_PRINT_RE = re.compile(r"^(\s*)print\s*\(")


def _replace_print_with_logging(lines: list[str]) -> tuple[list[str], bool]:
    """Replace leading print() calls with logging.info() in a line list."""
    changed = False
    out_lines: list[str] = []
    for line in lines:
        m = _PRINT_RE.match(line)
        if m:
            indent = m.group(1)
            out_lines.append(indent + "logging.info(" + line[m.end():])
            changed = True
        else:
            out_lines.append(line)
    return out_lines, changed


def _find_import_insert_position(out_lines: list[str]) -> int:
    """Find the line index where 'import logging' should be inserted."""
    insert_at = 0
    if out_lines and out_lines[0].startswith("#!"):
        insert_at = 1
    if len(out_lines) > insert_at and "coding" in out_lines[insert_at]:
        insert_at += 1

    # Handle module docstring.
    if len(out_lines) > insert_at and out_lines[insert_at].lstrip().startswith(('"""', "'''")):
        delim = '"""' if '"""' in out_lines[insert_at] else "'''"
        i = insert_at
        if out_lines[i].count(delim) >= 2:
            insert_at = i + 1
        else:
            i += 1
            while i < len(out_lines):
                if delim in out_lines[i]:
                    insert_at = i + 1
                    break
                i += 1
    return insert_at


def _autofix_print_debug_python(code: str) -> tuple[str, bool]:
    """Deterministic autofix: replace leading print(...) with logging.info(...).

    Also ensures `import logging` exists.
    """
    lines = code.splitlines(keepends=True)
    out_lines, changed = _replace_print_with_logging(lines)
    new_code = "".join(out_lines)

    if "import logging" in new_code:
        return new_code, changed
    if not changed:
        return new_code, False

    insert_at = _find_import_insert_position(out_lines)
    out_lines.insert(insert_at, "import logging\n")
    return "".join(out_lines), True


_FIX_EXCLUDE_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build"}


def _is_excluded_for_fix(path: Path, project_dir: Path) -> bool:
    """Check whether a file path should be excluded from autofix."""
    try:
        rel = str(path.resolve().relative_to(project_dir.resolve())).replace("\\", "/")
    except Exception:
        rel = str(path).replace("\\", "/")

    parts = {p for p in Path(rel).parts if p}
    if parts & _FIX_EXCLUDE_DIRS:
        return True

    exclude_paths = PROJECT_CONFIG.get("exclude_paths", [])
    if isinstance(exclude_paths, list):
        for pat in exclude_paths:
            if isinstance(pat, str) and pat and pat in rel:
                return True
    return False


def _collect_fix_targets(targets: list[str], project_dir: Path) -> list[Path]:
    """Collect Python files eligible for autofix from target paths."""
    files: list[Path] = []
    for t in targets:
        p = Path(t)
        if p.is_file():
            files.append(p)
        elif p.is_dir():
            for fp in sorted(p.rglob("*.py")):
                if not _is_excluded_for_fix(fp, project_dir):
                    files.append(fp)
    return files


def _apply_fixes_to_files(
    files: list[Path],
    apply: bool,
) -> tuple[int, int]:
    """Run autofix on files. Returns (changed_files_count, changed_lines_count)."""
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
    return changed_files, changed_lines


def _report_fix_telemetry(
    args: argparse.Namespace,
    changed_files: int,
    changed_lines: int,
    apply: bool,
) -> None:
    """Send autofix telemetry (best-effort)."""
    try:
        from importlib.metadata import version as _pkg_version
        pkg_version = _pkg_version("codetrust")
    except Exception:
        pkg_version = "unknown"
    try:
        from src.telemetry_client import send_telemetry
        send_telemetry(
            event_type="fix_applied",
            source="cli",
            version=pkg_version,
            payload={
                "fixes_applied": changed_files,
                "files_changed": changed_files,
                "lines_changed": changed_lines,
                "applied": bool(apply),
            },
        )
    except Exception:
        pass  # best-effort


def cmd_fix(args: argparse.Namespace) -> int:
    """Apply safe deterministic autofix recipes to files."""
    targets = getattr(args, "targets", []) or ["."]
    apply = bool(getattr(args, "apply", False))
    project_dir = Path.cwd()

    files = _collect_fix_targets(targets, project_dir)
    if not files:
        _echo("No files to fix.")
        return 0

    changed_files, changed_lines = _apply_fixes_to_files(files, apply)

    if apply:
        _echo(f"Applied fixes to {changed_files} file(s).")
    else:
        _echo(f"Fix preview: {changed_files} file(s) would change. Re-run with --apply to write.")

    if changed_files > 0:
        _report_fix_telemetry(args, changed_files, changed_lines, apply)

    return 0


_VULN_DEP_FILES = (
    "requirements.txt", "setup.py", "pyproject.toml",
    "package.json", "Cargo.toml", "go.mod", "pom.xml",
)


def _collect_packages_from_targets(
    targets: list[str],
    language_hint: str,
    dep_files: tuple[str, ...] = _VULN_DEP_FILES,
) -> list[str]:
    """Collect dependency package names from target files/directories."""
    packages: list[str] = []
    for t in targets:
        p = Path(t)
        if p.is_file():
            _collect_dependency_packages(p, packages, language_hint)
        elif p.is_dir():
            for dep_file in dep_files:
                candidate = p / dep_file
                if candidate.exists():
                    _collect_dependency_packages(candidate, packages, language_hint)
    return packages


def _resolve_language(language_hint: str, targets: list[str]) -> object:
    """Resolve a Language enum from hint string, falling back to detection."""
    if not language_hint:
        language_hint = _detect_language_from_dep_files(targets)
    from src.models.enums import Language
    try:
        return Language(language_hint) if language_hint else Language.PYTHON
    except ValueError:
        return Language.PYTHON


def _format_vuln_json(result: object) -> str:
    """Format vulnerability scan result as JSON string."""
    out = {
        "total_packages": result.total_packages,
        "vulnerable_count": result.vulnerable_count,
        "clean_count": result.clean_count,
        "total_vulnerabilities": result.total_vulnerabilities,
        "critical_count": result.critical_count,
        "high_count": result.high_count,
        "medium_count": result.medium_count,
        "low_count": result.low_count,
        "results": [
            {
                "package": r.package,
                "ecosystem": r.ecosystem,
                "is_vulnerable": r.is_vulnerable,
                "vulnerabilities": [
                    {"id": v.id, "severity": v.severity, "summary": v.summary,
                     "fixed_version": v.fixed_version}
                    for v in r.vulnerabilities
                ],
            }
            for r in result.results
        ],
    }
    return json.dumps(out, indent=2)


_VULN_SUMMARY_MAX_LEN = 80


def _format_vuln_text(result: object) -> None:
    """Print vulnerability scan result as human-readable text."""
    _echo("\n  CodeTrust Vulnerability Scan")
    _echo(f"  {'=' * 40}")
    _echo(f"  Packages scanned: {result.total_packages}")
    _echo(f"  Vulnerable:       {result.vulnerable_count}")
    _echo(f"  Clean:            {result.clean_count}")
    _echo(f"  Total CVEs:       {result.total_vulnerabilities}")
    if result.critical_count:
        _echo(f"  Critical:         {result.critical_count}")
    if result.high_count:
        _echo(f"  High:             {result.high_count}")
    if result.medium_count:
        _echo(f"  Medium:           {result.medium_count}")
    if result.low_count:
        _echo(f"  Low:              {result.low_count}")
    _echo()
    for r in result.results:
        if r.is_vulnerable:
            _echo(f"  VULNERABLE: {r.package} ({r.ecosystem})")
            for v in r.vulnerabilities:
                fixed = f" -> fix: {v.fixed_version}" if v.fixed_version else ""
                _echo(f"    [{v.severity}] {v.id}: {v.summary[:_VULN_SUMMARY_MAX_LEN]}{fixed}")
            _echo()


def cmd_vuln(args: argparse.Namespace) -> int:
    """Scan dependencies for known vulnerabilities via the OSV database."""
    targets = getattr(args, "targets", []) or ["."]
    lang_str = getattr(args, "language", "") or ""
    json_output = bool(getattr(args, "json_output", False))
    language_hint = lang_str.lower().strip()

    packages = _collect_packages_from_targets(targets, language_hint)
    if not packages:
        _echo("No dependency packages found. Specify a requirements.txt, package.json, etc.")
        return 0

    language = _resolve_language(language_hint, targets)

    import asyncio

    from src.services.cache import CacheService
    from src.services.vulnerability import VulnerabilityService

    async def _run() -> object:
        cache = CacheService("redis://localhost:6379")
        await cache.connect()
        import httpx
        async with httpx.AsyncClient(timeout=30.0) as http_client:
            vuln_svc = VulnerabilityService(cache, http_client)
            result = await vuln_svc.check_packages(language=language, packages=packages)
        await cache.disconnect()
        return result

    result = asyncio.run(_run())

    if json_output:
        _echo(_format_vuln_json(result))
    else:
        _format_vuln_text(result)

    return 1 if result.vulnerable_count > 0 else 0


_LICENSE_DEP_FILES = ("requirements.txt", "package.json")


def _format_license_json(result: object) -> str:
    """Format license check result as JSON string."""
    out = {
        "total_packages": result.total_packages,
        "compliant": result.compliant,
        "permissive_count": result.permissive_count,
        "weak_copyleft_count": result.weak_copyleft_count,
        "strong_copyleft_count": result.strong_copyleft_count,
        "network_copyleft_count": result.network_copyleft_count,
        "risk_packages": [
            {"package": r.package, "license": r.license_name, "risk": r.risk.value}
            for r in result.risk_packages
        ],
    }
    return json.dumps(out, indent=2)


def _format_license_text(result: object) -> None:
    """Print license check result as human-readable text."""
    _echo("\n  CodeTrust License Compliance Check")
    _echo(f"  {'=' * 40}")
    _echo(f"  Packages checked: {result.total_packages}")
    _echo(f"  Compliant:        {'Yes' if result.compliant else 'NO'}")
    _echo(f"  Permissive:       {result.permissive_count}")
    if result.weak_copyleft_count:
        _echo(f"  Weak copyleft:    {result.weak_copyleft_count}")
    if result.strong_copyleft_count:
        _echo(f"  Strong copyleft:  {result.strong_copyleft_count}")
    if result.network_copyleft_count:
        _echo(f"  Network copyleft: {result.network_copyleft_count}")
    if result.unknown_count:
        _echo(f"  Unknown:          {result.unknown_count}")
    _echo()
    if result.risk_packages:
        _echo("  Risk packages:")
        for r in result.risk_packages:
            _echo(f"    [{r.risk.value.upper()}] {r.package}: {r.license_name}")
        _echo()


def cmd_license(args: argparse.Namespace) -> int:
    """Check dependency licenses for compliance."""
    targets = getattr(args, "targets", []) or ["."]
    lang_str = getattr(args, "language", "") or ""
    json_output = bool(getattr(args, "json_output", False))
    language_hint = lang_str.lower().strip()

    packages = _collect_packages_from_targets(targets, language_hint, dep_files=_LICENSE_DEP_FILES)
    if not packages:
        _echo("No dependency packages found.")
        return 0

    language = _resolve_language(language_hint, targets)

    import asyncio

    from src.services.cache import CacheService
    from src.services.license_checker import LicenseService

    async def _run() -> object:
        cache = CacheService("redis://localhost:6379")
        await cache.connect()
        import httpx
        async with httpx.AsyncClient(timeout=30.0) as http_client:
            license_svc = LicenseService(cache, http_client)
            result = await license_svc.check_packages(language=language, packages=packages)
        await cache.disconnect()
        return result

    result = asyncio.run(_run())

    if json_output:
        _echo(_format_license_json(result))
    else:
        _format_license_text(result)

    return 0 if result.compliant else 1


_PKG_SPEC_SPLIT_RE = re.compile(r"[>=<!~\[]")


def _parse_requirements_txt(content: str, packages: list[str]) -> None:
    """Extract package names from requirements.txt content."""
    for line in content.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and not line.startswith("-"):
            pkg = _PKG_SPEC_SPLIT_RE.split(line)[0].strip()
            if pkg:
                packages.append(pkg)


def _parse_package_json(content: str, packages: list[str]) -> None:
    """Extract package names from package.json content."""
    try:
        data = json.loads(content)
        for section in ("dependencies", "devDependencies"):
            deps = data.get(section, {})
            if isinstance(deps, dict):
                packages.extend(deps.keys())
    except json.JSONDecodeError as exc:
        logger.debug("Skipping malformed package.json: %s", exc)


def _parse_cargo_toml(content: str, packages: list[str]) -> None:
    """Extract package names from Cargo.toml content."""
    for line in content.splitlines():
        line = line.strip()
        if "=" in line and not line.startswith("[") and not line.startswith("#"):
            pkg = line.split("=")[0].strip()
            if pkg and not pkg.startswith("["):
                packages.append(pkg)


def _parse_go_mod(content: str, packages: list[str]) -> None:
    """Extract package names from go.mod content."""
    in_require = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped == "require (":
            in_require = True
            continue
        if in_require and stripped == ")":
            in_require = False
            continue
        if in_require and stripped:
            pkg = stripped.split()[0]
            packages.append(pkg)


def _parse_pyproject_toml_deps(content: str, packages: list[str]) -> None:
    """Extract dependency names from pyproject.toml content."""
    in_deps = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped in ("[project.dependencies]", "dependencies = ["):
            in_deps = True
            continue
        if in_deps:
            if stripped.startswith("[") or stripped == "]":
                in_deps = False
                continue
            pkg = stripped.strip("\",' ")
            pkg = _PKG_SPEC_SPLIT_RE.split(pkg)[0].strip()
            if pkg:
                packages.append(pkg)


def _collect_dependency_packages(filepath: Path, packages: list[str], language_hint: str) -> None:
    """Extract package names from a dependency file."""
    name = filepath.name.lower()
    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return

    if name == "requirements.txt" or (name.endswith(".txt") and "require" in name):
        _parse_requirements_txt(content, packages)
    elif name == "package.json":
        _parse_package_json(content, packages)
    elif name == "cargo.toml":
        _parse_cargo_toml(content, packages)
    elif name == "go.mod":
        _parse_go_mod(content, packages)
    elif name == "pyproject.toml":
        _parse_pyproject_toml_deps(content, packages)


def _detect_language_from_dep_files(targets: list[str]) -> str:
    """Detect language from dependency files in target paths."""
    for t in targets:
        p = Path(t)
        if p.is_dir():
            if (p / "requirements.txt").exists() or (p / "pyproject.toml").exists():
                return "python"
            if (p / "package.json").exists():
                return "javascript"
            if (p / "go.mod").exists():
                return "go"
            if (p / "Cargo.toml").exists():
                return "rust"
            if (p / "pom.xml").exists():
                return "java"
            if (p / "Gemfile").exists():
                return "ruby"
            if (p / "composer.json").exists():
                return "php"
            if (p / "*.csproj").exists() or any((p).glob("*.csproj")):
                return "csharp"
        elif p.is_file():
            name = p.name.lower()
            if "requirements" in name or name == "pyproject.toml":
                return "python"
            if name == "package.json":
                return "javascript"
            if name == "go.mod":
                return "go"
            if name == "cargo.toml":
                return "rust"
            if name == "gemfile":
                return "ruby"
            if name == "composer.json":
                return "php"
    return ""


def _detect_npm_gates(project_dir: Path) -> list[str]:
    """Detect verification commands from package.json scripts."""
    gates: list[str] = []
    package_json = project_dir / "package.json"
    if not package_json.is_file():
        return gates
    data = _read_json_if_exists(package_json)
    scripts = data.get("scripts") if isinstance(data, dict) else None
    if isinstance(scripts, dict):
        if "verify" in scripts:
            gates.append("npm run verify")
        else:
            for k in ("lint", "test", "typecheck", "build"):
                if k in scripts:
                    gates.append(f"npm run {k}")
    return gates


def _detect_python_gates(project_dir: Path) -> list[str]:
    """Detect verification commands from pyproject.toml and config files."""
    gates: list[str] = []
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
            pass  # Best-effort detection only
    if ((project_dir / "pytest.ini").is_file() or (project_dir / "tox.ini").is_file()) and "pytest" not in gates:
        gates.append("pytest")
    if ((project_dir / ".ruff.toml").is_file() or (project_dir / "ruff.toml").is_file()) and "ruff check" not in gates:
        gates.append("ruff check")
    if (project_dir / "tsconfig.json").is_file():
        gates.append("tsc")
    return gates


def _detect_verify_gates(project_dir: Path) -> list[str]:
    """Best-effort detection of common repo verification gates.

    Used only for human-facing hints (must never affect machine outputs).
    """
    gates = _detect_npm_gates(project_dir) + _detect_python_gates(project_dir)

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


_CLI_ENTRYPOINTS = {"cli.py", "scan_runner.py", "scan.py"}
_TEST_PREFIXES = ("test_", "conftest")
_TEST_INFIXES = (".test.", ".spec.")


def _is_test_file(basename: str) -> bool:
    """Return True if basename indicates a test file."""
    return (
        basename.startswith(_TEST_PREFIXES)
        or any(infix in basename for infix in _TEST_INFIXES)
    )


_DEVOPS_K8S_RULES = (
    BLOCK_RULES + DEVOPS_BLOCK_RULES + K8S_BLOCK_RULES,
    WARN_RULES + DEVOPS_WARN_RULES + K8S_WARN_RULES,
    INFO_RULES + DEVOPS_INFO_RULES + K8S_INFO_RULES,
)


def _select_rule_sets(
    ext: str,
    is_dockerfile: bool,
    is_react: bool,
    is_ci: bool,
    is_k8s: bool,
    is_devops: bool,
    is_ruby: bool = False,
    is_php: bool = False,
    is_powershell: bool = False,
    is_nginx: bool = False,
    is_bicep: bool = False,
    is_systemd: bool = False,
) -> tuple[
    list[tuple[str, str, str]],
    list[tuple[str, str, str]],
    list[tuple[str, str, str]],
]:
    """Select (block, warn, info) rule sets based on file type flags."""
    if ext in SQL_EXTS:
        return SQL_BLOCK_RULES, SQL_WARN_RULES, SQL_INFO_RULES
    if is_dockerfile:
        return (
            BLOCK_RULES + DOCKER_BLOCK_RULES + DEVOPS_BLOCK_RULES,
            WARN_RULES + DOCKER_WARN_RULES + DEVOPS_WARN_RULES,
            INFO_RULES,
        )
    if is_react:
        return BLOCK_RULES + REACT_BLOCK_RULES, WARN_RULES + REACT_WARN_RULES, INFO_RULES
    if is_ruby:
        return BLOCK_RULES + RUBY_BLOCK_RULES, WARN_RULES + RUBY_WARN_RULES, INFO_RULES
    if is_php:
        return BLOCK_RULES + PHP_BLOCK_RULES, WARN_RULES + PHP_WARN_RULES, INFO_RULES
    if is_powershell:
        return (
            BLOCK_RULES + PS_BLOCK_RULES + DEVOPS_BLOCK_RULES,
            WARN_RULES + PS_WARN_RULES + DEVOPS_WARN_RULES,
            INFO_RULES + PS_INFO_RULES + DEVOPS_INFO_RULES,
        )
    if is_systemd:
        return [], SYSTEMD_WARN_RULES, SYSTEMD_INFO_RULES
    if is_nginx:
        return (
            NGINX_BLOCK_RULES + REDIS_BLOCK_RULES + DEVOPS_BLOCK_RULES,
            NGINX_WARN_RULES + REDIS_WARN_RULES + DEVOPS_WARN_RULES,
            NGINX_INFO_RULES + DEVOPS_INFO_RULES,
        )
    if is_bicep:
        return BLOCK_RULES + BICEP_BLOCK_RULES, WARN_RULES + BICEP_WARN_RULES, INFO_RULES
    if is_ci:
        return (
            _DEVOPS_K8S_RULES[0] + CI_BLOCK_RULES,
            WARN_RULES + CI_WARN_RULES + DEVOPS_WARN_RULES + K8S_WARN_RULES,
            _DEVOPS_K8S_RULES[2] + CI_INFO_RULES,
        )
    if is_k8s:
        return _DEVOPS_K8S_RULES
    if is_devops:
        return BLOCK_RULES + DEVOPS_BLOCK_RULES, WARN_RULES + DEVOPS_WARN_RULES, INFO_RULES + DEVOPS_INFO_RULES
    return BLOCK_RULES, WARN_RULES, INFO_RULES


def _append_rule_matches(
    line: str,
    line_num: int,
    filepath: str,
    rules: list[tuple[str, str, str]],
    severity: str,
    findings: list[dict[str, str | int]],
    skip_rule_id: str = "",
) -> None:
    """Append findings for all rules matching a single line."""
    for rule_id, pattern, message in rules:
        if skip_rule_id and rule_id == skip_rule_id:
            continue
        if re.search(pattern, line):
            findings.append({
                "rule_id": rule_id, "severity": severity,
                "message": message, "file": filepath, "line": line_num,
            })


def _is_docstring_boundary_cli(stripped: str) -> bool:
    """Check if a line toggles docstring state (open/close boundary).

    Only triggers on lines where triple-quotes appear at the START,
    not when referenced inside code (e.g. ``if '\"\"\"' in text:``).
    """
    for quote in ('"""', "'''"):
        if stripped.startswith(quote) and stripped.count(quote) == 1:
            return True
    return False


def _match_line_rules(
    lines: list[str],
    filepath: str,
    block_rules: list[tuple[str, str, str]],
    warn_rules: list[tuple[str, str, str]],
    info_rules: list[tuple[str, str, str]],
    is_cli_entrypoint: bool,
) -> list[dict[str, str | int]]:
    """Match per-line regex rules and return findings."""
    findings: list[dict[str, str | int]] = []
    _noqa = "no" + "qa"   # split to avoid self-triggering suppress_lint rule
    _type_ign = "type: " + "ignore"
    _eslint_dis = "eslint-" + "disable"
    skip_warn = "print_debug" if is_cli_entrypoint else ""
    in_docstring = False

    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        if _is_docstring_boundary_cli(stripped):
            in_docstring = not in_docstring
        # Skip anti-pattern matching inside docstrings
        if in_docstring:
            continue
        if _noqa in line or _type_ign in line or _eslint_dis in line:
            for rule_id, pattern, message in warn_rules:
                if rule_id == "suppress_lint" and re.search(pattern, line):
                    findings.append({
                        "rule_id": rule_id, "severity": "WARN",
                        "message": message, "file": filepath, "line": line_num,
                    })
            if "noqa" in line:
                continue
        _append_rule_matches(line, line_num, filepath, block_rules, "BLOCK", findings)
        _append_rule_matches(line, line_num, filepath, warn_rules, "WARN", findings, skip_rule_id=skip_warn)
        _append_rule_matches(line, line_num, filepath, info_rules, "INFO", findings)
    return findings


def _check_dockerfile_file_level(
    lines: list[str],
    filepath: str,
    findings: list[dict[str, str | int]],
) -> None:
    """Run file-level Dockerfile checks (USER, WORKDIR, HEALTHCHECK)."""
    content = "".join(lines)
    if not re.search(r"^\s*USER\s+\S+", content, re.MULTILINE):
        findings.append({
            "rule_id": "docker_root_user", "severity": "WARN",
            "message": "Dockerfile has no USER instruction \u2014 runs as root.",
            "file": filepath, "line": 1,
        })
    if not re.search(r"^\s*WORKDIR\s+", content, re.MULTILINE):
        findings.append({
            "rule_id": "docker_no_workdir", "severity": "INFO",
            "message": "Dockerfile has no WORKDIR \u2014 set explicit working directory.",
            "file": filepath, "line": 1,
        })
    if re.search(r"^\s*CMD\s", content, re.MULTILINE) and not re.search(r"^\s*HEALTHCHECK\s", content, re.MULTILINE):
        findings.append({
            "rule_id": "dockerfile_no_healthcheck", "severity": "INFO",
            "message": "Dockerfile has CMD but no HEALTHCHECK. Add HEALTHCHECK for container orchestration.",
            "file": filepath, "line": 1,
        })


def _run_special_handlers(
    lines: list[str],
    filepath: str,
    ext: str,
    basename: str,
    is_dockerfile: bool,
    is_devops: bool,
    is_ci: bool,
    findings: list[dict[str, str | int]],
) -> None:
    """Run all special handler checks and append findings in-place."""
    if is_dockerfile:
        _check_dockerfile_file_level(lines, filepath, findings)
    _check_except_swallow(lines, filepath, findings)
    _check_sleep_no_context(lines, filepath, findings)
    if ext == ".py":
        _check_function_length(lines, filepath, findings)
    _check_connection_timeout(lines, filepath, findings)
    if is_devops and ext in {".yml", ".yaml"} and "compose" in basename:
        _check_compose_healthcheck(lines, filepath, findings)
    if is_ci:
        _check_ci_no_timeout(lines, filepath, findings)


def _apply_config_overrides(
    findings: list[dict[str, str | int]],
) -> list[dict[str, str | int]]:
    """Filter findings by project config ignore_rules and severity_overrides."""
    ignore_rules: set[str] = set(PROJECT_CONFIG.get("ignore_rules", []))
    severity_overrides: dict[str, str] = PROJECT_CONFIG.get("severity_overrides", {})
    if not ignore_rules and not severity_overrides:
        return findings
    filtered: list[dict[str, str | int]] = []
    for f in findings:
        rid = str(f.get("rule_id", ""))
        if rid in ignore_rules:
            continue
        if rid in severity_overrides:
            f = {**f, "severity": severity_overrides[rid].upper()}
        filtered.append(f)
    return filtered


def scan_text(code: str, filepath: str) -> list[dict[str, str | int]]:
    """Scan in-memory code using the same routing logic as scan_file."""
    exclude_paths = PROJECT_CONFIG.get("exclude_paths", [])
    for pat in exclude_paths:
        if pat in filepath:
            return []

    basename = os.path.basename(filepath).lower()
    ext = Path(filepath).suffix.lower()

    if _is_test_file(basename):
        return []

    is_cli_entrypoint = basename in _CLI_ENTRYPOINTS
    is_dockerfile = basename.startswith("dockerfile")
    is_ci = ".github" in filepath and ext in {".yml", ".yaml"}
    is_devops = ext in DEVOPS_EXTS or basename in DEVOPS_NAMES
    is_react = ext in {".jsx", ".tsx"}
    is_k8s = ext in {".yml", ".yaml"} and not is_ci
    is_ruby = ext == ".rb"
    is_php = ext == ".php"
    is_powershell = ext in {".ps1", ".psm1", ".psd1"}
    is_nginx = ext == ".conf"
    is_bicep = ext == ".bicep"
    is_systemd = ext in {".service", ".timer"}

    block_rules, warn_rules, info_rules = _select_rule_sets(
        ext, is_dockerfile, is_react, is_ci, is_k8s, is_devops,
        is_ruby=is_ruby, is_php=is_php, is_powershell=is_powershell,
        is_nginx=is_nginx, is_bicep=is_bicep, is_systemd=is_systemd,
    )

    lines = code.splitlines(keepends=True)
    findings = _match_line_rules(lines, filepath, block_rules, warn_rules, info_rules, is_cli_entrypoint)
    _run_special_handlers(lines, filepath, ext, basename, is_dockerfile, is_devops, is_ci, findings)

    return _apply_config_overrides(findings)


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
    if _is_test_file(basename):
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


def _severity_counts(findings: list[dict[str, str | int]]) -> dict[str, int]:
    """Count findings by severity level."""
    return {
        "total": len(findings),
        "blocks": sum(1 for f in findings if f.get("severity") == "BLOCK"),
        "warnings": sum(1 for f in findings if f.get("severity") == "WARN"),
        "infos": sum(1 for f in findings if f.get("severity") == "INFO"),
    }


def _collect_head_and_current_findings(
    norm_files: list[str],
    project_dir: Path,
) -> tuple[list[dict[str, str | int]], list[dict[str, str | int]]]:
    """Collect findings for HEAD and current working tree."""
    head_findings: list[dict[str, str | int]] = []
    cur_findings: list[dict[str, str | int]] = []
    for rel in norm_files:
        head_text = _git_show_head(project_dir, rel)
        if head_text is not None:
            head_findings.extend(_scan_code_text(head_text, rel))
        abs_path = project_dir / rel
        if abs_path.is_file():
            cur_findings.extend(scan_file(str(abs_path)))
    return (
        _sort_findings(_dedupe_findings(head_findings)),
        _sort_findings(_dedupe_findings(cur_findings)),
    )


def _compute_trust_diff(*, project_dir: Path, changed_files: list[str], staged: bool) -> dict[str, object]:
    """Compute a trust/drift diff between HEAD and current changes."""
    norm_files = [_normalize_path_for_git(f, cwd=project_dir) for f in changed_files]
    norm_files = sorted({f for f in norm_files if Path(f).suffix.lower() in SOURCE_EXTS})

    head_findings, cur_findings = _collect_head_and_current_findings(norm_files, project_dir)
    head_drift = _calculate_drift_score(head_findings)
    cur_drift = _calculate_drift_score(cur_findings)
    head_counts = _severity_counts(head_findings)
    cur_counts = _severity_counts(cur_findings)

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
        _echo(json.dumps(report, indent=2, default=str))
        return 0

    delta = report.get("delta", {})
    head = report.get("head", {})
    cur = report.get("current", {})
    head_drift = head.get("drift", {}) if isinstance(head, dict) else {}
    cur_drift = cur.get("drift", {}) if isinstance(cur, dict) else {}
    _echo(f"\n{color('📈 CodeTrust Trust Diff', BOLD)}")
    _echo(f"   Scope: {report.get('scope', '-')}")
    _echo(f"   Files compared: {len(report.get('files', []) if isinstance(report.get('files', []), list) else [])}")
    _echo(f"   Drift score: {head_drift.get('score', 0)}/100 → {cur_drift.get('score', 0)}/100 (Δ {delta.get('drift_score', 0)})\n")
    _echo(f"   Findings Δ: total {delta.get('total_findings', 0)}, blocks {delta.get('blocks', 0)}, warns {delta.get('warnings', 0)}, infos {delta.get('infos', 0)}")
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


_TREND_DEFAULT_LIMIT = 20


def _cmd_trend_record(args: argparse.Namespace, project_dir: Path) -> int:
    """Handle 'codetrust trend record' subcommand."""
    targets = list(getattr(args, "targets", []) or ["."])
    entry = _trend_snapshot(project_dir, targets)
    _trend_write(project_dir, entry)
    if getattr(args, "json", False):
        _echo(json.dumps(entry, indent=2, default=str))
        return 0
    _echo(f"\n{color('\U0001f4cc CodeTrust Trend \u2014 Recorded', BOLD)}")
    _echo(f"   {entry['ts']} | {entry['verdict']} | drift {entry['drift_score'].get('score', 0)}/100")
    _echo(f"   Findings: {entry['total_findings']} (BLOCK {entry['blocks']}, WARN {entry['warnings']}, INFO {entry['infos']})")
    _echo(f"   Stored: {TREND_FILE_REL}\n")
    return 0


def _cmd_trend_show(args: argparse.Namespace, project_dir: Path, limit: int) -> int:
    """Handle 'codetrust trend show' subcommand."""
    entries = _trend_read(project_dir)
    entries = entries[-limit:]
    if getattr(args, "json", False):
        _echo(json.dumps({"entries": entries}, indent=2, default=str))
        return 0

    _echo(f"\n{color('\U0001f4c8 CodeTrust Trend', BOLD)}")
    if not entries:
        _echo("   No trend data yet. Run: codetrust trend record\n")
        return 0

    for e in entries:
        ts = str(e.get("ts", ""))
        verdict = str(e.get("verdict", ""))
        drift = e.get("drift_score", {})
        score = drift.get("score", 0) if isinstance(drift, dict) else 0
        total = int(e.get("total_findings", 0) or 0)
        blocks = int(e.get("blocks", 0) or 0)
        warns = int(e.get("warnings", 0) or 0)
        _echo(f"   {ts} | {verdict} | drift {score}/100 | {total} findings (B{blocks} W{warns})")
    _echo()
    return 0


def cmd_trend(args: argparse.Namespace) -> int:
    project_dir = Path.cwd()
    sub = str(getattr(args, "subcommand", "show"))
    limit = int(getattr(args, "limit", _TREND_DEFAULT_LIMIT) or _TREND_DEFAULT_LIMIT)
    if limit < 1:
        limit = 1

    if sub == "record":
        return _cmd_trend_record(args, project_dir)

    return _cmd_trend_show(args, project_dir, limit)


# ── Special handler implementations ──────────────────────────────


def _check_except_swallow(
    lines: list[str], filepath: str, findings: list[dict],
) -> None:
    """Flag except blocks that swallow errors with pass/..."""
    in_docstring = False
    for i, line in enumerate(lines):
        stripped = line.strip()
        if _is_docstring_boundary_cli(stripped):
            in_docstring = not in_docstring
        if in_docstring:
            continue
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
    """Flag sleep calls without a preceding comment explaining why."""
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
                    "message": "sleep call without explanation. Why is a delay needed? Document or fix root cause.",
                    "file": filepath,
                    "line": i + 1,
                })


def _check_function_length(
    lines: list[str], filepath: str, findings: list[dict],
) -> None:
    """Flag Python functions longer than 40 lines using AST."""
    if not filepath.endswith(".py"):
        return
    code = "\n".join(lines)
    try:
        tree = ast.parse(code)
    except SyntaxError:
        logger.debug("ast_parse_failed", filepath=filepath)
        return
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = node.end_lineno or node.lineno
            length = end - node.lineno + 1
            if length > 40:
                findings.append({
                    "rule_id": "long_function",
                    "severity": "INFO",
                    "message": (
                        f"Function '{node.name}' is "
                        f"{length} lines (max 40)."
                    ),
                    "file": filepath,
                    "line": node.lineno,
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
            prev_block = before[max(0, len(before) - _PREV_BLOCK_LOOKBACK):]
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


def _render_governance_terminal_lines(root: str, cfg: GovernanceConfig) -> list[str]:
    """Render governance core and terminal TOML lines."""
    return [
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
    ]


def _render_governance_extra_lines(root: str, cfg: GovernanceConfig) -> list[str]:
    """Render governance files, packages, audit, and webhook TOML lines."""
    lines: list[str] = [
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
    ]
    disabled_rules = sorted(cfg.disabled_rules)
    if disabled_rules:
        lines.append("")
        lines.append(f"disabled_rules = {_toml_string_array(disabled_rules)}")
    return lines


def _render_governance_sections(*, root: str, cfg: GovernanceConfig) -> str:
    """Render governance TOML sections under the given root table."""
    lines = _render_governance_terminal_lines(root, cfg)
    lines.extend(_render_governance_extra_lines(root, cfg))
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


def _policy_write_config_files(
    *, project_dir: Path, profile: str, yes: bool,
) -> None:
    """Write .codetrust.toml, .taplo.toml, and schema files."""
    ct_toml_path = project_dir / ".codetrust.toml"
    ct_content = _render_codetrust_toml_for_profile(profile)
    wrote_ct = _write_text_file_safe(ct_toml_path, ct_content, yes=yes)
    _echo(f"  {color('✅', GREEN) if wrote_ct else color('↪', BLUE)} {ct_toml_path}")

    taplo_path = project_dir / ".taplo.toml"
    wrote_taplo = _write_text_file_safe(taplo_path, _load_template("taplo.toml"), yes=yes)
    _echo(f"  {color('✅', GREEN) if wrote_taplo else color('↪', BLUE)} {taplo_path}")

    schema_path = project_dir / ".codetrust.schema.json"
    wrote_schema = _write_text_file_safe(schema_path, _load_template("codetrust.schema.json"), yes=yes)
    _echo(f"  {color('✅', GREEN) if wrote_schema else color('↪', BLUE)} {schema_path}")


def _policy_sync_pyproject(
    *, project_dir: Path, profile: str, py_mode: str, yes: bool,
) -> None:
    """Sync policy config into pyproject.toml if applicable."""
    if py_mode not in {"auto", "skip", "force"}:
        py_mode = "auto"

    pyproject = project_dir / "pyproject.toml"
    if py_mode == "skip" or not pyproject.is_file():
        return

    existing = pyproject.read_text(encoding="utf-8", errors="ignore")
    has_tool_section = "[tool.codetrust]" in existing or "[tool.codetrust." in existing

    if has_tool_section and PYPROJECT_POLICY_BEGIN not in existing and py_mode != "force":
        _echo(f"  {color('↪', BLUE)} {pyproject} (existing [tool.codetrust] found; skipping sync)")
        return

    inner = _render_pyproject_codetrust_for_profile(profile)
    updated, changed = _upsert_marked_block(
        existing,
        begin_marker=PYPROJECT_POLICY_BEGIN,
        end_marker=PYPROJECT_POLICY_END,
        inner_block=inner,
    )
    if changed:
        wrote_py = _write_text_file_safe(pyproject, updated, yes=yes)
        _echo(f"  {color('✅', GREEN) if wrote_py else color('↪', BLUE)} {pyproject} ({'synced' if wrote_py else 'no change'})")
    else:
        _echo(f"  {color('↪', BLUE)} {pyproject} (no change)")


def cmd_policy(args: argparse.Namespace) -> int:
    """Policy wizard for generating governance config presets."""
    project_dir = Path.cwd()

    sub = str(getattr(args, "subcommand", ""))
    if sub != "wizard":
        _echo("Run: codetrust policy wizard")
        return 1

    yes = bool(getattr(args, "yes", False))
    profile = str(getattr(args, "profile", POLICY_DEFAULT_PROFILE))
    if profile not in POLICY_PROFILE_CHOICES:
        _echo(f"Invalid --profile. Choose one of: {', '.join(POLICY_PROFILE_CHOICES)}")
        return 2

    _echo(f"\n{color('🧭 CodeTrust Policy Wizard', BOLD)}\n")
    _echo(f"  Profile: {profile}")

    _policy_write_config_files(project_dir=project_dir, profile=profile, yes=yes)

    py_mode = str(getattr(args, "pyproject", "auto"))
    _policy_sync_pyproject(
        project_dir=project_dir, profile=profile, py_mode=py_mode, yes=yes,
    )

    _echo("\nDone.\n")
    return 0


def _add_vscode_extensions(project_dir: Path, *, yes: bool) -> None:
    """Add CodeTrust to .vscode/extensions.json recommendations."""
    ext_file = project_dir / ".vscode" / "extensions.json"
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
    _echo(f"  {color('✅', GREEN) if wrote_ext else color('↪', BLUE)} {ext_file}")


def _add_vscode_settings(project_dir: Path, *, stack_arg: str, yes: bool) -> None:
    """Write .vscode/settings.json defaults (only missing keys)."""
    settings_file = project_dir / ".vscode" / "settings.json"
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
    stack = _detect_stack(project_dir) if stack_arg == "auto" else stack_arg
    defaults.update(_stack_settings_presets(stack))
    for k, v in defaults.items():
        if k not in settings:
            settings[k] = v
    wrote_settings = _write_json_file_safe(settings_file, settings, yes=yes)
    _echo(f"  {color('✅', GREEN) if wrote_settings else color('↪', BLUE)} {settings_file}")


def _add_devcontainer(project_dir: Path, *, yes: bool) -> None:
    """Write/merge .devcontainer/devcontainer.json."""
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
    _echo(f"  {color('✅', GREEN) if wrote_dc else color('↪', BLUE)} {dc_file}")


def _add_contributing(project_dir: Path, *, yes: bool) -> None:
    """Append CodeTrust section to CONTRIBUTING.md if not present."""
    contrib_file = project_dir / "CONTRIBUTING.md"
    if not contrib_file.exists():
        _echo(f"  {color('⚠️', YELLOW)}  CONTRIBUTING.md not found — skipping")
        return
    text = contrib_file.read_text(encoding="utf-8", errors="ignore")
    marker = "## CodeTrust"
    if marker in text:
        _echo(f"  {color('↪', BLUE)} {contrib_file} (already has CodeTrust section)")
        return
    snippet = (
        "\n\n## CodeTrust\n\n"
        "This repo uses CodeTrust as a quality gate for AI-assisted development.\n\n"
        "- Local: run `codetrust scan .` before opening a PR\n"
        "- Pre-commit: commits may be blocked until BLOCK findings are resolved\n"
        "- CI: PRs can fail the CodeTrust Quality Gate (SARIF uploaded to Security)\n"
    )
    wrote = _write_text_file_safe(contrib_file, text + snippet, yes=yes)
    _echo(f"  {color('✅', GREEN) if wrote else color('↪', BLUE)} {contrib_file}")


def cmd_add(args: argparse.Namespace) -> int:
    """Add CodeTrust bootstrap files to the current repo (VS Code/DevContainer/docs)."""
    project_dir = Path.cwd()
    yes = bool(getattr(args, "yes", False))

    _echo(f"\n{color('🧩 CodeTrust — Adding repo bootstrap files', BOLD)}\n")

    _add_vscode_extensions(project_dir, yes=yes)

    if args.settings:
        stack_arg = str(getattr(args, "stack", "auto"))
        _add_vscode_settings(project_dir, stack_arg=stack_arg, yes=yes)

    if args.devcontainer:
        _add_devcontainer(project_dir, yes=yes)

    if args.contributing:
        _add_contributing(project_dir, yes=yes)

    _echo("\nDone.\n")
    return 0


def _init_advisory_files(project_dir: Path, *, force: bool) -> list[str]:
    """Install CLAUDE.md and .cursorrules advisory files."""
    installed: list[str] = []
    claude_md = project_dir / "CLAUDE.md"
    if claude_md.exists() and not force:
        _echo(f"  {color('⚠️', YELLOW)}  CLAUDE.md exists (use --force to overwrite)")
    else:
        if claude_md.exists():
            shutil.copy2(claude_md, claude_md.with_suffix(".md.bak"))
        claude_md.write_text(_load_template("CLAUDE.md"))
        installed.append("CLAUDE.md")
        _echo(f"  {color('✅', GREEN)} CLAUDE.md installed")

    cursorrules = project_dir / ".cursorrules"
    cursorrules.write_text(_load_template("cursorrules"))
    installed.append(".cursorrules")
    _echo(f"  {color('✅', GREEN)} .cursorrules installed")
    return installed


def _init_precommit_hook(project_dir: Path) -> list[str]:
    """Install pre-commit hook via core.hooksPath."""
    installed: list[str] = []
    git_dir = project_dir / ".git"
    if not git_dir.is_dir():
        _echo(f"  {color('⚠️', YELLOW)}  Not a git repo — skipping hooks")
        return installed

    hooks_dir = project_dir / "hooks"
    hooks_dir.mkdir(exist_ok=True)
    hook_file = hooks_dir / "pre-commit"
    hook_file.write_text(_load_template("pre-commit"))
    hook_file.chmod(0o755)

    subprocess.run(
        ["git", "config", "core.hooksPath", "hooks"],
        cwd=project_dir,
        capture_output=True,
    )

    git_hook = git_dir / "hooks" / "pre-commit"
    git_hook.parent.mkdir(exist_ok=True)
    git_hook.write_text(_load_template("pre-commit"))
    git_hook.chmod(0o755)

    installed.append("pre-commit hook (core.hooksPath)")
    _echo(f"  {color('✅', GREEN)} Pre-commit hook installed via core.hooksPath")
    return installed


def _init_github_action(project_dir: Path, *, force: bool) -> list[str]:
    """Install GitHub Action workflow."""
    installed: list[str] = []
    workflows_dir = project_dir / ".github" / "workflows"
    workflows_dir.mkdir(parents=True, exist_ok=True)
    action_file = workflows_dir / "codetrust-scan.yml"
    if action_file.exists() and not force:
        _echo(f"  {color('⚠️', YELLOW)}  GitHub Action exists (use --force to overwrite)")
    else:
        action_file.write_text(_load_template("codetrust-scan.yml"))
        installed.append("GitHub Action")
        _echo(f"  {color('✅', GREEN)} GitHub Action installed")
    return installed


def _init_gitignore_and_governance(
    project_dir: Path, *, force: bool,
) -> list[str]:
    """Add .gitignore patterns and governance config + audit directory."""
    installed: list[str] = []
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

    governance_toml = project_dir / ".codetrust.toml"
    if governance_toml.exists() and not force:
        _echo(f"  {color('⚠️', YELLOW)}  .codetrust.toml exists (use --force to overwrite)")
    else:
        if governance_toml.exists():
            shutil.copy2(governance_toml, governance_toml.with_suffix(".toml.bak"))
        governance_toml.write_text(_load_template("codetrust.toml"))
        installed.append(".codetrust.toml")
        _echo(f"  {color('✅', GREEN)} Governance config (.codetrust.toml) installed")

    audit_dir = project_dir / ".codetrust"
    audit_dir.mkdir(exist_ok=True)
    installed.append(".codetrust/ audit directory")
    _echo(f"  {color('✅', GREEN)} Audit directory created")
    return installed


def _init_policy_integrity_manifest(project_dir: Path) -> list[str]:
    """Create a signed policy integrity manifest for gateway startup checks."""
    installed: list[str] = []

    from src.gateway.policy_integrity import create_policy_integrity_manifest

    sign_key = (
        os.environ.get("CODETRUST_RULES_HMAC_SECRET")
        or os.environ.get("CODETRUST_JWT_SECRET")
        or "codetrust"
    )
    try:
        from importlib.metadata import version as _pkg_version
        version = _pkg_version("codetrust")
    except Exception:
        version = "unknown"

    try:
        create_policy_integrity_manifest(
            project_dir,
            sign_key=sign_key,
            version=version,
        )
        installed.append(".codetrust/policy-integrity.json")
        _echo(f"  {color('✅', GREEN)} Policy integrity manifest signed")
    except OSError as exc:
        _echo(
            f"  {color('⚠️', YELLOW)}  Could not create policy integrity manifest: {exc}",
        )

    return installed


def _init_print_summary() -> None:
    """Print the post-init enforcement stack summary."""
    _echo(f"\n{'━' * 48}")
    _echo(f"\n  {color('✅ CodeTrust installed!', GREEN)}\n")
    _echo("  Enforcement stack:")
    _echo(f"    Layer 1: CLAUDE.md / .cursorrules  {color('(advisory)', BLUE)}")
    _echo(f"    Layer 2: VS Code extension         {color('(passive)', BLUE)}")
    _echo(f"    Layer 3: Pre-commit hook            {color('(blocking)', GREEN)}")
    _echo(f"    Layer 4: GitHub Action              {color('(absolute)', RED)}")
    _echo(f"    Layer 5: Gateway governance         {color('(interceptor)', RED)}")
    _echo()
    _echo("  Governance:")
    _echo(f"    Config:    .codetrust.toml   {color('(edit to customize)', BLUE)}")
    _echo("    Audit log: .codetrust/audit.jsonl")
    _echo("    Mode:      enforce (block violations)")
    _echo()
    _echo("  Next steps:")
    _echo("    1. Push to GitHub")
    _echo("    2. Settings → Branches → Require 'CodeTrust Quality Gate' to pass")
    _echo("    3. Install VS Code extension: code --install-extension SaidBorna.codetrust")
    _echo("    4. Add gateway to Claude/Cursor config (see: codetrust governance --setup)")
    _echo()


def cmd_init(args: argparse.Namespace) -> int:
    """Install CodeTrust enforcement layers into current project."""
    project_dir = Path.cwd()

    _echo(f"\n{color('🛡️  CodeTrust — Installing enforcement layers', BOLD)}\n")

    _init_advisory_files(project_dir, force=args.force)
    _init_precommit_hook(project_dir)
    _init_github_action(project_dir, force=args.force)
    _init_gitignore_and_governance(project_dir, force=args.force)
    _init_policy_integrity_manifest(project_dir)
    _init_print_summary()

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


def _sarif_collect_rules_and_results(
    findings: list[dict],
) -> tuple[list[dict], list[dict]]:
    """Collect unique SARIF rules and result entries from findings."""
    seen_rules: set[str] = set()
    rules: list[dict] = []
    results: list[dict] = []

    for f in findings:
        rid = str(f.get("rule_id", "unknown"))
        rule_meta = RULE_CATALOG.get(rid, {})
        sev = str(f.get("severity", rule_meta.get("severity", "INFO")))
        level = _SARIF_SEVERITY.get(sev, "note")
        sarif_rule_id = f"codetrust/{rid}"
        if rid not in seen_rules:
            seen_rules.add(rid)
            short_desc = str(rule_meta.get("description", f.get("message", "")))
            help_uri = str(rule_meta.get("help_uri", ""))
            rule_name = str(rule_meta.get("name", rid))
            properties: dict[str, object] = {}
            cwe_id = str(rule_meta.get("cwe", "")).strip()
            if cwe_id:
                properties["problem.severity"] = level
                properties["tags"] = [cwe_id]
            rules.append({
                "id": sarif_rule_id,
                "name": rule_name,
                "shortDescription": {"text": short_desc},
                "defaultConfiguration": {"level": level},
                "helpUri": help_uri,
                "properties": properties,
            })
        results.append({
            "ruleId": sarif_rule_id,
            "level": level,
            "message": {"text": str(f.get("message", ""))},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": str(f.get("file", "unknown"))},
                    "region": {"startLine": max(int(f.get("line", 1)), 1), "startColumn": 1},
                },
            }],
        })

    return rules, results


def _findings_to_sarif(findings: list[dict]) -> dict:
    """Convert CLI findings to a SARIF v2.1.0 document."""
    rules, results = _sarif_collect_rules_and_results(findings)
    return {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "CodeTrust",
                    "version": "2.1.0",
                    "informationUri": "https://codetrust.ai",
                    "rules": rules,
                },
            },
            "results": results,
        }],
    }


def _scan_baseline_changed_files(
    cwd: Path, targets: list[str], baseline_ref: str,
) -> list[str]:
    """Identify source files changed relative to baseline ref."""
    try:
        diff = subprocess.run(
            ["git", "diff", "--name-only", "--diff-filter=ACM", baseline_ref, "--"],
            cwd=cwd, capture_output=True, text=True, check=False,
        )
        changed_files = [ln.strip() for ln in diff.stdout.splitlines() if ln.strip()]
    except Exception:
        changed_files = []

    allowed: set[str] = set()
    for t in targets:
        p = Path(t)
        if p.is_file():
            allowed.add(_normalize_path_for_git(str(p), cwd=cwd) or str(p))

    scan_files: list[str] = []
    for rel in changed_files:
        if Path(rel).suffix.lower() not in SOURCE_EXTS:
            continue
        if allowed and rel not in allowed:
            continue
        if not Path(rel).exists():
            continue
        scan_files.append(rel)
    return scan_files


def _scan_baseline_filter_changed_lines(
    head_findings: list[dict[str, str | int]],
    baseline_ref: str,
    cwd: Path,
    *,
    machine_output: bool,
) -> list[dict[str, str | int]]:
    """Filter head findings to only those on lines changed vs baseline."""
    try:
        changed_ranges: dict[str, list[tuple[int, int]]] = {}
        for rel in {str(f.get("file", "")) for f in head_findings if f.get("file")}:
            base_cmd = ["git", "diff", "--unified=0", baseline_ref, "--", rel]
            d = subprocess.run(
                base_cmd, cwd=cwd, capture_output=True, text=True, check=False,
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
        return kept
    except Exception as exc:
        if not machine_output:
            _echo(
                color(
                    f"  ⚠️  Could not compute changed-line ranges vs baseline ({baseline_ref}): {exc}",
                    YELLOW,
                )
            )
        return head_findings


def _scan_baseline_collect(
    targets: list[str], baseline_ref: str, args: argparse.Namespace,
    *, machine_output: bool,
) -> tuple[list[dict[str, str | int]], int]:
    """Collect findings in baseline (diff) mode."""
    cwd = Path.cwd()
    scan_files = _scan_baseline_changed_files(cwd, targets, baseline_ref)

    baseline_findings: list[dict[str, str | int]] = []
    head_findings: list[dict[str, str | int]] = []

    for rel in scan_files:
        head_findings.extend(scan_file(rel))
        baseline_findings.extend(
            _scan_text_at_git_ref(cwd=cwd, ref=baseline_ref, rel_path=rel),
        )

    if getattr(args, "changed_only", False) and head_findings:
        head_findings = _scan_baseline_filter_changed_lines(
            head_findings, baseline_ref, cwd, machine_output=machine_output,
        )

    new_findings = _diff_new_findings_cli(head=head_findings, baseline=baseline_findings)
    return new_findings, len(scan_files)


def _scan_direct_collect(
    targets: list[str],
) -> tuple[list[dict[str, str | int]], int]:
    """Collect findings by scanning targets directly."""
    all_findings: list[dict[str, str | int]] = []
    files_scanned = 0
    for target in targets:
        findings = scan_path(target)
        all_findings.extend(findings)
        if Path(target).is_file():
            files_scanned += 1
        elif Path(target).is_dir():
            for _root, dirs, files in os.walk(target):
                dirs[:] = [d for d in dirs if d not in _SCAN_SKIP_DIRS]
                files_scanned += sum(1 for f in files if Path(f).suffix in SOURCE_EXTS)
    return all_findings, files_scanned


def _scan_process_import_findings(
    import_findings: list[dict],
    all_findings: list[dict[str, str | int]],
    args: argparse.Namespace,
    *,
    import_count: int,
    machine_output: bool,
) -> tuple[int, list[dict[str, str | int]]]:
    """Process import findings: count hallucinations, emit telemetry."""
    hallucinations_found = 0
    if import_findings:
        hallucinations_found = sum(
            1 for f in import_findings if str(f.get("rule_id", "")) == "import_not_found"
        )
        all_findings = [*all_findings, *import_findings]
        if not machine_output:
            _echo(f"  {color(f'   Found {len(import_findings)} unverified import(s)', RED)}\n")
    elif not machine_output:
        _echo(f"  {color('   All imports verified ✓', GREEN)}\n")

    try:
        from src.telemetry_client import send_telemetry as _send_import_tel

        _send_import_tel(
            event_type="import_verified",
            source="cli",
            version="unknown",
            payload={
                "total_imports_checked": import_count,
                "hallucinations_caught": hallucinations_found,
            },
        )
    except Exception:
        pass  # best-effort
    return hallucinations_found, all_findings


def _scan_verify_imports(
    targets: list[str],
    all_findings: list[dict[str, str | int]],
    args: argparse.Namespace,
    *,
    machine_output: bool,
) -> tuple[list[dict[str, str | int]], int]:
    """Verify imports against registries and return updated findings."""
    if getattr(args, "no_verify_imports", False):
        return all_findings, 0

    hallucinations_found = 0
    try:
        from src.services.import_verifier import (
            collect_source_files,
            verify_file_imports_sync,
        )

        py_files, js_files, rb_files, php_files, go_files, rs_files, java_files, cs_files = collect_source_files(targets)
        total_files = sum(len(f) for f in (py_files, js_files, rb_files, php_files, go_files, rs_files, java_files, cs_files))
        if total_files:
            if not machine_output:
                _echo(
                    f"  {color('🔍 Verifying imports against registries...', BLUE)}"
                    f" ({total_files} file(s))"
                )
            import_findings = verify_file_imports_sync(
                py_files, js_files, rb_files, php_files,
                go_files, rs_files, java_files, cs_files,
            )
            hallucinations_found, all_findings = _scan_process_import_findings(
                import_findings, all_findings, args,
                import_count=total_files, machine_output=machine_output,
            )
    except Exception as exc:
        logger.debug(
            "import_verification_failed",
            error=str(exc),
            error_type=type(exc).__name__,
        )
    return all_findings, hallucinations_found


# Extension-to-language mapping for signature validation
_SIG_EXT_LANG: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".jsx": "javascript",
}


def _scan_collect_source_files(
    targets: list[str],
) -> list[tuple[str, str]]:
    """Collect source files with language info for signature validation.

    Returns list of (filepath, language) tuples for supported languages.
    """
    result: list[tuple[str, str]] = []
    skip_dirs = {
        ".git", ".venv", "venv", "node_modules", "__pycache__",
        "dist", "build", ".next", ".open-next", ".turbo",
        ".nuxt", ".output", ".svelte-kit", ".vercel", ".wrangler",
        "coverage", "out", ".cache", "test", "__tests__",
    }
    for target in targets:
        p = Path(target)
        if p.is_file():
            ext = p.suffix.lower()
            lang = _SIG_EXT_LANG.get(ext, "")
            if lang:
                result.append((str(p), lang))
        elif p.is_dir():
            for root, dirs, files in os.walk(p):
                dirs[:] = [d for d in dirs if d not in skip_dirs]
                for fname in files:
                    ext = Path(fname).suffix.lower()
                    lang = _SIG_EXT_LANG.get(ext, "")
                    if lang:
                        fpath = os.path.join(root, fname)
                        basename = os.path.basename(fname).lower()
                        if not _is_test_file(basename):
                            result.append((fpath, lang))
    return result


def _scan_validate_signatures(
    targets: list[str],
    all_findings: list[dict[str, str | int]],
    args: argparse.Namespace,
    *,
    machine_output: bool,
) -> list[dict[str, str | int]]:
    """Run function signature validation on scanned files.

    Detects AI-hallucinated functions, wrong parameters, and deprecated API
    usage by checking calls against a curated signature database.
    """
    if getattr(args, "no_verify_signatures", False):
        return all_findings

    try:
        from src.services.signature_validator import validate_signatures

        source_files = _scan_collect_source_files(targets)
        if not source_files:
            return all_findings

        if not machine_output:
            _echo(
                f"  {color('🔬 Validating function signatures...', BLUE)}"
                f" ({len(source_files)} file(s))"
            )

        sig_findings_total = 0
        hallucinations_caught = 0

        for fpath, lang in source_files:
            try:
                with open(fpath, encoding="utf-8", errors="ignore") as f:
                    code = f.read()
                findings = validate_signatures(code, lang, fpath)
                for finding in findings:
                    all_findings.append({
                        "rule_id": finding.rule_id,
                        "severity": finding.severity.value
                        if hasattr(finding.severity, "value")
                        else str(finding.severity),
                        "message": finding.message,
                        "file": fpath,
                        "line": finding.line,
                        "suggestion": finding.suggestion,
                    })
                    sig_findings_total += 1
                    if "hallucinated" in finding.rule_id:
                        hallucinations_caught += 1
            except OSError:
                continue

        if not machine_output:
            if sig_findings_total:
                _echo(
                    f"  {color(f'   Found {sig_findings_total} signature issue(s)', RED)}"
                    f" ({hallucinations_caught} hallucination(s))\n"
                )
            else:
                _echo(f"  {color('   All signatures verified ✓', GREEN)}\n")

    except Exception as exc:
        logger.debug(
            "signature_validation_failed",
            error=str(exc),
            error_type=type(exc).__name__,
        )
    return all_findings


def _scan_post_process(
    all_findings: list[dict[str, str | int]],
    args: argparse.Namespace,
    cwd: Path,
    *,
    baseline_mode: bool,
) -> tuple[list[dict[str, str | int]], int]:
    """Apply post-processing filters (changed-only, suppress, dedupe, sort)."""
    if (not baseline_mode) and getattr(args, "changed_only", False):
        all_findings = _filter_findings_to_changed_lines(cwd=cwd, findings=all_findings)

    suppressed_count = 0
    if getattr(args, "suppress_lint_noise", False):
        all_findings, suppressed_count = _suppress_lint_covered_findings(
            project_dir=cwd, findings=all_findings,
        )

    if getattr(args, "dedupe", False):
        all_findings = _dedupe_findings(all_findings)

    all_findings = _sort_findings(all_findings)
    return all_findings, suppressed_count


def _scan_build_result(
    all_findings: list[dict[str, str | int]],
    args: argparse.Namespace,
    files_scanned: int,
    baseline_ref: str,
    *,
    baseline_mode: bool,
) -> dict:
    """Categorize findings and build scan result dict."""
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

    return {
        "verdict": verdict,
        "files_scanned": files_scanned,
        "total_findings": len(all_findings),
        "blocks": len(blocks),
        "warnings": len(warns),
        "infos": len(infos),
        "drift_score": drift,
        "baseline": baseline_ref if baseline_mode else "",
        "fail_on_new": str(getattr(args, "fail_on_new", "")) if baseline_mode else "",
        "upgrade_hints": [],
        "findings": all_findings,
    }


def _scan_telemetry_payload(
    result: dict,
    hallucinations_found: int,
    start_time: float,
    args: argparse.Namespace,
    *,
    baseline_mode: bool,
) -> dict[str, object]:
    """Build telemetry payload for scan_completed event."""
    all_findings = result.get("findings", [])
    findings_payload: list[dict[str, str]] = []
    if isinstance(all_findings, list):
        for finding in all_findings[:_SCAN_MAX_FINDINGS_TELEMETRY]:
            if not isinstance(finding, dict):
                continue
            rule_id = str(finding.get("rule_id", "") or "").strip()
            if not rule_id:
                continue
            item: dict[str, str] = {
                "rule": rule_id,
                "rule_id": rule_id,
            }
            severity = str(finding.get("severity", "") or "").strip().upper()
            if severity:
                item["severity"] = severity
            file_name = str(finding.get("file", "") or "").strip()
            if file_name:
                item["file"] = file_name
            findings_payload.append(item)
    drift = result.get("drift_score", {})
    unique_rules = list({str(f.get("rule_id", "")) for f in all_findings if f.get("rule_id")})
    output_format, _output_path = _scan_resolve_output_options(args)
    return {
        "scan_type": "static",
        "files_scanned": int(result.get("files_scanned", 0) or 0),
        "languages": {},
        "total_findings": int(result.get("total_findings", 0) or 0),
        "findings_by_severity": {
            "BLOCK": int(result.get("blocks", 0) or 0),
            "WARN": int(result.get("warnings", 0) or 0),
            "INFO": int(result.get("infos", 0) or 0),
        },
        "rules_triggered": unique_rules[:_SCAN_MAX_RULES_TELEMETRY],
        "findings": findings_payload,
        "layers_hit": [],
        "trust_score": int(drift.get("score", 0) or 0),
        "grade": str(drift.get("grade", "")),
        "trend": str(drift.get("trend", "")),
        "trend_delta": int(drift.get("delta", 0) or 0),
        "hallucinations_found": hallucinations_found,
        "scan_duration_ms": int((time.monotonic() - start_time) * 1000),
        "used_baseline": bool(baseline_mode),
        "used_dedupe": bool(getattr(args, "dedupe", False)),
        "used_sarif_output": output_format == "sarif",
        "used_json_output": output_format == "json",
    }


def _scan_resolve_output_options(args: argparse.Namespace) -> tuple[str, str]:
    """Resolve output format/path from new and legacy scan flags."""
    output_format = str(getattr(args, "format", "text") or "text")
    output_path = str(getattr(args, "output", "") or "")
    legacy_sarif_file = str(getattr(args, "sarif_file", "") or "")

    if output_format in {"json", "sarif"}:
        if output_format == "sarif" and not output_path and legacy_sarif_file:
            output_path = legacy_sarif_file
        return output_format, output_path

    if bool(getattr(args, "sarif", False)) or bool(legacy_sarif_file):
        return "sarif", output_path or legacy_sarif_file

    if bool(getattr(args, "json", False)):
        return "json", output_path

    return "text", ""


def _scan_emit_telemetry(
    args: argparse.Namespace,
    result: dict,
    hallucinations_found: int,
    start_time: float,
    *,
    baseline_mode: bool,
) -> None:
    """Emit scan_completed telemetry (best-effort, fire-and-forget)."""
    try:
        from importlib.metadata import version as _pkg_version

        pkg_version = _pkg_version("codetrust")
    except Exception:
        pkg_version = "unknown"

    try:
        from src.telemetry_client import send_telemetry

        payload = _scan_telemetry_payload(
            result, hallucinations_found, start_time, args,
            baseline_mode=baseline_mode,
        )
        send_telemetry(
            event_type="scan_completed",
            source="cli",
            version=pkg_version,
            payload=payload,
        )
    except Exception as exc:
        logger.debug(
            "telemetry_emit_failed",
            error=str(exc),
            error_type=type(exc).__name__,
            event_type="scan_completed",
            source="cli",
        )


def _scan_output_findings_by_severity(
    blocks: list[dict], warns: list[dict], infos: list[dict],
) -> None:
    """Print findings grouped by severity for human output."""
    if blocks:
        _echo(color("  🚫 BLOCK — must fix:", RED))
        for f in blocks:
            _echo(f"     {f['file']}:{f['line']} [{f['rule_id']}] {f['message']}")
        _echo()

    if warns:
        _echo(color("  ⚠️  WARN — should fix:", YELLOW))
        for f in warns[:_SCAN_MAX_WARN_DISPLAY]:
            _echo(f"     {f['file']}:{f['line']} [{f['rule_id']}] {f['message']}")
        if len(warns) > _SCAN_MAX_WARN_DISPLAY:
            _echo(f"     ... and {len(warns) - _SCAN_MAX_WARN_DISPLAY} more")
        _echo()

    if infos:
        _echo(color("  i  INFO:", BLUE))
        for f in infos[:_SCAN_MAX_INFO_DISPLAY]:
            _echo(f"     {f['file']}:{f['line']} [{f['rule_id']}] {f['message']}")
        if len(infos) > _SCAN_MAX_INFO_DISPLAY:
            _echo(f"     ... and {len(infos) - _SCAN_MAX_INFO_DISPLAY} more")
        _echo()

    if not blocks and not warns and not infos:
        _echo(color("  ✅ PASS — no issues found\n", GREEN))


def _scan_output_upgrade_hints(upgrade_hints: list[str]) -> None:
    """Print one-line Pro upgrade hint summary when available."""
    if not upgrade_hints:
        return
    _echo(
        "  i Pro features available: signature validation, CVE scanning, "
        "license compliance, trust score trending"
    )
    _echo("    Upgrade: https://app.codetrust.ai/settings")


def _scan_output_api_error(result: dict) -> bool:
    """Render known API error payloads and indicate whether output was handled."""
    error = str(result.get("error", ""))
    if error == "daily_scan_limit_reached":
        used = int(result.get("used", 0) or 0)
        limit = int(result.get("limit", 0) or 0)
        resets = str(result.get("resets_at", ""))
        _echo(color("  ⚠️  Free tier daily limit reached", YELLOW))
        _echo(f"    Usage: {used}/{limit}")
        if resets:
            _echo(f"    Resets at: {resets}")
        _echo("    Upgrade: https://app.codetrust.ai/settings")
        return True
    if error == "upgrade_required":
        required = str(result.get("required_plan", "pro"))
        _echo(color(f"  ⛔ This feature requires {required} plan", RED))
        _echo("    Upgrade: https://app.codetrust.ai/settings")
        return True
    return False


def _scan_output_human(
    result: dict,
    suppressed_count: int,
    cwd: Path,
) -> None:
    """Render human-readable scan output to terminal."""
    if _scan_output_api_error(result):
        return

    gates = _detect_verify_gates(cwd)
    if gates:
        gates_str = ", ".join(gates[:_SCAN_MAX_GATES_DISPLAY]) + (
            "" if len(gates) <= _SCAN_MAX_GATES_DISPLAY else ", …"
        )
        _echo(color(f"  🔒 Repo gates detected: {gates_str}", BLUE))
        _echo(color("  Tip: run these gates before merging to reduce CI churn\n", BLUE))

    if suppressed_count:
        _echo(color(f"  🧹 Suppressed {suppressed_count} linter-covered finding(s) (opt-in)", BLUE))
        _echo()

    drift = result.get("drift_score", {})
    _echo(f"\n{color('🛡️  CodeTrust Scan', BOLD)}")
    _echo(f"   Files: {result['files_scanned']} | Findings: {result['total_findings']}")
    _echo(f"   AI Drift Score: {drift['score']}/100 ({drift['grade']})\n")

    findings = result.get("findings", [])
    blocks = [f for f in findings if f.get("severity") == "BLOCK"]
    warns = [f for f in findings if f.get("severity") == "WARN"]
    infos = [f for f in findings if f.get("severity") == "INFO"]
    _scan_output_findings_by_severity(blocks, warns, infos)

    hints = result.get("upgrade_hints", [])
    if isinstance(hints, list):
        _scan_output_upgrade_hints([str(hint) for hint in hints])


def _scan_output_machine(
    args: argparse.Namespace,
    result: dict,
    all_findings: list[dict[str, str | int]],
    *,
    machine_output: bool,
) -> None:
    """Emit JSON and/or SARIF output."""
    output_format, output_path = _scan_resolve_output_options(args)
    if output_format == "json":
        _echo(json.dumps(result, indent=2, default=str))
        return

    if output_format == "sarif":
        sarif_doc = _findings_to_sarif(all_findings)
        sarif_json = json.dumps(sarif_doc, indent=2, default=str)
        if output_path:
            Path(output_path).write_text(sarif_json, encoding="utf-8")
            if not machine_output:
                _echo(f"  SARIF written to {output_path}")
        else:
            _echo(sarif_json)


def _scan_should_fail(verdict: str, fail_on: str) -> bool:
    """Check if scan verdict meets the failure threshold."""
    if fail_on == "never":
        return False
    if fail_on == "block":
        return verdict == "BLOCK"
    return fail_on == "warn" and verdict in ("BLOCK", "WARN")


def _scan_exit_code(
    verdict: str,
    args: argparse.Namespace,
    all_findings: list[dict[str, str | int]],
    *,
    baseline_mode: bool,
) -> int:
    """Compute the scan exit code based on verdict and settings."""
    if baseline_mode:
        threshold = str(getattr(args, "fail_on_new", "BLOCK"))
        fail = any(
            _severity_meets_threshold(str(f.get("severity", "INFO")), threshold)
            for f in all_findings
        )
        return 1 if fail else 0

    fail_on = str(getattr(args, "fail_on", "block"))
    return 1 if _scan_should_fail(verdict, fail_on) else 0


def _scan_parse_options(
    args: argparse.Namespace,
) -> tuple[list[str], bool, str, bool]:
    """Extract scan options from parsed arguments."""
    targets: list[str] = args.targets or ["."]
    output_format, output_path = _scan_resolve_output_options(args)
    explicit_format = str(getattr(args, "format", "text") or "text")
    # Preserve legacy --sarif-file behavior (human summary + file write) unless --format is used.
    if explicit_format == "text" and output_format == "sarif" and bool(output_path):
        machine_output = False
    else:
        machine_output = output_format != "text"
    baseline_ref = str(getattr(args, "baseline", "") or "").strip()
    baseline_mode = bool(baseline_ref)
    return targets, machine_output, baseline_ref, baseline_mode


def cmd_scan(args: argparse.Namespace) -> int:
    """Scan files for anti-patterns."""
    start_time = time.monotonic()
    targets, machine_output, baseline_ref, baseline_mode = _scan_parse_options(args)

    if baseline_mode:
        all_findings, files_scanned = _scan_baseline_collect(
            targets, baseline_ref, args, machine_output=machine_output,
        )
    else:
        all_findings, files_scanned = _scan_direct_collect(targets)

    all_findings, hallucinations = _scan_verify_imports(
        targets, all_findings, args, machine_output=machine_output,
    )

    all_findings = _scan_validate_signatures(
        targets, all_findings, args, machine_output=machine_output,
    )

    cwd = Path.cwd()
    all_findings, suppressed_count = _scan_post_process(
        all_findings, args, cwd, baseline_mode=baseline_mode,
    )

    result = _scan_build_result(
        all_findings, args, files_scanned, baseline_ref,
        baseline_mode=baseline_mode,
    )

    _scan_emit_telemetry(
        args, result, hallucinations, start_time,
        baseline_mode=baseline_mode,
    )

    if not machine_output:
        _scan_output_human(result, suppressed_count, cwd)

    _scan_output_machine(args, result, all_findings, machine_output=machine_output)

    return _scan_exit_code(
        str(result["verdict"]), args, all_findings, baseline_mode=baseline_mode,
    )


# --- Status command ---


def _status_collect_checks(project_dir: Path) -> list[tuple[str, bool]]:
    """Collect enforcement layer status checks."""
    return [
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


def _status_check_hooks_path(project_dir: Path) -> bool:
    """Check if core.hooksPath is set to 'hooks'."""
    try:
        result = subprocess.run(
            ["git", "config", "core.hooksPath"],
            capture_output=True, text=True, cwd=project_dir,
        )
        return result.returncode == 0 and result.stdout.strip() == "hooks"
    except FileNotFoundError:
        return False


def cmd_status(_args: argparse.Namespace) -> int:
    """Check which enforcement layers are installed."""
    project_dir = Path.cwd()

    _echo(f"\n{color('🛡️  CodeTrust Status', BOLD)}\n")

    checks = _status_collect_checks(project_dir)
    hooks_path_set = _status_check_hooks_path(project_dir)

    all_ok = True
    for name, installed in checks:
        icon = color("✅", GREEN) if installed else color("❌", RED)
        _echo(f"  {icon} {name}")
        if not installed:
            all_ok = False

    icon = color("✅", GREEN) if hooks_path_set else color("❌", RED)
    _echo(f"  {icon} core.hooksPath = hooks")
    if not hooks_path_set:
        all_ok = False

    _echo()
    if all_ok:
        _echo(color("  All enforcement layers active.\n", GREEN))
    else:
        _echo(f"  Run {color('codetrust init', BOLD)} to install missing layers.\n")

    return 0 if all_ok else 1


# --- Doctor command ---


def _doctor_fix_hooks(project_dir: Path, *, yes: bool) -> list[str]:
    """Install/fix pre-commit hooks and hooksPath."""
    actions: list[str] = []
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

        try:
            subprocess.run(
                ["git", "config", "core.hooksPath", "hooks"],
                cwd=project_dir, capture_output=True, text=True, check=False,
            )
            actions.append("Set git core.hooksPath=hooks")
        except Exception as exc:
            actions.append(f"Warning: could not set core.hooksPath ({exc})")

    return actions


def _doctor_fix_config_files(project_dir: Path, *, yes: bool) -> list[str]:
    """Install missing config files (toml, workflows, cursorrules, CLAUDE.md)."""
    actions: list[str] = []

    ct_toml = project_dir / ".codetrust.toml"
    wrote_toml = _write_text_file_safe(ct_toml, _load_template("codetrust.toml"), yes=yes)
    if wrote_toml:
        actions.append("Installed .codetrust.toml")

    wf = project_dir / ".github" / "workflows" / "codetrust-scan.yml"
    wf.parent.mkdir(parents=True, exist_ok=True)
    wrote_wf = _write_text_file_safe(wf, _load_template("codetrust-scan.yml"), yes=yes)
    if wrote_wf:
        actions.append("Installed .github/workflows/codetrust-scan.yml")

    cursorrules = project_dir / ".cursorrules"
    wrote_cursor = _write_text_file_safe(cursorrules, _load_template("cursorrules"), yes=yes)
    if wrote_cursor:
        actions.append("Installed .cursorrules")

    claude_md = project_dir / "CLAUDE.md"
    if not claude_md.exists():
        wrote_claude = _write_text_file_safe(claude_md, _load_template("CLAUDE.md"), yes=yes)
        if wrote_claude:
            actions.append("Installed CLAUDE.md")

    return actions


def _doctor_fix_gitignore(project_dir: Path) -> list[str]:
    """Ensure .gitignore contains CodeTrust patterns."""
    actions: list[str] = []
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


def _doctor_fix(*, project_dir: Path, yes: bool) -> list[str]:
    """Install missing enforcement layers.

    Returns a list of actions performed.
    """
    actions = _doctor_fix_hooks(project_dir, yes=yes)
    actions.extend(_doctor_fix_config_files(project_dir, yes=yes))
    actions.extend(_doctor_fix_gitignore(project_dir))
    return actions


def _doctor_check_hooks_path(project_dir: Path) -> str:
    """Check core.hooksPath git config. Returns the path or empty string."""
    try:
        result = subprocess.run(
            ["git", "config", "core.hooksPath"],
            capture_output=True, text=True, cwd=project_dir,
        )
        return result.stdout.strip() if result.returncode == 0 else ""
    except FileNotFoundError:
        return ""


def _doctor_check_claude_md(project_dir: Path) -> list[str]:
    """Check CLAUDE.md status. Returns list of issues found."""
    issues: list[str] = []
    claude_md = project_dir / "CLAUDE.md"
    if claude_md.exists():
        content = claude_md.read_text()
        if "codetrust" not in content.lower():
            issues.append("CLAUDE.md exists but doesn't mention CodeTrust")
            _echo(f"  {color('⚠️', YELLOW)}  CLAUDE.md missing CodeTrust rules")
        else:
            _echo(f"  {color('✅', GREEN)} CLAUDE.md has CodeTrust enforcement")
    else:
        issues.append("CLAUDE.md not found")
        _echo(f"  {color('❌', RED)} CLAUDE.md not found")
    return issues


def _doctor_check_hook_file(project_dir: Path, hooks_path_set: bool) -> list[str]:
    """Check pre-commit hook existence, executability, and legacy status."""
    issues: list[str] = []
    hook = project_dir / "hooks" / "pre-commit"
    if hook.exists():
        if os.access(hook, os.X_OK):
            _echo(f"  {color('✅', GREEN)} Pre-commit hook is executable")
        else:
            issues.append("Pre-commit hook not executable")
            _echo(f"  {color('❌', RED)} Pre-commit hook not executable")
    else:
        issues.append("Pre-commit hook not found")
        _echo(f"  {color('❌', RED)} Pre-commit hook not found")

    legacy_hook = project_dir / ".git" / "hooks" / "pre-commit"
    if legacy_hook.exists() and not hooks_path_set:
        _echo(f"  {color('⚠️', YELLOW)}  Legacy hook detected (.git/hooks/pre-commit)")
        _echo(f"     Recommendation: {color('git config core.hooksPath hooks', BOLD)} (version-controlled hooks)")
    if hook.exists() and not hooks_path_set:
        issues.append("core.hooksPath not set to hooks (hook may not run)")

    if hook.exists() and os.access(hook, os.X_OK):
        result = subprocess.run(
            [sys.executable, str(hook)],
            capture_output=True, text=True, cwd=project_dir,
        )
        if result.returncode == 0:
            _echo(f"  {color('✅', GREEN)} Pre-commit hook runs successfully")
        else:
            _echo(f"  {color('⚠️', YELLOW)}  Pre-commit hook returned exit code {result.returncode}")

    return issues


def _doctor_handle_issues(
    args: argparse.Namespace, issues: list[str], project_dir: Path,
) -> int:
    """Handle doctor issues: fix or report."""
    if getattr(args, "fix", False):
        yes = bool(getattr(args, "yes", False))
        actions = _doctor_fix(project_dir=project_dir, yes=yes)
        if actions:
            _echo(color("  Applied fixes:", GREEN))
            for a in actions:
                _echo(f"    - {a}")
            _echo()
        else:
            _echo(color("  No safe fixes applied.", YELLOW))
            _echo()

        _echo(color("  Re-checking...\n", BLUE))
        return cmd_doctor(argparse.Namespace(fix=False, yes=False))

    _echo(f"  {len(issues)} issue(s) found. Run {color('codetrust doctor --fix', BOLD)} to install missing layers.\n")
    return 1


def cmd_doctor(args: argparse.Namespace) -> int:
    """Run diagnostic checks on CodeTrust installation."""
    _echo(f"\n{color('🛡️  CodeTrust Doctor', BOLD)}\n")

    issues: list[str] = []
    project_dir = Path.cwd()

    if not (project_dir / ".git").is_dir():
        issues.append("Not a git repository")

    hooks_path = _doctor_check_hooks_path(project_dir)
    hooks_path_set = hooks_path == "hooks"
    if hooks_path_set:
        _echo(f"  {color('✅', GREEN)} core.hooksPath = hooks")
    else:
        _echo(f"  {color('⚠️', YELLOW)}  core.hooksPath not set to hooks")
        _echo(f"     Fix: {color('git config core.hooksPath hooks', BOLD)}")

    issues.extend(_doctor_check_claude_md(project_dir))
    issues.extend(_doctor_check_hook_file(project_dir, hooks_path_set))

    action = project_dir / ".github" / "workflows" / "codetrust-scan.yml"
    if action.exists():
        _echo(f"  {color('✅', GREEN)} GitHub Action workflow exists")
    else:
        issues.append("GitHub Action not found")
        _echo(f"  {color('❌', RED)} GitHub Action not found")

    _echo()
    if not issues:
        _echo(color("  All checks passed. CodeTrust is fully operational.\n", GREEN))
        return 0

    return _doctor_handle_issues(args, issues, project_dir)


# --- PR risk command ---


def cmd_pr_risk(args: argparse.Namespace) -> int:
    """Estimate PR risk based on changed files (git diff)."""
    project_dir = Path.cwd()
    changed_files, staged = _get_git_changed_files(cwd=project_dir)
    risk = _compute_pr_risk(project_dir=project_dir, changed_files=changed_files, staged=staged)

    if getattr(args, "json", False):
        payload = {**risk, "staged": staged}
        _echo(json.dumps(payload, indent=2, default=str))
        return 0

    _echo(f"\n{color('📡 CodeTrust PR Risk Radar', BOLD)}")
    scope = "staged changes" if staged else "working tree vs HEAD"
    _echo(f"   Scope: {scope}")
    _echo(f"   Changed files: {int(risk.get('changed_files_count', 0) or 0)}")
    _echo(f"   Changed lines: {int(risk.get('changed_lines', 0) or 0)}")
    _echo(f"   Risk: {risk['level']} ({risk['score']}/{PR_RISK_MAX_SCORE})\n")

    eps = risk.get("touched_endpoints", [])
    if isinstance(eps, list) and eps:
        _echo(color("  Touched endpoints:", BLUE))
        for ep in eps[:8]:
            _echo(f"    - {ep}")
        if len(eps) > 8:
            _echo(f"    ... and {len(eps) - 8} more")
        _echo()

    signals = risk.get("signals", [])
    if isinstance(signals, list) and signals:
        _echo(color("  Top signals:", BLUE))
        for s in signals[:6]:
            label = str(s.get("label", ""))
            points = int(s.get("points", 0) or 0)
            _echo(f"    - +{points}: {label}")
        _echo()
    else:
        _echo(color("  No high-risk touchpoints detected from file paths.", GREEN))
        _echo()

    return 0


# --- Governance command ---


# ── MCP config injection constants ──────────────────────────────────────────────

GUARDIAN_SERVER_NAME = "codetrust"
GATEWAY_SERVER_NAME = "codetrust-gateway"
GUARDIAN_COMMAND = "codetrust-mcp"
GATEWAY_COMMAND = "codetrust-gateway-mcp"
GUARDIAN_MODULE = "src.server"
GATEWAY_MODULE = "src.gateway.server"
MCP_INJECTION_MARKER = "codetrust-auto-injected"
PYPI_PACKAGE_NAME = "codetrust"


def _get_mcp_targets() -> list[tuple[str, Path]]:
    """Return list of (display_name, config_path) for all IDE MCP config targets."""
    home = Path.home()
    targets: list[tuple[str, Path]] = [
        ("Claude Code", home / ".claude" / "mcp.json"),
        ("Cursor", home / ".cursor" / "mcp.json"),
    ]
    if sys.platform == "darwin":
        targets.append((
            "Claude Desktop",
            home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
        ))
    return targets


def _detect_source_root() -> Path | None:
    """Detect the CodeTrust source repository root from cwd or parents.

    Looks for a pyproject.toml containing 'name = \"codetrust\"'.
    """
    cwd = Path.cwd()
    for candidate in [cwd, *cwd.parents]:
        pyproject = candidate / "pyproject.toml"
        if pyproject.is_file():
            try:
                content = pyproject.read_text()
                if 'name = "codetrust"' in content:
                    return candidate
            except OSError:
                continue
        # Stop at filesystem root or home
        if candidate == Path.home() or candidate == candidate.parent:
            break
    return None


def _resolve_server_entry(
    console_script: str,
    module_path: str,
) -> dict[str, object]:
    """Resolve the best available MCP server entry config.

    Falls through strategies in priority order:
      1. Console script on PATH (pip install — fastest)
      2. uvx zero-install (uv available, no pip needed)
      3. python3 -m module (source repo in cwd)
      4. Fallback to console script name (user sees startup error)

    Returns:
        Dict suitable for a mcpServers entry in mcp.json.
    """
    # Strategy 1: Console script on PATH
    if shutil.which(console_script):
        _echo(f"    → '{console_script}' found on PATH")
        return {
            "command": console_script,
            "_injectedBy": MCP_INJECTION_MARKER,
        }

    # Strategy 2: uvx zero-install
    if shutil.which("uvx"):
        _echo(f"    → '{console_script}' not on PATH, using uvx zero-install")
        return {
            "command": "uvx",
            "args": ["--from", PYPI_PACKAGE_NAME, console_script],
            "_injectedBy": MCP_INJECTION_MARKER,
        }

    # Strategy 3: python3 -m with current directory as source root
    source_root = _detect_source_root()
    python_cmd = "python" if sys.platform == "win32" else "python3"
    if source_root and shutil.which(python_cmd):
        _echo(f"    → Using '{python_cmd} -m {module_path}' with cwd={source_root}")
        return {
            "command": python_cmd,
            "args": ["-m", module_path],
            "cwd": str(source_root),
            "_injectedBy": MCP_INJECTION_MARKER,
        }

    # Fallback: write console script name — user will see startup error
    _echo(f"    → WARNING: '{console_script}' not found, writing anyway")
    return {
        "command": console_script,
        "_injectedBy": MCP_INJECTION_MARKER,
    }


def _inject_mcp_servers() -> int:
    """Inject CodeTrust MCP servers into all detected IDE configs.

    Idempotent: only adds entries that are missing. Never overwrites
    existing server configs (user may have custom args/env).

    Auto-detects the best command strategy:
      1. Console script on PATH (pip install)
      2. uvx zero-install
      3. python3 -m module (source checkout)

    Returns:
        Number of IDE configs that were modified.
    """
    targets = _get_mcp_targets()
    modified_count = 0

    for display_name, config_path in targets:
        if not config_path.parent.exists():
            _echo(f"  {color('⏭️', BLUE)} {display_name} — directory not found, skipping")
            continue

        # Read existing config
        config: dict[str, object] = {}
        if config_path.is_file():
            try:
                raw = config_path.read_text().strip()
                if raw:
                    config = json.loads(raw)
            except (json.JSONDecodeError, OSError):
                _echo(f"  {color('⚠️', YELLOW)} {display_name} — could not parse config, skipping")
                continue

        servers: dict[str, object] = config.get("mcpServers", {})  # type: ignore[assignment]
        if not isinstance(servers, dict):
            servers = {}

        modified = False

        if GUARDIAN_SERVER_NAME not in servers:
            servers[GUARDIAN_SERVER_NAME] = _resolve_server_entry(
                GUARDIAN_COMMAND, GUARDIAN_MODULE,
            )
            _echo(f"  {color('✅', GREEN)} {display_name} — added '{GUARDIAN_SERVER_NAME}' server")
            modified = True
        else:
            _echo(f"  {color('⏭️', BLUE)} {display_name} — '{GUARDIAN_SERVER_NAME}' already present")

        if GATEWAY_SERVER_NAME not in servers:
            servers[GATEWAY_SERVER_NAME] = _resolve_server_entry(
                GATEWAY_COMMAND, GATEWAY_MODULE,
            )
            _echo(f"  {color('✅', GREEN)} {display_name} — added '{GATEWAY_SERVER_NAME}' server")
            modified = True
        else:
            _echo(f"  {color('⏭️', BLUE)} {display_name} — '{GATEWAY_SERVER_NAME}' already present")

        if modified:
            config["mcpServers"] = servers
            config_path.parent.mkdir(parents=True, exist_ok=True)
            config_path.write_text(json.dumps(config, indent=2) + "\n")
            modified_count += 1

    return modified_count


def _governance_show_setup(project_dir: Path) -> int:
    """Inject MCP servers into IDE configs and show governance setup status."""
    _echo(f"\n{color('🛡️  CodeTrust Gateway — MCP Setup', BOLD)}\n")
    _echo(f"  {color('Injecting MCP server configs into detected IDEs...', BOLD)}\n")

    modified = _inject_mcp_servers()

    _echo()
    if modified > 0:
        _echo(f"  {color('✅', GREEN)} {modified} IDE config(s) updated with CodeTrust MCP servers.")
    else:
        _echo(f"  {color('i', BLUE)} All detected IDEs already have CodeTrust MCP servers configured.")

    _echo(f"\n  {color('Configuration', BOLD)}:\n")
    _echo("    Config file:  .codetrust.toml")
    _echo("    Audit log:    .codetrust/audit.jsonl")
    _echo("    Env override: CODETRUST_GOVERNANCE_MODE=enforce|audit|off\n")
    return 0


def _governance_set_mode(project_dir: Path, mode: str) -> int:
    """Set governance mode in .codetrust.toml."""
    toml_path = project_dir / ".codetrust.toml"
    if not toml_path.is_file():
        _echo(f"  {color('❌', RED)} No .codetrust.toml found. Run: codetrust init")
        return 1
    content = toml_path.read_text()
    import re as _re

    content = _re.sub(r'mode\s*=\s*"[^"]*"', f'mode = "{mode}"', content)
    toml_path.write_text(content)
    _echo(f"  {color('✅', GREEN)} Governance mode set to: {mode}")
    return 0


def _governance_show_status(engine: PolicyEngine) -> int:
    """Display current governance status and policies."""
    config = engine.config
    policies = engine.get_policies()
    enabled = sum(1 for p in policies if p.enabled)
    disabled = sum(1 for p in policies if not p.enabled)

    _echo(f"\n{color('🛡️  CodeTrust Governance Status', BOLD)}\n")
    _echo(f"  Mode:     {color(config.mode.value.upper(), GREEN if config.mode.value == 'enforce' else YELLOW)}")
    _echo(f"  Enabled:  {config.enabled}")
    _echo(f"  Policies: {enabled} active, {disabled} disabled")
    _echo(f"  Audit:    {config.audit_path}")
    _echo()

    _echo(f"  {color('Terminal Policies:', BOLD)}")
    terminal_flags = {
        "Heredoc":       config.block_heredoc,
        "Eval":          config.block_eval,
        "Sudo su":       config.block_sudo,
        "rm -rf /":      config.block_rm_rf,
        "curl|sh":       config.block_curl_pipe_sh,
        "git push":      config.block_git_push,
        "chmod " + "777":  config.block_chmod_777,
    }
    for name, enabled_flag in terminal_flags.items():
        icon = color("✅", GREEN) if enabled_flag else color("⚪", BLUE)
        _echo(f"    {icon} {name}")

    _echo()
    if config.protected_paths:
        _echo(f"  {color('Protected Files:', BOLD)}")
        for p in config.protected_paths:
            _echo(f"    🔒 {p}")
        _echo()

    return 0


def cmd_governance(args: argparse.Namespace) -> int:
    """Manage AI governance policies."""
    from src.gateway.policies import PolicyEngine

    project_dir = Path.cwd()
    engine = PolicyEngine.from_workspace(str(project_dir))

    if args.setup:
        return _governance_show_setup(project_dir)

    if args.mode:
        return _governance_set_mode(project_dir, args.mode)

    return _governance_show_status(engine)


# --- Audit command ---


def _audit_handle_purge(audit: AuditLogger, retention: int) -> int:
    """Purge old audit entries."""
    purged = audit.purge(older_than_days=retention)
    remaining = audit.entry_count()
    _echo(f"Purged {purged} entries older than {retention} days. {remaining} entries remaining.")
    return 0


def _audit_handle_stats(audit: AuditLogger) -> int:
    """Display audit statistics."""
    stats = audit.get_stats()
    _echo(f"\n{color('📊 Audit Statistics', BOLD)}\n")
    if stats["total"] == 0:
        _echo("  No audit entries found.\n")
        return 0
    _echo(f"  Total actions: {stats['total']}")
    for verdict, count in stats.get("by_verdict", {}).items():
        v_color = RED if verdict == "BLOCK" else (YELLOW if verdict == "WARN" else GREEN)
        _echo(f"  {color(verdict, v_color)}: {count}")
    if stats.get("top_rules"):
        _echo(f"\n  {color('Top Triggered Rules:', BOLD)}")
        for rule in stats["top_rules"][:_AUDIT_TOP_RULES_DISPLAY]:
            _echo(f"    {rule['rule_id']}: {rule['count']}x")
    _echo()
    return 0


def _audit_show_entries(args: argparse.Namespace, entries: list[AuditEntry]) -> int:
    """Display or export audit entries."""
    import time as _time

    fmt = getattr(args, "format", "table")
    if fmt != "table":
        from src.gateway.siem import SiemFormat, export_entries, export_to_file

        siem_fmt = SiemFormat(fmt)
        if args.export:
            count = export_to_file(entries, siem_fmt, args.export)
            _echo(f"Exported {count} entries to {args.export} ({fmt})")
            return 0
        for line in export_entries(entries, siem_fmt):
            _echo(line)
        return 0

    _echo(f"\n{color(f'📋 Audit Log — Last {args.hours} Hours', BOLD)}\n")

    if not entries:
        _echo("  No entries found.\n")
        return 0

    for entry in entries:
        ts = _time.strftime("%H:%M:%S", _time.localtime(entry.timestamp))
        v_color = RED if entry.verdict == "BLOCK" else (YELLOW if entry.verdict == "WARN" else GREEN)
        verdict_str = color(entry.verdict.ljust(5), v_color)
        action = entry.original_action[:70]
        if len(entry.original_action) > 70:
            action += "..."
        rule = entry.rule_id or "-"
        _echo(f"  {ts}  {verdict_str}  {rule.ljust(28)}  {action}")

    _echo(f"\n  Showing {len(entries)} entries.\n")
    return 0


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
        return _audit_handle_purge(audit, engine.config.retention_days)

    if args.stats:
        return _audit_handle_stats(audit)

    since = _time.time() - (args.hours * _SECONDS_PER_HOUR)
    entries = audit.get_entries(
        since=since,
        verdict=args.verdict,
        limit=_AUDIT_ENTRY_LIMIT,
    )

    return _audit_show_entries(args, entries)


# --- Agent Optimizer (setup command) ---

SETUP_VSCODE_DIR: str = ".vscode"
SETUP_SESSION_LOG: str = "SESSION_LOG.md"
SETUP_AGENT_CLAUDE: str = "CLAUDE.md"


def _setup_install_agent_claude(
    project_dir: Path,
    *,
    force: bool,
) -> bool:
    """Install the enhanced Agent Optimizer CLAUDE.md."""
    target = project_dir / SETUP_AGENT_CLAUDE
    version = _get_setup_version()
    content = _load_template("agent-claude.md").replace("{VERSION}", version)

    if target.exists() and not force:
        _echo(f"  {color('⚠️', YELLOW)}  CLAUDE.md exists (use --force to overwrite)")
        return False

    if target.exists():
        shutil.copy2(target, target.with_suffix(".md.bak"))

    target.write_text(content, encoding="utf-8")
    _echo(f"  {color('✅', GREEN)} CLAUDE.md — Agent Operating System installed")
    return True


def _setup_install_session_log(project_dir: Path) -> bool:
    """Install SESSION_LOG.md template for session tracking."""
    target = project_dir / SETUP_SESSION_LOG
    if target.exists():
        _echo(f"  {color('⚠️', YELLOW)}  SESSION_LOG.md exists (preserving)")
        return False

    project_name = project_dir.name
    content = _load_template("SESSION_LOG.md").replace(
        "[PROJECT_NAME]", project_name,
    )
    target.write_text(content, encoding="utf-8")
    _echo(f"  {color('✅', GREEN)} SESSION_LOG.md — session tracking template")
    return True


def _setup_install_vscode_settings(
    project_dir: Path,
    *,
    force: bool,
) -> bool:
    """Install or merge VS Code workspace settings for agent optimization."""
    vscode_dir = project_dir / SETUP_VSCODE_DIR
    vscode_dir.mkdir(exist_ok=True)
    settings_path = vscode_dir / "settings.json"

    template_text = _load_template("vscode-settings.json")
    template_settings = json.loads(template_text)

    if settings_path.exists() and not force:
        existing = json.loads(settings_path.read_text(encoding="utf-8"))
        merged = False
        for key, value in template_settings.items():
            if key.startswith("//"):
                continue
            if key not in existing:
                existing[key] = value
                merged = True
        if merged:
            settings_path.write_text(
                json.dumps(existing, indent=2) + "\n",
                encoding="utf-8",
            )
            _echo(f"  {color('✅', GREEN)} .vscode/settings.json — merged agent settings")
            return True
        _echo(f"  {color('⚠️', YELLOW)}  .vscode/settings.json — already has agent settings")
        return False

    settings_path.write_text(
        json.dumps(template_settings, indent=2) + "\n",
        encoding="utf-8",
    )
    _echo(f"  {color('✅', GREEN)} .vscode/settings.json — agent settings installed")
    return True


def _setup_install_cursorrules(
    project_dir: Path,
    *,
    force: bool,
) -> bool:
    """Install .cursorrules for Cursor IDE agent optimization."""
    target = project_dir / ".cursorrules"
    if target.exists() and not force:
        _echo(f"  {color('⚠️', YELLOW)}  .cursorrules exists (use --force to overwrite)")
        return False

    target.write_text(_load_template("cursorrules"), encoding="utf-8")
    _echo(f"  {color('✅', GREEN)} .cursorrules — Cursor IDE agent rules")
    return True


def _get_setup_version() -> str:
    """Get current CodeTrust version for template stamping."""
    try:
        from importlib.metadata import version as _pkg_version
        return _pkg_version("codetrust")
    except Exception:
        return "2.9.0"


def _setup_print_summary(installed_count: int) -> None:
    """Print the Agent Optimizer installation summary."""
    _echo(f"\n{'━' * 48}")
    _echo(f"\n  {color('✅ Agent Optimizer configured!', GREEN)}\n")
    _echo(f"  {installed_count} file(s) installed/updated\n")
    _echo("  What was configured:")
    _echo(f"    CLAUDE.md           {color('Agent Operating System', BLUE)}")
    _echo(f"    SESSION_LOG.md      {color('Session tracking', BLUE)}")
    _echo(f"    .vscode/settings    {color('VS Code agent instructions', BLUE)}")
    _echo(f"    .cursorrules        {color('Cursor IDE rules', BLUE)}")
    _echo()
    _echo("  How it works:")
    _echo("    • AI agents read CLAUDE.md at session start")
    _echo("    • CodeTrust governance is enforced via MCP tools")
    _echo("    • Session state is tracked in SESSION_LOG.md")
    _echo("    • VS Code settings enable instruction files")
    _echo()
    _echo("  No other product optimizes how AI agents work.")
    _echo(f"  {color('CodeTrust Agent Optimizer — https://codetrust.ai', BOLD)}")
    _echo()


def cmd_setup(args: argparse.Namespace) -> int:
    """Configure AI agent optimization for the current project.

    Installs CLAUDE.md, SESSION_LOG.md, VS Code settings, and
    .cursorrules to optimize how AI coding agents work.
    """
    project_dir = Path.cwd()
    force = getattr(args, "force", False)

    _echo(f"\n{color('🧠 CodeTrust Agent Optimizer — Configuring AI agents', BOLD)}\n")

    installed = 0
    if _setup_install_agent_claude(project_dir, force=force):
        installed += 1
    if _setup_install_session_log(project_dir):
        installed += 1
    if _setup_install_vscode_settings(project_dir, force=force):
        installed += 1
    if _setup_install_cursorrules(project_dir, force=force):
        installed += 1

    # Inject MCP server configs into all detected IDEs
    _echo(f"\n  {color('MCP Server Registration:', BOLD)}\n")
    mcp_modified = _inject_mcp_servers()
    if mcp_modified > 0:
        installed += 1

    _setup_print_summary(installed)
    return 0


# --- Main ---


def _create_main_parser() -> argparse.ArgumentParser:
    """Create the top-level CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="codetrust",
        description="CodeTrust — AI code verification. Install, scan, enforce.",
    )
    return parser


def _add_init_and_add_subparsers(
    subparsers: argparse._SubParsersAction,
) -> None:
    """Register 'init', 'add', and 'setup' subcommands."""
    init_parser = subparsers.add_parser("init", help="Install enforcement layers")
    init_parser.add_argument("--force", action="store_true", help="Overwrite existing files")

    setup_parser = subparsers.add_parser(
        "setup",
        help="Configure AI Agent Optimizer — CLAUDE.md, SESSION_LOG, VS Code settings",
    )
    setup_parser.add_argument("--force", action="store_true", help="Overwrite existing files")

    add_parser = subparsers.add_parser(
        "add",
        help="Add CodeTrust repo bootstrap files (.vscode/.devcontainer/CONTRIBUTING)",
    )
    add_parser.add_argument(
        "--settings", action="store_true",
        help="Also write .vscode/settings.json defaults (only missing keys)",
    )
    add_parser.add_argument(
        "--stack",
        choices=["auto", "nextjs", "node", "python", "go", "generic"],
        default="auto",
        help="Stack presets to apply when writing settings.json (default: auto-detect)",
    )
    add_parser.add_argument(
        "--devcontainer", action="store_true",
        help="Also write/merge .devcontainer/devcontainer.json",
    )
    add_parser.add_argument(
        "--contributing", action="store_true",
        help="Also append a CodeTrust section to CONTRIBUTING.md (if present)",
    )
    add_parser.add_argument("--yes", action="store_true", help="Overwrite/merge without prompting")


def _add_scan_subparser(
    subparsers: argparse._SubParsersAction,
) -> None:
    """Register the 'scan' subcommand with all its options."""
    scan_parser = subparsers.add_parser("scan", help="Scan files for anti-patterns")
    scan_parser.add_argument("targets", nargs="*", default=["."], help="Files or directories")
    scan_parser.add_argument(
        "--format",
        choices=["text", "json", "sarif"],
        default="text",
        help="Output format (default: text)",
    )
    scan_parser.add_argument(
        "--output",
        type=str,
        default="",
        help="Write machine-readable output to file (supports --format sarif)",
    )
    scan_parser.add_argument("--json", action="store_true", help="Output as JSON")
    scan_parser.add_argument("--sarif", action="store_true", help="Output as SARIF v2.1.0")
    scan_parser.add_argument("--sarif-file", type=str, default="", help="Write SARIF to file")
    scan_parser.add_argument(
        "--fail-on", dest="fail_on", choices=["never", "warn", "block"],
        default="block", help="Exit non-zero when verdict meets threshold (default: block)",
    )
    scan_parser.add_argument(
        "--no-verify-imports", action="store_true",
        help="Skip live registry verification of imports",
    )
    scan_parser.add_argument(
        "--no-verify-signatures", action="store_true",
        help="Skip function signature validation (hallucination detection)",
    )
    scan_parser.add_argument(
        "--changed-only", action="store_true",
        help="Only report findings that fall on changed lines (uses git diff)",
    )
    scan_parser.add_argument(
        "--baseline", type=str, default="",
        help="Baseline git ref (e.g. origin/main). When set, gates on new findings vs baseline and scans only files changed against that ref.",
    )
    scan_parser.add_argument(
        "--fail-on-new", dest="fail_on_new", choices=["INFO", "WARN", "BLOCK"],
        default="BLOCK",
        help="Exit non-zero if NEW findings include this severity or higher (requires --baseline). Default: BLOCK.",
    )
    scan_parser.add_argument(
        "--dedupe", action="store_true", help="Dedupe identical findings for noise control",
    )
    scan_parser.add_argument(
        "--suppress-lint-noise", dest="suppress_lint_noise", action="store_true",
        help="Suppress findings commonly covered by existing linters (opt-in)",
    )


def _add_fix_vuln_license_subparsers(
    subparsers: argparse._SubParsersAction,
) -> None:
    """Register 'fix', 'vuln', and 'license' subcommands."""
    fix_parser = subparsers.add_parser("fix", help="Apply safe deterministic autofix recipes")
    fix_parser.add_argument("targets", nargs="*", default=["."], help="Files or directories")
    fix_parser.add_argument("--apply", action="store_true", help="Write changes to disk (default: preview only)")
    fix_parser.add_argument("--pr", action="store_true", help="Create a GitHub PR with the fixes (requires CODETRUST_GITHUB_TOKEN)")
    fix_parser.add_argument("--github-owner", default="", help="GitHub repo owner for --pr")
    fix_parser.add_argument("--github-repo", default="", help="GitHub repo name for --pr")
    fix_parser.add_argument("--github-branch", default="main", help="Base branch for --pr")

    vuln_parser = subparsers.add_parser("vuln", help="Scan dependencies for known vulnerabilities (CVE/GHSA)")
    vuln_parser.add_argument("targets", nargs="*", default=["."], help="Files or directories to scan")
    vuln_parser.add_argument("--language", "-l", default="", help="Language (python, javascript, go, rust, java, csharp)")
    vuln_parser.add_argument("--json", dest="json_output", action="store_true", help="Output as JSON")

    license_parser = subparsers.add_parser("license", help="Check dependency licenses for compliance")
    license_parser.add_argument("targets", nargs="*", default=["."], help="Files or directories to scan")
    license_parser.add_argument("--language", "-l", default="", help="Language (python, javascript)")
    license_parser.add_argument("--json", dest="json_output", action="store_true", help="Output as JSON")


def _add_utility_subparsers(
    subparsers: argparse._SubParsersAction,
) -> None:
    """Register 'status', 'doctor', 'pr-risk', and 'trust-diff' subcommands."""
    subparsers.add_parser("status", help="Check installed enforcement layers")

    doctor_parser = subparsers.add_parser("doctor", help="Diagnose CodeTrust installation")
    doctor_parser.add_argument(
        "--fix", action="store_true",
        help="Install missing enforcement layers (safe; no overwrite without confirmation)",
    )
    doctor_parser.add_argument(
        "--yes", action="store_true", help="Apply fixes without prompting (when safe)",
    )

    pr_parser = subparsers.add_parser("pr-risk", help="Estimate PR risk based on changed files")
    pr_parser.add_argument("--json", action="store_true", help="Output as JSON")

    td_parser = subparsers.add_parser("trust-diff", help="Compare trust/drift between HEAD and current changes")
    td_parser.add_argument("--json", action="store_true", help="Output as JSON")


def _add_trend_subparser(
    subparsers: argparse._SubParsersAction,
) -> None:
    """Register 'trend' subcommand with show/record sub-commands."""
    trend_parser = subparsers.add_parser("trend", help="Record/show drift trend snapshots")
    trend_sub = trend_parser.add_subparsers(dest="subcommand")

    trend_show = trend_sub.add_parser("show", help="Show last snapshots")
    trend_show.add_argument("--limit", type=int, default=20, help="How many entries to show")
    trend_show.add_argument("--json", action="store_true", help="Output as JSON")

    trend_record = trend_sub.add_parser("record", help="Record a snapshot")
    trend_record.add_argument("targets", nargs="*", default=["."], help="Files or directories")
    trend_record.add_argument("--json", action="store_true", help="Output as JSON")


def _add_governance_policy_audit_subparsers(
    subparsers: argparse._SubParsersAction,
) -> None:
    """Register 'governance', 'policy', and 'audit' subcommands."""
    gov_parser = subparsers.add_parser("governance", help="Manage AI governance policies")
    gov_parser.add_argument("--setup", action="store_true", help="Show MCP gateway setup instructions")
    gov_parser.add_argument("--status", action="store_true", help="Show current governance status")
    gov_parser.add_argument("--mode", choices=["enforce", "audit", "off"], help="Set governance mode")

    policy_parser = subparsers.add_parser("policy", help="Policy wizard for governance config")
    policy_sub = policy_parser.add_subparsers(dest="subcommand")
    policy_wizard = policy_sub.add_parser("wizard", help="Generate policy presets + config autocomplete")
    policy_wizard.add_argument(
        "--profile", choices=list(POLICY_PROFILE_CHOICES), default=POLICY_DEFAULT_PROFILE,
        help="Policy preset: startup|team|enterprise (default: team)",
    )
    policy_wizard.add_argument(
        "--pyproject", choices=["auto", "skip", "force"], default="auto",
        help="Sync into pyproject.toml [tool.codetrust]: auto|skip|force (default: auto)",
    )
    policy_wizard.add_argument("--yes", action="store_true", help="Overwrite/update without prompting")

    _add_audit_subparser(subparsers)


def _add_audit_subparser(
    subparsers: argparse._SubParsersAction,
) -> None:
    """Register 'audit' subcommand."""
    audit_parser = subparsers.add_parser("audit", help="Query governance audit log")
    audit_parser.add_argument("--hours", type=int, default=24, help="Hours to look back (default: 24)")
    audit_parser.add_argument("--verdict", choices=["ALLOW", "WARN", "BLOCK"], help="Filter by verdict")
    audit_parser.add_argument("--stats", action="store_true", help="Show aggregate statistics")
    audit_parser.add_argument(
        "--format", choices=["table", "cef", "leef", "syslog", "json"],
        default="table", help="Output format: table (default), cef, leef, syslog, json",
    )
    audit_parser.add_argument(
        "--export", type=str, default="",
        help="Export audit entries to file in the chosen --format",
    )
    audit_parser.add_argument(
        "--purge", action="store_true",
        help="Purge entries older than retention_days (default: 90 days)",
    )


def _route_command(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    """Route parsed CLI args to the appropriate command handler."""
    if args.command == "init":
        return cmd_init(args)
    if args.command == "setup":
        return cmd_setup(args)
    if args.command == "add":
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
    if args.command == "vuln":
        return cmd_vuln(args)
    if args.command == "license":
        return cmd_license(args)
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


def main() -> int:
    """CLI entry point."""
    # License check — warn but do not block CLI usage
    from src.services.license_guard import validate_license_sync

    license_status = validate_license_sync(os.environ.get("CODETRUST_API_KEY", ""))
    if not license_status.valid and license_status.plan != "free":
        sys.stderr.write(
            "\033[33m\u26a0 CodeTrust license not validated. "
            "Running in limited mode.\033[0m\n"
            "  Get a license at https://codetrust.ai\n\n",
        )

    parser = _create_main_parser()
    subparsers = parser.add_subparsers(dest="command")

    _add_init_and_add_subparsers(subparsers)
    _add_scan_subparser(subparsers)
    _add_fix_vuln_license_subparsers(subparsers)
    _add_utility_subparsers(subparsers)
    _add_trend_subparser(subparsers)
    _add_governance_policy_audit_subparsers(subparsers)

    args = parser.parse_args()
    return _route_command(args, parser)


if __name__ == "__main__":
    sys.exit(main())
