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
        "docker_block": [], "docker_warn": [], "docker_info": [],
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
            # Language-specific rules → store with file_types for runtime filtering
            _TYPED_RULES.setdefault(f"typed_{sev_lower}", []).append(
                (entry, ft_set),
            )
    else:
        cats.get(f"generic_{sev_lower}", cats["generic_warn"]).append(entry)


_TYPED_RULES: dict[str, list[tuple[tuple[str, str, str], set[str]]]] = {}


def _build_cli_rules() -> dict[str, list[tuple[str, str, str]]]:
    """Build CLI rule lists from the authoritative backend ANTI_PATTERNS.

    Returns categorized (id, pattern, message) tuples grouped by severity
    and file_types for the CLI's file-type routing logic.
    Rules with special_handler are skipped here — they are implemented
    directly in scan_file() as multi-line / file-level checks.

    Language-specific rules (with file_types not matching a dedicated bucket)
    go into _TYPED_RULES with their file_types set, and are filtered at
    scan time by _get_typed_rules_for_ext().
    """
    cats = _init_cli_rule_categories()

    for rule in ANTI_PATTERNS:
        if rule.get("special_handler"):
            continue  # CLI does regex-only; skip rules needing Python handlers

        severity = str(rule["severity"])  # Severity enum -> str
        entry = (rule["id"], rule["pattern"], rule["message"])
        _classify_rule_entry(cats, rule, entry, severity)

    return cats


def _get_typed_rules_for_ext(ext: str) -> tuple[
    list[tuple[str, str, str]],
    list[tuple[str, str, str]],
    list[tuple[str, str, str]],
]:
    """Return typed rules that match a given file extension."""
    block: list[tuple[str, str, str]] = []
    warn: list[tuple[str, str, str]] = []
    info: list[tuple[str, str, str]] = []
    for entry, ft_set in _TYPED_RULES.get("typed_block", []):
        if ext in ft_set:
            block.append(entry)
    for entry, ft_set in _TYPED_RULES.get("typed_warn", []):
        if ext in ft_set:
            warn.append(entry)
    for entry, ft_set in _TYPED_RULES.get("typed_info", []):
        if ext in ft_set:
            info.append(entry)
    return block, warn, info


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
        logger.debug("autofix_telemetry_failed", exc_info=True)


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
    tb, tw, ti = _get_typed_rules_for_ext(ext)
    if ext in SQL_EXTS:
        return SQL_BLOCK_RULES + tb, SQL_WARN_RULES + tw, SQL_INFO_RULES + ti
    if is_dockerfile:
        return (
            BLOCK_RULES + DOCKER_BLOCK_RULES + DEVOPS_BLOCK_RULES + tb,
            WARN_RULES + DOCKER_WARN_RULES + DEVOPS_WARN_RULES + tw,
            INFO_RULES + ti,
        )
    if is_react:
        return BLOCK_RULES + REACT_BLOCK_RULES + tb, WARN_RULES + REACT_WARN_RULES + tw, INFO_RULES + ti
    if is_ruby:
        return BLOCK_RULES + RUBY_BLOCK_RULES + tb, WARN_RULES + RUBY_WARN_RULES + tw, INFO_RULES + ti
    if is_php:
        return BLOCK_RULES + PHP_BLOCK_RULES + tb, WARN_RULES + PHP_WARN_RULES + tw, INFO_RULES + ti
    if is_powershell:
        return (
            BLOCK_RULES + PS_BLOCK_RULES + DEVOPS_BLOCK_RULES + tb,
            WARN_RULES + PS_WARN_RULES + DEVOPS_WARN_RULES + tw,
            INFO_RULES + PS_INFO_RULES + DEVOPS_INFO_RULES + ti,
        )
    if is_systemd:
        return tb, SYSTEMD_WARN_RULES + tw, SYSTEMD_INFO_RULES + ti
    if is_nginx:
        return (
            NGINX_BLOCK_RULES + REDIS_BLOCK_RULES + DEVOPS_BLOCK_RULES + tb,
            NGINX_WARN_RULES + REDIS_WARN_RULES + DEVOPS_WARN_RULES + tw,
            NGINX_INFO_RULES + DEVOPS_INFO_RULES + ti,
        )
    if is_bicep:
        return BLOCK_RULES + BICEP_BLOCK_RULES + tb, WARN_RULES + BICEP_WARN_RULES + tw, INFO_RULES + ti
    if is_ci:
        return (
            _DEVOPS_K8S_RULES[0] + CI_BLOCK_RULES + tb,
            WARN_RULES + CI_WARN_RULES + DEVOPS_WARN_RULES + K8S_WARN_RULES + tw,
            _DEVOPS_K8S_RULES[2] + CI_INFO_RULES + ti,
        )
    if is_k8s:
        return _DEVOPS_K8S_RULES
    if is_devops:
        tb, tw, ti = _get_typed_rules_for_ext(ext)
        return BLOCK_RULES + DEVOPS_BLOCK_RULES + tb, WARN_RULES + DEVOPS_WARN_RULES + tw, INFO_RULES + DEVOPS_INFO_RULES + ti
    # Default: universal rules + typed rules matching this extension
    tb, tw, ti = _get_typed_rules_for_ext(ext)
    return BLOCK_RULES + tb, WARN_RULES + tw, INFO_RULES + ti


_COMPILED_CACHE: dict[str, re.Pattern[str]] = {}


def _compiled(pattern: str) -> re.Pattern[str]:
    """Return a compiled regex, caching to avoid repeated compilation."""
    c = _COMPILED_CACHE.get(pattern)
    if c is None:
        c = re.compile(pattern)
        _COMPILED_CACHE[pattern] = c
    return c


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
        if _compiled(pattern).search(line):
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
    "src/rules/",
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
    """Policy wizard and commit policy management."""
    project_dir = Path.cwd()

    sub = str(getattr(args, "subcommand", ""))
    if sub == "show":
        return _policy_show(project_dir)
    if sub == "init":
        return _policy_init(project_dir, yes=bool(getattr(args, "yes", False)))
    if sub == "validate":
        return _policy_validate(project_dir)
    if sub == "test":
        return _policy_test(
            project_dir,
            model=str(getattr(args, "model", "gpt-4o")),
            editor=str(getattr(args, "editor", "copilot")),
        )
    if sub != "wizard":
        _echo("Usage: codetrust policy {wizard|show|init|validate|test}")
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


def _policy_show(project_dir: Path) -> int:
    """Show current commit policy from .codetrust.toml."""
    from src.services.commit_policy import load_policy_config

    config = load_policy_config(project_dir)
    _echo(f"\n{color('Commit Policy', BOLD)}\n")
    _echo(f"  Model mode:     {config.model_mode}")
    if config.models_allowed:
        _echo(f"  Models allowed: {', '.join(config.models_allowed)}")
    if config.models_blocked:
        _echo(f"  Models blocked: {', '.join(config.models_blocked)}")
    _echo(f"  Editor mode:    {config.editor_mode}")
    if config.editors_allowed:
        _echo(f"  Editors allowed: {', '.join(config.editors_allowed)}")
    if config.editors_blocked:
        _echo(f"  Editors blocked: {', '.join(config.editors_blocked)}")
    _echo(f"  Allow AI:       {config.allow_ai_generated}")
    _echo(f"  Require review: {config.require_human_review}")
    _echo(f"  Max AI ratio:   {config.max_ai_ratio}")
    _echo(f"  Personality:    {config.personality}")
    _echo()
    return 0


_DEFAULT_POLICY_TOML = """\
[policy]
# Model controls: "none", "allowlist", "blocklist", "audit"
model_mode = "none"
models_allowed = []
models_blocked = []

# Editor controls: "none", "allowlist", "blocklist", "audit"
editor_mode = "none"
editors_allowed = []
editors_blocked = []

# AI commit controls
allow_ai_generated = true
require_human_review = false
max_ai_ratio = 1.0

# Review personality: "strict", "standard", "mentor"
personality = "strict"
"""


def _policy_init(project_dir: Path, *, yes: bool) -> int:
    """Create default [policy] section in .codetrust.toml."""
    toml_path = project_dir / ".codetrust.toml"

    if toml_path.exists():
        existing = toml_path.read_text(encoding="utf-8")
        if "[policy]" in existing and not yes:
            _echo(f"  {color('!', YELLOW)} [policy] already exists in .codetrust.toml")
            _echo("  Use --yes to overwrite")
            return 1

    if toml_path.exists():
        content = toml_path.read_text(encoding="utf-8")
        if "[policy]" not in content:
            content = content.rstrip() + "\n\n" + _DEFAULT_POLICY_TOML
        else:
            # Replace existing [policy] section — find from [policy] to next section or EOF
            lines = content.split("\n")
            new_lines: list[str] = []
            in_policy = False
            for line in lines:
                if line.strip() == "[policy]":
                    in_policy = True
                    continue
                if in_policy and line.strip().startswith("["):
                    in_policy = False
                if not in_policy:
                    new_lines.append(line)
            content = "\n".join(new_lines).rstrip() + "\n\n" + _DEFAULT_POLICY_TOML

        toml_path.write_text(content, encoding="utf-8")
    else:
        toml_path.write_text(_DEFAULT_POLICY_TOML, encoding="utf-8")

    _echo(f"  {color('+', GREEN)} Policy config written to {toml_path}")
    return 0


def _policy_validate(project_dir: Path) -> int:
    """Validate the current commit policy config."""
    from src.services.commit_policy import VALID_MODES, VALID_PERSONALITIES, load_policy_config

    config = load_policy_config(project_dir)
    errors: list[str] = []

    if config.model_mode not in VALID_MODES:
        errors.append(f"Invalid model_mode: {config.model_mode}")
    if config.editor_mode not in VALID_MODES:
        errors.append(f"Invalid editor_mode: {config.editor_mode}")
    if config.personality not in VALID_PERSONALITIES:
        errors.append(f"Invalid personality: {config.personality}")
    if not (0.0 <= config.max_ai_ratio <= 1.0):
        errors.append(f"max_ai_ratio must be 0.0-1.0, got {config.max_ai_ratio}")
    if config.model_mode == "allowlist" and not config.models_allowed:
        errors.append("model_mode=allowlist but models_allowed is empty")
    if config.editor_mode == "allowlist" and not config.editors_allowed:
        errors.append("editor_mode=allowlist but editors_allowed is empty")

    if errors:
        _echo(f"\n{color('Policy Validation', BOLD)} — FAILED\n")
        for e in errors:
            _echo(f"  {color('X', RED)} {e}")
        _echo()
        return 1

    _echo(f"\n{color('Policy Validation', BOLD)} — {color('PASS', GREEN)}\n")
    return 0


def _policy_test(project_dir: Path, *, model: str, editor: str) -> int:
    """Test policy against a mock commit."""
    from src.services.commit_policy import CommitPolicyEngine, FileAttribution

    engine = CommitPolicyEngine(project_dir)
    mock_files = [
        FileAttribution(
            file="test_file.py", model=model, provider="simulated",
            editor=editor, ai_probability=0.95,
        ),
    ]
    violations = engine.evaluate(mock_files)

    _echo(f"\n{color('Policy Test', BOLD)}\n")
    _echo(f"  Simulated: model={model}, editor={editor}, ai_prob=0.95\n")

    if not violations:
        _echo(f"  {color('+', GREEN)} Commit would be ALLOWED\n")
        return 0

    for v in violations:
        v_color = RED if v.severity == "BLOCK" else YELLOW
        _echo(f"  {color(v.severity, v_color)} [{v.rule}] {v.message}")

    blocks = sum(1 for v in violations if v.severity == "BLOCK")
    if blocks:
        _echo(f"\n  {color('Commit would be BLOCKED', RED)}\n")
        return 1

    _echo(f"\n  {color('Commit would be ALLOWED with warnings', YELLOW)}\n")
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
    """Install GitHub Action workflow.

    Never overwrites an existing workflow — even with --force.
    CI workflows accumulate manual hardening (timeouts, exclusions,
    file caps) that templates cannot reproduce.  Use --force only
    for first-time creation after manual deletion.
    """
    installed: list[str] = []
    workflows_dir = project_dir / ".github" / "workflows"
    workflows_dir.mkdir(parents=True, exist_ok=True)
    action_file = workflows_dir / "codetrust-scan.yml"
    if action_file.exists():
        _echo(f"  {color('✅', GREEN)} GitHub Action already exists (preserved)")
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


def _init_pretooluse_hooks() -> tuple[int, list[str]]:
    """Install PreToolUse hooks for real-time agent interception.

    Copies gateway and file-write hook scripts to ~/.claude/hooks/
    and registers them in ~/.claude/settings.json.

    Returns:
        (hooks_installed, messages) — count of hooks installed and status messages.
    """
    hooks_dir = Path.home() / ".claude" / "hooks"
    settings_path = Path.home() / ".claude" / "settings.json"
    messages: list[str] = []
    installed = 0

    # Step 1: Create hooks directory
    hooks_dir.mkdir(parents=True, exist_ok=True)

    # Step 2: Copy hook templates
    hook_files = [
        ("pretooluse_gateway_hook.py", "codetrust_gateway_hook.py"),
        ("pretooluse_file_write_hook.py", "codetrust_file_write_hook.py"),
    ]
    for template_name, target_name in hook_files:
        target = hooks_dir / target_name
        content = _load_template(template_name)
        if target.exists():
            existing = target.read_text(encoding="utf-8")
            if existing == content:
                messages.append(f"  {color('✅', GREEN)} {target_name} (already up to date)")
                installed += 1
                continue
        target.write_text(content, encoding="utf-8")
        target.chmod(0o755)
        messages.append(f"  {color('✅', GREEN)} {target_name} installed")
        installed += 1

    # Step 3: Register hooks in ~/.claude/settings.json
    gateway_hook_path = str(hooks_dir / "codetrust_gateway_hook.py")
    file_write_hook_path = str(hooks_dir / "codetrust_file_write_hook.py")

    desired_hooks = [
        {
            "matcher": "Bash",
            "hooks": [
                {
                    "type": "command",
                    "command": f"python3 {gateway_hook_path}",
                    "timeout": 5,
                },
            ],
        },
        {
            "matcher": "Write|Edit|MultiEdit",
            "hooks": [
                {
                    "type": "command",
                    "command": f"python3 {file_write_hook_path}",
                    "timeout": 5,
                },
            ],
        },
    ]

    # Read existing settings or create new
    settings: dict = {}
    if settings_path.exists():
        try:
            settings = json.loads(settings_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            settings = {}

    # Merge hooks — don't duplicate, don't overwrite non-hook settings
    existing_hooks = settings.get("hooks", {})
    pre_tool_use = existing_hooks.get("PreToolUse", [])

    existing_matchers = {
        h.get("matcher", ""): i for i, h in enumerate(pre_tool_use)
    }

    hooks_modified = False
    for desired in desired_hooks:
        matcher = desired["matcher"]
        if matcher in existing_matchers:
            idx = existing_matchers[matcher]
            inner_hooks = pre_tool_use[idx].get("hooks", [])
            hook_cmd = desired["hooks"][0]["command"]
            already_registered = any(
                h.get("command", "") == hook_cmd for h in inner_hooks
            )
            if not already_registered:
                inner_hooks.append(desired["hooks"][0])
                pre_tool_use[idx]["hooks"] = inner_hooks
                hooks_modified = True
        else:
            pre_tool_use.append(desired)
            hooks_modified = True

    if hooks_modified:
        existing_hooks["PreToolUse"] = pre_tool_use
        settings["hooks"] = existing_hooks
        settings_path.parent.mkdir(parents=True, exist_ok=True)
        settings_path.write_text(
            json.dumps(settings, indent=2) + "\n", encoding="utf-8",
        )
        messages.append(f"  {color('✅', GREEN)} Hooks registered in ~/.claude/settings.json")
    else:
        messages.append(f"  {color('✅', GREEN)} Hooks already registered in settings.json")

    return installed, messages


# --- BASH_ENV Guard (universal enforcement for VS Code extension) ---

_BASH_ENV_GUARD_FILENAME = "bash_env_guard.sh"
_BASH_ENV_LINE = 'export BASH_ENV="$HOME/.codetrust/shield/bash_env_guard.sh"  # CodeTrust'
_BASH_ENV_MARKER = "# CodeTrust"


def _init_bash_env_guard() -> list[str]:
    """Install BASH_ENV guard for universal command interception.

    PreToolUse hooks only fire in Claude Code CLI, NOT in VS Code extension.
    BASH_ENV is sourced by bash before every non-interactive -c command,
    which is how ALL Claude Code variants (CLI and extension) spawn bash.

    This provides real-time enforcement that works everywhere.

    Returns:
        List of status messages.
    """
    messages: list[str] = []
    shield_dir = Path.home() / ".codetrust" / "shield"
    guard_target = shield_dir / _BASH_ENV_GUARD_FILENAME

    # Step 1: Copy guard script to ~/.codetrust/shield/
    shield_dir.mkdir(parents=True, exist_ok=True)
    guard_source = Path(__file__).parent / "templates" / _BASH_ENV_GUARD_FILENAME
    if not guard_source.exists():
        messages.append(f"  {color('⚠️', YELLOW)} bash_env_guard.sh template not found")
        return messages

    content = guard_source.read_text(encoding="utf-8")
    if guard_target.exists():
        existing = guard_target.read_text(encoding="utf-8")
        if existing == content:
            messages.append(
                f"  {color('✅', GREEN)} bash_env_guard.sh (already up to date)",
            )
        else:
            guard_target.write_text(content, encoding="utf-8")
            guard_target.chmod(0o755)
            messages.append(f"  {color('✅', GREEN)} bash_env_guard.sh updated")
    else:
        guard_target.write_text(content, encoding="utf-8")
        guard_target.chmod(0o755)
        messages.append(f"  {color('✅', GREEN)} bash_env_guard.sh installed")

    # Step 2: Add BASH_ENV export to shell profile
    profile_path = _find_shell_profile()
    if profile_path is None:
        messages.append(
            f"  {color('⚠️', YELLOW)} No shell profile found — add manually: "
            f"{_BASH_ENV_LINE}",
        )
        return messages

    profile_content = profile_path.read_text(encoding="utf-8")
    if _BASH_ENV_MARKER in profile_content:
        messages.append(
            f"  {color('✅', GREEN)} BASH_ENV already configured in {profile_path.name}",
        )
    else:
        separator = "" if profile_content.endswith("\n") else "\n"
        profile_path.write_text(
            profile_content + separator
            + "\n# CodeTrust BASH_ENV guard — real-time command validation\n"
            + _BASH_ENV_LINE + "\n",
            encoding="utf-8",
        )
        messages.append(
            f"  {color('✅', GREEN)} BASH_ENV configured in {profile_path.name}",
        )

    # Step 3: Set BASH_ENV for current session via launchctl (macOS)
    import platform

    if platform.system() == "Darwin":
        import subprocess

        try:
            subprocess.run(
                ["launchctl", "setenv", "BASH_ENV", str(guard_target)],
                check=True,
                capture_output=True,
                timeout=5,
            )
            messages.append(
                f"  {color('✅', GREEN)} BASH_ENV set for current session (launchctl)",
            )
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            messages.append(
                f"  {color('⚠️', YELLOW)} launchctl setenv failed — restart terminal",
            )

    return messages


def _find_shell_profile() -> Path | None:
    """Find the user's active shell profile file."""
    import os

    shell = os.environ.get("SHELL", "/bin/bash")
    home = Path.home()

    if "zsh" in shell:
        candidates = [home / ".zshrc", home / ".zprofile"]
    else:
        candidates = [home / ".bash_profile", home / ".bashrc", home / ".profile"]

    for candidate in candidates:
        if candidate.exists():
            return candidate

    return None


def _init_dod_file(project_dir: Path) -> None:
    """Create a default Definition of Done file if it doesn't exist."""
    dod_dir = project_dir / ".codetrust"
    dod_dir.mkdir(parents=True, exist_ok=True)
    dod_path = dod_dir / "definition_of_done.toml"
    if dod_path.exists():
        _echo(f"  {color('✅', GREEN)} Definition of Done file already exists")
        return

    default_content = (
        '# Definition of Done — external enforcement gate\n'
        '# Run: codetrust dod\n'
        '# Exit code 0 = ALL checks pass. Exit code 1 = ANY check fails.\n'
        '\n'
        '[[checks]]\n'
        'name = "Full test suite"\n'
        'command = "pytest tests/ -x -q"\n'
        'expected_exit_code = 0\n'
        'expected_output_contains = ["passed"]\n'
        'expected_output_excludes = ["FAILED", "ERROR"]\n'
        '\n'
        '[[checks]]\n'
        'name = "Linting"\n'
        'command = "ruff check src/ --ignore RUF001"\n'
        'expected_exit_code = 0\n'
        'expected_output_excludes = ["error"]\n'
        '\n'
        '[[checks]]\n'
        'name = "Doctor all layers"\n'
        'command = "python -m src.cli doctor"\n'
        'expected_exit_code = 0\n'
        'expected_output_excludes = ["MISSING", "FAILED"]\n'
    )
    dod_path.write_text(default_content, encoding="utf-8")
    _echo(f"  {color('✅', GREEN)} Created Definition of Done: {dod_path}")


def _init_pii_policy(project_dir: Path) -> None:
    """Create a default PII detection policy if it doesn't exist."""
    policy_path = project_dir / ".codetrust" / "pii-policy.toml"
    if policy_path.exists():
        _echo(f"  {color('✅', GREEN)} PII policy already exists")
        return

    content = (
        "# PII Detection Policy\n"
        "# Controls how CodeTrust handles personally identifiable information.\n"
        "\n"
        "[pii]\n"
        'enabled = true\n'
        'mode = "warn"              # "block" | "warn" | "redact" | "off"\n'
        "min_confidence = 0.7\n"
        "log_findings = true\n"
        "\n"
        "[pii.categories]\n"
        '# Override mode per category\n'
        'api_key = "block"\n'
        'private_key = "block"\n'
        'password = "block"\n'
        'credit_card = "block"\n'
        'personnummer = "block"\n'
        'email = "warn"\n'
        'phone = "warn"\n'
        'name = "off"\n'
    )
    policy_path.write_text(content, encoding="utf-8")
    _echo(f"  {color('✅', GREEN)} Created PII policy: {policy_path}")


def _init_model_routing_policy(project_dir: Path) -> None:
    """Create a default model routing policy if it doesn't exist."""
    policy_path = project_dir / ".codetrust" / "model-routing.toml"
    if policy_path.exists():
        _echo(f"  {color('✅', GREEN)} Model routing policy already exists")
        return

    content = (
        "# Model Routing Policy\n"
        "# Controls which LLM models can access data at each sensitivity level.\n"
        "\n"
        "[model_routing]\n"
        "enabled = true\n"
        '"default_action" = "warn"\n'
        "\n"
        "[model_routing.levels.public]\n"
        'allowed_models = ["*"]\n'
        "\n"
        "[model_routing.levels.internal]\n"
        'allowed_models = ["claude-*", "gpt-4o", "gpt-4o-mini"]\n'
        'blocked_models = ["*-preview", "experimental-*"]\n'
        "\n"
        "[model_routing.levels.confidential]\n"
        'allowed_models = ["claude-opus-*", "claude-sonnet-*", "gpt-4o"]\n'
        "\n"
        "[model_routing.levels.restricted]\n"
        "allowed_models = []\n"
        'action = "block"\n'
        "redact_before_send = true\n"
    )
    policy_path.write_text(content, encoding="utf-8")
    _echo(f"  {color('✅', GREEN)} Created model routing policy: {policy_path}")


def _init_print_summary() -> None:
    """Print the post-init enforcement stack summary."""
    _echo(f"\n{'━' * 48}")
    _echo(f"  {color('✅ CodeTrust installed — 9 enforcement layers active', GREEN)}")
    _echo(f"  Config: .codetrust.toml  |  Verify: {color('codetrust doctor', BOLD)}")
    _echo(f"{'━' * 48}\n")


def audit_allow_list(project_dir: Path) -> list[dict[str, str]]:
    """Scan Claude Code settings for allow-list entries that bypass hooks.

    PreToolUse hooks do NOT run for commands in permissions.allow.
    This means any allow-listed command bypasses CodeTrust Gateway entirely.

    Returns:
        List of findings, each with 'file', 'line', 'entry', 'reason'.
    """
    # Patterns that bypass critical Gateway protections
    dangerous_patterns: list[tuple[re.Pattern[str], str]] = [
        (re.compile(r"git\s+push"), "bypasses git push blockering"),
        (re.compile(r"rm\s+-[rR]f"), "bypasses destructive file deletion blockering"),
        (re.compile(r"\beval\b"), "bypasses eval blockering"),
        (re.compile(r"curl.*\|\s*(?:ba)?sh"), "bypasses remote code execution blockering"),
        (re.compile(r"\bsudo\s+su\b"), "bypasses privilege escalation blockering"),
        (re.compile(r"\bchmod\s+777\b"), "bypasses permission weakening blockering"),
        (re.compile(r"\bdd\s+.*of="), "bypasses disk write blockering"),
        (re.compile(r"\bmkfs\b"), "bypasses filesystem format blockering"),
        (re.compile(r"docker\s+run.*--privileged"), "bypasses privileged container blockering"),
    ]

    findings: list[dict[str, str]] = []
    settings_paths = [
        Path.home() / ".claude" / "settings.json",
        project_dir / ".claude" / "settings.json",
    ]

    for settings_path in settings_paths:
        if not settings_path.is_file():
            continue
        try:
            raw = settings_path.read_text(encoding="utf-8")
            data = json.loads(raw)
        except (json.JSONDecodeError, OSError):
            continue

        allow_list = data.get("permissions", {}).get("allow", [])
        if not isinstance(allow_list, list):
            continue

        lines = raw.splitlines()
        for entry in allow_list:
            if not isinstance(entry, str):
                continue
            for pattern, reason in dangerous_patterns:
                if pattern.search(entry):
                    # Find line number
                    line_num = 0
                    for i, line in enumerate(lines, start=1):
                        if entry in line:
                            line_num = i
                            break
                    findings.append({
                        "file": str(settings_path),
                        "line": str(line_num),
                        "entry": entry,
                        "reason": reason,
                    })
                    break  # One finding per entry

    return findings


def _print_allow_list_audit(findings: list[dict[str, str]]) -> None:
    """Print allow-list audit warnings."""
    if not findings:
        _echo(f"  {color('✅ Allow-list clean', GREEN)} — no Gateway bypasses found")
        return

    _echo(f"\n  {color('⚠️  WARNING: Allow-list entries bypass PreToolUse hooks', YELLOW)}")
    _echo(f"  {color('These commands will NOT be validated by CodeTrust Gateway:', YELLOW)}\n")
    for f in findings:
        _echo(f"    {f['file']}:{f['line']}  {color(f['entry'], RED)}")
        _echo(f"      → {f['reason']}")
    _echo(f"\n  {color('Fix:', BOLD)} Remove these entries. PreToolUse hooks do not run")
    _echo("  for allow-listed commands (Claude Code architecture limitation).\n")


def cmd_init(args: argparse.Namespace) -> int:
    """Install CodeTrust enforcement layers into current project."""
    project_dir = Path.cwd()

    if not (project_dir / ".git").is_dir():
        _echo(
            f"\n{color('❌', RED)} Not a git repository. "
            f"Run {color('git init', BOLD)} first.\n"
        )
        return 1

    if getattr(args, "check", False):
        _echo(f"\n{color('🛡️  CodeTrust — Installation check', BOLD)}\n")
        audit_findings = audit_allow_list(project_dir)
        _print_allow_list_audit(audit_findings)
        return 1 if audit_findings else 0

    _echo(f"\n{color('🛡️  CodeTrust — Installing AI Governance enforcement', BOLD)}\n")

    # Project-level layers
    _init_advisory_files(project_dir, force=args.force)
    _init_precommit_hook(project_dir)
    _init_github_action(project_dir, force=args.force)
    _init_gitignore_and_governance(project_dir, force=args.force)
    _init_policy_integrity_manifest(project_dir)

    # Real-time enforcement: PreToolUse hooks (user-level)
    _echo(f"\n  {color('Installing real-time enforcement hooks...', BOLD)}")
    _hooks_count, hook_messages = _init_pretooluse_hooks()
    for msg in hook_messages:
        _echo(msg)

    # BASH_ENV guard (universal enforcement — works in VS Code extension)
    _echo(f"\n  {color('Installing BASH_ENV command guard...', BOLD)}")
    _bash_env_messages = _init_bash_env_guard()
    for msg in _bash_env_messages:
        _echo(msg)

    # MCP server configuration (user-level)
    _echo(f"\n  {color('Configuring MCP servers...', BOLD)}")
    mcp_count = _inject_mcp_servers()
    if mcp_count > 0:
        _echo(f"  {color('✅', GREEN)} {mcp_count} IDE config(s) updated with MCP servers")
    else:
        _echo(f"  {color('✅', GREEN)} MCP servers already configured")

    # Definition of Done file
    _init_dod_file(project_dir)

    # PII policy + model routing policy
    _init_pii_policy(project_dir)
    _init_model_routing_policy(project_dir)

    # Audit allow-list after installation — BLOCK if dangerous entries found
    audit_findings = audit_allow_list(project_dir)
    _print_allow_list_audit(audit_findings)

    _init_print_summary()

    if audit_findings:
        _echo(
            f"\n  {color('⛔ GOVERNANCE INCOMPLETE', RED)}: "
            f"{len(audit_findings)} allow-list entry(s) bypass enforcement.",
        )
        _echo(
            f"  Remove dangerous entries from ~/.claude/settings.json "
            f"or run: {color('codetrust doctor', BOLD)}",
        )
        return 1

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
        logger.debug("import_telemetry_failed", exc_info=True)
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
            except OSError as exc:
                logger.debug("sig_scan_read_error", file=str(fpath), error=str(exc))
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


_TAINT_CLI_SUPPORTED_LANGUAGES: set[str] = {"python", "javascript", "typescript"}

_TAINT_EXT_LANG: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".jsx": "javascript",
}


def _scan_runtime_verify(
    targets: list[str],
    all_findings: list[dict[str, str | int]],
    args: argparse.Namespace,
    *,
    machine_output: bool,
) -> list[dict[str, str | int]]:
    """Run runtime taint verification on scanned files.

    Performs taint analysis on each source file, then attempts to confirm
    findings by running proof-of-concept exploits in a sandboxed Docker
    container. Verified findings are appended with enriched metadata.
    """
    if not getattr(args, "runtime_verify", False):
        return all_findings

    try:
        import asyncio

        from src.models.enums import Language
        from src.services.runtime_taint_verifier import RuntimeTaintVerifier
        from src.services.sandbox import SandboxService
        from src.services.taint_analyzer import TaintAnalyzer

        source_files = _scan_collect_taint_files(targets)
        if not source_files:
            return all_findings

        if not machine_output:
            _echo(
                f"  {color('🧪 Running runtime taint verification...', BLUE)}"
                f" ({len(source_files)} file(s))"
            )

        taint_anal = TaintAnalyzer()
        sandbox_svc = SandboxService()
        verifier = RuntimeTaintVerifier(sandbox=sandbox_svc)

        verified_total = 0
        exploitable_total = 0

        for fpath, lang_str in source_files:
            try:
                with open(fpath, encoding="utf-8", errors="ignore") as f:
                    code = f.read()
                lang = Language(lang_str)
                findings = taint_anal.analyze(code, lang, fpath)
                if not findings:
                    continue

                summary = asyncio.run(
                    verifier.verify_findings(findings, language=lang),
                )
                for vf in summary.results:
                    status_label = "VERIFIED" if vf.verified else "unverified"
                    all_findings.append({
                        "rule_id": vf.finding.rule_id,
                        "severity": vf.finding.severity.value
                        if hasattr(vf.finding.severity, "value")
                        else str(vf.finding.severity),
                        "message": f"[{status_label}] {vf.finding.message}",
                        "file": fpath,
                        "line": vf.finding.line,
                        "suggestion": vf.finding.suggestion,
                        "confidence": vf.confidence,
                        "exploit_payload": vf.exploit_payload,
                        "verification_method": vf.verification_method,
                    })
                    verified_total += 1
                    if vf.verified:
                        exploitable_total += 1
            except OSError as exc:
                logger.debug("runtime_verify_read_error", file=str(fpath), error=str(exc))
                continue

        if not machine_output:
            if verified_total:
                _echo(
                    f"  {color(f'   Taint findings: {verified_total}', YELLOW)}"
                    f" ({exploitable_total} confirmed exploitable)\n"
                )
            else:
                _echo(f"  {color('   No taint flows detected ✓', GREEN)}\n")

    except Exception as exc:
        logger.debug(
            "runtime_taint_verify_failed",
            error=str(exc),
            error_type=type(exc).__name__,
        )
    return all_findings


def _scan_collect_taint_files(
    targets: list[str],
) -> list[tuple[str, str]]:
    """Collect source files for taint analysis.

    Returns list of (filepath, language_string) tuples for taint-supported languages.
    """
    result: list[tuple[str, str]] = []
    skip_dirs = {
        ".git", ".venv", "venv", "node_modules", "__pycache__",
        "dist", "build", ".next", ".open-next", ".turbo",
        ".nuxt", ".output", ".svelte-kit", ".vercel", ".wrangler",
        "coverage", "out", ".cache",
    }
    for target in targets:
        p = Path(target)
        if p.is_file():
            ext = p.suffix.lower()
            lang = _TAINT_EXT_LANG.get(ext, "")
            if lang:
                result.append((str(p), lang))
        elif p.is_dir():
            for root, dirs, files in os.walk(p):
                dirs[:] = [d for d in dirs if d not in skip_dirs]
                for fname in files:
                    ext = Path(fname).suffix.lower()
                    lang = _TAINT_EXT_LANG.get(ext, "")
                    if lang:
                        fpath = os.path.join(root, fname)
                        result.append((fpath, lang))
    return result


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
    *,
    is_free_plan: bool = False,
) -> None:
    """Print findings grouped by severity for human output."""
    if blocks and not is_free_plan:
        _echo(color("  ✖ BLOCKED — execution stopped:", RED))
        for f in blocks:
            _echo(f"     {f['file']}:{f['line']} [{f['rule_id']}] {f['message']}")
        _echo()
    elif blocks and is_free_plan:
        _echo(color("  ⚠️  WARN — issues detected (Free plan):", YELLOW))
        for f in blocks:
            _echo(f"     {f['file']}:{f['line']} [{f['rule_id']}] {f['message']}")
        _echo(color("     Execution allowed (Free plan)", YELLOW))
        _echo(color("     🔒 Upgrade to Pro to block before execution → codetrust upgrade", BLUE))
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
    """Print upgrade hint when free-tier features are limited."""
    if not upgrade_hints:
        return
    _echo(
        "  🔒 Upgrade to Pro: registry BLOCK enforcement, GitHub Action PR gate, "
        "Docker verification, sandbox execution",
    )
    _echo("     → https://app.codetrust.ai/pricing")


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

    hints = result.get("upgrade_hints", [])
    is_free = bool(hints)  # upgrade_hints only present for free tier
    _scan_output_findings_by_severity(blocks, warns, infos, is_free_plan=is_free)

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


# --- Login command ---


def cmd_login(args: argparse.Namespace) -> int:
    """Authenticate with CodeTrust, fetch scan token, store locally."""
    api_key = getattr(args, "api_key", "") or ""

    if not api_key:
        _echo(f"\n{color('🔑 CodeTrust Login', BOLD)}\n")
        _echo("  Get your API key at https://app.codetrust.ai\n")
        try:
            import getpass
            api_key = getpass.getpass("  API key: ").strip()
        except (EOFError, KeyboardInterrupt):
            _echo("\n")
            return 1
        if not api_key:
            return 1

    _echo("  Validating API key...")
    try:
        import httpx

        # Step 1: Validate key and get profile
        profile_resp = httpx.get(
            f"{_API_BASE_URL}/v1/profile",
            headers={"X-API-Key": api_key},
            timeout=10,
        )
        if profile_resp.status_code != 200:
            _echo(color("  ❌ Invalid API key or server error.\n", RED))
            return 1

        profile = profile_resp.json()
        email = str(profile.get("email", ""))

        # Step 2: Fetch scan token
        token_resp = httpx.post(
            f"{_API_BASE_URL}/v1/auth/token",
            headers={"X-API-Key": api_key},
            timeout=10,
        )
        if token_resp.status_code not in {200, 429}:
            _echo(color("  ❌ Could not issue scan token.\n", RED))
            return 1

        token_data = token_resp.json()
        plan = str(token_data.get("plan", "free"))
        quota_limit = token_data.get("quota_limit", 25)

        auth_data = {
            "api_key": api_key,
            "token": str(token_data.get("token", "")),
            "plan": plan,
            "email": email,
            "quota_limit": str(quota_limit),
            "quota_used": str(token_data.get("quota_used", 0)),
            "expires_at": str(token_data.get("expires_at", "")),
        }
        if token_resp.status_code == 429:
            auth_data["quota_exceeded"] = "true"

        _save_local_auth(auth_data)

    except (ImportError, OSError, ValueError) as exc:
        _echo(color(f"  ❌ Could not reach API: {exc}\n", RED))
        return 1

    _echo(color(f"  ✅ Logged in ({plan} plan)", GREEN))
    if email:
        _echo(f"     Account: {email}")
    _echo(f"     Scan quota: {quota_limit}/day")
    if plan == "free":
        _echo(color("     Upgrade to Pro for unlimited: https://app.codetrust.ai/pricing", BLUE))
    _echo()
    return 0


def cmd_logout(_args: argparse.Namespace) -> int:
    """Remove local authentication data."""
    if not _AUTH_FILE.exists():
        _echo("  No active session.\n")
        return 0
    try:
        _AUTH_FILE.unlink()
    except OSError as exc:
        _echo(f"  Failed to remove auth data: {exc}\n")
        return 1
    _echo(color("  ✅ Logged out — auth data removed.\n", GREEN))
    return 0


# --- Local scan gate (auth + usage quota) ---

_AUTH_FILE = Path.home() / ".codetrust" / "auth.json"
_API_BASE_URL = os.environ.get("CODETRUST_API_URL", "https://api.codetrust.ai")

_TOKEN_EXPIRY_HOURS: int = 24
_TOKEN_REFRESH_BUFFER_HOURS: int = 2


def _load_local_auth() -> dict[str, str]:
    """Load local auth from ~/.codetrust/auth.json."""
    if not _AUTH_FILE.exists():
        return {}
    try:
        return json.loads(_AUTH_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _save_local_auth(auth: dict[str, str | int]) -> None:
    """Save auth data to ~/.codetrust/auth.json."""
    _AUTH_FILE.parent.mkdir(parents=True, exist_ok=True)
    _AUTH_FILE.write_text(json.dumps(auth), encoding="utf-8")


def _token_is_valid(auth: dict[str, str]) -> bool:
    """Check if the stored token is present and not expired."""
    token = auth.get("token", "")
    expires_at = auth.get("expires_at", "")
    if not token or not expires_at:
        return False
    try:
        from datetime import UTC as _UTC
        from datetime import datetime as _dt

        expiry = _dt.fromisoformat(expires_at)
        return _dt.now(tz=_UTC) < expiry
    except (ValueError, TypeError):
        return False


def _token_needs_refresh(auth: dict[str, str]) -> bool:
    """Check if the token is within the refresh buffer window."""
    expires_at = auth.get("expires_at", "")
    if not expires_at:
        return True
    try:
        from datetime import UTC as _UTC
        from datetime import datetime as _dt
        from datetime import timedelta

        expiry = _dt.fromisoformat(expires_at)
        return _dt.now(tz=_UTC) > expiry - timedelta(hours=_TOKEN_REFRESH_BUFFER_HOURS)
    except (ValueError, TypeError):
        return True


def _refresh_token(auth: dict[str, str]) -> dict[str, str] | None:
    """Request a fresh token from the server. Returns updated auth or None."""
    api_key = auth.get("api_key", "")
    if not api_key:
        return None
    try:
        import httpx

        resp = httpx.post(
            f"{_API_BASE_URL}/v1/auth/token",
            headers={"X-API-Key": api_key},
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            auth["token"] = str(data.get("token", ""))
            auth["plan"] = str(data.get("plan", "free"))
            auth["quota_limit"] = str(data.get("quota_limit", 25))
            auth["quota_used"] = str(data.get("quota_used", 0))
            auth["expires_at"] = str(data.get("expires_at", ""))
            _save_local_auth(auth)
            return auth
        if resp.status_code == 429:
            auth["quota_exceeded"] = "true"
            _save_local_auth(auth)
            return auth
    except (ImportError, OSError, ValueError):
        pass
    return None


def _check_local_scan_gate() -> int:
    """Check auth and token before allowing a scan.

    No account = no scans. Token is server-signed and validated locally.
    Refreshed once per day. Cannot be fabricated or manipulated.

    Returns 0 to proceed, 1 to block.
    """
    # Pre-commit hook and CI bypass scan gate (they use their own auth)
    if os.environ.get("CODETRUST_PRECOMMIT") == "1":
        return 0
    if os.environ.get("CI") == "true":
        return 0

    # Environment variable overrides auth.json (master key, CI, dev)
    env_key = os.environ.get("CODETRUST_MASTER_KEY") or os.environ.get("CODETRUST_API_KEY")
    if env_key and env_key != "[I will paste the key myself]":
        return 0

    auth = _load_local_auth()
    api_key = auth.get("api_key", "")

    # No account → blocked
    if not api_key:
        _echo(color("\n  🔒 Account required to scan.", YELLOW))
        _echo("     Create a free account (25 scans/day):")
        _echo(color("     → codetrust login", BOLD))
        _echo("")
        _echo("     Get your API key at https://app.codetrust.ai")
        _echo("     Upgrade to Pro for unlimited scans:")
        _echo(color("     → https://app.codetrust.ai/pricing\n", BLUE))
        return 1

    # Token expired or missing → refresh
    if not _token_is_valid(auth) or _token_needs_refresh(auth):
        refreshed = _refresh_token(auth)
        if refreshed is None:
            # Server unreachable — allow if token was recently valid
            if auth.get("token") and auth.get("expires_at"):
                _echo(color("  i  Server unreachable — using cached token\n", BLUE))
                return 0
            _echo(color("\n  🔒 Could not validate account. Check internet connection.", YELLOW))
            _echo(color("     → codetrust login\n", BOLD))
            return 1
        auth = refreshed

    # Quota exceeded
    if auth.get("quota_exceeded") == "true":
        plan = auth.get("plan", "free")
        limit = auth.get("quota_limit", "25")
        _echo(color(f"\n  🔒 Daily scan limit reached ({limit}/day on {plan} plan)", YELLOW))
        _echo("     Upgrade for higher limits:")
        _echo(color("     → https://app.codetrust.ai/pricing\n", BLUE))
        return 1

    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    """Scan files for anti-patterns."""
    gate_result = _check_local_scan_gate()
    if gate_result != 0:
        return gate_result

    start_time = time.monotonic()
    targets, machine_output, baseline_ref, baseline_mode = _scan_parse_options(args)

    if baseline_mode:
        all_findings, files_scanned = _scan_baseline_collect(
            targets, baseline_ref, args, machine_output=machine_output,
        )
    else:
        all_findings, files_scanned = _scan_direct_collect(targets)

    # Skip network-dependent checks in CI (no Redis cache, slow registry
    # lookups, tree-sitter compilation).  Regex scan covers the quality gate.
    is_ci = os.environ.get("CI") == "true"

    if not is_ci:
        all_findings, hallucinations = _scan_verify_imports(
            targets, all_findings, args, machine_output=machine_output,
        )

        all_findings = _scan_validate_signatures(
            targets, all_findings, args, machine_output=machine_output,
        )

        all_findings = _scan_runtime_verify(
            targets, all_findings, args, machine_output=machine_output,
        )
    else:
        hallucinations = 0

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


def _doctor_check_bash_env_guard() -> list[str]:
    """Check BASH_ENV guard installation and functionality."""
    issues: list[str] = []
    guard_path = Path.home() / ".codetrust" / "shield" / "bash_env_guard.sh"

    _echo(f"\n  {color('Layer 1: BASH_ENV Guard (universal real-time)', BOLD)}")

    # Check guard script exists
    if guard_path.exists():
        _echo(f"    {color('✅', GREEN)} bash_env_guard.sh installed")
    else:
        issues.append("BASH_ENV guard not installed")
        _echo(f"    {color('❌', RED)} bash_env_guard.sh NOT FOUND")
        _echo(f"       Fix: {color('codetrust init', BOLD)}")
        return issues

    # Check BASH_ENV is set in environment
    bash_env_val = os.environ.get("BASH_ENV", "")
    if "bash_env_guard" in bash_env_val:
        _echo(f"    {color('✅', GREEN)} BASH_ENV active in environment")
    else:
        issues.append("BASH_ENV not set — guard inactive until shell restart")
        _echo(f"    {color('⚠️', YELLOW)}  BASH_ENV not set in current environment")
        _echo(f"       Fix: restart terminal or run: export BASH_ENV=\"{guard_path}\"")

    # Check shell profile has BASH_ENV export
    profile = _find_shell_profile()
    if profile is not None:
        try:
            content = profile.read_text(encoding="utf-8")
            if _BASH_ENV_MARKER in content:
                _echo(f"    {color('✅', GREEN)} BASH_ENV configured in {profile.name}")
            else:
                issues.append(f"BASH_ENV not in {profile.name}")
                _echo(f"    {color('❌', RED)} BASH_ENV not configured in {profile.name}")
                _echo(f"       Fix: {color('codetrust init', BOLD)}")
        except OSError:
            pass

    # Functional test: heredoc → expect block
    try:
        result = subprocess.run(
            ["/bin/bash", "-c", "echo test"],
            env={**os.environ, "BASH_ENV": str(guard_path)},
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            _echo(f"    {color('✅', GREEN)} Test: normal command → PASS")
        else:
            issues.append("BASH_ENV guard blocks normal commands")
            _echo(f"    {color('❌', RED)} Test: normal command → FAILED (exit {result.returncode})")
    except (subprocess.TimeoutExpired, OSError) as exc:
        issues.append(f"BASH_ENV guard test failed: {exc}")

    # Verify guard script contains heredoc detection rule
    try:
        guard_content = guard_path.read_text(encoding="utf-8")
        heredoc_marker = "<" + "<"  # Split to avoid self-detection
        if heredoc_marker in guard_content and "guard_heredoc" in guard_content:
            _echo(f"    {color('✅', GREEN)} Guard contains heredoc detection rule")
        else:
            issues.append("BASH_ENV guard missing heredoc rule")
            _echo(f"    {color('❌', RED)} Guard missing heredoc detection rule")
    except OSError as exc:
        issues.append(f"Cannot read guard script: {exc}")

    # Detect VS Code extension environment
    if os.environ.get("CLAUDECODE") == "1" and "vscode" in os.environ.get("CLAUDE_CODE_ENTRYPOINT", ""):
        _echo(f"    {color('⚠️', YELLOW)}  Running in VS Code extension — PreToolUse hooks INACTIVE")
        _echo("       BASH_ENV guard is your primary enforcement layer here")

    return issues


def _doctor_check_pretooluse_hooks() -> list[str]:
    """Check PreToolUse hooks installation and registration."""
    issues: list[str] = []
    hooks_dir = Path.home() / ".claude" / "hooks"
    settings_path = Path.home() / ".claude" / "settings.json"

    _echo(f"\n  {color('Layer 2: PreToolUse Hooks (CLI real-time)', BOLD)}")

    # Check hook files exist
    gateway_hook = hooks_dir / "codetrust_gateway_hook.py"
    file_write_hook = hooks_dir / "codetrust_file_write_hook.py"

    for hook_path, label in [
        (gateway_hook, "Gateway hook (Bash interception)"),
        (file_write_hook, "File-write hook (Write/Edit protection)"),
    ]:
        if hook_path.exists():
            _echo(f"    {color('✅', GREEN)} {label}: {hook_path}")
        else:
            issues.append(f"PreToolUse hook missing: {hook_path}")
            _echo(f"    {color('❌', RED)} {label}: NOT FOUND")
            _echo(f"       Fix: {color('codetrust init', BOLD)}")

    # Check hooks registered in settings.json
    if settings_path.exists():
        try:
            settings = json.loads(settings_path.read_text(encoding="utf-8"))
            pre_tool_use = settings.get("hooks", {}).get("PreToolUse", [])
            matchers = [h.get("matcher", "") for h in pre_tool_use]

            if "Bash" in matchers:
                _echo(f"    {color('✅', GREEN)} Bash hook registered in settings.json")
            else:
                issues.append("Bash PreToolUse hook not registered")
                _echo(f"    {color('❌', RED)} Bash hook NOT registered in settings.json")

            write_registered = any(
                "Write" in m or "Edit" in m for m in matchers
            )
            if write_registered:
                _echo(f"    {color('✅', GREEN)} Write/Edit hook registered in settings.json")
            else:
                issues.append("Write/Edit PreToolUse hook not registered")
                _echo(f"    {color('❌', RED)} Write/Edit hook NOT registered in settings.json")

        except (json.JSONDecodeError, OSError):
            issues.append("Cannot read ~/.claude/settings.json")
            _echo(f"    {color('❌', RED)} Cannot read ~/.claude/settings.json")
    else:
        issues.append("~/.claude/settings.json not found")
        _echo(f"    {color('❌', RED)} ~/.claude/settings.json not found")

    # Functional test: simulate git push → expect block
    if gateway_hook.exists():
        test_input = json.dumps({
            "tool_name": "Bash",
            "tool_input": {"command": "git push origin main"},
        })
        try:
            result = subprocess.run(
                [sys.executable, str(gateway_hook)],
                input=test_input, capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 2:
                _echo(f"    {color('✅', GREEN)} Test: 'git push' → BLOCKED (exit 2)")
            else:
                issues.append("Gateway hook did not block 'git push'")
                _echo(f"    {color('❌', RED)} Test: 'git push' → NOT BLOCKED (exit {result.returncode})")
        except (subprocess.TimeoutExpired, OSError) as exc:
            issues.append(f"Gateway hook test failed: {exc}")
            _echo(f"    {color('❌', RED)} Test failed: {exc}")

        # Health-check: safe command → expect ALLOW (exit 0)
        safe_input = json.dumps({
            "tool_name": "Bash",
            "tool_input": {"command": "ls -la"},
        })
        try:
            safe_result = subprocess.run(
                [sys.executable, str(gateway_hook)],
                input=safe_input, capture_output=True, text=True, timeout=5,
            )
            if safe_result.returncode == 0:
                _echo(f"    {color('✅', GREEN)} Health: 'ls -la' → ALLOWED (exit 0)")
            else:
                issues.append(
                    f"Gateway hook rejected safe command (exit {safe_result.returncode})",
                )
                _echo(
                    f"    {color('❌', RED)} Health: 'ls -la' → REJECTED "
                    f"(exit {safe_result.returncode}) — hook may be broken",
                )
        except (subprocess.TimeoutExpired, OSError) as exc:
            issues.append(f"Gateway hook health-check failed: {exc}")
            _echo(f"    {color('❌', RED)} Health-check failed: {exc}")

    return issues


def _doctor_check_compliance() -> list[str]:
    """Check compliance coverage across all registered frameworks."""
    # Compliance is ADVISORY — gaps do not block doctor exit code.
    # Use 'codetrust compliance --strict' for enforcement.
    try:
        from src.services.compliance import (
            compliance_summary,
            get_compliance_report,
            list_frameworks,
        )

        for fid, fname in list_frameworks().items():
            report = get_compliance_report(fid)
            summary = compliance_summary(report)
            full_count = sum(1 for r in report.risks if r.coverage_level == "full")
            total = len(report.risks)
            if full_count == total:
                _echo(f"    {color('✅', GREEN)} {fname}: {summary}")
            else:
                _echo(f"    {color('⚠️', YELLOW)}  {fname}: {summary} (advisory)")
    except (ImportError, ValueError, OSError) as exc:
        _echo(f"    {color('⚠️', YELLOW)}  Compliance check failed: {exc}")
    return []


def _doctor_check_mcp_config() -> list[str]:
    """Check MCP server configuration in IDE config files."""
    issues: list[str] = []
    _echo(f"\n  {color('Layer 3: MCP Gateway + Guardian', BOLD)}")

    targets = _get_mcp_targets()
    found_any = False
    for name, config_path in targets:
        if not config_path.exists():
            _echo(f"    {color('—', BLUE)} {name}: config not found (IDE not installed?)")
            continue
        try:
            config = json.loads(config_path.read_text(encoding="utf-8"))
            servers = config.get("mcpServers", {})
            has_guardian = GUARDIAN_SERVER_NAME in servers
            has_gateway = GATEWAY_SERVER_NAME in servers
            if has_guardian and has_gateway:
                _echo(f"    {color('✅', GREEN)} {name}: Guardian + Gateway configured")
                found_any = True
            elif has_guardian:
                _echo(f"    {color('⚠️', YELLOW)}  {name}: Guardian only (no Gateway)")
                found_any = True
            elif has_gateway:
                _echo(f"    {color('⚠️', YELLOW)}  {name}: Gateway only (no Guardian)")
                found_any = True
            else:
                _echo(f"    {color('❌', RED)} {name}: no CodeTrust servers")
        except (json.JSONDecodeError, OSError):
            _echo(f"    {color('⚠️', YELLOW)}  {name}: cannot read config")

    if not found_any:
        issues.append("No IDE has MCP servers configured")
        _echo(f"    {color('❌', RED)} No IDE has CodeTrust MCP servers configured")
        _echo(f"       Fix: {color('codetrust init', BOLD)}")

    return issues


def cmd_doctor(args: argparse.Namespace) -> int:
    """Run diagnostic checks on CodeTrust AI Governance installation."""
    _echo(f"\n{color('🛡️  CodeTrust Doctor — AI Governance Verification', BOLD)}\n")

    issues: list[str] = []
    project_dir = Path.cwd()

    if not (project_dir / ".git").is_dir():
        issues.append("Not a git repository")

    # Layer 1: BASH_ENV guard (universal real-time enforcement)
    issues.extend(_doctor_check_bash_env_guard())

    # Layer 2: PreToolUse hooks (CLI real-time enforcement)
    issues.extend(_doctor_check_pretooluse_hooks())

    # Layer 3: MCP servers
    issues.extend(_doctor_check_mcp_config())

    # Layer 4: Pre-commit hook
    _echo(f"\n  {color('Layer 4: Pre-commit Hook (commit gate)', BOLD)}")
    hooks_path = _doctor_check_hooks_path(project_dir)
    hooks_path_set = hooks_path == "hooks"
    if hooks_path_set:
        _echo(f"    {color('✅', GREEN)} core.hooksPath = hooks")
    else:
        _echo(f"    {color('⚠️', YELLOW)}  core.hooksPath not set to hooks")
        _echo(f"       Fix: {color('git config core.hooksPath hooks', BOLD)}")
    issues.extend(_doctor_check_hook_file(project_dir, hooks_path_set))

    # Layer 5: GitHub Action
    _echo(f"\n  {color('Layer 5: GitHub Action (PR gate)', BOLD)}")
    action = project_dir / ".github" / "workflows" / "codetrust-scan.yml"
    if action.exists():
        _echo(f"    {color('✅', GREEN)} GitHub Action workflow exists")
    else:
        issues.append("GitHub Action not found")
        _echo(f"    {color('❌', RED)} GitHub Action not found")

    # Layer 6: Advisory files
    _echo(f"\n  {color('Layer 6: Advisory Files', BOLD)}")
    issues.extend(_doctor_check_claude_md(project_dir))

    # Layer 7: Governance config
    _echo(f"\n  {color('Layer 7: Governance Config', BOLD)}")
    toml_path = project_dir / ".codetrust.toml"
    if toml_path.exists():
        _echo(f"    {color('✅', GREEN)} .codetrust.toml exists")
    else:
        issues.append(".codetrust.toml not found")
        _echo(f"    {color('❌', RED)} .codetrust.toml not found")

    # Allow-list audit (advisory — warnings, not blocking)
    _echo(f"\n  {color('Layer 8: Allow-list Audit', BOLD)}")
    audit_findings = audit_allow_list(project_dir)
    if audit_findings:
        for f in audit_findings:
            _echo(f"    {color('⚠️', YELLOW)}  {f['entry']} → {f['reason']}")
        _echo(f"    {color('⚠️', YELLOW)}  {len(audit_findings)} bypass(es) — fix with: codetrust init")
    else:
        _echo(f"    {color('✅', GREEN)} No dangerous allow-list entries")

    # Layer 9: Compliance coverage
    _echo(f"\n  {color('Layer 9: Compliance Coverage', BOLD)}")
    issues.extend(_doctor_check_compliance())

    # Data classification + model routing (informational)
    from src.services.model_router import load_routing_policy
    routing_policy = load_routing_policy(project_dir)
    _echo(f"\n  {color('Data Classification + Model Routing', BOLD)}")
    if routing_policy.get("enabled", True):
        level_count = len(routing_policy.get("levels", {}))
        model_lists = routing_policy.get("levels", {})
        configured_models = set()
        for lp in model_lists.values():
            for m in lp.get("allowed_models", []):
                if m != "*":
                    configured_models.add(m)
        _echo(f"    ✅ Enabled ({level_count} sensitivity levels, {len(configured_models)} model patterns configured)")
    else:
        _echo("    Data classification disabled")

    # PII policy (informational)
    from src.services.pii_detector import load_pii_policy
    pii_policy = load_pii_policy(project_dir)
    _echo(f"\n  {color('PII Detection', BOLD)}")
    if pii_policy.get("enabled", True):
        pii_mode = pii_policy.get("mode", "warn")
        blocked_cats = [
            cat for cat, m in pii_policy.get("categories", {}).items() if m == "block"
        ]
        _echo(f"    ✅ Enabled (mode: {pii_mode}, {len(blocked_cats)} categories on block)")
    else:
        _echo("    PII detection disabled")

    # Cost tracking (informational)
    from src.services.cost_tracker import load_cost_config
    cost_cfg = load_cost_config(project_dir)
    _echo(f"\n  {color('Cost Tracking', BOLD)}")
    if cost_cfg.get("enabled", True):
        budget = cost_cfg.get("budget", {})
        limit = budget.get("monthly_limit", 0)
        if limit and limit > 0:
            _echo(f"    ✅ Enabled (budget ${limit:.0f}/month)")
        else:
            _echo("    ✅ Enabled (no budget limit configured)")
    else:
        _echo("    Cost tracking disabled")

    # Framework integrations (informational — not an enforcement layer)
    detected = detect_frameworks()
    installed_frameworks = [fw for fw in detected if fw["installed"]]
    if installed_frameworks:
        _echo(f"\n  {color('Framework Integrations (detected)', BOLD)}")
        for fw in installed_frameworks:
            _echo(f"    ✅ {fw['name']} v{fw['version']} — governance via {fw['class']}")
    else:
        _echo(f"\n  {color('Framework Integrations', BOLD)}")
        _echo("    No frameworks detected (LangChain, CrewAI, OpenAI Agents)")
        _echo("    Install with: pip install codetrust[langchain]")

    # Summary
    _echo(f"\n{'━' * 48}")
    if not issues:
        _echo(color("\n  ✅ All layers active — AI Governance enforced.\n", GREEN))
        return 0

    _echo(f"\n  {len(issues)} issue(s) found.")
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
            except OSError as exc:
                logger.debug("pyproject_read_error", path=str(pyproject), error=str(exc))
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
        return "3.0.0"


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
    init_parser.add_argument("--check", action="store_true", help="Audit installation without modifying files")

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
    login_parser = subparsers.add_parser("login", help="Authenticate with CodeTrust")
    login_parser.add_argument("--api-key", dest="api_key", help="API key from app.codetrust.ai")
    subparsers.add_parser("logout", help="Remove local authentication")

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
    scan_parser.add_argument(
        "--runtime-verify", dest="runtime_verify", action="store_true",
        help="Run runtime taint verification via sandboxed exploit execution (requires Docker)",
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

    policy_sub.add_parser("show", help="Show current commit policy from .codetrust.toml")
    policy_init = policy_sub.add_parser("init", help="Create default [policy] section in .codetrust.toml")
    policy_init.add_argument("--yes", action="store_true", help="Overwrite existing policy")
    policy_sub.add_parser("validate", help="Validate the current commit policy config")
    policy_test = policy_sub.add_parser("test", help="Test policy against a mock commit")
    policy_test.add_argument(
        "--model", default="gpt-4o", help="Model to simulate (default: gpt-4o)",
    )
    policy_test.add_argument(
        "--editor", default="copilot", help="Editor to simulate (default: copilot)",
    )

    _add_audit_subparser(subparsers)
    _add_compliance_subparser(subparsers)
    _add_dod_subparser(subparsers)
    _add_integrity_subparser(subparsers)
    _add_integrations_subparser(subparsers)
    _add_pii_subparser(subparsers)
    _add_classify_subparser(subparsers)
    _add_cost_subparser(subparsers)
    _add_eu_nist_subparsers(subparsers)


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


def _add_compliance_subparser(
    subparsers: argparse._SubParsersAction,
) -> None:
    """Register 'compliance' subcommand for framework compliance reports."""
    comp_parser = subparsers.add_parser(
        "compliance",
        help="Generate compliance mapping reports for security frameworks",
    )
    comp_parser.add_argument(
        "--framework", "-f", type=str, default="",
        help="Framework ID (e.g. owasp-asi-2026, eu-ai-act, nist-ai-rmf)",
    )
    comp_parser.add_argument(
        "--list", action="store_true", dest="list_frameworks",
        help="List all supported compliance frameworks",
    )
    comp_parser.add_argument(
        "--json", action="store_true", dest="json_output",
        help="Output as JSON instead of Markdown",
    )
    comp_parser.add_argument(
        "--strict", action="store_true", default=True, dest="strict",
        help="Exit code 1 if not fully compliant (default: True)",
    )
    comp_parser.add_argument(
        "--no-strict", action="store_false", dest="strict",
        help="Show report without exit code enforcement",
    )


def cmd_compliance(args: argparse.Namespace) -> int:
    """Handle the 'compliance' CLI command."""
    from src.services.compliance import (
        compliance_summary,
        get_compliance_report,
        is_fully_compliant,
        list_frameworks,
    )

    if getattr(args, "list_frameworks", False):
        frameworks = list_frameworks()
        _echo("Supported compliance frameworks:\n")
        for fid, fname in frameworks.items():
            _echo(f"  {fid:20s}  {fname}")
        _echo(
            "\nUsage: codetrust compliance --framework owasp-asi-2026"
            "\n       codetrust compliance --framework owasp-asi-2026 --json",
        )
        return 0

    framework_id: str = getattr(args, "framework", "")
    if not framework_id:
        _echo("Error: specify --framework or use --list to see options.")
        return 1

    try:
        report = get_compliance_report(framework_id)
    except ValueError as exc:
        _echo(f"Error: {exc}")
        return 1

    use_json: bool = getattr(args, "json_output", False)
    if use_json:
        sys.stdout.write(report.to_json() + "\n")
    else:
        sys.stdout.write(report.to_markdown() + "\n")

    # Summary line
    summary = compliance_summary(report)
    compliant = is_fully_compliant(framework_id)
    label = "COMPLIANT" if compliant else "NON-COMPLIANT"
    icon = color("✅", GREEN) if compliant else color("❌", RED)
    _echo(f"\n{icon} {label}: {summary}")

    strict: bool = getattr(args, "strict", True)
    if strict and not compliant:
        return 1
    return 0


def _add_dod_subparser(
    subparsers: argparse._SubParsersAction,
) -> None:
    """Register 'dod' subcommand for Definition of Done enforcement."""
    dod_parser = subparsers.add_parser(
        "dod",
        help="Run Definition of Done acceptance checks",
    )
    dod_parser.add_argument(
        "--check", type=str, default="",
        help="Filter checks by name substring",
    )
    dod_parser.add_argument(
        "--json", action="store_true", dest="json_output",
        help="Output as JSON",
    )
    dod_parser.add_argument(
        "--file", type=str, default="",
        help="Path to DoD TOML file (default: .codetrust/definition_of_done.toml)",
    )


def _add_integrity_subparser(
    subparsers: argparse._SubParsersAction,
) -> None:
    """Register 'integrity' subcommand for agent integrity analysis."""
    int_parser = subparsers.add_parser(
        "integrity",
        help="Analyze agent session for integrity patterns (sycophancy, unsubstantiated claims)",
    )
    int_parser.add_argument(
        "--session", type=str, default="",
        help="Path to session history JSON file",
    )
    int_parser.add_argument(
        "--last", action="store_true",
        help="Analyze the most recent session from audit log (last 4 hours)",
    )
    int_parser.add_argument(
        "--hours", type=int, default=4,
        help="Hours to look back when using --last (default: 4)",
    )
    int_parser.add_argument(
        "--json", action="store_true", dest="json_output",
        help="Output as JSON",
    )


def _add_integrations_subparser(
    subparsers: argparse._SubParsersAction,
) -> None:
    """Register 'integrations' subcommand for framework detection."""
    int_parser = subparsers.add_parser(
        "integrations",
        help="List detected AI frameworks and CodeTrust integration status",
    )
    int_parser.add_argument(
        "--check", action="store_true",
        help="Verify that integrations can be imported",
    )
    int_parser.add_argument(
        "--json", action="store_true", dest="json_output",
        help="Output as JSON",
    )


def _add_pii_subparser(
    subparsers: argparse._SubParsersAction,
) -> None:
    """Register 'pii' subcommand for PII detection."""
    pii_parser = subparsers.add_parser(
        "pii",
        help="Detect personally identifiable information (PII)",
    )
    pii_sub = pii_parser.add_subparsers(dest="pii_action")

    scan_p = pii_sub.add_parser("scan", help="Scan file or stdin for PII")
    scan_p.add_argument("file", nargs="?", help="File to scan (omit for --stdin)")
    scan_p.add_argument("--stdin", action="store_true", help="Read from stdin")
    scan_p.add_argument("--json", action="store_true", dest="json_output")

    redact_p = pii_sub.add_parser("redact", help="Show redacted version of file")
    redact_p.add_argument("file", help="File to redact")

    pii_sub.add_parser("policy", help="Show active PII policy")

    report_p = pii_sub.add_parser("report", help="PII report for project")
    report_p.add_argument("--json", action="store_true", dest="json_output")


def _add_classify_subparser(
    subparsers: argparse._SubParsersAction,
) -> None:
    """Register 'classify' subcommand for data classification + model routing."""
    cls_parser = subparsers.add_parser(
        "classify",
        help="Classify data sensitivity and check model routing",
    )
    cls_parser.add_argument("path", nargs="?", help="File or directory to classify")
    cls_parser.add_argument("--stdin", action="store_true", help="Read from stdin")
    cls_parser.add_argument("--model", help="Check if model is allowed for this data")
    cls_parser.add_argument("--report", action="store_true", help="Full report with summary")
    cls_parser.add_argument("--json", action="store_true", dest="json_output")


def _add_cost_subparser(
    subparsers: argparse._SubParsersAction,
) -> None:
    """Register 'cost' subcommand for LLM cost tracking."""
    cost_parser = subparsers.add_parser(
        "cost", help="LLM cost tracking per developer/team",
    )
    cost_sub = cost_parser.add_subparsers(dest="cost_action")

    # Default: report
    report_p = cost_sub.add_parser("report", help="Cost report (default)")
    report_p.add_argument("--period", choices=["daily", "weekly", "monthly"], default="monthly")
    report_p.add_argument("--developer", help="Filter by developer")
    report_p.add_argument("--team", help="Filter by team")
    report_p.add_argument("--model", help="Filter by model pattern")
    report_p.add_argument("--project", help="Filter by project")
    report_p.add_argument("--json", action="store_true", dest="json_output")
    report_p.add_argument("--export", choices=["csv"], help="Export format")

    cost_sub.add_parser("budget", help="Show budget status")
    cost_sub.add_parser("anomalies", help="Show cost anomalies")

    log_p = cost_sub.add_parser("log", help="Log a usage event")
    log_p.add_argument("event_json", help="JSON string with model, provider, input_tokens, output_tokens")

    # Also support bare `codetrust cost` as alias for report
    cost_parser.add_argument("--period", choices=["daily", "weekly", "monthly"], default="monthly")
    cost_parser.add_argument("--developer", help="Filter by developer")
    cost_parser.add_argument("--team", help="Filter by team")
    cost_parser.add_argument("--model", help="Filter by model pattern")
    cost_parser.add_argument("--project", help="Filter by project")
    cost_parser.add_argument("--json", action="store_true", dest="json_output")


def _audit_entries_to_session(
    entries: list[dict[str, object]],
) -> tuple[list[dict[str, str]], list[str]]:
    """Convert audit log entries into session messages and commands.

    Maps audit entry action_types to message roles:
    - validate_command / run_in_terminal → tool message (command executed)
    - verify_claim / integrity_check → assistant verification
    - Other actions with message content → tool output

    Args:
        entries: Parsed audit entries (dicts with action_type, message, etc.).

    Returns:
        Tuple of (messages as role/content dicts, flat command list).
    """
    messages: list[dict[str, str]] = []
    commands: list[str] = []

    for entry in entries:
        action_type = str(entry.get("action_type", ""))
        original = str(entry.get("original_action", ""))
        message = str(entry.get("message", ""))
        verdict = str(entry.get("verdict", ""))

        if action_type in ("validate_command", "run_in_terminal"):
            commands.append(original)
            messages.append({"role": "tool", "content": f"{original}\n{message}"})
        elif action_type in ("validate_file_write", "create_file", "replace_string"):
            messages.append({"role": "tool", "content": f"[file write] {original}"})
        elif action_type in ("verify_claim", "integrity_check", "definition_of_done"):
            messages.append({"role": "assistant", "content": message})
        elif verdict == "BLOCK":
            messages.append({"role": "tool", "content": f"BLOCKED: {original} — {message}"})
        elif message:
            messages.append({"role": "tool", "content": message})

    return messages, commands


# ═══════════════════════════════════════════════════════════════
#  Framework Integrations
# ═══════════════════════════════════════════════════════════════

_FRAMEWORK_SPECS: list[dict[str, str]] = [
    {
        "name": "LangChain",
        "import": "langchain",
        "integration": "src.integrations.langchain",
        "class": "CodeTrustGovernance",
        "install": "pip install codetrust[langchain]",
    },
    {
        "name": "CrewAI",
        "import": "crewai",
        "integration": "src.integrations.crewai",
        "class": "CodeTrustCrew",
        "install": "pip install codetrust[crewai]",
    },
    {
        "name": "OpenAI Agents SDK",
        "import": "agents",
        "integration": "src.integrations.openai_agents",
        "class": "governed_agent",
        "install": "pip install codetrust[openai-agents]",
    },
]


def detect_frameworks() -> list[dict[str, object]]:
    """Detect installed AI frameworks and CodeTrust integration availability.

    Returns:
        List of dicts with name, installed (bool), integration_available (bool).
    """
    import importlib

    results: list[dict[str, object]] = []
    for spec in _FRAMEWORK_SPECS:
        installed = False
        integration_ok = False
        version = ""

        try:
            mod = importlib.import_module(spec["import"])
            installed = True
            version = getattr(mod, "__version__", "unknown")
        except ImportError:
            pass

        try:
            importlib.import_module(spec["integration"])
            integration_ok = True
        except ImportError:
            pass

        results.append({
            "name": spec["name"],
            "installed": installed,
            "version": version,
            "integration_available": integration_ok,
            "class": spec["class"],
            "install_hint": spec["install"],
        })
    return results


def cmd_integrations(args: argparse.Namespace) -> int:
    """Handle the 'integrations' CLI command — list frameworks and status."""
    use_check: bool = getattr(args, "check", False)
    use_json: bool = getattr(args, "json_output", False)

    results = detect_frameworks()

    if use_json:
        _echo(json.dumps(results, indent=2))
        return 0

    _echo(f"\n{color('Framework Integrations', BOLD)}\n")

    for fw in results:
        if fw["installed"]:
            status = color(f"installed (v{fw['version']})", GREEN)
            gov = f"governance via {fw['class']}"
        else:
            status = color("not installed", YELLOW if not use_check else RED)
            gov = fw["install_hint"]

        _echo(f"  {fw['name']:20s}  {status}")
        _echo(f"  {'':20s}  {gov}")
        _echo("")

    if use_check:
        all_ok = all(r["integration_available"] for r in results if r["installed"])
        if all_ok:
            _echo(color("  All detected frameworks have governance integrations.\n", GREEN))
        else:
            _echo(color("  Some integrations failed to load.\n", RED))
            return 1

    return 0


def cmd_pii(args: argparse.Namespace) -> int:
    """Handle the 'pii' CLI command — PII detection and redaction."""
    from src.services.pii_detector import (
        load_pii_policy,
        redact,
        scan_text,
    )

    action = getattr(args, "pii_action", None)
    if not action:
        _echo("Usage: codetrust pii {scan,redact,policy,report}")
        return 1

    if action == "policy":
        policy = load_pii_policy()
        _echo(f"\n{color('PII Policy', BOLD)}\n")
        _echo(f"  Enabled:        {policy['enabled']}")
        _echo(f"  Mode:           {policy['mode']}")
        _echo(f"  Min confidence: {policy['min_confidence']}")
        _echo("\n  Category overrides:")
        for cat, mode in sorted(policy.get("categories", {}).items()):
            _echo(f"    {cat:20s}  {mode}")
        _echo("")
        return 0

    if action == "scan":
        use_stdin: bool = getattr(args, "stdin", False)
        file_path: str = getattr(args, "file", "") or ""
        use_json: bool = getattr(args, "json_output", False)

        if use_stdin:
            text = sys.stdin.read()
        elif file_path:
            try:
                text = Path(file_path).read_text(encoding="utf-8")
            except OSError as exc:
                _echo(f"Error reading file: {exc}")
                return 1
        else:
            _echo("Error: specify a file or --stdin")
            return 1

        policy = load_pii_policy()
        report = scan_text(text, min_confidence=policy.get("min_confidence", 0.7))

        if use_json:
            _echo(json.dumps(report.to_dict(), indent=2))
        else:
            _echo(f"\n{color('PII Scan Results', BOLD)}")
            _echo(f"  Risk level: {report.risk_level}")
            _echo(f"  {report.summary}\n")
            for f in report.findings:
                _echo(f"  [{f.category.upper()}] confidence={f.confidence:.0%} "
                      f"offset={f.start}-{f.end}")
                _echo(f"    {f.context}")
            if not report.findings:
                _echo(color("  No PII detected.\n", GREEN))
        return 0

    if action == "redact":
        file_path = getattr(args, "file", "")
        if not file_path:
            _echo("Error: specify a file to redact")
            return 1
        try:
            text = Path(file_path).read_text(encoding="utf-8")
        except OSError as exc:
            _echo(f"Error reading file: {exc}")
            return 1
        _echo(redact(text, min_confidence=0.7))
        return 0

    if action == "report":
        use_json = getattr(args, "json_output", False)
        project_dir = Path.cwd()
        # Scan common config/env files
        targets = list(project_dir.glob("**/.env*")) + list(project_dir.glob("**/config*"))
        targets = [f for f in targets if f.is_file() and f.stat().st_size < 100_000]

        all_findings: list[dict[str, object]] = []
        for target in targets[:50]:  # limit to 50 files
            try:
                text = target.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            report = scan_text(text, min_confidence=0.7)
            if report.findings:
                all_findings.append({
                    "file": str(target.relative_to(project_dir)),
                    "findings": len(report.findings),
                    "risk_level": report.risk_level,
                    "summary": report.summary,
                })

        if use_json:
            _echo(json.dumps(all_findings, indent=2))
        else:
            _echo(f"\n{color('PII Report', BOLD)}\n")
            if all_findings:
                for entry in all_findings:
                    _echo(f"  {entry['file']}: {entry['summary']} [{entry['risk_level']}]")
            else:
                _echo(color("  No PII detected in scanned files.\n", GREEN))
        return 0

    _echo(f"Unknown pii action: {action}")
    return 1


def cmd_classify(args: argparse.Namespace) -> int:
    """Handle the 'classify' CLI command — data classification + model routing."""
    from src.services.data_classifier import classify_file, classify_text
    from src.services.model_router import evaluate_routing

    target_path: str = getattr(args, "path", "") or ""
    use_stdin: bool = getattr(args, "stdin", False)
    model_name: str = getattr(args, "model", "") or ""
    use_report: bool = getattr(args, "report", False)
    use_json: bool = getattr(args, "json_output", False)

    # Collect files to classify
    results: list[dict[str, object]] = []

    if use_stdin:
        text = sys.stdin.read()
        result = classify_text(text)
        entry: dict[str, object] = {"file": "<stdin>", "classification": result}
        if model_name:
            routing = evaluate_routing(text, model_name)
            entry["routing"] = routing
        results.append(entry)

    elif target_path:
        p = Path(target_path)
        if p.is_file():
            try:
                result = classify_file(p)
                entry = {"file": str(p), "classification": result}
                if model_name:
                    text = p.read_text(encoding="utf-8", errors="replace")
                    routing = evaluate_routing(text, model_name, file_path=str(p))
                    entry["routing"] = routing
                results.append(entry)
            except OSError as exc:
                _echo(f"Error reading {p}: {exc}")
                return 1
        elif p.is_dir():
            # Scan directory — common code file extensions
            extensions = {".py", ".js", ".ts", ".go", ".java", ".rs", ".rb", ".md", ".toml", ".yaml", ".yml", ".json", ".env"}
            files = sorted(f for f in p.rglob("*") if f.is_file() and (f.suffix in extensions or f.name.startswith(".env")))
            files = [f for f in files if ".git/" not in str(f) and "__pycache__" not in str(f) and f.stat().st_size < 200_000]
            for fp in files[:100]:
                try:
                    result = classify_file(fp)
                    entry = {"file": str(fp.relative_to(p) if fp.is_relative_to(p) else fp), "classification": result}
                    if model_name:
                        text = fp.read_text(encoding="utf-8", errors="replace")
                        routing = evaluate_routing(text, model_name, file_path=str(fp))
                        entry["routing"] = routing
                    results.append(entry)
                except OSError:
                    continue
        else:
            _echo(f"Error: path not found: {target_path}")
            return 1
    else:
        _echo("Usage: codetrust classify <file|dir> [--model MODEL] [--report] [--json]")
        return 1

    if use_json:
        json_results = []
        for r in results:
            jr: dict[str, object] = {"file": r["file"], **r["classification"].to_dict()}
            if "routing" in r:
                jr["routing"] = r["routing"].to_dict()
            json_results.append(jr)
        _echo(json.dumps(json_results, indent=2))
        return 0

    # Human-readable output
    _echo("")
    level_counts: dict[str, int] = {}
    route_counts: dict[str, int] = {"allow": 0, "warn": 0, "block": 0, "redact": 0}

    for r in results:
        cls = r["classification"]
        level = cls.sensitivity.label.upper()
        level_counts[level] = level_counts.get(level, 0) + 1
        reason_hint = ""
        if cls.reasons and cls.reasons[0] != "No sensitivity indicators detected":
            reason_hint = f" — {cls.reasons[0]}"

        line = f"  {r['file']:.<50s} {level} ({cls.confidence:.2f}){reason_hint}"
        _echo(line)

        if "routing" in r:
            rt = r["routing"]
            action = rt.action.upper()
            route_counts[rt.action] = route_counts.get(rt.action, 0) + 1
            _echo(f"  {'':50s} routing: {action} for {model_name}")

    if use_report or len(results) > 1:
        _echo("")
        parts = [f"{c} {lev.lower()}" for lev, c in sorted(level_counts.items())]
        _echo(f"  Summary: {', '.join(parts)}")
        if model_name:
            route_parts = [f"{c} {act}" for act, c in sorted(route_counts.items()) if c > 0]
            _echo(f"  Model routing for {model_name}: {', '.join(route_parts)}")

    _echo("")
    return 0


def cmd_cost(args: argparse.Namespace) -> int:
    """Handle the 'cost' CLI command — LLM cost tracking."""
    from src.services.cost_storage import read_events
    from src.services.cost_tracker import check_budget, detect_anomalies, generate_report, log_usage

    action = getattr(args, "cost_action", None) or "report"

    if action == "log":
        event_json_str: str = getattr(args, "event_json", "")
        try:
            raw = json.loads(event_json_str)
        except json.JSONDecodeError as exc:
            _echo(f"Invalid JSON: {exc}")
            return 1
        event = log_usage(
            model=raw.get("model", "unknown"),
            provider=raw.get("provider", "unknown"),
            input_tokens=int(raw.get("input_tokens", 0)),
            output_tokens=int(raw.get("output_tokens", 0)),
            action=raw.get("action", "code_generation"),
            developer=raw.get("developer", ""),
            team=raw.get("team", ""),
            session_id=raw.get("session_id", ""),
        )
        _echo(f"Logged: {event.model} {event.total_tokens} tokens ${event.estimated_cost_usd:.4f}")
        return 0

    if action == "budget":
        events = read_events()
        total = sum(e.estimated_cost_usd for e in events)
        by_dev = {}
        for e in events:
            by_dev[e.developer] = by_dev.get(e.developer, 0) + e.estimated_cost_usd
        status = check_budget(total, by_dev)
        _echo(f"\n{color('Budget Status', BOLD)}\n")
        if not status.get("configured"):
            _echo("  No budget configured in .codetrust.toml [cost.budget]")
            _echo("  Add monthly_limit to enable budget tracking.\n")
        else:
            _echo(f"  {status['message']}")
            _echo(f"  Monthly limit: ${status['monthly_limit']:.2f}")
            _echo(f"  Used: ${status['total_cost']:.2f} ({status['usage_percent']:.0f}%)")
            if status.get("developer_alerts"):
                _echo("\n  Developer alerts:")
                for alert in status["developer_alerts"]:
                    _echo(f"    {alert['developer']}: ${alert['cost']:.2f} / ${alert['limit']:.2f} [{alert['level']}]")
            _echo("")
        return 0

    if action == "anomalies":
        events = read_events()
        anomalies = detect_anomalies(events)
        _echo(f"\n{color('Cost Anomalies', BOLD)}\n")
        if not anomalies:
            _echo("  No anomalies detected.\n")
        else:
            for a in anomalies:
                _echo(f"  [{a['type']}] {a['detail']}")
            _echo("")
        return 0

    # Default: report
    period = getattr(args, "period", "monthly") or "monthly"
    developer = getattr(args, "developer", "") or ""
    team = getattr(args, "team", "") or ""
    model_filter = getattr(args, "model", "") or ""
    project_filter = getattr(args, "project", "") or ""
    use_json = getattr(args, "json_output", False)
    export_fmt = getattr(args, "export", None)

    report = generate_report(
        period=period, developer=developer, team=team,
        model_filter=model_filter, project_filter=project_filter,
    )

    if use_json:
        _echo(json.dumps(report.to_dict(), indent=2))
        return 0

    if export_fmt == "csv":
        _echo("timestamp,model,provider,developer,team,project,input_tokens,output_tokens,cost_usd")
        events = read_events()
        for e in events:
            _echo(f"{e.timestamp},{e.model},{e.provider},{e.developer},{e.team},{e.project},{e.input_tokens},{e.output_tokens},{e.estimated_cost_usd}")
        return 0

    _echo(f"\n{color(f'Cost Report ({period})', BOLD)}")
    _echo(f"  Period: {report.start_date[:10]} to {report.end_date[:10]}")
    _echo(f"  Events: {report.event_count}")
    _echo(f"  Total tokens: {report.total_tokens:,}")
    _echo(f"  Total cost: ${report.total_cost_usd:.2f}\n")

    if report.by_model:
        _echo("  By model:")
        for model_name, cost in sorted(report.by_model.items(), key=lambda x: -x[1]):
            _echo(f"    {model_name:30s} ${cost:.2f}")
        _echo("")

    if report.by_developer:
        _echo("  By developer:")
        for dev, cost in sorted(report.by_developer.items(), key=lambda x: -x[1]):
            _echo(f"    {dev:30s} ${cost:.2f}")
        _echo("")

    if report.anomalies:
        _echo(f"  {color('Anomalies:', YELLOW)}")
        for a in report.anomalies:
            _echo(f"    {a['detail']}")
        _echo("")

    if report.budget_status and report.budget_status.get("configured"):
        bs = report.budget_status
        _echo(f"  Budget: {bs['message']}\n")

    return 0


def cmd_integrity(args: argparse.Namespace) -> int:
    """Handle the 'integrity' CLI command — agent integrity analysis."""
    from src.services.agent_integrity import (
        analyze_session,
        format_report,
        parse_session_messages,
    )

    session_path_str: str = getattr(args, "session", "")
    use_last: bool = getattr(args, "last", False)

    if not session_path_str and not use_last:
        _echo("Error: specify --session <path> or --last")
        return 1

    # ── Mode 1: --session <file> ──
    if session_path_str:
        session_path = Path(session_path_str)
        if not session_path.is_file():
            _echo(f"Error: session file not found: {session_path}")
            return 1

        try:
            raw = json.loads(session_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            _echo(f"Error reading session file: {exc}")
            return 1

        raw_messages = raw.get("messages", []) if isinstance(raw, dict) else raw
        raw_commands: list[str] = raw.get("commands", []) if isinstance(raw, dict) else []
        session_id = raw.get("session_id", session_path.stem) if isinstance(raw, dict) else session_path.stem

    # ── Mode 2: --last (read from audit.jsonl) ──
    else:
        audit_path = Path.cwd() / ".codetrust" / "audit.jsonl"
        if not audit_path.is_file():
            _echo("Error: no audit log found at .codetrust/audit.jsonl")
            _echo("Run commands through CodeTrust governance to generate audit data.")
            return 1

        hours: int = getattr(args, "hours", 4)
        cutoff = time.time() - (hours * _SECONDS_PER_HOUR)

        entries: list[dict[str, object]] = []
        try:
            with open(audit_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        if float(entry.get("timestamp", 0)) >= cutoff:
                            entries.append(entry)
                    except (json.JSONDecodeError, ValueError):
                        continue
        except OSError as exc:
            _echo(f"Error reading audit log: {exc}")
            return 1

        if not entries:
            _echo(f"No audit entries found in the last {hours} hours.")
            return 1

        raw_messages, raw_commands = _audit_entries_to_session(entries)

        _echo(f"Analyzing {len(entries)} audit entries from the last {hours} hours.\n")
        session_id = f"audit-last-{hours}h"

    messages = parse_session_messages(
        raw_messages if isinstance(raw_messages, list) else [],
    )
    report = analyze_session(messages, raw_commands, session_id=session_id)

    # Guard: 0 claims analyzed means no assertions were found to evaluate.
    # Returning TRUSTWORTHY for an empty analysis is misleading — the audit
    # log lacks agent dialog, so no behavioral analysis was possible.
    if report.total_claims == 0 and use_last:
        _echo("No agent claims found to analyze.")
        _echo("")
        _echo("The audit log records governance actions (command validation, file writes)")
        _echo("but not the agent's reasoning or claims. Without dialog, integrity")
        _echo("analysis cannot detect behavioral issues like sycophancy or false claims.")
        _echo("")
        _echo("Use --session <file> to analyze a session transcript instead.")
        _echo("Export format: {\"messages\": [{\"role\": \"...\", \"content\": \"...\"}], \"commands\": [...]}")
        return 1

    use_json: bool = getattr(args, "json_output", False)
    if use_json:
        sys.stdout.write(json.dumps(report.to_dict(), indent=2) + "\n")
    else:
        sys.stdout.write(format_report(report) + "\n")

    # Exit 0 only if TRUSTWORTHY
    if report.verdict == "TRUSTWORTHY":
        return 0
    return 1


def cmd_dod(args: argparse.Namespace) -> int:
    """Handle the 'dod' CLI command — Definition of Done enforcement."""
    from src.services.definition_of_done import (
        format_report,
        load_checks,
        run_dod,
    )

    dod_path_str: str = getattr(args, "file", "")
    dod_path = Path(dod_path_str) if dod_path_str else None

    try:
        checks = load_checks(dod_path)
    except FileNotFoundError as exc:
        _echo(f"Error: {exc}")
        _echo("Run 'codetrust init' to create a default DoD file.")
        return 1
    except ValueError as exc:
        _echo(f"Error: {exc}")
        return 1

    if not checks:
        _echo("No checks found in DoD file.")
        return 1

    check_filter: str = getattr(args, "check", "")
    report = run_dod(checks, check_filter=check_filter or None)

    use_json: bool = getattr(args, "json_output", False)
    if use_json:
        import json as json_mod
        result = {
            "summary": report.summary,
            "all_passed": report.all_passed,
            "checks": [
                {
                    "name": r.check.name,
                    "command": r.check.command,
                    "passed": r.passed,
                    "actual_exit_code": r.actual_exit_code,
                    "failure_reason": r.failure_reason,
                }
                for r in report.checks
            ],
        }
        sys.stdout.write(json_mod.dumps(result, indent=2) + "\n")
    else:
        sys.stdout.write(format_report(report) + "\n")

    return 0 if report.all_passed else 1


def _add_eu_nist_subparsers(
    subparsers: argparse._SubParsersAction,
) -> None:
    """Register EU AI Act and NIST AI RMF subcommands."""
    # risk-register
    rr = subparsers.add_parser("risk-register", help="Manage formal risk register")
    rr_sub = rr.add_subparsers(dest="subcommand")
    rr_sub.add_parser("init", help="Create empty risk register")
    rr_sub.add_parser("list", help="List all risks")
    rr_add = rr_sub.add_parser("add", help="Add a new risk")
    rr_add.add_argument("--title", required=True)
    rr_add.add_argument("--description", default="")
    rr_add.add_argument("--likelihood", type=int, default=3)
    rr_add.add_argument("--impact", type=int, default=3)
    rr_add.add_argument("--mitigation", default="")
    rr_add.add_argument("--owner", default="")

    # assess
    subparsers.add_parser("assess", help="Run full conformity assessment")

    # red-team
    subparsers.add_parser("red-team", help="Run adversarial robustness tests")

    # privacy
    subparsers.add_parser("privacy", help="Show privacy and data governance report")

    # governance-report
    subparsers.add_parser("governance-report", help="Generate formal governance documentation")

    # risk-map
    subparsers.add_parser("risk-map", help="Generate automated risk catalog")

    # metrics
    subparsers.add_parser("metrics", help="Show formal metrics with SLO status")

    # treatment-plan
    tp = subparsers.add_parser("treatment-plan", help="Manage finding treatment plan")
    tp_sub = tp.add_subparsers(dest="subcommand")
    tp_sub.add_parser("show", help="Show current treatment plan")
    tp_import = tp_sub.add_parser("import", help="Import findings from scan report")
    tp_import.add_argument("report_path", help="Path to JSON scan report")


def cmd_risk_register(args: argparse.Namespace) -> int:
    """Handle risk-register command."""
    from src.services.risk_register import (
        RiskRegister,
        add_risk,
        format_register,
        load_register,
        save_register,
    )

    subcmd = getattr(args, "subcommand", None)

    if subcmd == "init":
        register = RiskRegister()
        path = save_register(register)
        _echo(f"Created empty risk register: {path}")
        return 0

    if subcmd == "add":
        register = load_register()
        risk = add_risk(
            register,
            title=args.title,
            description=args.description,
            likelihood=args.likelihood,
            impact=args.impact,
            mitigation=args.mitigation,
            owner=args.owner,
        )
        save_register(register)
        _echo(f"Added {risk.risk_id}: {risk.title} (score: {risk.risk_score})")
        return 0

    # Default: list
    register = load_register()
    sys.stdout.write(format_register(register) + "\n")
    return 0


def cmd_assess(args: argparse.Namespace) -> int:
    """Handle assess (conformity assessment) command."""
    from src.services.conformity_assessment import (
        format_assessment,
        run_assessment,
    )

    _echo("Running conformity assessment...\n")
    report = run_assessment()
    sys.stdout.write(format_assessment(report) + "\n")
    return 0 if report.all_passed else 1


def cmd_red_team(args: argparse.Namespace) -> int:
    """Handle red-team command."""
    from src.services.red_team import format_red_team, run_red_team

    _echo("Running adversarial robustness tests...\n")
    report = run_red_team()
    sys.stdout.write(format_red_team(report) + "\n")
    bypasses = len(report.bypasses)
    return 1 if bypasses > 0 else 0


def cmd_privacy(args: argparse.Namespace) -> int:
    """Handle privacy command."""
    from src.services.privacy import format_privacy_report, generate_privacy_report

    report = generate_privacy_report()
    sys.stdout.write(format_privacy_report(report) + "\n")
    return 0


def cmd_governance_report(args: argparse.Namespace) -> int:
    """Handle governance-report command."""
    from src.services.governance_report import (
        format_governance_report,
        generate_governance_report,
    )

    report = generate_governance_report()
    sys.stdout.write(format_governance_report(report) + "\n")
    return 0


def cmd_risk_map(args: argparse.Namespace) -> int:
    """Handle risk-map command."""
    from src.services.risk_map import format_risk_map, generate_risk_map

    risk_map = generate_risk_map()
    sys.stdout.write(format_risk_map(risk_map) + "\n")
    return 0


def cmd_metrics(args: argparse.Namespace) -> int:
    """Handle metrics command."""
    from src.services.metrics_report import (
        format_metrics_report,
        generate_metrics_report,
    )

    report = generate_metrics_report()
    sys.stdout.write(format_metrics_report(report) + "\n")
    return 0


def cmd_treatment_plan(args: argparse.Namespace) -> int:
    """Handle treatment-plan command."""
    from src.services.treatment_plan import (
        format_treatment_plan,
        import_findings_to_plan,
        load_treatment_plan,
        save_treatment_plan,
    )

    subcmd = getattr(args, "subcommand", None)

    if subcmd == "import":
        plan = load_treatment_plan()
        imported = import_findings_to_plan(plan, Path(args.report_path))
        save_treatment_plan(plan)
        _echo(f"Imported {imported} findings. {plan.progress}")
        return 0

    # Default: show
    plan = load_treatment_plan()
    sys.stdout.write(format_treatment_plan(plan) + "\n")
    return 0


def _add_shield_subparser(
    subparsers: argparse._SubParsersAction,
) -> None:
    """Register 'shield' subcommand for OS-level AI governance."""
    shield_parser = subparsers.add_parser(
        "shield",
        help="OS-level AI governance enforcement",
    )
    shield_parser.add_argument(
        "action",
        choices=["start", "stop", "status", "log", "install", "uninstall"],
        help="Shield action to perform",
    )
    shield_parser.add_argument(
        "--workspace", "-w", default=".",
        help="Workspace directory to protect (default: .)",
    )
    shield_parser.add_argument(
        "--tail", "-n", type=int, default=20,
        help="Number of log entries to show (default: 20)",
    )


def cmd_shield(args: argparse.Namespace) -> int:
    """Handle the 'shield' CLI command."""
    from pathlib import Path

    from src.shield.daemon import ShieldDaemon

    daemon = ShieldDaemon(workspace=Path(args.workspace))
    action: str = args.action

    if action == "start":
        result = daemon.start()
        if result.get("status") == "already_running":
            sys.stdout.write(
                f"Shield already running (PID {result.get('pid', '')})\n",
            )
        else:
            sys.stdout.write(
                f"Shield active - workspace: {result.get('workspace', '')}\n"
                f"  Shell wrapper: {result.get('shell_wrapper', '')}\n"
                f"  File watcher: {result.get('file_watcher', '')}\n"
                f"  Audit log: {result.get('audit_log', '')}\n"
                "\n  Run 'codetrust shield install' to auto-configure IDEs\n"
            )
        return 0

    if action == "stop":
        daemon.stop()
        sys.stdout.write("Shield stopped\n")
        return 0

    if action == "status":
        result = daemon.status()
        running = result.get("running", False)
        icon = "\033[32m*\033[0m" if running else "\033[31m*\033[0m"
        label = "active" if running else "inactive"
        sys.stdout.write(
            f"{icon} Shield {label}\n"
            f"  Workspace: {result.get('workspace', '')}\n"
            f"  Shell wrapper: "
            f"{'installed' if result.get('shell_wrapper_installed') else 'not installed'}\n"
            f"  Audit entries: {result.get('audit_entries', 0)}"
            f" ({result.get('blocks', 0)} blocked)\n"
        )
        return 0

    if action == "log":
        from src.shield.config import AUDIT_FILE

        if not AUDIT_FILE.exists():
            sys.stdout.write("No audit entries yet.\n")
            return 0

        lines = AUDIT_FILE.read_text().strip().split("\n")
        tail_count: int = args.tail
        for line in lines[-tail_count:]:
            try:
                entry = json.loads(line)
                verdict = entry.get("verdict", "?")
                color_map = {"BLOCK": "\033[91m", "WARN": "\033[93m"}
                color = color_map.get(verdict, "\033[92m")
                source = entry.get("source", "")
                if source == "shield":
                    detail = entry.get("command", "")[:80]
                else:
                    detail = (
                        f"{entry.get('file', '')} - "
                        f"{entry.get('rule_id', '')}"
                    )
                sys.stdout.write(f"  {color}[{verdict}]\033[0m {detail}\n")
            except json.JSONDecodeError as exc:
                logger.debug("audit_log_parse_error", line=line[:80], error=str(exc))
        return 0

    if action == "install":
        result = daemon.install_ide_hooks()
        for ide, ide_status in result.items():
            icon = "+" if ide_status == "configured" else "-"
            sys.stdout.write(f"  {icon} {ide}: {ide_status}\n")
        sys.stdout.write("\n  Restart your IDE for changes to take effect.\n")
        return 0

    if action == "uninstall":
        result = daemon.uninstall_ide_hooks()
        for ide, ide_status in result.items():
            icon = "+" if ide_status == "restored" else "-"
            sys.stdout.write(f"  {icon} {ide}: {ide_status}\n")
        return 0

    return 1


# ─────────────────────────────────────────────────────────────────
#  AI Observability subparsers & commands
# ─────────────────────────────────────────────────────────────────

_HOOK_SCRIPT = "codetrust_pre_commit.py"


def _add_ai_observability_subparsers(
    subparsers: argparse._SubParsersAction,
) -> None:
    """Register AI Observability CLI subcommands."""
    # --- mcp-audit ---
    mcp_audit_p = subparsers.add_parser(
        "mcp-audit", help="Scan IDE configs for MCP servers",
    )
    mcp_audit_p.add_argument(
        "--workspace", "-w", default=".", help="Project root (default: .)",
    )
    mcp_audit_p.add_argument(
        "--json", action="store_true", help="Output as JSON",
    )

    # --- shadow-scan ---
    shadow_p = subparsers.add_parser(
        "shadow-scan", help="Detect installed AI coding tools",
    )
    shadow_p.add_argument(
        "--approved", nargs="*", default=None,
        help="Approved tool IDs (e.g. github_copilot cursor)",
    )
    shadow_p.add_argument(
        "--json", action="store_true", help="Output as JSON",
    )

    # --- attribute ---
    attr_p = subparsers.add_parser(
        "attribute", help="Attribute AI model origin for files",
    )
    attr_p.add_argument(
        "targets", nargs="*", default=["."],
        help="Files or directories to analyze",
    )
    attr_p.add_argument(
        "--json", action="store_true", help="Output as JSON",
    )

    # --- risk-profile ---
    risk_p = subparsers.add_parser(
        "risk-profile", help="Developer AI risk scoring",
    )
    risk_p.add_argument(
        "--workspace", "-w", default=".", help="Repository root (default: .)",
    )
    risk_p.add_argument(
        "--max-commits", type=int, default=200,
        help="Max commits to analyze per author (default: 200)",
    )
    risk_p.add_argument(
        "--json", action="store_true", help="Output as JSON",
    )

    # --- benchmark ---
    bench_p = subparsers.add_parser(
        "benchmark", help="LLM code quality benchmarks",
    )
    bench_p.add_argument(
        "--workspace", "-w", default=".", help="Repository root (default: .)",
    )
    bench_p.add_argument(
        "--json", action="store_true", help="Output as JSON",
    )

    # --- hook ---
    hook_p = subparsers.add_parser(
        "hook", help="Manage CodeTrust pre-commit hook",
    )
    hook_sub = hook_p.add_subparsers(dest="subcommand")
    hook_sub.add_parser("install", help="Install pre-commit hook into .git/hooks")
    hook_sub.add_parser("uninstall", help="Remove CodeTrust pre-commit hook")
    hook_sub.add_parser("report", help="Show latest commit report")


# ─────────────────────────────────────────────────────────────────
#  AI Observability command handlers
# ─────────────────────────────────────────────────────────────────


def cmd_mcp_audit(args: argparse.Namespace) -> int:
    """Scan IDE configs for MCP server definitions."""
    from src.services.mcp_discovery import MCPDiscoveryService

    workspace = Path(args.workspace).resolve()
    svc = MCPDiscoveryService()
    result = svc.audit(workspace=workspace, include_project_local=True)

    if getattr(args, "json", False):
        import json as _json
        data = {
            "configs_scanned": result.configs_scanned,
            "configs_found": result.configs_found,
            "servers": [
                {
                    "name": s.name, "source_ide": s.source_ide,
                    "risk_level": s.risk_level,
                    "command": s.command, "risk_reason": s.risk_reason,
                }
                for s in result.servers
            ],
        }
        _echo(_json.dumps(data, indent=2))
        return 0

    _echo(f"\n{color('MCP Server Audit', BOLD)}\n")
    _echo(f"  Configs scanned: {result.configs_scanned}")
    _echo(f"  Configs found:   {result.configs_found}")
    _echo(f"  Servers:         {len(result.servers)}\n")

    for s in result.servers:
        risk_color = RED if s.risk_level == "high" else (
            YELLOW if s.risk_level == "medium" else GREEN
        )
        icon = "!" if s.risk_level != "low" else "+"
        _echo(
            f"  {color(icon, risk_color)} {s.name} ({s.source_ide}) — "
            f"{color(s.risk_level, risk_color)}"
        )
        if s.risk_reason:
            _echo(f"    {s.risk_reason}")

    _echo()
    return 0


def cmd_shadow_scan(args: argparse.Namespace) -> int:
    """Detect installed AI coding tools."""
    from src.services.shadow_ai import ShadowAIScanner

    approved = frozenset(args.approved) if args.approved is not None else None
    scanner = ShadowAIScanner()
    result = scanner.scan(approved_tools=approved)

    if getattr(args, "json", False):
        import json as _json
        data = {
            "total_found": result.total_found,
            "approved": [
                {"tool_id": d.tool_id, "display_name": d.display_name,
                 "detected_via": d.detected_via}
                for d in result.approved
            ],
            "unapproved": [
                {"tool_id": d.tool_id, "display_name": d.display_name,
                 "detected_via": d.detected_via}
                for d in result.unapproved
            ],
        }
        _echo(_json.dumps(data, indent=2))
        return 0

    _echo(f"\n{color('Shadow AI Scan', BOLD)}\n")
    _echo(f"  AI tools found: {result.total_found}\n")

    for d in result.approved:
        _echo(f"  {color('+', GREEN)} {d.display_name} — approved ({d.detected_via})")

    for d in result.unapproved:
        _echo(f"  {color('!', YELLOW)} {d.display_name} — unapproved ({d.detected_via})")

    if not result.detections:
        _echo("  No AI coding tools detected.")

    _echo()
    return 0


def cmd_attribute(args: argparse.Namespace) -> int:
    """Attribute AI model origin for files."""
    from src.services.ai_attribution import AIAttributor

    attributor = AIAttributor()
    all_results: list[object] = []

    for target in args.targets:
        target_path = Path(target).resolve()
        if target_path.is_dir():
            results = attributor.analyze_directory(target_path)
            all_results.extend(results)
        elif target_path.is_file():
            result = attributor.analyze_file(target_path, workspace=target_path.parent)
            all_results.append(result)
        else:
            _echo(f"  {color('!', YELLOW)} Not found: {target}")

    if getattr(args, "json", False):
        import json as _json
        data = [
            {
                "file": r.file, "primary_source": r.primary_source,
                "primary_model": r.primary_model,
                "ai_probability": r.ai_probability, "method": r.method,
            }
            for r in all_results
        ]
        _echo(_json.dumps(data, indent=2))
        return 0

    _echo(f"\n{color('AI Attribution', BOLD)}\n")

    ai_count = 0
    for r in all_results:
        if r.ai_probability > 0.5:
            ai_count += 1
            prob_pct = int(r.ai_probability * 100)
            _echo(
                f"  {color('!', YELLOW)} {r.file} — {r.primary_source} "
                f"({r.primary_model}) {prob_pct}% [{r.method}]"
            )
        else:
            _echo(f"  {color('+', GREEN)} {r.file} — human")

    _echo(f"\n  {len(all_results)} files analyzed, {ai_count} AI-attributed\n")
    return 0


def cmd_risk_profile(args: argparse.Namespace) -> int:
    """Developer AI risk scoring."""
    from src.services.developer_risk import DeveloperRiskService

    workspace = Path(args.workspace).resolve()
    svc = DeveloperRiskService()
    result = svc.assess(workspace=workspace, max_commits=args.max_commits)

    if getattr(args, "json", False):
        import json as _json
        data = {
            "total_developers": result.total_developers,
            "high_risk_count": result.high_risk_count,
            "profiles": [
                {
                    "author": p.author, "email": p.email,
                    "total_commits": p.total_commits,
                    "ai_commits": p.ai_commits, "ai_ratio": p.ai_ratio,
                    "models_used": p.models_used, "block_rate": p.block_rate,
                    "risk_score": p.risk_score, "trust_level": p.trust_level,
                }
                for p in result.profiles
            ],
        }
        _echo(_json.dumps(data, indent=2))
        return 0

    _echo(f"\n{color('Developer Risk Profiles', BOLD)}\n")
    _echo(f"  Developers: {result.total_developers}")
    _echo(f"  High risk:  {result.high_risk_count}\n")

    for p in result.profiles:
        level_color = RED if p.trust_level == "high_risk" else (
            YELLOW if p.trust_level == "elevated" else GREEN
        )
        _echo(
            f"  {color(p.trust_level.upper().ljust(11), level_color)} "
            f"{p.author} — score {p.risk_score}, "
            f"AI ratio {int(p.ai_ratio * 100)}%, "
            f"blocks {p.block_count}"
        )
        if p.models_used:
            _echo(f"             Models: {', '.join(p.models_used)}")

    _echo()
    return 0


def cmd_benchmark(args: argparse.Namespace) -> int:
    """Show LLM code quality benchmarks."""
    from src.services.llm_benchmark import LLMBenchmarkService

    workspace = Path(args.workspace).resolve()
    svc = LLMBenchmarkService()
    result = svc.aggregate(workspace=workspace)

    if getattr(args, "json", False):
        import json as _json
        data = {
            "total_entries": result.total_entries,
            "total_files": result.total_files,
            "models": [
                {
                    "model": m.model, "files_scanned": m.files_scanned,
                    "total_lines": m.total_lines,
                    "total_blocks": m.total_blocks,
                    "total_warns": m.total_warns,
                    "block_rate_per_100": m.block_rate_per_100,
                    "warn_rate_per_100": m.warn_rate_per_100,
                }
                for m in result.models
            ],
        }
        _echo(_json.dumps(data, indent=2))
        return 0

    _echo(f"\n{color('LLM Benchmark', BOLD)}\n")
    _echo(f"  Data points: {result.total_entries}")
    _echo(f"  Files:       {result.total_files}\n")

    if not result.models:
        _echo("  No benchmark data yet. Run scans with attribution enabled.\n")
        return 0

    for m in sorted(result.models, key=lambda x: x.block_rate_per_100):
        rate_color = RED if m.block_rate_per_100 > 5 else (
            YELLOW if m.block_rate_per_100 > 2 else GREEN
        )
        _echo(
            f"  {m.model.ljust(25)} "
            f"{color(f'{m.block_rate_per_100:.1f}', rate_color)} blocks/100L  "
            f"{m.warn_rate_per_100:.1f} warns/100L  "
            f"{m.files_scanned} files"
        )

    _echo()
    return 0


def cmd_hook(args: argparse.Namespace) -> int:
    """Manage CodeTrust pre-commit hook."""
    sub = str(getattr(args, "subcommand", ""))

    if sub == "install":
        return _hook_install()
    if sub == "uninstall":
        return _hook_uninstall()
    if sub == "report":
        return _hook_report()

    _echo("Usage: codetrust hook {install|uninstall|report}")
    return 1


def _hook_install() -> int:
    """Install CodeTrust pre-commit hook into .git/hooks."""
    git_dir = Path.cwd() / ".git"
    if not git_dir.is_dir():
        _echo(f"  {color('X', RED)} Not a git repository")
        return 1

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(exist_ok=True)
    target = hooks_dir / "pre-commit"

    # Find the hook source
    src_candidates = [
        Path(__file__).parent.parent / "hooks" / _HOOK_SCRIPT,
        Path.cwd() / "hooks" / _HOOK_SCRIPT,
    ]
    src_path: Path | None = None
    for candidate in src_candidates:
        if candidate.is_file():
            src_path = candidate
            break

    if src_path is None:
        _echo(f"  {color('X', RED)} Hook script not found: {_HOOK_SCRIPT}")
        return 1

    # Check if pre-commit already exists and is not ours
    if target.exists():
        existing = target.read_text(encoding="utf-8", errors="replace")
        if "codetrust" not in existing.lower():
            backup = target.with_suffix(".pre-codetrust")
            shutil.copy2(target, backup)
            _echo(f"  Existing hook backed up to {backup.name}")

    # Write wrapper that invokes the hook via python
    wrapper_content = (
        "#!/usr/bin/env bash\n"
        "# CodeTrust pre-commit hook — do not edit manually\n"
        f'exec python3 "{src_path.resolve()}" "$@"\n'
    )
    target.write_text(wrapper_content, encoding="utf-8")
    target.chmod(0o755)

    _echo(f"  {color('+', GREEN)} Pre-commit hook installed: {target}")
    _echo(f"  Source: {src_path.resolve()}")
    return 0


def _hook_uninstall() -> int:
    """Remove CodeTrust pre-commit hook."""
    target = Path.cwd() / ".git" / "hooks" / "pre-commit"
    if not target.exists():
        _echo("  No pre-commit hook installed.")
        return 0

    content = target.read_text(encoding="utf-8", errors="replace")
    if "codetrust" not in content.lower():
        _echo(f"  {color('!', YELLOW)} Pre-commit hook is not a CodeTrust hook — skipping")
        return 1

    target.unlink()
    _echo(f"  {color('+', GREEN)} Pre-commit hook removed")

    # Restore backup if exists
    backup = target.with_suffix(".pre-codetrust")
    if backup.exists():
        shutil.move(str(backup), str(target))
        _echo(f"  Previous hook restored from {backup.name}")

    return 0


def _hook_report() -> int:
    """Show the latest commit report."""
    report_dir = Path.cwd() / ".codetrust" / "reports"
    if not report_dir.is_dir():
        _echo("  No commit reports found.")
        return 0

    reports = sorted(report_dir.glob("commit_*.json"), reverse=True)
    if not reports:
        _echo("  No commit reports found.")
        return 0

    latest = reports[0]
    try:
        data = json.loads(latest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _echo(f"  {color('X', RED)} Failed to read report: {exc}")
        return 1

    _echo(f"\n{color('Latest Commit Report', BOLD)}\n")
    _echo(f"  Timestamp: {data.get('timestamp', '?')}")
    _echo(f"  Files:     {data.get('files_analyzed', 0)}")
    _echo(f"  Blocks:    {data.get('total_blocks', 0)}")
    _echo(f"  Warns:     {data.get('total_warns', 0)}")

    models = data.get("models_used", [])
    if models:
        _echo(f"  Models:    {', '.join(models)}")

    editors = data.get("editors_used", [])
    if editors:
        _echo(f"  Editors:   {', '.join(editors)}")

    policy_v = data.get("policy_violations", 0)
    if policy_v:
        _echo(f"  Policy violations: {policy_v}")

    _echo(f"\n  Report: {latest}\n")
    return 0


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
    if args.command == "login":
        return cmd_login(args)
    if args.command == "logout":
        return cmd_logout(args)
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
    if args.command == "shield":
        return cmd_shield(args)
    if args.command == "mcp-audit":
        return cmd_mcp_audit(args)
    if args.command == "shadow-scan":
        return cmd_shadow_scan(args)
    if args.command == "attribute":
        return cmd_attribute(args)
    if args.command == "risk-profile":
        return cmd_risk_profile(args)
    if args.command == "benchmark":
        return cmd_benchmark(args)
    if args.command == "hook":
        return cmd_hook(args)
    if args.command == "compliance":
        return cmd_compliance(args)
    if args.command == "integrity":
        return cmd_integrity(args)
    if args.command == "integrations":
        return cmd_integrations(args)
    if args.command == "pii":
        return cmd_pii(args)
    if args.command == "classify":
        return cmd_classify(args)
    if args.command == "cost":
        return cmd_cost(args)
    if args.command == "dod":
        return cmd_dod(args)
    if args.command == "risk-register":
        return cmd_risk_register(args)
    if args.command == "assess":
        return cmd_assess(args)
    if args.command == "red-team":
        return cmd_red_team(args)
    if args.command == "privacy":
        return cmd_privacy(args)
    if args.command == "governance-report":
        return cmd_governance_report(args)
    if args.command == "risk-map":
        return cmd_risk_map(args)
    if args.command == "metrics":
        return cmd_metrics(args)
    if args.command == "treatment-plan":
        return cmd_treatment_plan(args)

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
    _add_shield_subparser(subparsers)
    _add_ai_observability_subparsers(subparsers)

    args = parser.parse_args()
    return _route_command(args, parser)


if __name__ == "__main__":
    sys.exit(main())
