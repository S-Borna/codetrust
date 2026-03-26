#!/usr/bin/env python3
# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""CodeTrust pre-commit hook — full commit-level analysis.

Runs on every ``git commit``. For each staged file:
1. Scans through CodeTrust static + AST analyzers
2. Reads IDE hook attribution data
3. Evaluates against repository policy
4. Prints colored report with model tags
5. Blocks commit on BLOCK findings or policy violations
6. Saves report to ``.codetrust/reports/``
"""

from __future__ import annotations

import contextlib
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

# ─────────────────────────────────────────────────────────────────
#  Constants
# ─────────────────────────────────────────────────────────────────

CODE_EXTENSIONS: frozenset[str] = frozenset({
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".rb", ".php",
    ".java", ".cs", ".cpp", ".c", ".yaml", ".yml", ".toml", ".json",
    ".sql", ".tf", ".sh", ".dockerfile",
})

# Infrastructure config files that use env var references — skip scanning
# to avoid false positives on ${VAR:-default} patterns.
INFRA_CONFIG_SKIP: frozenset[str] = frozenset({
    "docker-compose.yml", "docker-compose.yaml",
    "docker-compose.override.yml", "docker-compose.override.yaml",
})

# Rule definition files contain the patterns they detect — they
# self-match by design and must be excluded from pre-commit scanning.
# Not a security bypass — these files are reviewed in PRs.
RULE_DEFINITION_FILES: frozenset[str] = frozenset({
    "anti_patterns.py", "enterprise.py", "taint_rules.py",
})

# Directories containing CI/CD workflows — skip scanning to avoid
# false positives on template literals and embedded code snippets.
SKIP_PATH_PREFIXES: tuple[str, ...] = (".github/",)

SEVERITY_BLOCK = "BLOCK"
SEVERITY_WARN = "WARN"

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
BOLD = "\033[1m"
RESET = "\033[0m"


# ─────────────────────────────────────────────────────────────────
#  Git helpers
# ─────────────────────────────────────────────────────────────────


def get_staged_files() -> list[str]:
    """Get list of staged files (added, copied, modified, renamed)."""
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
        capture_output=True,
        text=True,
    )
    return [f for f in result.stdout.strip().split("\n") if f]


# ─────────────────────────────────────────────────────────────────
#  Attribution lookup
# ─────────────────────────────────────────────────────────────────


def get_attribution(filepath: str, workspace: Path) -> dict[str, str] | None:
    """Look up the most recent IDE hook attribution for a file."""
    hook_file = workspace / ".codetrust" / "attribution.jsonl"
    if not hook_file.exists():
        return None

    latest: dict[str, str] | None = None
    try:
        for line in hook_file.read_text(encoding="utf-8").strip().split("\n"):
            if not line:
                continue
            with contextlib.suppress(json.JSONDecodeError):
                event = json.loads(line)
                if event.get("active_file") == filepath:
                    latest = event
    except OSError as exc:
        sys.stderr.write(f"  CodeTrust: attribution read error: {exc}\n")
    return latest


# ─────────────────────────────────────────────────────────────────
#  Scanning
# ─────────────────────────────────────────────────────────────────


def _run_static_scan(content: str, filepath: str) -> list[dict[str, object]]:
    """Run static regex scan. Returns findings or empty list."""
    try:
        from src.services.static_analyzer import StaticAnalyzer
        analyzer = StaticAnalyzer()
        return [
            {"rule_id": f.rule_id, "severity": f.severity.value,
             "line": f.line, "message": f.message}
            for f in analyzer.scan_code(content, filename=filepath)
        ]
    except ImportError:
        sys.stderr.write("  CodeTrust: static analyzer not available\n")
        return []


def _run_ast_scan(content: str, filepath: str) -> list[dict[str, object]]:
    """Run AST tree-sitter scan. Returns findings or empty list."""
    try:
        from src.models.enums import Language
        from src.services.ast_analyzer import AstAnalyzer

        lang_map: dict[str, Language] = {
            ".py": Language.PYTHON, ".js": Language.JAVASCRIPT,
            ".ts": Language.TYPESCRIPT, ".go": Language.GO,
            ".rs": Language.RUST, ".java": Language.JAVA,
            ".cs": Language.CSHARP, ".cpp": Language.CPP,
            ".rb": Language.RUBY, ".php": Language.PHP,
        }
        lang = lang_map.get(Path(filepath).suffix.lower())
        if lang is None:
            return []
        ast_analyzer = AstAnalyzer()
        return [
            {"rule_id": f.rule_id, "severity": f.severity.value,
             "line": f.line, "message": f.message}
            for f in ast_analyzer.analyze(content, lang, filepath)
        ]
    except ImportError:
        return []


def scan_file(filepath: str) -> list[dict[str, object]]:
    """Run CodeTrust static + AST scan on a single file."""
    try:
        content = Path(filepath).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    findings = _run_static_scan(content, filepath)
    findings.extend(_run_ast_scan(content, filepath))
    return findings


# ─────────────────────────────────────────────────────────────────
#  Output
# ─────────────────────────────────────────────────────────────────


def _print_file_result(
    filepath: str,
    model: str,
    blocks: list[dict[str, object]],
    warns: list[dict[str, object]],
) -> None:
    """Print colored file scan result."""
    model_tag = f" [{model}]" if model != "unknown" else ""
    if blocks:
        sys.stdout.write(
            f"  {RED}X {filepath}{model_tag} — {len(blocks)} BLOCK{RESET}\n"
        )
        for f in blocks:
            sys.stdout.write(
                f"    L{f.get('line', '?')}: {f.get('rule_id')} — "
                f"{str(f.get('message', ''))[:80]}\n"
            )
    elif warns:
        sys.stdout.write(
            f"  {YELLOW}! {filepath}{model_tag} — {len(warns)} WARN{RESET}\n"
        )
    else:
        sys.stdout.write(f"  {GREEN}+ {filepath}{model_tag}{RESET}\n")


def _save_report(
    workspace: Path,
    file_reports: list[dict[str, object]],
    total_blocks: int,
    total_warns: int,
    models_used: set[str],
    editors_used: set[str],
    policy_violation_count: int,
) -> Path:
    """Save commit report to .codetrust/reports/."""
    report = {
        "timestamp": datetime.now(tz=UTC).isoformat(),
        "files_analyzed": len(file_reports),
        "total_blocks": total_blocks,
        "total_warns": total_warns,
        "models_used": sorted(models_used),
        "editors_used": sorted(editors_used),
        "policy_violations": policy_violation_count,
        "files": file_reports,
    }

    report_dir = workspace / ".codetrust" / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    timestamp_str = datetime.now(tz=UTC).strftime("%Y%m%d_%H%M%S")
    report_path = report_dir / f"commit_{timestamp_str}.json"

    with contextlib.suppress(OSError):
        report_path.write_text(
            json.dumps(report, indent=2, default=str), encoding="utf-8",
        )
    return report_path


# ─────────────────────────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────────────────────────


def main() -> int:
    """Run the pre-commit analysis pipeline."""
    workspace = Path.cwd()
    staged = get_staged_files()

    if not staged:
        return 0

    total_blocks = 0
    total_warns = 0
    models_used: set[str] = set()
    editors_used: set[str] = set()
    file_reports: list[dict[str, object]] = []
    has_blocks = False
    policy_violations: list[object] = []

    # Load policy engine if available
    policy_engine = None
    file_attributions: list[object] = []
    has_policy = False
    try:
        from src.services.commit_policy import CommitPolicyEngine, FileAttribution
        policy_engine = CommitPolicyEngine(workspace)
        has_policy = True
    except ImportError:
        sys.stderr.write("  CodeTrust: commit policy engine not available (optional)\n")

    for filepath in staged:
        if Path(filepath).suffix.lower() not in CODE_EXTENSIONS:
            continue
        if Path(filepath).name.lower() in INFRA_CONFIG_SKIP:
            continue
        if Path(filepath).name in RULE_DEFINITION_FILES:
            continue
        if any(filepath.startswith(prefix) for prefix in SKIP_PATH_PREFIXES):
            continue

        findings = scan_file(filepath)
        blocks = [f for f in findings if f.get("severity") == SEVERITY_BLOCK]
        warns = [f for f in findings if f.get("severity") == SEVERITY_WARN]

        attr = get_attribution(filepath, workspace)
        model = attr.get("model", "unknown") if attr else "unknown"
        provider = attr.get("provider", "unknown") if attr else "unknown"
        editor = attr.get("source_extension", "unknown") if attr else "unknown"

        if model != "unknown":
            models_used.add(model)
        if editor != "unknown":
            editors_used.add(editor)

        if has_policy:
            ai_prob = 0.95 if model != "unknown" else 0.0
            file_attributions.append(FileAttribution(
                file=filepath, model=model, provider=provider,
                editor=editor, ai_probability=ai_prob,
            ))

        file_reports.append({
            "file": filepath, "model": model, "provider": provider,
            "editor": editor, "blocks": len(blocks),
            "warns": len(warns), "findings": findings,
        })
        total_blocks += len(blocks)
        total_warns += len(warns)
        if blocks:
            has_blocks = True

        _print_file_result(filepath, model, blocks, warns)

    # Policy evaluation
    if policy_engine is not None and file_attributions:
        policy_violations = policy_engine.evaluate(file_attributions)
        for v in policy_violations:
            if hasattr(v, "severity") and v.severity == SEVERITY_BLOCK:
                has_blocks = True
                sys.stdout.write(f"  {RED}X POLICY: {v.message}{RESET}\n")
            elif hasattr(v, "severity"):
                sys.stdout.write(f"  {YELLOW}! POLICY: {v.message}{RESET}\n")

    # Summary
    sys.stdout.write(
        f"\n  CodeTrust: {len(staged)} files, "
        f"{total_blocks} blocks, {total_warns} warns\n"
    )
    if models_used:
        sys.stdout.write(f"  Models: {', '.join(sorted(models_used))}\n")

    report_path = _save_report(
        workspace, file_reports, total_blocks, total_warns,
        models_used, editors_used, len(policy_violations),
    )

    if has_blocks:
        block_policy = sum(
            1 for v in policy_violations
            if hasattr(v, "severity") and v.severity == SEVERITY_BLOCK
        )
        sys.stdout.write(
            f"\n  {RED}{BOLD}Commit blocked — fix {total_blocks} findings "
            f"and {block_policy} policy violations first.{RESET}\n"
        )
        sys.stdout.write(f"  Report: {report_path}\n")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
