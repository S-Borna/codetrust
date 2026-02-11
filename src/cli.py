"""
CodeTrust CLI — install, scan, and enforce from any project.

Usage:
    codetrust init          Install enforcement layers into current project
    codetrust scan <file>   Scan a file for anti-patterns
    codetrust scan .        Scan all source files in current directory
    codetrust status        Check if CodeTrust is installed in current project
    codetrust doctor        Verify all enforcement layers are working
"""

import argparse
import importlib.resources
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

# --- Embedded rules (mirrors src/rules/anti_patterns.py) ---

BLOCK_RULES: list[tuple[str, str, str]] = [
    ("heredoc", r"<<[-']?\w+", "Heredoc detected. Use template files."),
    (
        "hardcoded_secret",
        r'(?i)(api[_-]?key|secret|password|token|credentials)\s*[:=]\s*["\'][^"\']{8,}["\']',
        "Possible hardcoded secret.",
    ),
    ("eval_exec", r"\b(eval|exec)\s*\(", "eval/exec is a security risk."),
    (
        "sql_injection",
        r'(?:execute|executemany|cursor\.execute)\s*\(\s*(?:f["\']|[^)]*\.format\s*\()',
        "Possible SQL injection.",
    ),
    ("pickle_load", r"pickle\.loads?\s*\(", "pickle.load is unsafe with untrusted data."),
]

WARN_RULES: list[tuple[str, str, str]] = [
    ("todo_hack", r"(?i)#\s*(todo|hack|fixme|xxx|temp)\b", "Temporary marker found."),
    ("console_log", r"\bconsole\.(log|debug|info)\s*\(", "Use structured logger."),
    ("print_debug", r"^\s*print\s*\(", "Use logging, not print()."),
    ("wildcard_import", r"from\s+\S+\s+import\s+\*", "Wildcard import."),
    ("bare_except", r"except\s*:", "Bare except — catch specific exceptions."),
    ("any_type", r":\s*[Aa]ny\b", "Avoid Any type."),
]

SOURCE_EXTS = {".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java", ".sh"}

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


# --- Scan engine ---


def scan_file(filepath: str) -> list[dict[str, str | int]]:
    """Scan a single file for anti-patterns."""
    findings: list[dict[str, str | int]] = []
    try:
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return findings

    basename = os.path.basename(filepath)
    if basename.startswith("test_") or basename.startswith("conftest"):
        return findings  # Skip test files

    for line_num, line in enumerate(lines, 1):
        if "noqa" in line:
            continue
        for rule_id, pattern, message in BLOCK_RULES:
            if re.search(pattern, line):
                findings.append({
                    "rule_id": rule_id,
                    "severity": "BLOCK",
                    "message": message,
                    "file": filepath,
                    "line": line_num,
                })
        for rule_id, pattern, message in WARN_RULES:
            if re.search(pattern, line):
                findings.append({
                    "rule_id": rule_id,
                    "severity": "WARN",
                    "message": message,
                    "file": filepath,
                    "line": line_num,
                })
    return findings


def scan_path(target: str) -> list[dict[str, str | int]]:
    """Scan a file or directory."""
    findings: list[dict[str, str | int]] = []
    target_path = Path(target)

    if target_path.is_file():
        return scan_file(str(target_path))

    if target_path.is_dir():
        skip_dirs = {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build"}
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
    patterns_to_add = ["codetrust-report.md"]
    if gitignore.exists():
        existing = gitignore.read_text()
        new_patterns = [p for p in patterns_to_add if p not in existing]
        if new_patterns:
            with open(gitignore, "a") as f:
                f.write("\n# CodeTrust\n")
                for p in new_patterns:
                    f.write(f"{p}\n")

    # Summary
    print(f"\n{'━' * 48}")
    print(f"\n  {color('✅ CodeTrust installed!', GREEN)}\n")
    print("  Enforcement stack:")
    print(f"    Layer 1: CLAUDE.md / .cursorrules  {color('(advisory)', BLUE)}")
    print(f"    Layer 2: VS Code extension         {color('(passive)', BLUE)}")
    print(f"    Layer 3: Pre-commit hook            {color('(blocking)', GREEN)}")
    print(f"    Layer 4: GitHub Action              {color('(absolute)', RED)}")
    print()
    print("  Next steps:")
    print("    1. Push to GitHub")
    print("    2. Settings → Branches → Require 'CodeTrust Quality Gate' to pass")
    print("    3. Install VS Code extension: code --install-extension codetrust.codetrust")
    print()

    return 0


# --- Scan command ---


def cmd_scan(args: argparse.Namespace) -> int:
    """Scan files for anti-patterns."""
    targets = args.targets
    if not targets:
        targets = ["."]

    all_findings: list[dict[str, str | int]] = []
    files_scanned = 0

    for target in targets:
        findings = scan_path(target)
        all_findings.extend(findings)
        if Path(target).is_file():
            files_scanned += 1
        elif Path(target).is_dir():
            skip_dirs = {".git", ".venv", "venv", "node_modules", "__pycache__"}
            for _root, dirs, files in os.walk(target):
                dirs[:] = [d for d in dirs if d not in skip_dirs]
                files_scanned += sum(1 for f in files if Path(f).suffix in SOURCE_EXTS)

    blocks = [f for f in all_findings if f.get("severity") == "BLOCK"]
    warns = [f for f in all_findings if f.get("severity") == "WARN"]

    # Output
    print(f"\n{color('🛡️  CodeTrust Scan', BOLD)}")
    print(f"   Files: {files_scanned} | Findings: {len(all_findings)}\n")

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

    if not blocks and not warns:
        print(color("  ✅ PASS — no issues found\n", GREEN))

    # JSON output
    if args.json:
        result = {
            "verdict": "BLOCK" if blocks else ("WARN" if warns else "PASS"),
            "files_scanned": files_scanned,
            "total_findings": len(all_findings),
            "blocks": len(blocks),
            "warnings": len(warns),
            "findings": all_findings,
        }
        print(json.dumps(result, indent=2, default=str))

    return 1 if blocks else 0


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
        pass

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


def cmd_doctor(_args: argparse.Namespace) -> int:
    """Run diagnostic checks on CodeTrust installation."""
    print(f"\n{color('🛡️  CodeTrust Doctor', BOLD)}\n")

    issues: list[str] = []
    project_dir = Path.cwd()

    # 1. Check git
    if not (project_dir / ".git").is_dir():
        issues.append("Not a git repository")

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
    else:
        print(f"  {len(issues)} issue(s) found. Run {color('codetrust init', BOLD)} to fix.\n")

    return 0 if not issues else 1


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

    # scan
    scan_parser = subparsers.add_parser("scan", help="Scan files for anti-patterns")
    scan_parser.add_argument("targets", nargs="*", default=["."], help="Files or directories")
    scan_parser.add_argument("--json", action="store_true", help="Output as JSON")

    # status
    subparsers.add_parser("status", help="Check installed enforcement layers")

    # doctor
    subparsers.add_parser("doctor", help="Diagnose CodeTrust installation")

    args = parser.parse_args()

    if args.command == "init":
        return cmd_init(args)
    if args.command == "scan":
        return cmd_scan(args)
    if args.command == "status":
        return cmd_status(args)
    if args.command == "doctor":
        return cmd_doctor(args)

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
