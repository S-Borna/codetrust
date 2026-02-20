#!/usr/bin/env python3
"""
CodeTrust CI Scanner — scans changed files via API or embedded rules.

Usage:
    CODETRUST_API_URL=... CODETRUST_API_KEY=... CHANGED_FILES="file1.py\nfile2.py" python scan.py

Exit codes:
    0 = PASS (no BLOCK findings)
    1 = BLOCK findings detected
"""

import json
import os
import re
import sys
import time
import uuid
from pathlib import Path

# --- Embedded anti-pattern rules (mirrors src/rules/anti_patterns.py) ---

BLOCK_RULES: list[dict[str, str]] = [
    {
        "id": "heredoc",
        "pattern": r"<<[-']?\w+",
        "message": "Heredoc detected. Use template files or multi-line strings.",
    },
    {
        "id": "hardcoded_secret",
        "pattern": (
            r'(?i)(api[_-]?key|secret|password|token|credentials)'
            r'\s*[:=]\s*["\'][^"\']{8,}["\']'
        ),
        "message": "Possible hardcoded secret. Use environment variables.",
    },
    {
        "id": "eval_exec",
        "pattern": r"\b(eval|exec)\s*\(",
        "message": "eval/exec is a security risk.",
    },
    {
        "id": "sql_injection",
        "pattern": r'(?:execute|executemany|cursor\.execute)\s*\(\s*(?:f["\']|[^)]*\.format\s*\()',
        "message": "Possible SQL injection via string formatting.",
    },
    {
        "id": "pickle_load",
        "pattern": r"pickle\.loads?\s*\(",
        "message": "pickle.load is unsafe with untrusted data.",
    },
]

WARN_RULES: list[dict[str, str]] = [
    {
        "id": "todo_hack",
        "pattern": r"(?i)#\s*(todo|hack|fixme|xxx|temp)\b",
        "message": "Temporary marker found.",
    },
    {
        "id": "console_log",
        "pattern": r"\bconsole\.(log|debug|info)\s*\(",
        "message": "Replace console logging with structured logger.",
    },
    {
        "id": "print_debug",
        "pattern": r"^\s*print\s*\(",
        "message": "Use logging module instead of print().",
    },
    {
        "id": "wildcard_import",
        "pattern": r"from\s+\S+\s+import\s+\*",
        "message": "Wildcard imports reduce clarity.",
    },
    {
        "id": "bare_except",
        "pattern": r"except\s*:",
        "message": "Bare except. Catch specific exceptions.",
    },
    {
        "id": "any_type",
        "pattern": r":\s*[Aa]ny\b",
        "message": "Avoid Any type. Use explicit types.",
    },
]


def scan_file_local(filepath: str) -> list[dict]:
    """Scan a file using embedded rules."""
    findings = []
    try:
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return findings

    for line_num, line in enumerate(lines, 1):
        if "noqa" in line:
            continue
        for rule in BLOCK_RULES:
            if re.search(rule["pattern"], line):
                findings.append({
                    "rule_id": rule["id"],
                    "severity": "BLOCK",
                    "message": rule["message"],
                    "file": filepath,
                    "line": line_num,
                })
        for rule in WARN_RULES:
            if re.search(rule["pattern"], line):
                findings.append({
                    "rule_id": rule["id"],
                    "severity": "WARN",
                    "message": rule["message"],
                    "file": filepath,
                    "line": line_num,
                })
    return findings


def scan_file_api(filepath: str, api_url: str, api_key: str) -> list[dict]:
    """Scan a file using CodeTrust cloud API."""
    try:
        import httpx
    except ImportError:
        print("httpx not installed, falling back to local scan")
        return scan_file_local(filepath)

    try:
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            code = f.read()
    except OSError:
        return []

    if not code.strip():
        return []

    try:
        response = httpx.post(
            f"{api_url.rstrip('/')}/v1/scan/static",
            json={"code": code, "filename": filepath},
            headers={"X-API-Key": api_key, "Content-Type": "application/json"},
            timeout=30.0,
        )
        if response.status_code == 200:
            data = response.json()
            return data.get("findings", [])
        print(f"  API returned {response.status_code} for {filepath}, using local scan")
        return scan_file_local(filepath)
    except Exception as exc:
        print(f"  API error for {filepath}: {exc}, using local scan")
        return scan_file_local(filepath)


def generate_report(all_findings: list[dict], files_scanned: int) -> str:
    """Generate markdown report."""
    blocks = [f for f in all_findings if f.get("severity") == "BLOCK"]
    warns = [f for f in all_findings if f.get("severity") == "WARN"]
    infos = [f for f in all_findings if f.get("severity") == "INFO"]

    if blocks:
        verdict = "🚫 BLOCK"
        verdict_line = f"**Verdict: BLOCK** — {len(blocks)} critical issues must be fixed"
    elif warns:
        verdict = "⚠️ WARN"
        verdict_line = f"**Verdict: WARN** — {len(warns)} warnings to review"
    else:
        verdict = "✅ PASS"
        verdict_line = "**Verdict: PASS** — No issues found"

    lines = [
        "## 🛡️ CodeTrust Scan Results",
        "",
        f"{verdict_line}",
        "",
        f"📁 Files scanned: {files_scanned} | "
        f"🚫 {len(blocks)} blocks | "
        f"⚠️ {len(warns)} warnings | "
        f"ℹ️ {len(infos)} infos",
        "",
    ]

    if blocks:
        lines.append("### 🚫 BLOCK — Must fix before merge")
        lines.append("")
        lines.append("| File | Line | Rule | Message |")
        lines.append("|------|------|------|---------|")
        for f in blocks:
            file_str = f.get("file", "")
            line_num = f.get("line", 0)
            lines.append(
                f"| `{file_str}` | {line_num} | `{f['rule_id']}` | {f['message']} |"
            )
        lines.append("")

    if warns:
        lines.append("<details><summary>⚠️ Warnings ({} items)</summary>".format(len(warns)))
        lines.append("")
        lines.append("| File | Line | Rule | Message |")
        lines.append("|------|------|------|---------|")
        for f in warns:
            file_str = f.get("file", "")
            line_num = f.get("line", 0)
            lines.append(
                f"| `{file_str}` | {line_num} | `{f['rule_id']}` | {f['message']} |"
            )
        lines.append("")
        lines.append("</details>")
        lines.append("")

    if not blocks and not warns:
        lines.append("All checks passed. Ship it! 🚀")
        lines.append("")

    lines.append("---")
    lines.append("*Powered by CodeTrust — https://codetrust.ai*")

    return "\n".join(lines)


def _send_telemetry(payload: dict) -> None:
    """Best-effort telemetry send (never fails the action)."""

    api_url = os.environ.get("CODETRUST_API_URL", "https://api.codetrust.ai").rstrip("/")
    url = f"{api_url}/v1/telemetry"

    try:
        import httpx
    except ImportError:
        return

    try:
        httpx.post(url, json=payload, timeout=3.0)
    except Exception:
        return


def main() -> int:
    """Main entry point."""
    api_url = os.environ.get("CODETRUST_API_URL", "")
    api_key = os.environ.get("CODETRUST_API_KEY", "")
    changed_files_str = os.environ.get("CHANGED_FILES", "")

    start = time.monotonic()

    files = [f.strip() for f in changed_files_str.strip().split("\n") if f.strip()]

    # Filter to only existing source files
    source_exts = {".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java", ".sh"}
    files = [f for f in files if Path(f).suffix in source_exts and Path(f).exists()]

    # Exclude test files from BLOCK enforcement (they intentionally contain anti-patterns)
    def _is_test_file(filepath: str) -> bool:
        """Check if a file is a test file by name or path."""
        name = Path(filepath).name
        parts = Path(filepath).parts
        return (
            name.startswith("test_")
            or name.endswith(".test.ts")
            or name.endswith(".test.js")
            or name.endswith(".spec.ts")
            or name.endswith(".spec.js")
            or "test" in parts
            or "__tests__" in parts
        )

    scan_files = [f for f in files if not _is_test_file(f)]
    test_files = [f for f in files if _is_test_file(f)]

    if not scan_files and not test_files:
        print("No source files changed — skipping scan.")
        report = "## 🛡️ CodeTrust Scan Results\n\n✅ No source files changed.\n"
        Path("codetrust-report.md").write_text(report)
        return 0

    use_api = bool(api_url and api_key)
    mode = "API" if use_api else "local"
    print(f"CodeTrust scanning {len(scan_files)} files ({mode} mode)...")

    all_findings: list[dict] = []
    for filepath in scan_files:
        print(f"  Scanning {filepath}...")
        if use_api:
            findings = scan_file_api(filepath, api_url, api_key)
        else:
            findings = scan_file_local(filepath)
        all_findings.extend(findings)

    # Generate report
    report = generate_report(all_findings, len(scan_files))
    Path("codetrust-report.md").write_text(report)
    print(report)

    # Exit code: 1 if any BLOCK findings
    has_blocks = any(f.get("severity") == "BLOCK" for f in all_findings)
    duration_ms = int((time.monotonic() - start) * 1000)

    _send_telemetry(
        {
            "event_type": "ci_run_completed",
            "source": "github_action",
            "installation_id": f"gha-{uuid.uuid4()}",
            "version": "2.4.0",
            "payload": {
                "scan_type": "static" if use_api else "local",
                "files_scanned": len(scan_files),
                "total_findings": len(all_findings),
                "gate_result": "FAIL" if has_blocks else "PASS",
                "duration_ms": duration_ms,
                "pr_mode": os.environ.get("GITHUB_EVENT_NAME", ""),
            },
        }
    )

    if has_blocks:
        print("\n🚫 CodeTrust: BLOCKED — fix critical issues before merge.")
        return 1

    print("\n✅ CodeTrust: PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
