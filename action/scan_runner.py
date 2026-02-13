"""CodeTrust GitHub Action scan runner.

Runs CodeTrust scans locally (no API needed) or via the cloud API,
outputs results to the console with GitHub Actions annotations, and
writes SARIF output for the Security tab.
"""

import argparse
import json
import sys
from pathlib import Path

# Add parent directory to path so we can import src modules
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.formatters.sarif import findings_to_sarif
from src.gateway.interceptor import CommandInterceptor, Verdict
from src.models.enums import Severity
from src.models.responses import Finding
from src.services.static_analyzer import StaticAnalyzer


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="CodeTrust scan runner")
    parser.add_argument("--scan-type", default="deep")
    parser.add_argument("--language", default="python")
    parser.add_argument("--path", default=".")
    parser.add_argument("--sarif-file", default="codetrust-results.sarif")
    parser.add_argument("--fail-on", default="block", choices=["block", "warn", "never"])
    parser.add_argument("--max-file-size", type=int, default=500_000)
    parser.add_argument("--include-pattern", default="")
    parser.add_argument("--api-key", default="")
    parser.add_argument("--api-url", default="https://codetrust-api-production.up.railway.app")
    return parser.parse_args()


def discover_files(
    scan_path: str,
    language: str,
    include_pattern: str,
    max_file_size: int,
) -> list[Path]:
    """Discover files to scan based on language and path.

    Args:
        scan_path: File or directory to scan.
        language: Programming language filter.
        include_pattern: Optional glob pattern override.
        max_file_size: Maximum file size in bytes.

    Returns:
        List of file paths to scan.
    """
    root = Path(scan_path)

    if root.is_file():
        return [root]

    pattern = include_pattern or _language_glob(language)

    files: list[Path] = []
    for path in sorted(root.rglob(pattern)):
        if not path.is_file():
            continue
        if _is_excluded(path):
            continue
        if path.stat().st_size > max_file_size:
            continue
        files.append(path)

    return files


def _language_glob(language: str) -> str:
    """Get glob pattern for a language."""
    patterns: dict[str, str] = {
        "python": "*.py",
        "javascript": "*.js",
        "typescript": "*.ts",
        "go": "*.go",
        "rust": "*.rs",
    }
    return patterns.get(language, "*.*")


def _is_excluded(path: Path) -> bool:
    """Check if a path should be excluded from scanning."""
    excluded_dirs = {
        ".git", ".venv", "venv", "node_modules", "__pycache__",
        ".mypy_cache", ".ruff_cache", ".pytest_cache", "dist",
        "build", ".tox", ".eggs", "*.egg-info",
        ".next", ".open-next", ".turbo", ".nuxt", ".output",
        ".svelte-kit", ".vercel", ".wrangler", "coverage", "out", ".cache",
    }
    return any(
        part in excluded_dirs or part.endswith(".egg-info")
        for part in path.parts
    )


def scan_files(
    files: list[Path],
    language: str,
) -> list[Finding]:
    """Run static analysis on discovered files.

    Args:
        files: List of file paths to scan.
        language: Programming language.

    Returns:
        Combined list of findings from all files.
    """
    analyzer = StaticAnalyzer()
    all_findings: list[Finding] = []

    for file_path in files:
        try:
            code = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            print(f"Warning: cannot read {file_path}: {exc}")
            continue

        findings = analyzer.scan_code(code, str(file_path))
        all_findings.extend(findings)

    return all_findings


def scan_governance(files: list[Path]) -> list[Finding]:
    """Run gateway content rules on files for CI governance enforcement.

    Checks for eval/exec, hardcoded secrets, and other governance
    violations that the gateway would block in real-time.

    Args:
        files: List of file paths to check.

    Returns:
        List of governance findings as Finding objects.
    """
    interceptor = CommandInterceptor()
    governance_findings: list[Finding] = []

    for file_path in files:
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        result = interceptor.check_file_write(str(file_path), content)
        if result.verdict != Verdict.ALLOW:
            severity = (
                Severity.BLOCK if result.verdict == Verdict.BLOCK
                else Severity.WARN
            )
            governance_findings.append(Finding(
                rule_id=result.rule_id,
                severity=severity,
                message=f"[Governance] {result.message}",
                file=str(file_path),
                line=1,
                suggestion=result.suggestion,
            ))

    return governance_findings


def emit_annotations(findings: list[Finding]) -> None:
    """Emit GitHub Actions annotations for findings.

    Uses ::error:: and ::warning:: workflow commands so findings
    appear inline in PR diffs.

    Args:
        findings: List of findings to annotate.
    """
    for finding in findings:
        level = "error" if finding.severity == Severity.BLOCK else "warning"
        file_ref = finding.file or "unknown"
        line = finding.line or 1

        msg = f"{finding.rule_id}: {finding.message}"
        annotation = f"::{level} file={file_ref},line={line}::{msg}"
        _write_output(annotation)


def write_sarif(
    findings: list[Finding],
    sarif_path: str,
) -> None:
    """Write SARIF output file.

    Args:
        findings: List of findings.
        sarif_path: Path to write SARIF JSON.
    """
    if not sarif_path:
        return

    sarif = findings_to_sarif(findings)
    path = Path(sarif_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(sarif, indent=2) + "\n",
        encoding="utf-8",
    )
    _write_output(f"SARIF output written to {sarif_path}")


def compute_verdict(findings: list[Finding]) -> str:
    """Compute overall verdict from findings.

    Args:
        findings: All findings from scan.

    Returns:
        Verdict string: PASS, WARN, or BLOCK.
    """
    has_block = any(f.severity == Severity.BLOCK for f in findings)
    has_warn = any(f.severity == Severity.WARN for f in findings)

    if has_block:
        return "BLOCK"
    if has_warn:
        return "WARN"
    return "PASS"


def set_outputs(
    verdict: str,
    findings: list[Finding],
    sarif_path: str,
) -> None:
    """Set GitHub Actions outputs.

    Args:
        verdict: Overall verdict.
        findings: All findings.
        sarif_path: Path to SARIF file.
    """
    blocks = sum(1 for f in findings if f.severity == Severity.BLOCK)
    warns = sum(1 for f in findings if f.severity == Severity.WARN)
    total = len(findings)

    _set_output("verdict", verdict)
    _set_output("total-findings", str(total))
    _set_output("blocks", str(blocks))
    _set_output("warnings", str(warns))
    _set_output("sarif-file", sarif_path)


def _set_output(name: str, value: str) -> None:
    """Write a GitHub Actions output variable."""
    import os

    github_output = os.environ.get("GITHUB_OUTPUT", "")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as f:
            f.write(f"{name}={value}\n")


def _write_output(message: str) -> None:
    """Write a message to stdout."""
    sys.stdout.write(message + "\n")
    sys.stdout.flush()


def print_summary(
    verdict: str,
    findings: list[Finding],
    files_scanned: int,
) -> None:
    """Print scan summary to console.

    Args:
        verdict: Overall verdict.
        findings: All findings.
        files_scanned: Number of files scanned.
    """
    blocks = sum(1 for f in findings if f.severity == Severity.BLOCK)
    warns = sum(1 for f in findings if f.severity == Severity.WARN)
    infos = sum(1 for f in findings if f.severity == Severity.INFO)

    _write_output("")
    _write_output("=" * 50)
    _write_output(f"CodeTrust Scan — Verdict: {verdict}")
    _write_output(f"Files scanned: {files_scanned}")
    _write_output(f"Total findings: {len(findings)}")
    _write_output(f"  BLOCK: {blocks}  WARN: {warns}  INFO: {infos}")
    _write_output("=" * 50)


def should_fail(verdict: str, fail_on: str) -> bool:
    """Determine if the action should fail based on verdict and threshold.

    Args:
        verdict: Scan verdict.
        fail_on: Failure threshold.

    Returns:
        True if the action should exit with non-zero code.
    """
    if fail_on == "never":
        return False
    if fail_on == "block" and verdict == "BLOCK":
        return True
    return fail_on == "warn" and verdict in ("BLOCK", "WARN")


def main() -> int:
    """Run the CodeTrust scan and return exit code.

    Returns:
        0 for pass, 1 for failure.
    """
    args = parse_args()

    # Discover files
    files = discover_files(
        args.path, args.language,
        args.include_pattern, args.max_file_size,
    )

    if not files:
        _write_output("No files found to scan.")
        set_outputs("PASS", [], args.sarif_file)
        return 0

    _write_output(f"Found {len(files)} file(s) to scan")

    # Run static scan
    findings = scan_files(files, args.language)

    # Run governance scan (gateway content rules in CI)
    gov_findings = scan_governance(files)
    if gov_findings:
        _write_output(f"Governance: {len(gov_findings)} finding(s)")
    findings.extend(gov_findings)

    # Emit annotations
    emit_annotations(findings)

    # Compute verdict
    verdict = compute_verdict(findings)

    # Write SARIF
    write_sarif(findings, args.sarif_file)

    # Set outputs
    set_outputs(verdict, findings, args.sarif_file)

    # Print summary
    print_summary(verdict, findings, len(files))

    # Determine exit code
    if should_fail(verdict, args.fail_on):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
