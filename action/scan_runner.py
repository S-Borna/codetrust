"""CodeTrust GitHub Action scan runner.

Runs CodeTrust scans locally (no API needed) or via the cloud API,
outputs results to the console with GitHub Actions annotations, and
writes SARIF output for the Security tab.
"""

import argparse
import json
import sys
import os
import subprocess
from pathlib import Path

# Add parent directory to path so we can import src modules
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.formatters.sarif import findings_to_sarif
from src.gateway.interceptor import CommandInterceptor, Verdict
from src.models.enums import Severity
from src.models.responses import Finding
from src.services.static_analyzer import StaticAnalyzer

COMMENT_START = "<!-- codetrust-scan:start -->"
COMMENT_END = "<!-- codetrust-scan:end -->"


def upsert_comment(existing: str, new_report: str) -> str:
    """Upsert the CodeTrust comment block using stable start/end markers."""
    report = new_report.strip("\n")
    if COMMENT_START in existing and COMMENT_END in existing:
        before = existing.split(COMMENT_START)[0]
        after = existing.split(COMMENT_END)[1]
        return f"{before}{COMMENT_START}\n\n{report}\n\n{COMMENT_END}{after}"
    return f"{COMMENT_START}\n\n{report}\n\n{COMMENT_END}\n"


def calculate_trust_score(findings: list[Finding]) -> float:
    """Compute trust score (0.00–1.00) using the canonical CLI scorer."""
    try:
        from src.cli import _calculate_drift_score  # canonical scorer

        items = [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "message": f.message,
                "file": f.file,
                "line": f.line,
            }
            for f in findings
        ]
        drift = _calculate_drift_score(items)
        score = float(drift.get("score", 0))
        return max(0.0, min(1.0, score / 100.0))
    except Exception:
        return 0.0


def verify_imports(
    files: list[Path],
    language: str,
) -> list[Finding]:
    """Verify imports from scanned files against live registries.

    Extracts imports from source files and checks that every imported
    package actually exists on PyPI/npm. Returns BLOCK findings for
    packages that don't exist (possible AI hallucinations).

    Args:
        files: List of file paths to check.
        language: Programming language.

    Returns:
        List of Finding objects for unverified imports.
    """
    py_exts = {".py"}
    js_exts = {".js", ".ts", ".jsx", ".tsx"}

    py_files: list[tuple[str, str]] = []
    js_files: list[tuple[str, str]] = []

    for file_path in files:
        ext = file_path.suffix.lower()
        basename = file_path.name.lower()

        # Skip test files
        if (
            basename.startswith("test_")
            or basename.startswith("conftest")
            or ".test." in basename
            or ".spec." in basename
        ):
            continue

        try:
            code = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        if ext in py_exts:
            py_files.append((str(file_path), code))
        elif ext in js_exts:
            js_files.append((str(file_path), code))

    if not py_files and not js_files:
        return []

    return verify_imports_from_sources(py_files, js_files)


def verify_imports_from_sources(
    py_files: list[tuple[str, str]],
    js_files: list[tuple[str, str]],
) -> list[Finding]:
    """Verify imports against registries from in-memory sources (best-effort)."""
    if not py_files and not js_files:
        return []

    try:
        from src.services.import_verifier import verify_file_imports_sync

        raw_findings = verify_file_imports_sync(py_files, js_files)
        return [
            Finding(
                rule_id=str(f["rule_id"]),
                severity=(
                    Severity.BLOCK if f.get("severity") == "BLOCK"
                    else Severity.WARN if f.get("severity") == "WARN"
                    else Severity.INFO
                ),
                message=str(f["message"]),
                file=str(f.get("file", "")),
                line=int(f.get("line", 1)),
            )
            for f in raw_findings
        ]
    except Exception:
        return []


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
    parser.add_argument(
        "--pr-mode",
        default="auto",
        choices=["auto", "always", "never"],
        help="PR-mode: auto (default), always, or never",
    )
    parser.add_argument(
        "--pr-comment",
        default="auto",
        choices=["auto", "always", "never"],
        help="PR comment: auto (default), always, or never",
    )
    parser.add_argument(
        "--new-findings-only",
        default="auto",
        choices=["auto", "always", "never"],
        help="Hard gate: auto (default), always, or never. When enabled on PRs, gates only on new findings vs base SHA.",
    )
    parser.add_argument("--api-key", default="")
    parser.add_argument("--api-url", default="https://codetrust-api.saidborna.com")
    return parser.parse_args()


def _is_pull_request_event() -> bool:
    """Return True if running under a pull_request GitHub Actions event."""
    if os.environ.get("GITHUB_EVENT_NAME", "") == "pull_request":
        return True
    return bool(os.environ.get("GITHUB_BASE_REF", ""))


def _get_pr_base_sha() -> str | None:
    """Best-effort: get PR base SHA from GitHub event payload."""
    event_path = os.environ.get("GITHUB_EVENT_PATH", "")
    if not event_path:
        return None
    try:
        data = json.loads(Path(event_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    pr = data.get("pull_request")
    if not isinstance(pr, dict):
        return None
    base = pr.get("base")
    if not isinstance(base, dict):
        return None
    sha = base.get("sha")
    if isinstance(sha, str) and sha.strip():
        return sha.strip()
    return None


def _get_pr_number() -> int | None:
    """Best-effort: get PR number from env or GitHub event payload."""
    from_env = os.environ.get("PR_NUMBER", "").strip()
    if from_env.isdigit():
        return int(from_env)

    event_path = os.environ.get("GITHUB_EVENT_PATH", "")
    if not event_path:
        return None
    try:
        data = json.loads(Path(event_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    pr = data.get("pull_request")
    if not isinstance(pr, dict):
        return None
    number = pr.get("number")
    if isinstance(number, int) and number > 0:
        return number
    return None


def _post_or_update_pr_comment(report_path: str) -> None:
    """Post or update a CodeTrust PR comment (best-effort).

    Requires:
    - GITHUB_TOKEN
    - GITHUB_REPOSITORY (owner/repo)
    - PR number (PR_NUMBER or event payload)
    """
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    repo = os.environ.get("GITHUB_REPOSITORY", "").strip()
    pr_number = _get_pr_number()

    if not token or not repo or not pr_number:
        return

    report_file = Path(report_path)
    if not report_file.exists():
        return

    try:
        import httpx
    except ImportError:
        _write_output("::warning::PR comment skipped (httpx not installed)")
        return

    body_text = report_file.read_text(encoding="utf-8", errors="replace")
    new_block = body_text.strip("\n")

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    base_url = f"https://api.github.com/repos/{repo}"
    list_url = f"{base_url}/issues/{pr_number}/comments?per_page=100"

    try:
        with httpx.Client(timeout=10.0, headers=headers) as client:
            existing_id: int | None = None
            existing_body: str | None = None
            resp = client.get(list_url)
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list):
                    for c in data:
                        if not isinstance(c, dict):
                            continue
                        cid = c.get("id")
                        cbody = c.get("body")
                        if isinstance(cid, int) and isinstance(cbody, str) and (
                            COMMENT_START in cbody or "<!-- codetrust-scan -->" in cbody
                        ):
                            existing_id = cid
                            existing_body = cbody
                            break

            if existing_id is not None:
                update_url = f"{base_url}/issues/comments/{existing_id}"
                merged = upsert_comment(existing_body or "", new_block)
                upd = client.patch(update_url, json={"body": merged})
                if upd.status_code >= 200 and upd.status_code < 300:
                    _write_output("PR comment updated.")
                else:
                    _write_output(f"::warning::PR comment update failed (HTTP {upd.status_code})")
                return

            post_url = f"{base_url}/issues/{pr_number}/comments"
            created = client.post(post_url, json={"body": upsert_comment("", new_block)})
            if created.status_code >= 200 and created.status_code < 300:
                _write_output("PR comment posted.")
            else:
                _write_output(f"::warning::PR comment post failed (HTTP {created.status_code})")
    except Exception:
        _write_output("::warning::PR comment failed (exception)")


def _git(args: list[str]) -> str | None:
    """Run a git command and return stdout (or None on failure)."""
    try:
        result = subprocess.run(
            ["git", *args],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    return result.stdout


def _get_changed_files(base_sha: str, head_sha: str) -> list[Path]:
    """Get changed files between base and head SHAs (best-effort)."""
    out = _git(["diff", "--name-only", "--diff-filter=ACM", base_sha, head_sha])
    if not out:
        return []
    files: list[Path] = []
    for line in out.splitlines():
        rel = line.strip()
        if not rel:
            continue
        p = Path(rel)
        if p.exists() and p.is_file() and not _is_excluded(p):
            files.append(p)
    return files


def _read_file_at_ref(ref: str, file_path: Path) -> str | None:
    """Read a file's contents at a given git ref (best-effort)."""
    spec = f"{ref}:{file_path.as_posix()}"
    out = _git(["show", spec])
    if out is None:
        return None
    return out


def _finding_key(f: Finding) -> tuple[str, str, int, str, str]:
    """Stable identity key for a finding for diffing across refs."""
    return (
        str(f.rule_id),
        str(f.file or ""),
        int(f.line or 1),
        str(f.severity.value if hasattr(f.severity, "value") else f.severity),
        str(f.message),
    )


def diff_new_findings(head: list[Finding], baseline: list[Finding]) -> list[Finding]:
    """Return only findings that exist in head but not baseline."""
    baseline_keys = {_finding_key(f) for f in baseline}
    return [f for f in head if _finding_key(f) not in baseline_keys]


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
    report_path: str,
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
    _set_output("report", report_path)
    _set_output("sarif-file", sarif_path)


def write_markdown_report(
    verdict: str,
    findings: list[Finding],
    files_scanned: int,
    report_path: str,
    pr_mode_active: bool,
    new_findings_note: str | None = None,
) -> None:
    """Write a markdown report to disk.

    Intended for PR comments and artifact use.
    """
    blocks = [f for f in findings if f.severity == Severity.BLOCK]
    warns = [f for f in findings if f.severity == Severity.WARN]
    infos = [f for f in findings if f.severity == Severity.INFO]

    trust = calculate_trust_score(findings)
    baseline = "origin/main"
    new_findings = len(findings) if not pr_mode_active else len(findings)

    lines: list[str] = [
        "CodeTrust Verdict: " + verdict,
        f"CodeTrust Trust Score: {trust:.2f}",
        f"CodeTrust New Findings: {new_findings}",
        f"CodeTrust Baseline: {baseline}",
        "CodeTrust Enforcement: ACTIVE",
        "",
        "Fix locally:",
        "",
        "pip install codetrust",
        "codetrust scan --changed-only --baseline origin/main --fail-on-new BLOCK",
        "",
        "Full governance check:",
        "",
        "codetrust governance",
        "",
        "---",
        "",
    ]

    def add_table(title: str, items: list[Finding]) -> None:
        if not items:
            return
        lines.append(f"### {title}")
        lines.append("")
        lines.append("| File | Line | Rule | Message |")
        lines.append("|------|------|------|---------|")
        for f in items[:50]:
            file_str = f.file or "unknown"
            line_num = f.line or 1
            rule_id = f.rule_id
            msg = f.message.replace("\n", " ")
            lines.append(f"| `{file_str}` | {line_num} | `{rule_id}` | {msg} |")
        lines.append("")

    add_table("🚫 BLOCK", blocks)
    add_table("⚠️ WARN", warns)
    add_table("ℹ️ INFO", infos)

    Path(report_path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_step_summary(
    verdict: str,
    findings: list[Finding],
    files_scanned: int,
    pr_mode_active: bool,
) -> None:
    """Append a concise summary to GitHub Actions step summary (if available)."""
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY", "")
    if not summary_path:
        return

    blocks = sum(1 for f in findings if f.severity == Severity.BLOCK)
    warns = sum(1 for f in findings if f.severity == Severity.WARN)
    infos = sum(1 for f in findings if f.severity == Severity.INFO)
    mode = "PR-mode (new findings only)" if pr_mode_active else "Full scan"

    top = findings[:10]
    lines = [
        "## 🛡️ CodeTrust",
        "",
        f"**Verdict:** `{verdict}`  ",
        f"**Mode:** {mode}  ",
        f"**Files scanned:** {files_scanned}  ",
        f"**Findings:** BLOCK {blocks} · WARN {warns} · INFO {infos}",
        "",
    ]

    if top:
        lines.append("### Top findings")
        for f in top:
            file_str = f.file or "unknown"
            line_num = f.line or 1
            msg = f.message.replace("\n", " ")
            lines.append(f"- `{f.rule_id}` {file_str}:{line_num} — {msg}")
        lines.append("")

    try:
        with open(summary_path, "a", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    except OSError:
        return


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

    is_pr = _is_pull_request_event()

    new_findings_only_active = (
        (args.new_findings_only == "always")
        or (args.new_findings_only == "auto" and is_pr)
    )
    if new_findings_only_active and not is_pr:
        _write_output("::notice::new-findings-only enabled but not a PR event — ignoring")
        new_findings_only_active = False

    # PR-mode scanning is required for new-findings-only gate.
    pr_mode_active = (
        new_findings_only_active
        or (args.pr_mode == "always")
        or (args.pr_mode == "auto" and is_pr)
    )

    pr_comment_active = (
        (args.pr_comment == "always")
        or (args.pr_comment == "auto" and _is_pull_request_event())
    )

    # Discover files
    files = discover_files(
        args.path, args.language,
        args.include_pattern, args.max_file_size,
    )

    baseline_findings: list[Finding] = []
    baseline_sha: str | None = None
    if pr_mode_active and Path(args.path).is_dir():
        baseline_sha = _get_pr_base_sha()
        head_sha = os.environ.get("GITHUB_SHA", "HEAD") or "HEAD"
        if baseline_sha:
            changed = _get_changed_files(baseline_sha, head_sha)
            if changed:
                files = changed
                _write_output(f"PR-mode: scanning {len(files)} changed file(s)")
            else:
                _write_output("PR-mode: no changed files detected — falling back to normal discovery")
        else:
            if new_findings_only_active:
                _write_output(
                    "::error::CodeTrust new-findings-only gate requires PR base SHA. "
                    "Ensure checkout has full history (fetch-depth: 0) and the workflow runs on pull_request."
                )
                report_path = "codetrust-report.md"
                write_markdown_report(
                    verdict="BLOCK",
                    findings=[],
                    files_scanned=0,
                    report_path=report_path,
                    pr_mode_active=True,
                    new_findings_note="New findings: unknown (baseline unavailable)",
                )
                write_step_summary("BLOCK", [], 0, True)
                if (
                    (args.pr_comment == "always")
                    or (args.pr_comment == "auto" and is_pr)
                ):
                    _post_or_update_pr_comment(report_path)
                set_outputs("BLOCK", [], report_path, args.sarif_file)
                return 1

            _write_output("PR-mode: base SHA unavailable — falling back to normal discovery")

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

    # Run live import verification against registries
    import_findings = verify_imports(files, args.language)
    if import_findings:
        _write_output(f"Import verification: {len(import_findings)} finding(s)")
    findings.extend(import_findings)

    effective_findings = findings
    new_findings_note: str | None = None
    if pr_mode_active and baseline_sha:
        analyzer = StaticAnalyzer()
        interceptor = CommandInterceptor()

        py_exts = {".py"}
        js_exts = {".js", ".ts", ".jsx", ".tsx"}
        baseline_py: list[tuple[str, str]] = []
        baseline_js: list[tuple[str, str]] = []

        baseline_files: list[tuple[Path, str]] = []
        for file_path in files:
            content = _read_file_at_ref(baseline_sha, file_path)
            if content is None:
                continue
            baseline_files.append((file_path, content))

        # Baseline: static + governance + import verification (best-effort).
        for file_path, content in baseline_files:
            baseline_findings.extend(analyzer.scan_code(content, str(file_path)))

            result = interceptor.check_file_write(str(file_path), content)
            if result.verdict != Verdict.ALLOW:
                severity = Severity.BLOCK if result.verdict == Verdict.BLOCK else Severity.WARN
                baseline_findings.append(
                    Finding(
                        rule_id=result.rule_id,
                        severity=severity,
                        message=f"[Governance] {result.message}",
                        file=str(file_path),
                        line=1,
                        suggestion=result.suggestion,
                    )
                )

            ext = file_path.suffix.lower()
            if ext in py_exts:
                baseline_py.append((str(file_path), content))
            elif ext in js_exts:
                baseline_js.append((str(file_path), content))

        baseline_findings.extend(verify_imports_from_sources(baseline_py, baseline_js))

        effective_findings = diff_new_findings(findings, baseline_findings)
        new_findings_note = (
            f"New findings: {len(effective_findings)} "
            f"(head {len(findings)} vs base {len(baseline_findings)})"
        )
        _write_output(f"PR-mode: {new_findings_note}")

    # Emit annotations (PR-mode emits only new findings)
    emit_annotations(effective_findings)

    # Compute verdict
    verdict = compute_verdict(effective_findings)

    # Write SARIF
    write_sarif(effective_findings, args.sarif_file)

    # Write markdown report + step summary
    report_path = "codetrust-report.md"
    write_markdown_report(
        verdict,
        effective_findings,
        len(files),
        report_path,
        pr_mode_active,
        new_findings_note,
    )
    write_step_summary(verdict, effective_findings, len(files), pr_mode_active)

    if pr_comment_active:
        _post_or_update_pr_comment(report_path)

    # Set outputs
    set_outputs(verdict, effective_findings, report_path, args.sarif_file)

    # Print summary
    print_summary(verdict, effective_findings, len(files))

    # Determine exit code
    if should_fail(verdict, args.fail_on):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
