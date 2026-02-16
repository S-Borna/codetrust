"""MCP server entry point — CodeTrust Layers 1-4 + SARIF + Deep Scan tools."""

import json
import os
import time

import httpx
import structlog
from mcp.server.fastmcp import FastMCP

from src.config import settings
from src.formatters.sarif import findings_to_sarif
from src.models.enums import Language, Severity, VerifyStatus
from src.models.requests import DockerImageInput
from src.models.responses import DockerImageResult, Finding, PackageResult, SandboxResponse
from src.rules.anti_patterns import ANTI_PATTERNS
from src.services.ast_analyzer import SUPPORTED_LANGUAGES as AST_LANGUAGES
from src.services.ast_analyzer import AstAnalyzer
from src.services.cache import CacheService
from src.services.docker_verify import DockerVerifyService
from src.services.registry import RegistryService
from src.services.sandbox import SandboxService
from src.services.static_analyzer import StaticAnalyzer
from src.telemetry_client import send_telemetry
from src.utils.parsers import (
    extract_go_imports,
    extract_js_imports,
    extract_python_imports,
    extract_rust_imports,
    parse_dockerfile_from,
)

logger = structlog.get_logger()


def _emit_mcp_tool_invoked(
    *,
    tool: str,
    ok: bool,
    duration_ms: int,
    payload: dict[str, object],
) -> None:
    """Best-effort anonymous telemetry for MCP tool usage."""

    safe_payload: dict[str, object] = {
        "tool": tool,
        "ok": ok,
        "duration_ms": duration_ms,
        **payload,
    }

    send_telemetry(
        event_type="mcp_tool_invoked",
        source="mcp",
        version=settings.version,
        cli_opt_out=False,
        payload=safe_payload,
    )

mcp = FastMCP("codetrust")
analyzer = StaticAnalyzer()
ast_analyzer = AstAnalyzer()
sandbox = SandboxService()

# Lazy-initialized shared resources for Layer 2
_cache: CacheService | None = None
_http_client: httpx.AsyncClient | None = None
_registry: RegistryService | None = None
_docker: DockerVerifyService | None = None


async def _get_registry() -> RegistryService:
    """Lazily initialize shared cache, HTTP client, and registry service."""
    global _cache, _http_client, _registry, _docker

    if _registry is not None:
        return _registry

    _cache = CacheService(settings.redis_url)
    await _cache.connect()

    _http_client = httpx.AsyncClient(
        timeout=settings.http_timeout,
        limits=httpx.Limits(
            max_connections=settings.http_max_connections,
            max_keepalive_connections=settings.http_max_keepalive,
        ),
    )

    _registry = RegistryService(_cache, _http_client)
    _docker = DockerVerifyService(_cache, _http_client)
    return _registry


async def _get_docker() -> DockerVerifyService:
    """Lazily initialize and return Docker verification service."""
    global _docker

    if _docker is not None:
        return _docker

    # Calling _get_registry initializes all shared resources including _docker
    await _get_registry()
    assert _docker is not None
    return _docker


@mcp.tool(name="codetrust_static_scan")
async def codetrust_static_scan(
    code: str,
    filename: str = "untitled",
    language: str | None = None,
) -> str:
    """Scan code for anti-patterns, security issues, and quality problems.

    Args:
        code: Source code to analyze.
        filename: Name of the file being scanned.
        language: Programming language (optional, for future use).

    Returns:
        Markdown-formatted report of findings.
    """
    logger.info("mcp_static_scan", filename=filename)
    started = time.monotonic()
    ok = False
    try:
        findings = analyzer.scan_code(code, filename)
        ok = True
        return analyzer.build_report(findings, title="Static Analysis Report")
    finally:
        duration_ms = int((time.monotonic() - started) * 1000)
        total = 0
        blocks = 0
        warns = 0
        infos = 0
        try:
            total = len(findings) if "findings" in locals() else 0
            blocks = sum(1 for f in findings if f.severity == Severity.BLOCK) if "findings" in locals() else 0
            warns = sum(1 for f in findings if f.severity == Severity.WARN) if "findings" in locals() else 0
            infos = sum(1 for f in findings if f.severity == Severity.INFO) if "findings" in locals() else 0
        except Exception as exc:
            logger.debug(
                "mcp_tool_metrics_compute_failed",
                error=str(exc),
                error_type=type(exc).__name__,
                tool="codetrust_static_scan",
            )

        _emit_mcp_tool_invoked(
            tool="codetrust_static_scan",
            ok=ok,
            duration_ms=duration_ms,
            payload={
                "code_len": len(code),
                "language_provided": bool(language),
                "total_findings": total,
                "findings_by_severity": {"BLOCK": blocks, "WARN": warns, "INFO": infos},
            },
        )


@mcp.tool(name="codetrust_pre_action")
async def codetrust_pre_action(
    task_description: str,
    proposed_stack: str | None = None,
    proposed_files: list[str] | None = None,
    has_user_specified_stack: bool = False,
    has_user_specified_structure: bool = False,
) -> str:
    """Validate the plan BEFORE writing any code.

    Checks whether requirements are clear enough to proceed. Flags assumptions
    about tech stack, project structure, or scope that the user didn't confirm.

    Args:
        task_description: Description of the task to validate.
        proposed_stack: Proposed technology stack.
        proposed_files: List of proposed files to create/modify.
        has_user_specified_stack: Whether the user confirmed the stack.
        has_user_specified_structure: Whether the user confirmed the structure.

    Returns:
        Validation report with PASS/WARN/BLOCK verdict.
    """
    logger.info("mcp_pre_action", task=task_description[:80])
    started = time.monotonic()
    ok = False
    findings: list[Finding] = []
    try:
        findings = _validate_plan(
            task_description,
            proposed_stack,
            proposed_files,
            has_user_specified_stack,
            has_user_specified_structure,
        )
        ok = True
        return analyzer.build_report(findings, title="Pre-Action Validation")
    finally:
        duration_ms = int((time.monotonic() - started) * 1000)
        blocks = 0
        warns = 0
        infos = 0
        try:
            blocks = sum(1 for f in findings if f.severity == Severity.BLOCK)
            warns = sum(1 for f in findings if f.severity == Severity.WARN)
            infos = sum(1 for f in findings if f.severity == Severity.INFO)
        except Exception as exc:
            logger.debug(
                "mcp_tool_metrics_compute_failed",
                error=str(exc),
                error_type=type(exc).__name__,
                tool="codetrust_pre_action",
            )

        _emit_mcp_tool_invoked(
            tool="codetrust_pre_action",
            ok=ok,
            duration_ms=duration_ms,
            payload={
                "task_description_len": len(task_description),
                "proposed_stack_provided": bool(proposed_stack),
                "proposed_files_count": len(proposed_files) if proposed_files else 0,
                "has_user_specified_stack": bool(has_user_specified_stack),
                "has_user_specified_structure": bool(has_user_specified_structure),
                "findings_total": len(findings),
                "findings_by_severity": {"BLOCK": blocks, "WARN": warns, "INFO": infos},
            },
        )


@mcp.tool(name="codetrust_post_action")
async def codetrust_post_action(
    repo_root: str,
    task_description: str,
    files_changed: list[str] | None = None,
    verify_imports: bool = False,
) -> str:
    """Validate the completed work against enterprise standards.

    Checks repo structure, required files, and scans all changed files for issues.

    Args:
        repo_root: Path to the repository root.
        task_description: Description of completed task.
        files_changed: List of files that were changed.
        verify_imports: Whether to verify imports (Phase 2 feature).

    Returns:
        Enterprise readiness report with PASS/WARN/BLOCK verdict.
    """
    logger.info("mcp_post_action", repo_root=repo_root, task=task_description[:80])
    started = time.monotonic()
    ok = False
    all_findings: list[Finding] = []
    try:
        all_findings = analyzer.check_repo_structure(repo_root)

        if files_changed:
            for filepath in files_changed:
                full_path = os.path.join(repo_root, filepath)
                if os.path.isfile(full_path):
                    all_findings.extend(
                        _scan_file(full_path, filepath)
                    )

        ok = True
        return analyzer.build_report(all_findings, title="Post-Action Validation")
    finally:
        duration_ms = int((time.monotonic() - started) * 1000)
        blocks = 0
        warns = 0
        infos = 0
        try:
            blocks = sum(1 for f in all_findings if f.severity == Severity.BLOCK)
            warns = sum(1 for f in all_findings if f.severity == Severity.WARN)
            infos = sum(1 for f in all_findings if f.severity == Severity.INFO)
        except Exception as exc:
            logger.debug(
                "mcp_tool_metrics_compute_failed",
                error=str(exc),
                error_type=type(exc).__name__,
                tool="codetrust_post_action",
            )

        _emit_mcp_tool_invoked(
            tool="codetrust_post_action",
            ok=ok,
            duration_ms=duration_ms,
            payload={
                "task_description_len": len(task_description),
                "files_changed_count": len(files_changed) if files_changed else 0,
                "verify_imports": bool(verify_imports),
                "findings_total": len(all_findings),
                "findings_by_severity": {"BLOCK": blocks, "WARN": warns, "INFO": infos},
            },
        )


@mcp.tool(name="codetrust_list_rules")
async def codetrust_list_rules() -> str:
    """List all anti-pattern rules, structure requirements, and their severities.

    Returns:
        Complete rule catalog in markdown format.
    """
    logger.info("mcp_list_rules")
    started = time.monotonic()
    ok = False
    lines: list[str] = [
        "## CodeTrust Rule Catalog",
        "",
        "### Anti-Pattern Rules",
        "",
        "| ID | Severity | Description |",
        "|---|---|---|",
    ]

    for rule in ANTI_PATTERNS:
        lines.append(
            f"| {rule['id']} | {rule['severity']} | {rule['message']} |"
        )

    lines.extend([
        "",
        "### Structure Rules",
        "",
        "| ID | Severity | Description |",
        "|---|---|---|",
        "| missing_required_file | BLOCK | Required files must exist |",
        "| missing_recommended_file | WARN | Recommended files should exist |",
        "| missing_recommended_dir | WARN | Recommended directories should exist |",
        "| forbidden_file | WARN | Sensitive files should not be committed |",
    ])

    ok = True
    out = "\n".join(lines)
    duration_ms = int((time.monotonic() - started) * 1000)
    _emit_mcp_tool_invoked(
        tool="codetrust_list_rules",
        ok=ok,
        duration_ms=duration_ms,
        payload={"anti_pattern_rules_count": len(ANTI_PATTERNS)},
    )
    return out


def _validate_plan(
    task_description: str,
    proposed_stack: str | None,
    proposed_files: list[str] | None,
    has_user_specified_stack: bool,
    has_user_specified_structure: bool,
) -> list[Finding]:
    """Validate a plan before code is written."""

    findings: list[Finding] = []

    if len(task_description) < 20:
        findings.append(Finding(
            rule_id="vague_task",
            severity=Severity.WARN,
            message="Task description is very short. Consider adding more detail.",
            suggestion="Describe what should be built, for whom, and key requirements.",
        ))

    if proposed_stack and not has_user_specified_stack:
        findings.append(Finding(
            rule_id="unconfirmed_stack",
            severity=Severity.WARN,
            message=f"Tech stack '{proposed_stack}' was not confirmed by the user.",
            suggestion="Ask the user to confirm the proposed technology stack.",
        ))

    if proposed_files and not has_user_specified_structure:
        file_count = len(proposed_files)
        if file_count > 10:
            findings.append(Finding(
                rule_id="large_scope",
                severity=Severity.WARN,
                message=f"Plan involves {file_count} files. Consider breaking into phases.",
                suggestion="Split into smaller, testable increments.",
            ))

    return findings


def _scan_file(full_path: str, relative_path: str) -> list[Finding]:
    """Read and scan a single file for anti-patterns."""

    try:
        with open(full_path, encoding="utf-8") as f:
            code = f.read()
        return analyzer.scan_code(code, relative_path)
    except (OSError, UnicodeDecodeError):
        return [Finding(
            rule_id="file_read_error",
            severity=Severity.WARN,
            message=f"Could not read file '{relative_path}' for scanning.",
            file=relative_path,
        )]


@mcp.tool(name="codetrust_verify_imports")
async def codetrust_verify_imports(
    code: str,
    language: str = "python",
    filename: str = "untitled",
    requirements: str = "",
) -> str:
    """Verify that all imports in code exist in package registries.

    Extracts imports from code, then checks each against the appropriate
    registry (PyPI for Python, npm for JavaScript/TypeScript).

    Args:
        code: Source code to extract imports from.
        language: Programming language (python, javascript, typescript).
        filename: Name of the file being checked.
        requirements: Optional requirements.txt content for version pinning.

    Returns:
        Markdown-formatted verification report.
    """
    logger.info("mcp_verify_imports", filename=filename, language=language)
    started = time.monotonic()
    ok = False
    imports_count = 0
    verified = 0
    failed = 0
    warnings = 0
    try:
        lang = Language(language)
        imports = _extract_imports(code, lang)
        imports_count = len(imports)

        if not imports:
            ok = True
            return "## Import Verification\n\nNo third-party imports found.\n"

        registry = await _get_registry()
        results = await registry.verify_packages(lang, imports, requirements)

        verified = sum(1 for r in results if r.status == VerifyStatus.VERIFIED)
        failed = sum(1 for r in results if r.status in (VerifyStatus.NOT_FOUND, VerifyStatus.VERSION_MISMATCH))
        warnings = sum(1 for r in results if r.status in (VerifyStatus.DEPRECATED, VerifyStatus.TIMEOUT, VerifyStatus.ERROR))

        ok = True
        elapsed_ms = int((time.monotonic() - started) * 1000)
        return _format_import_report(results, elapsed_ms)
    finally:
        duration_ms = int((time.monotonic() - started) * 1000)
        _emit_mcp_tool_invoked(
            tool="codetrust_verify_imports",
            ok=ok,
            duration_ms=duration_ms,
            payload={
                "language": language,
                "code_len": len(code),
                "total_imports_checked": imports_count,
                "verified": verified,
                "failed": failed,
                "warnings": warnings,
            },
        )


def _extract_imports(code: str, language: Language) -> list[str]:
    """Extract imports based on language."""
    if language == Language.PYTHON:
        return extract_python_imports(code)
    if language in (Language.JAVASCRIPT, Language.TYPESCRIPT):
        return extract_js_imports(code)
    if language == Language.GO:
        return extract_go_imports(code)
    if language == Language.RUST:
        return extract_rust_imports(code)
    return []


def _format_import_report(
    results: list[PackageResult], elapsed_ms: int
) -> str:
    """Format package verification results as markdown."""
    verified = sum(1 for r in results if r.status == VerifyStatus.VERIFIED)
    failed = sum(
        1 for r in results
        if r.status in (VerifyStatus.NOT_FOUND, VerifyStatus.VERSION_MISMATCH)
    )
    warnings = sum(
        1 for r in results
        if r.status in (VerifyStatus.DEPRECATED, VerifyStatus.TIMEOUT, VerifyStatus.ERROR)
    )

    lines: list[str] = [
        "## Import Verification Report",
        "",
        f"**{verified} verified** | **{failed} failed** | **{warnings} warnings** | {elapsed_ms}ms",
        "",
    ]

    _append_failed_imports(lines, results)
    _append_warning_imports(lines, results)
    _append_verified_imports(lines, results)

    return "\n".join(lines)


def _append_failed_imports(
    lines: list[str], results: list[PackageResult],
) -> None:
    """Append failed import results to the report lines."""
    failed = [r for r in results if r.status in (VerifyStatus.NOT_FOUND, VerifyStatus.VERSION_MISMATCH)]
    if not failed:
        return
    lines.append("### Failed")
    for r in failed:
        sug = f" -> {r.suggestion}" if r.suggestion else ""
        lines.append(f"- **{r.package}**: {r.message}{sug}")
    lines.append("")


def _append_warning_imports(
    lines: list[str], results: list[PackageResult],
) -> None:
    """Append warning import results to the report lines."""
    warned = [r for r in results if r.status in (VerifyStatus.DEPRECATED, VerifyStatus.TIMEOUT, VerifyStatus.ERROR)]
    if not warned:
        return
    lines.append("### Warnings")
    for r in warned:
        lines.append(f"- **{r.package}**: {r.message}")
    lines.append("")


def _append_verified_imports(
    lines: list[str], results: list[PackageResult],
) -> None:
    """Append verified import results to the report lines."""
    verified = [r for r in results if r.status == VerifyStatus.VERIFIED]
    if not verified:
        return
    lines.append("### Verified")
    for r in verified:
        cached_tag = " (cached)" if r.cached else ""
        lines.append(f"- {r.package} {r.latest_version}{cached_tag}")
    lines.append("")


@mcp.tool(name="codetrust_verify_dockerfile")
async def codetrust_verify_dockerfile(
    dockerfile_content: str,
) -> str:
    """Verify Docker base images and tags exist on Docker Hub.

    Parses FROM statements from Dockerfile content and verifies
    each image:tag combination against Docker Hub.

    Args:
        dockerfile_content: Raw Dockerfile content to parse and verify.

    Returns:
        Markdown-formatted verification report.
    """
    logger.info("mcp_verify_dockerfile")
    started = time.monotonic()
    ok = False
    images_checked = 0
    try:
        parsed = parse_dockerfile_from(dockerfile_content)
        images_checked = len(parsed)

        if not parsed:
            ok = True
            return "## Docker Image Verification\n\nNo FROM statements found in Dockerfile.\n"

        docker = await _get_docker()
        inputs = [DockerImageInput(image=img, tag=tag) for img, tag in parsed]
        results = await docker.verify_images(inputs)

        ok = True
        elapsed_ms = int((time.monotonic() - started) * 1000)
        return _format_docker_report(results, elapsed_ms)
    finally:
        duration_ms = int((time.monotonic() - started) * 1000)
        _emit_mcp_tool_invoked(
            tool="codetrust_verify_dockerfile",
            ok=ok,
            duration_ms=duration_ms,
            payload={
                "dockerfile_len": len(dockerfile_content),
                "images_checked": images_checked,
            },
        )


def _format_docker_report(
    results: list[DockerImageResult], elapsed_ms: int
) -> str:
    """Format Docker verification results as markdown."""
    verified = sum(1 for r in results if r.status == VerifyStatus.VERIFIED)
    failed = len(results) - verified

    lines: list[str] = [
        "## Docker Image Verification Report",
        "",
        f"**{verified} verified** | **{failed} failed** | {elapsed_ms}ms",
        "",
    ]

    if failed:
        lines.append("### Failed")
        for r in results:
            if r.status != VerifyStatus.VERIFIED:
                sug = f" -> {r.suggestion}" if r.suggestion else ""
                lines.append(f"- **{r.image}:{r.tag}**: {r.message}{sug}")
        lines.append("")

    if verified:
        lines.append("### Verified")
        for r in results:
            if r.status == VerifyStatus.VERIFIED:
                lines.append(f"- {r.image}:{r.tag}")
        lines.append("")

    return "\n".join(lines)


@mcp.tool(name="codetrust_ast_scan")
async def codetrust_ast_scan(
    code: str,
    filename: str = "untitled",
    language: str = "python",
    max_nesting: int = 4,
    complexity_threshold: int = 10,
) -> str:
    """Run AST-based code analysis using tree-sitter.

    Analyzes source code structure for cyclomatic complexity,
    unused variables, unreachable code, and deep nesting.

    Args:
        code: Source code to analyze.
        filename: Name of the file being scanned.
        language: Programming language (python, javascript, typescript, go, rust).
        max_nesting: Maximum allowed nesting depth (default: 4).
        complexity_threshold: Maximum allowed cyclomatic complexity (default: 10).

    Returns:
        Markdown-formatted AST analysis report.
    """
    logger.info("mcp_ast_scan", filename=filename, language=language)
    started = time.monotonic()
    ok = False
    supported = False
    findings_count = 0
    try:
        try:
            lang = Language(language)
        except ValueError:
            ok = True
            return f"Unsupported language for AST analysis: {language}"

        if lang not in AST_LANGUAGES:
            ok = True
            return f"AST analysis not available for: {language}"

        supported = True
        findings = ast_analyzer.analyze(
            code, lang, filename, max_nesting, complexity_threshold,
        )
        findings_count = len(findings)
        ok = True
        return ast_analyzer.build_report(findings)
    finally:
        duration_ms = int((time.monotonic() - started) * 1000)
        _emit_mcp_tool_invoked(
            tool="codetrust_ast_scan",
            ok=ok,
            duration_ms=duration_ms,
            payload={
                "language": language,
                "code_len": len(code),
                "ast_available": supported,
                "findings_total": findings_count,
                "max_nesting": int(max_nesting),
                "complexity_threshold": int(complexity_threshold),
            },
        )


@mcp.tool(name="codetrust_sandbox_run")
async def codetrust_sandbox_run(
    code: str,
    language: str = "python",
    timeout: int = 10,
) -> str:
    """Execute code in an isolated Docker sandbox.

    Runs code in a short-lived container with no network access,
    read-only filesystem, and strict memory/CPU limits.

    Args:
        code: Source code to execute.
        language: Programming language (python, javascript, typescript, go, rust).
        timeout: Maximum execution time in seconds (1-30).

    Returns:
        Markdown-formatted sandbox execution result.
    """
    logger.info("mcp_sandbox_run", language=language, timeout=timeout)
    started = time.monotonic()
    ok = False
    supported = False
    success: bool | None = None
    timed_out: bool | None = None
    exit_code: int | None = None

    try:
        try:
            lang = Language(language)
        except ValueError:
            ok = True
            return f"Unsupported language for sandbox: {language}"

        supported = True
        result = await sandbox.execute_code(code, lang, timeout)
        success = bool(result.success)
        timed_out = bool(result.timed_out)
        exit_code = int(result.exit_code)

        ok = True
        return _format_sandbox_report(result)
    finally:
        duration_ms = int((time.monotonic() - started) * 1000)
        _emit_mcp_tool_invoked(
            tool="codetrust_sandbox_run",
            ok=ok,
            duration_ms=duration_ms,
            payload={
                "language": language,
                "code_len": len(code),
                "sandbox_available": supported,
                "timeout_seconds": int(timeout),
                "success": success if success is not None else False,
                "timed_out": timed_out if timed_out is not None else False,
                "exit_code": exit_code if exit_code is not None else -1,
            },
        )


def _format_sandbox_report(result: SandboxResponse) -> str:
    """Format a SandboxResponse as markdown."""
    lines: list[str] = ["## Sandbox Execution Report", ""]

    if result.error:
        lines.append(f"**Error:** {result.error}")
        return "\n".join(lines)

    status = "TIMEOUT" if result.timed_out else (
        "PASS" if result.exit_code == 0 else "FAIL"
    )
    lines.append(f"**Status: {status}** | Exit code: {result.exit_code}")
    lines.append(f"Latency: {result.latency_ms}ms")
    lines.append("")

    if result.stdout:
        lines.extend(["### stdout", "```", result.stdout.rstrip(), "```", ""])

    if result.stderr:
        lines.extend(["### stderr", "```", result.stderr.rstrip(), "```", ""])

    return "\n".join(lines)


@mcp.tool(name="codetrust_sarif_export")
async def codetrust_sarif_export(
    code: str,
    filename: str = "untitled",
    language: str = "python",
) -> str:
    """Run static analysis and export results as SARIF JSON.

    SARIF (Static Analysis Results Interchange Format) output is
    compatible with GitHub Security tab and other SARIF tools.

    Args:
        code: Source code to analyze.
        filename: Name of the file being scanned.
        language: Programming language.

    Returns:
        SARIF JSON string.
    """
    logger.info("mcp_sarif_export", filename=filename)
    started = time.monotonic()
    ok = False
    total_findings = 0
    used_ast = False
    try:
        findings = analyzer.scan_code(code, filename)

        try:
            lang = Language(language)
        except ValueError:
            lang = None

        if lang is not None and lang in AST_LANGUAGES:
            used_ast = True
            ast_findings = ast_analyzer.analyze(code, lang, filename)
            findings.extend(ast_findings)

        total_findings = len(findings)
        sarif = findings_to_sarif(findings)
        ok = True
        return json.dumps(sarif, indent=2)
    finally:
        duration_ms = int((time.monotonic() - started) * 1000)
        _emit_mcp_tool_invoked(
            tool="codetrust_sarif_export",
            ok=ok,
            duration_ms=duration_ms,
            payload={
                "language": language,
                "code_len": len(code),
                "used_ast": used_ast,
                "findings_total": total_findings,
            },
        )


@mcp.tool(name="codetrust_deep_scan")
async def codetrust_deep_scan(
    code: str,
    filename: str = "untitled",
    language: str = "python",
    verify_imports: bool = True,
    verify_docker: bool = False,
    sandbox_run: bool = False,
    dockerfile_content: str = "",
    requirements_content: str = "",
) -> str:
    """Run all validation layers and return a Markdown report with verdict."""
    logger.info("mcp_deep_scan", filename=filename, language=language)
    started = time.monotonic()
    ok = False
    static_count = 0
    ast_count = 0
    try:
        findings = analyzer.scan_code(code, filename)
        static_count = len(findings)
        ast_findings = _deep_scan_ast_findings(code, language, filename)
        ast_count = len(ast_findings) if ast_findings is not None else 0

        sections = await _build_deep_scan_sections(
            findings, ast_findings, code, language,
            requirements_content, verify_imports,
            dockerfile_content, verify_docker,
            sandbox_run, started,
        )
        ok = True
        return "\n".join(sections)
    finally:
        duration_ms = int((time.monotonic() - started) * 1000)
        _emit_mcp_tool_invoked(
            tool="codetrust_deep_scan",
            ok=ok,
            duration_ms=duration_ms,
            payload={
                "language": language,
                "code_len": len(code),
                "verify_imports": bool(verify_imports),
                "verify_docker": bool(verify_docker),
                "sandbox_run": bool(sandbox_run),
                "static_findings": static_count,
                "ast_findings": ast_count,
            },
        )


async def _build_deep_scan_sections(
    findings: list[Finding],
    ast_findings: list[Finding] | None,
    code: str,
    language: str,
    requirements_content: str,
    verify_imports: bool,
    dockerfile_content: str,
    verify_docker: bool,
    sandbox_run: bool,
    start: float,
) -> list[str]:
    """Build all report sections for the deep scan."""
    sections: list[str] = ["# CodeTrust Deep Scan Report", ""]

    static_report = analyzer.build_report(findings, title="Static Analysis")
    sections.extend([static_report, ""])

    if ast_findings is not None:
        sections.extend([ast_analyzer.build_report(ast_findings), ""])

    import_report = await _deep_scan_imports(
        code, language, requirements_content, verify_imports,
    )
    if import_report:
        sections.extend([import_report, ""])

    docker_report = await _deep_scan_docker(dockerfile_content, verify_docker)
    if docker_report:
        sections.extend([docker_report, ""])

    sandbox_report = await _deep_scan_sandbox(code, language, sandbox_run)
    if sandbox_report:
        sections.extend([sandbox_report, ""])

    sections.append(_deep_scan_verdict_line(
        findings, ast_findings, import_report,
        docker_report, sandbox_report, start,
    ))
    return sections


def _deep_scan_verdict_line(
    findings: list[Finding],
    ast_findings: list[Finding] | None,
    import_report: str,
    docker_report: str,
    sandbox_report: str,
    start: float,
) -> str:
    """Compute final verdict and format the summary line."""
    elapsed_ms = int((time.monotonic() - start) * 1000)
    all_findings = findings + (ast_findings or [])
    verdict = _compute_deep_verdict(
        all_findings, import_report, docker_report, sandbox_report,
    )
    return f"## Overall Verdict: **{verdict}** ({elapsed_ms}ms)"


async def _deep_scan_sandbox(
    code: str, language: str, sandbox_run: bool,
) -> str:
    """Run sandbox execution as part of deep scan."""
    if not sandbox_run:
        return ""
    result = await sandbox.execute_code(code, Language(language))
    return _format_sandbox_report(result)


def _deep_scan_ast_findings(
    code: str,
    language: str,
    filename: str,
) -> list[Finding] | None:
    """Run AST analysis as part of deep scan, returns None if unsupported."""
    try:
        lang = Language(language)
    except ValueError:
        return None

    if lang not in AST_LANGUAGES:
        return None

    return ast_analyzer.analyze(code, lang, filename)


async def _deep_scan_imports(
    code: str,
    language: str,
    requirements_content: str,
    verify_imports: bool,
) -> str:
    """Run import verification as part of deep scan."""
    if not verify_imports:
        return ""

    lang = Language(language)
    imports = _extract_imports(code, lang)

    if not imports:
        return "## Import Verification\n\nNo third-party imports found."

    registry = await _get_registry()
    results = await registry.verify_packages(lang, imports, requirements_content)
    elapsed_ms = 0  # timing is rolled into the parent
    return _format_import_report(results, elapsed_ms)


async def _deep_scan_docker(
    dockerfile_content: str,
    verify_docker: bool,
) -> str:
    """Run Docker verification as part of deep scan."""
    if not verify_docker or not dockerfile_content:
        return ""

    parsed = parse_dockerfile_from(dockerfile_content)
    if not parsed:
        return "## Docker Image Verification\n\nNo FROM statements found."

    docker = await _get_docker()
    inputs = [DockerImageInput(image=img, tag=tag) for img, tag in parsed]
    results = await docker.verify_images(inputs)
    return _format_docker_report(results, 0)


def _compute_deep_verdict(
    findings: list[Finding],
    import_report: str,
    docker_report: str,
    sandbox_report: str = "",
) -> str:
    """Compute the overall deep scan verdict."""
    has_block = any(f.severity == Severity.BLOCK for f in findings)
    has_warn = any(f.severity == Severity.WARN for f in findings)

    if has_block:
        return "BLOCK"

    # Check import failures
    if import_report and "### Failed" in import_report:
        return "BLOCK"

    # Check docker failures
    if docker_report and "### Failed" in docker_report:
        return "BLOCK"

    # Check sandbox failures
    if sandbox_report and "**Status: FAIL**" in sandbox_report:
        return "BLOCK"
    if sandbox_report and "**Status: TIMEOUT**" in sandbox_report:
        return "BLOCK"
    if sandbox_report and "**Error:**" in sandbox_report:
        return "WARN"

    if has_warn:
        return "WARN"

    if import_report and "### Warnings" in import_report:
        return "WARN"

    return "PASS"


if __name__ == "__main__":
    mcp.run()
