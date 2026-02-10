"""MCP server entry point — CodeTrust Layer 1 + Layer 2 + Deep Scan tools."""

import os
import time

import httpx
import structlog
from mcp.server.fastmcp import FastMCP

from src.config import settings
from src.models.enums import Language, Severity, VerifyStatus
from src.models.requests import DockerImageInput
from src.models.responses import DockerImageResult, Finding, PackageResult
from src.rules.anti_patterns import ANTI_PATTERNS
from src.services.cache import CacheService
from src.services.docker_verify import DockerVerifyService
from src.services.registry import RegistryService
from src.services.static_analyzer import StaticAnalyzer
from src.utils.parsers import (
    extract_go_imports,
    extract_js_imports,
    extract_python_imports,
    extract_rust_imports,
    parse_dockerfile_from,
)

logger = structlog.get_logger()

mcp = FastMCP("codetrust")
analyzer = StaticAnalyzer()

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
    findings = analyzer.scan_code(code, filename)
    return analyzer.build_report(findings, title="Static Analysis Report")


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
    findings = _validate_plan(
        task_description,
        proposed_stack,
        proposed_files,
        has_user_specified_stack,
        has_user_specified_structure,
    )
    return analyzer.build_report(findings, title="Pre-Action Validation")


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

    all_findings = analyzer.check_repo_structure(repo_root)

    if files_changed:
        for filepath in files_changed:
            full_path = os.path.join(repo_root, filepath)
            if os.path.isfile(full_path):
                all_findings.extend(
                    _scan_file(full_path, filepath)
                )

    return analyzer.build_report(all_findings, title="Post-Action Validation")


@mcp.tool(name="codetrust_list_rules")
async def codetrust_list_rules() -> str:
    """List all anti-pattern rules, structure requirements, and their severities.

    Returns:
        Complete rule catalog in markdown format.
    """
    logger.info("mcp_list_rules")
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

    return "\n".join(lines)


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
    start = time.monotonic()

    lang = Language(language)
    imports = _extract_imports(code, lang)

    if not imports:
        return "## Import Verification\n\nNo third-party imports found.\n"

    registry = await _get_registry()
    results = await registry.verify_packages(lang, imports, requirements)

    elapsed_ms = int((time.monotonic() - start) * 1000)
    return _format_import_report(results, elapsed_ms)


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

    if failed:
        lines.append("### Failed")
        for r in results:
            if r.status in (VerifyStatus.NOT_FOUND, VerifyStatus.VERSION_MISMATCH):
                sug = f" -> {r.suggestion}" if r.suggestion else ""
                lines.append(f"- **{r.package}**: {r.message}{sug}")
        lines.append("")

    if warnings:
        lines.append("### Warnings")
        for r in results:
            if r.status in (VerifyStatus.DEPRECATED, VerifyStatus.TIMEOUT, VerifyStatus.ERROR):
                lines.append(f"- **{r.package}**: {r.message}")
        lines.append("")

    if verified:
        lines.append("### Verified")
        for r in results:
            if r.status == VerifyStatus.VERIFIED:
                cached_tag = " (cached)" if r.cached else ""
                lines.append(f"- {r.package} {r.latest_version}{cached_tag}")
        lines.append("")

    return "\n".join(lines)


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
    start = time.monotonic()

    parsed = parse_dockerfile_from(dockerfile_content)

    if not parsed:
        return "## Docker Image Verification\n\nNo FROM statements found in Dockerfile.\n"

    docker = await _get_docker()
    inputs = [DockerImageInput(image=img, tag=tag) for img, tag in parsed]
    results = await docker.verify_images(inputs)

    elapsed_ms = int((time.monotonic() - start) * 1000)
    return _format_docker_report(results, elapsed_ms)


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


@mcp.tool(name="codetrust_deep_scan")
async def codetrust_deep_scan(
    code: str,
    filename: str = "untitled",
    language: str = "python",
    verify_imports: bool = True,
    verify_docker: bool = False,
    dockerfile_content: str = "",
    requirements_content: str = "",
) -> str:
    """Run all validation layers in a single pass.

    Combines static analysis with import and Docker verification
    for a comprehensive code quality report.

    Args:
        code: Source code to analyze.
        filename: Name of the file being scanned.
        language: Programming language (python, javascript, typescript).
        verify_imports: Whether to verify imports against registries.
        verify_docker: Whether to verify Docker images.
        dockerfile_content: Raw Dockerfile content (required if verify_docker).
        requirements_content: Raw requirements.txt for version pinning.

    Returns:
        Markdown-formatted combined report with overall verdict.
    """
    logger.info("mcp_deep_scan", filename=filename, language=language)
    start = time.monotonic()

    sections: list[str] = ["# CodeTrust Deep Scan Report", ""]

    # Layer 1: Static analysis (always runs locally)
    findings = analyzer.scan_code(code, filename)
    static_report = analyzer.build_report(findings, title="Static Analysis")
    sections.append(static_report)
    sections.append("")

    # Layer 2a: Import verification
    import_report = await _deep_scan_imports(
        code, language, requirements_content, verify_imports
    )
    if import_report:
        sections.append(import_report)
        sections.append("")

    # Layer 2b: Docker verification
    docker_report = await _deep_scan_docker(dockerfile_content, verify_docker)
    if docker_report:
        sections.append(docker_report)
        sections.append("")

    # Overall verdict
    elapsed_ms = int((time.monotonic() - start) * 1000)
    verdict = _compute_deep_verdict(findings, import_report, docker_report)
    sections.append(f"## Overall Verdict: **{verdict}** ({elapsed_ms}ms)")

    return "\n".join(sections)


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

    if has_warn:
        return "WARN"

    if import_report and "### Warnings" in import_report:
        return "WARN"

    return "PASS"


if __name__ == "__main__":
    mcp.run()
