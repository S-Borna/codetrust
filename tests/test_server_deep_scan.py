from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import pytest

import src.server as server
from src.models.enums import Language, Registry, Severity, VerifyStatus
from src.models.responses import DockerImageResult, Finding, PackageResult, SandboxResponse

if TYPE_CHECKING:
    from src.models.requests import DockerImageInput


@dataclass(frozen=True)
class _FakeRegistry:
    results: list[PackageResult]

    async def verify_packages(
        self,
        language: Language,
        imports: list[str],
        requirements: str,
    ) -> list[PackageResult]:
        _ = (language, imports, requirements)
        return self.results


@dataclass(frozen=True)
class _FakeDocker:
    results: list[DockerImageResult]

    async def verify_images(self, inputs: list[DockerImageInput]) -> list[DockerImageResult]:
        _ = inputs
        return self.results


@pytest.mark.parametrize(
    ("task", "stack", "confirmed_stack", "files", "confirmed_structure", "expected_rule"),
    [
        ("too short", None, False, None, False, "vague_task"),
        ("a" * 30, "python", False, None, False, "unconfirmed_stack"),
        ("a" * 30, None, False, [f"f{i}.py" for i in range(11)], False, "large_scope"),
    ],
)
def test_validate_plan_emits_expected_warnings(
    task: str,
    stack: str | None,
    confirmed_stack: bool,
    files: list[str] | None,
    confirmed_structure: bool,
    expected_rule: str,
) -> None:
    findings = server._validate_plan(
        task,
        stack,
        files,
        confirmed_stack,
        confirmed_structure,
    )
    assert any(f.rule_id == expected_rule for f in findings)


def test_scan_file_returns_file_read_error_for_missing_path(tmp_path) -> None:
    missing = tmp_path / "does-not-exist.txt"
    findings = server._scan_file(str(missing), "does-not-exist.txt")
    assert len(findings) == 1
    assert findings[0].rule_id == "file_read_error"
    assert findings[0].severity == Severity.WARN


def test_format_sandbox_report_covers_error_and_success() -> None:
    err = SandboxResponse(exit_code=1, error="docker unavailable")
    out = server._format_sandbox_report(err)
    assert "**Error:** docker unavailable" in out

    ok = SandboxResponse(
        exit_code=0,
        stdout="hello\n",
        stderr="warn\n",
        timed_out=False,
        latency_ms=12,
    )
    out2 = server._format_sandbox_report(ok)
    assert "**Status: PASS**" in out2
    assert "### stdout" in out2
    assert "hello" in out2
    assert "### stderr" in out2

    to = SandboxResponse(exit_code=137, timed_out=True, latency_ms=5)
    out3 = server._format_sandbox_report(to)
    assert "**Status: TIMEOUT**" in out3


def test_compute_deep_verdict_detects_failures() -> None:
    findings_warn = [Finding(rule_id="x", severity=Severity.WARN, message="m")]

    assert (
        server._compute_deep_verdict(
            findings_warn,
            import_report="## Import Verification Report\n\n### Failed\n- x",
            docker_report="",
            sandbox_report="",
        )
        == "BLOCK"
    )

    assert (
        server._compute_deep_verdict(
            findings_warn,
            import_report="",
            docker_report="## Docker Image Verification Report\n\n### Failed\n- x",
            sandbox_report="",
        )
        == "BLOCK"
    )

    assert (
        server._compute_deep_verdict(
            findings_warn,
            import_report="",
            docker_report="",
            sandbox_report="## Sandbox Execution Report\n\n**Status: FAIL** | Exit code: 1",
        )
        == "BLOCK"
    )

    assert (
        server._compute_deep_verdict(
            findings_warn,
            import_report="",
            docker_report="",
            sandbox_report="## Sandbox Execution Report\n\n**Error:** x",
        )
        == "WARN"
    )

    assert (
        server._compute_deep_verdict(
            [Finding(rule_id="x", severity=Severity.INFO, message="m")],
            import_report="## Import Verification Report\n\n### Warnings\n- x",
            docker_report="",
            sandbox_report="",
        )
        == "WARN"
    )


@pytest.mark.asyncio()
async def test_codetrust_deep_scan_includes_import_docker_and_sandbox_sections(monkeypatch) -> None:
    async def fake_get_registry() -> _FakeRegistry:
        return _FakeRegistry(
            results=[
                PackageResult(
                    package="requests",
                    registry=Registry.PYPI,
                    status=VerifyStatus.VERIFIED,
                    severity=Severity.INFO,
                    latest_version="99.0.0",
                    cached=True,
                ),
                PackageResult(
                    package="definitely-not-a-real-package-xyz",
                    registry=Registry.PYPI,
                    status=VerifyStatus.NOT_FOUND,
                    severity=Severity.BLOCK,
                    message="not found",
                    suggestion="remove",
                ),
            ]
        )

    async def fake_get_docker() -> _FakeDocker:
        return _FakeDocker(
            results=[
                DockerImageResult(
                    image="python",
                    tag="3.12",
                    status=VerifyStatus.VERIFIED,
                    severity=Severity.INFO,
                    message="ok",
                ),
                DockerImageResult(
                    image="definitely-not-real-image",
                    tag="0",
                    status=VerifyStatus.NOT_FOUND,
                    severity=Severity.BLOCK,
                    message="not found",
                ),
            ]
        )

    async def fake_execute_code(code: str, language: Language, timeout: int = 10) -> SandboxResponse:
        _ = (code, language, timeout)
        return SandboxResponse(
            exit_code=0,
            stdout="hello",
            stderr="",
            timed_out=False,
            latency_ms=1,
        )

    monkeypatch.setattr(server, "_get_registry", fake_get_registry)
    monkeypatch.setattr(server, "_get_docker", fake_get_docker)
    monkeypatch.setattr(server.sandbox, "execute_code", fake_execute_code)

    report = await server.codetrust_deep_scan(
        "import requests\nprint('hi')\n",
        filename="x.py",
        language="python",
        verify_imports=True,
        verify_docker=True,
        sandbox_run=True,
        dockerfile_content="FROM python:3.12\n",
        requirements_content="requests==2.0.0\n",
    )

    assert "# CodeTrust Deep Scan Report" in report
    assert "## Import Verification Report" in report
    assert "## Docker Image Verification Report" in report
    assert "## Sandbox Execution Report" in report
    assert "## Overall Verdict:" in report
