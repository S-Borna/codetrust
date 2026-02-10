"""Tests for codetrust_deep_scan MCP tool and deep scan orchestration."""

from unittest.mock import AsyncMock, patch

from src.models.enums import Registry, Severity, VerifyStatus
from src.models.responses import DockerImageResult, Finding, PackageResult
from src.server import (
    _compute_deep_verdict,
    _deep_scan_docker,
    _deep_scan_imports,
    codetrust_deep_scan,
)


class TestDeepScanMCPTool:
    """Tests for the codetrust_deep_scan MCP tool."""

    async def test_deep_scan_clean_code_returns_pass(self) -> None:
        """Clean code with no imports returns PASS."""
        result = await codetrust_deep_scan(
            code="x = 1\ny = 2\n",
            filename="clean.py",
            language="python",
            verify_imports=False,
            verify_docker=False,
        )

        assert "# CodeTrust Deep Scan Report" in result
        assert "PASS" in result

    async def test_deep_scan_eval_returns_block(self) -> None:
        """Code with eval returns BLOCK verdict."""
        result = await codetrust_deep_scan(
            code="result = eval('2+2')\n",
            filename="bad.py",
            language="python",
            verify_imports=False,
            verify_docker=False,
        )

        assert "BLOCK" in result

    async def test_deep_scan_warning_code_returns_warn(self) -> None:
        """Code with warnings returns WARN verdict."""
        result = await codetrust_deep_scan(
            code="from os import *\n",
            filename="warn.py",
            language="python",
            verify_imports=False,
            verify_docker=False,
        )

        assert "WARN" in result

    async def test_deep_scan_static_section_present(self) -> None:
        """Deep scan always includes static analysis section."""
        result = await codetrust_deep_scan(
            code="x = 1\n",
            filename="test.py",
            verify_imports=False,
            verify_docker=False,
        )

        assert "Static Analysis" in result

    async def test_deep_scan_no_imports_skips_verification(self) -> None:
        """When verify_imports=False, import section is omitted."""
        result = await codetrust_deep_scan(
            code="x = 1\n",
            filename="test.py",
            verify_imports=False,
        )

        assert "Import Verification" not in result

    async def test_deep_scan_no_docker_skips_verification(self) -> None:
        """When verify_docker=False, docker section is omitted."""
        result = await codetrust_deep_scan(
            code="x = 1\n",
            filename="test.py",
            verify_docker=False,
        )

        assert "Docker Image Verification" not in result

    @patch("src.server._get_registry")
    async def test_deep_scan_with_imports(
        self, mock_get_registry: AsyncMock
    ) -> None:
        """Deep scan with import verification included."""
        mock_registry = AsyncMock()
        mock_registry.verify_packages.return_value = [
            PackageResult(
                package="fastapi",
                registry=Registry.PYPI,
                status=VerifyStatus.VERIFIED,
                severity=Severity.INFO,
                latest_version="0.115.0",
                message="Package exists on PyPI",
            ),
        ]
        mock_get_registry.return_value = mock_registry

        result = await codetrust_deep_scan(
            code="import fastapi\n",
            filename="app.py",
            language="python",
            verify_imports=True,
            verify_docker=False,
        )

        assert "Import Verification" in result
        assert "fastapi" in result
        mock_registry.verify_packages.assert_called_once()

    @patch("src.server._get_registry")
    async def test_deep_scan_failed_import_returns_block(
        self, mock_get_registry: AsyncMock
    ) -> None:
        """Deep scan with failed import returns BLOCK."""
        mock_registry = AsyncMock()
        mock_registry.verify_packages.return_value = [
            PackageResult(
                package="nonexistent_xyz",
                registry=Registry.PYPI,
                status=VerifyStatus.NOT_FOUND,
                severity=Severity.BLOCK,
                message="Package not found on PyPI",
            ),
        ]
        mock_get_registry.return_value = mock_registry

        result = await codetrust_deep_scan(
            code="import nonexistent_xyz\n",
            filename="app.py",
            language="python",
            verify_imports=True,
            verify_docker=False,
        )

        assert "BLOCK" in result

    @patch("src.server._get_docker")
    async def test_deep_scan_with_docker(
        self, mock_get_docker: AsyncMock
    ) -> None:
        """Deep scan with Docker verification included."""
        mock_docker = AsyncMock()
        mock_docker.verify_images.return_value = [
            DockerImageResult(
                image="python",
                tag="3.12-slim",
                status=VerifyStatus.VERIFIED,
                severity=Severity.INFO,
                message="Image tag verified",
            ),
        ]
        mock_get_docker.return_value = mock_docker

        result = await codetrust_deep_scan(
            code="x = 1\n",
            filename="app.py",
            language="python",
            verify_imports=False,
            verify_docker=True,
            dockerfile_content="FROM python:3.12-slim\n",
        )

        assert "Docker Image Verification" in result
        assert "python" in result
        mock_docker.verify_images.assert_called_once()

    @patch("src.server._get_docker")
    async def test_deep_scan_failed_docker_returns_block(
        self, mock_get_docker: AsyncMock
    ) -> None:
        """Deep scan with failed Docker image returns BLOCK."""
        mock_docker = AsyncMock()
        mock_docker.verify_images.return_value = [
            DockerImageResult(
                image="python",
                tag="99.99",
                status=VerifyStatus.NOT_FOUND,
                severity=Severity.BLOCK,
                message="Tag not found",
            ),
        ]
        mock_get_docker.return_value = mock_docker

        result = await codetrust_deep_scan(
            code="x = 1\n",
            filename="app.py",
            verify_docker=True,
            dockerfile_content="FROM python:99.99\n",
        )

        assert "BLOCK" in result

    async def test_deep_scan_empty_dockerfile_skips_docker(self) -> None:
        """Empty dockerfile_content with verify_docker=True still skips."""
        result = await codetrust_deep_scan(
            code="x = 1\n",
            verify_docker=True,
            dockerfile_content="",
        )

        assert "Docker Image Verification" not in result

    @patch("src.server._get_registry")
    async def test_deep_scan_no_imports_found(
        self, mock_get_registry: AsyncMock
    ) -> None:
        """Code with no third-party imports shows appropriate message."""
        result = await codetrust_deep_scan(
            code="x = 1\ny = 2\n",
            filename="test.py",
            language="python",
            verify_imports=True,
        )

        assert "No third-party imports" in result
        mock_get_registry.assert_not_called()

    async def test_deep_scan_includes_latency(self) -> None:
        """Deep scan report includes latency in ms."""
        result = await codetrust_deep_scan(
            code="x = 1\n",
            verify_imports=False,
            verify_docker=False,
        )

        assert "ms)" in result


class TestComputeDeepVerdict:
    """Tests for the _compute_deep_verdict helper."""

    def test_block_finding_returns_block(self) -> None:
        """BLOCK finding in static analysis returns BLOCK."""
        findings = [
            Finding(
                rule_id="eval_exec",
                severity=Severity.BLOCK,
                message="eval is bad",
            )
        ]
        assert _compute_deep_verdict(findings, "", "") == "BLOCK"

    def test_warn_finding_returns_warn(self) -> None:
        """WARN finding returns WARN."""
        findings = [
            Finding(
                rule_id="todo",
                severity=Severity.WARN,
                message="todo marker",
            )
        ]
        assert _compute_deep_verdict(findings, "", "") == "WARN"

    def test_clean_returns_pass(self) -> None:
        """No findings returns PASS."""
        assert _compute_deep_verdict([], "", "") == "PASS"

    def test_import_failure_returns_block(self) -> None:
        """Failed imports cause BLOCK verdict."""
        import_report = "## Import Verification\n### Failed\n- pkg not found"
        assert _compute_deep_verdict([], import_report, "") == "BLOCK"

    def test_docker_failure_returns_block(self) -> None:
        """Failed Docker images cause BLOCK verdict."""
        docker_report = "## Docker Verification\n### Failed\n- image:tag missing"
        assert _compute_deep_verdict([], "", docker_report) == "BLOCK"

    def test_import_warnings_returns_warn(self) -> None:
        """Import warnings cause WARN verdict."""
        import_report = "## Import Verification\n### Warnings\n- timeout"
        assert _compute_deep_verdict([], import_report, "") == "WARN"

    def test_block_takes_precedence_over_warn(self) -> None:
        """BLOCK severity overrides WARN."""
        findings = [
            Finding(rule_id="eval", severity=Severity.BLOCK, message="bad"),
            Finding(rule_id="todo", severity=Severity.WARN, message="todo"),
        ]
        assert _compute_deep_verdict(findings, "", "") == "BLOCK"

    def test_info_only_returns_pass(self) -> None:
        """INFO-only findings still return PASS."""
        findings = [
            Finding(rule_id="magic", severity=Severity.INFO, message="magic number"),
        ]
        assert _compute_deep_verdict(findings, "", "") == "PASS"


class TestDeepScanImports:
    """Tests for _deep_scan_imports helper."""

    async def test_disabled_returns_empty(self) -> None:
        """verify_imports=False returns empty string."""
        result = await _deep_scan_imports("x = 1", "python", "", False)
        assert result == ""

    async def test_no_imports_returns_message(self) -> None:
        """Code without imports returns helpful message."""
        result = await _deep_scan_imports("x = 1\n", "python", "", True)
        assert "No third-party imports" in result


class TestDeepScanDocker:
    """Tests for _deep_scan_docker helper."""

    async def test_disabled_returns_empty(self) -> None:
        """verify_docker=False returns empty string."""
        result = await _deep_scan_docker("FROM python:3.12\n", False)
        assert result == ""

    async def test_empty_content_returns_empty(self) -> None:
        """Empty dockerfile content returns empty string."""
        result = await _deep_scan_docker("", True)
        assert result == ""

    async def test_no_from_returns_message(self) -> None:
        """Dockerfile without FROM returns message."""
        result = await _deep_scan_docker("RUN echo hello\n", True)
        assert "No FROM statements" in result
