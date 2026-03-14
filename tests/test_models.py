"""Tests for Pydantic models (enums, requests, responses)."""

import pytest
from pydantic import ValidationError

from src.models.enums import Language, Registry, Severity, VerifyStatus
from src.models.requests import (
    DeepScanRequest,
    DockerImageInput,
    FullScanInput,
    MidActionInput,
    PostActionInput,
    PreActionInput,
    StaticScanRequest,
    VerifyApiCallsRequest,
    VerifyImportsRequest,
)
from src.models.responses import (
    DockerImageResult,
    Finding,
    HealthResponse,
    PackageResult,
    StaticScanResponse,
)

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TestEnums:
    """Tests for enum values and behavior."""

    def test_severity_values(self) -> None:
        assert Severity.BLOCK == "BLOCK"
        assert Severity.WARN == "WARN"
        assert Severity.INFO == "INFO"

    def test_verify_status_values(self) -> None:
        assert VerifyStatus.VERIFIED == "VERIFIED"
        assert VerifyStatus.NOT_FOUND == "NOT_FOUND"
        assert VerifyStatus.DEPRECATED == "DEPRECATED"

    def test_language_values(self) -> None:
        assert Language.PYTHON == "python"
        assert Language.JAVASCRIPT == "javascript"
        assert Language.TYPESCRIPT == "typescript"
        assert Language.GO == "go"
        assert Language.RUST == "rust"
        assert Language.JSON == "json"

    def test_registry_values(self) -> None:
        assert Registry.PYPI == "pypi"
        assert Registry.NPM == "npm"
        assert Registry.DOCKER_HUB == "docker_hub"


# ---------------------------------------------------------------------------
# Response models — Finding
# ---------------------------------------------------------------------------


class TestFinding:
    """Tests for Finding model."""

    def test_valid_finding(self) -> None:
        finding = Finding(
            rule_id="test_rule",
            severity=Severity.BLOCK,
            message="Test message",
        )
        assert finding.rule_id == "test_rule"
        assert finding.severity == Severity.BLOCK
        assert finding.file == ""
        assert finding.line == 0
        assert finding.confidence == 1.0

    def test_finding_with_all_fields(self) -> None:
        finding = Finding(
            rule_id="test_rule",
            severity=Severity.WARN,
            message="Test message",
            file="app.py",
            line=42,
            suggestion="Fix it",
            confidence=0.8,
        )
        assert finding.file == "app.py"
        assert finding.line == 42
        assert finding.suggestion == "Fix it"
        assert finding.confidence == 0.8

    def test_finding_invalid_confidence(self) -> None:
        with pytest.raises(ValidationError):
            Finding(
                rule_id="test_rule",
                severity=Severity.BLOCK,
                message="Test",
                confidence=1.5,  # Out of range [0, 1]
            )

    def test_finding_missing_required_field(self) -> None:
        with pytest.raises(ValidationError):
            Finding(
                severity=Severity.BLOCK,
                message="Test",
                # Missing rule_id
            )


# ---------------------------------------------------------------------------
# Response models — PackageResult
# ---------------------------------------------------------------------------


class TestPackageResult:
    """Tests for PackageResult model."""

    def test_valid_package_result(self) -> None:
        result = PackageResult(
            package="fastapi",
            registry=Registry.PYPI,
            status=VerifyStatus.VERIFIED,
            severity=Severity.INFO,
        )
        assert result.package == "fastapi"
        assert result.cached is False

    def test_package_result_with_version(self) -> None:
        result = PackageResult(
            package="flask",
            registry=Registry.PYPI,
            status=VerifyStatus.VERSION_MISMATCH,
            severity=Severity.WARN,
            requested_version="99.0.0",
            latest_version="3.0.0",
            message="Version 99.0.0 not found",
            suggestion="Use version 3.0.0",
        )
        assert result.requested_version == "99.0.0"
        assert result.latest_version == "3.0.0"


# ---------------------------------------------------------------------------
# Response models — DockerImageResult
# ---------------------------------------------------------------------------


class TestDockerImageResult:
    """Tests for DockerImageResult model."""

    def test_valid_docker_result(self) -> None:
        result = DockerImageResult(
            image="python",
            tag="3.12-slim",
            status=VerifyStatus.VERIFIED,
            severity=Severity.INFO,
        )
        assert result.image == "python"
        assert result.available_tags == []


# ---------------------------------------------------------------------------
# Response models — StaticScanResponse
# ---------------------------------------------------------------------------


class TestStaticScanResponse:
    """Tests for StaticScanResponse model."""

    def test_valid_scan_response(self) -> None:
        response = StaticScanResponse(
            total_findings=2,
            blocks=1,
            warnings=1,
            infos=0,
            findings=[
                Finding(rule_id="r1", severity=Severity.BLOCK, message="m1"),
                Finding(rule_id="r2", severity=Severity.WARN, message="m2"),
            ],
            verdict="BLOCK",
        )
        assert response.total_findings == 2
        assert response.verdict == "BLOCK"


# ---------------------------------------------------------------------------
# Response models — HealthResponse
# ---------------------------------------------------------------------------


class TestHealthResponse:
    """Tests for HealthResponse model."""

    def test_valid_health_response(self) -> None:
        response = HealthResponse(version="1.0.0", cache_connected=True)
        assert response.status == "ok"
        assert response.version == "1.0.0"


# ---------------------------------------------------------------------------
# Request models — StaticScanRequest
# ---------------------------------------------------------------------------


class TestStaticScanRequest:
    """Tests for StaticScanRequest model."""

    def test_valid_request(self) -> None:
        req = StaticScanRequest(code="print('hello')")
        assert req.code == "print('hello')"
        assert req.filename == "untitled"

    def test_empty_code_accepted(self) -> None:
        req = StaticScanRequest(code="")
        assert req.code == ""

    def test_code_with_language(self) -> None:
        req = StaticScanRequest(
            code="print('hello')",
            filename="app.py",
            language=Language.PYTHON,
        )
        assert req.language == Language.PYTHON


# ---------------------------------------------------------------------------
# Request models — VerifyImportsRequest
# ---------------------------------------------------------------------------


class TestVerifyImportsRequest:
    """Tests for VerifyImportsRequest model."""

    def test_valid_request(self) -> None:
        req = VerifyImportsRequest(
            language=Language.PYTHON,
            imports=["fastapi", "flask"],
        )
        assert req.language == Language.PYTHON
        assert len(req.imports) == 2

    def test_empty_imports_rejected(self) -> None:
        with pytest.raises(ValidationError):
            VerifyImportsRequest(
                language=Language.PYTHON,
                imports=[],
            )


# ---------------------------------------------------------------------------
# Request models — DockerImageInput
# ---------------------------------------------------------------------------


class TestDockerImageInput:
    """Tests for DockerImageInput model."""

    def test_valid_input(self) -> None:
        inp = DockerImageInput(image="python")
        assert inp.image == "python"
        assert inp.tag == "latest"

    def test_custom_tag(self) -> None:
        inp = DockerImageInput(image="node", tag="20-alpine")
        assert inp.tag == "20-alpine"


# ---------------------------------------------------------------------------
# Request models — PreActionInput
# ---------------------------------------------------------------------------


class TestPreActionInput:
    """Tests for PreActionInput model."""

    def test_valid_input(self) -> None:
        inp = PreActionInput(task_description="Build a REST API for user management")
        assert inp.task_description == "Build a REST API for user management"
        assert inp.has_user_specified_stack is False

    def test_short_description_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PreActionInput(task_description="hi")

    def test_extra_fields_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PreActionInput(
                task_description="Build a REST API for user management",
                unknown_field="value",
            )


# ---------------------------------------------------------------------------
# Request models — MidActionInput
# ---------------------------------------------------------------------------


class TestMidActionInput:
    """Tests for MidActionInput model."""

    def test_valid_input(self) -> None:
        inp = MidActionInput(code="def hello(): pass")
        assert inp.verify_imports is False

    def test_empty_code_accepted(self) -> None:
        inp = MidActionInput(code="")
        assert inp.code == ""


# ---------------------------------------------------------------------------
# Request models — PostActionInput
# ---------------------------------------------------------------------------


class TestPostActionInput:
    """Tests for PostActionInput model."""

    def test_valid_input(self) -> None:
        inp = PostActionInput(
            repo_root="/tmp/project",
            task_description="Implement user authentication",
        )
        assert inp.repo_root == "/tmp/project"
        assert inp.files_changed is None

    def test_short_task_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PostActionInput(repo_root="/tmp/project", task_description="hi")


# ---------------------------------------------------------------------------
# Request models — FullScanInput
# ---------------------------------------------------------------------------


class TestFullScanInput:
    """Tests for FullScanInput model."""

    def test_valid_input(self) -> None:
        inp = FullScanInput(
            repo_root="/tmp/project",
            task_description="Full project validation scan",
        )
        assert inp.verify_imports is False
        assert inp.files_to_scan is None

    def test_with_files(self) -> None:
        inp = FullScanInput(
            repo_root="/tmp/project",
            task_description="Full project validation scan",
            files_to_scan=["src/app.py", "src/models.py"],
        )
        assert len(inp.files_to_scan) == 2


# ---------------------------------------------------------------------------
# Request models — DeepScanRequest
# ---------------------------------------------------------------------------


class TestDeepScanRequest:
    """Tests for DeepScanRequest model."""

    def test_valid_request(self) -> None:
        req = DeepScanRequest(code="import os\nprint('hello')")
        assert req.verify_imports is True
        assert req.verify_docker is False
        assert req.filename == "untitled"

    def test_empty_code_accepted(self) -> None:
        req = DeepScanRequest(code="")
        assert req.code == ""


# ---------------------------------------------------------------------------
# Request models — VerifyApiCallsRequest
# ---------------------------------------------------------------------------


class TestVerifyApiCallsRequest:
    """Tests for VerifyApiCallsRequest model."""

    def test_valid_request(self) -> None:
        req = VerifyApiCallsRequest(urls=["https://api.example.com"])
        assert req.method == "HEAD"

    def test_invalid_method_rejected(self) -> None:
        with pytest.raises(ValidationError):
            VerifyApiCallsRequest(urls=["https://api.example.com"], method="DELETE")

    def test_empty_urls_rejected(self) -> None:
        with pytest.raises(ValidationError):
            VerifyApiCallsRequest(urls=[])
