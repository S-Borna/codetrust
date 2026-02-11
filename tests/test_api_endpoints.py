"""Tests for FastAPI endpoints."""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient

from src.api import app
from src.config import settings
from src.models.enums import Registry, Severity, VerifyStatus
from src.models.responses import (
    DockerImageResult,
    PackageResult,
)
from src.services.ast_analyzer import AstAnalyzer
from src.services.billing import BillingService
from src.services.cache import CacheService
from src.services.docker_verify import DockerVerifyService
from src.services.registry import RegistryService
from src.services.sandbox import SandboxService
from src.services.static_analyzer import StaticAnalyzer


@pytest.fixture()
def _setup_app_state() -> None:
    """Set up app.state with test dependencies."""
    import fakeredis.aioredis

    cache = CacheService("redis://localhost:6379")
    cache._client = fakeredis.aioredis.FakeRedis(decode_responses=True)

    http_client = httpx.AsyncClient()
    app.state.cache = cache
    app.state.http_client = http_client
    app.state.registry = RegistryService(cache, http_client)
    app.state.docker = DockerVerifyService(cache, http_client)
    app.state.analyzer = StaticAnalyzer()
    app.state.ast_analyzer = AstAnalyzer()
    app.state.sandbox = SandboxService()
    app.state.db = None  # Database not needed for existing endpoint tests
    app.state.billing = MagicMock(spec=BillingService)


@pytest.fixture()
def client(_setup_app_state: None) -> TestClient:
    """Create a TestClient with mocked app state."""
    return TestClient(app, raise_server_exceptions=False)


# --- Health Check ---


class TestHealthCheck:
    """Tests for GET /v1/status."""

    def test_health_returns_ok(self, client: TestClient) -> None:
        """Health check returns status ok."""
        response = client.get("/v1/status")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["version"] == settings.version

    def test_health_includes_cache_status(self, client: TestClient) -> None:
        """Health check includes cache_connected field."""
        response = client.get("/v1/status")

        data = response.json()
        assert "cache_connected" in data


# --- Auth ---


class TestAuth:
    """Tests for API key authentication."""

    def test_no_auth_required_when_api_key_empty(
        self, client: TestClient
    ) -> None:
        """When CODETRUST_API_KEY is empty, no auth required."""
        original = settings.api_key
        settings.api_key = ""
        try:
            response = client.post(
                "/v1/scan/static",
                json={"code": "x = 1", "filename": "test.py"},
            )
            assert response.status_code == 200
        finally:
            settings.api_key = original

    def test_auth_required_when_api_key_set(
        self, client: TestClient
    ) -> None:
        """When CODETRUST_API_KEY is set, missing key returns 401."""
        original = settings.api_key
        settings.api_key = "test-secret-key"
        try:
            response = client.post(
                "/v1/scan/static",
                json={"code": "x = 1", "filename": "test.py"},
            )
            assert response.status_code == 401
        finally:
            settings.api_key = original

    def test_valid_api_key_passes_auth(
        self, client: TestClient
    ) -> None:
        """Valid API key passes authentication."""
        original = settings.api_key
        settings.api_key = "test-secret-key"
        try:
            response = client.post(
                "/v1/scan/static",
                json={"code": "x = 1", "filename": "test.py"},
                headers={"X-API-Key": "test-secret-key"},
            )
            assert response.status_code == 200
        finally:
            settings.api_key = original

    def test_wrong_api_key_returns_401(
        self, client: TestClient
    ) -> None:
        """Wrong API key returns 401."""
        original = settings.api_key
        settings.api_key = "test-secret-key"
        try:
            response = client.post(
                "/v1/scan/static",
                json={"code": "x = 1", "filename": "test.py"},
                headers={"X-API-Key": "wrong-key"},
            )
            assert response.status_code == 401
        finally:
            settings.api_key = original


# --- Static Scan ---


class TestStaticScan:
    """Tests for POST /v1/scan/static."""

    def test_clean_code_returns_pass(self, client: TestClient) -> None:
        """Clean code returns PASS verdict."""
        response = client.post(
            "/v1/scan/static",
            json={"code": "x = 1\ny = 2\n", "filename": "clean.py"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["verdict"] == "PASS"
        assert data["blocks"] == 0

    def test_eval_detected_returns_block(self, client: TestClient) -> None:
        """Code with eval() returns BLOCK verdict."""
        response = client.post(
            "/v1/scan/static",
            json={"code": "result = eval('2+2')\n", "filename": "bad.py"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["verdict"] == "BLOCK"
        assert data["blocks"] > 0

    def test_print_detected_returns_warn(self, client: TestClient) -> None:
        """Code with print() returns WARN verdict."""
        response = client.post(
            "/v1/scan/static",
            json={"code": "print('hello')\n", "filename": "warn.py"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["verdict"] == "WARN"
        assert data["warnings"] > 0

    def test_invalid_request_returns_422(self, client: TestClient) -> None:
        """Missing required field returns 422."""
        response = client.post(
            "/v1/scan/static",
            json={"filename": "test.py"},  # missing "code"
        )
        assert response.status_code == 422


# --- Verify Imports ---


class TestVerifyImports:
    """Tests for POST /v1/verify/imports."""

    def test_verify_imports_valid_request(
        self, client: TestClient
    ) -> None:
        """Valid verify imports request is accepted."""
        with patch.object(
            RegistryService,
            "verify_packages",
            new_callable=AsyncMock,
            return_value=[
                PackageResult(
                    package="fastapi",
                    registry=Registry.PYPI,
                    status=VerifyStatus.VERIFIED,
                    severity=Severity.INFO,
                    latest_version="0.115.0",
                    message="Package 'fastapi' exists on PyPI.",
                ),
            ],
        ):
            response = client.post(
                "/v1/verify/imports",
                json={
                    "language": "python",
                    "imports": ["fastapi"],
                },
            )

        assert response.status_code == 200
        data = response.json()
        assert data["verified"] == 1
        assert data["failed"] == 0

    def test_verify_imports_not_found(
        self, client: TestClient
    ) -> None:
        """Import not found returns failed count."""
        with patch.object(
            RegistryService,
            "verify_packages",
            new_callable=AsyncMock,
            return_value=[
                PackageResult(
                    package="nonexistent_xyz",
                    registry=Registry.PYPI,
                    status=VerifyStatus.NOT_FOUND,
                    severity=Severity.BLOCK,
                    message="Package 'nonexistent_xyz' not found on PyPI.",
                ),
            ],
        ):
            response = client.post(
                "/v1/verify/imports",
                json={
                    "language": "python",
                    "imports": ["nonexistent_xyz"],
                },
            )

        assert response.status_code == 200
        data = response.json()
        assert data["failed"] == 1

    def test_verify_imports_empty_list_returns_422(
        self, client: TestClient
    ) -> None:
        """Empty imports list returns 422."""
        response = client.post(
            "/v1/verify/imports",
            json={"language": "python", "imports": []},
        )
        assert response.status_code == 422


# --- Verify Dockerfile ---


class TestVerifyDockerfile:
    """Tests for POST /v1/verify/dockerfile."""

    def test_verify_dockerfile_valid_request(
        self, client: TestClient
    ) -> None:
        """Valid Dockerfile verification request."""
        with patch.object(
            DockerVerifyService,
            "verify_images",
            new_callable=AsyncMock,
            return_value=[
                DockerImageResult(
                    image="python",
                    tag="3.12-slim",
                    status=VerifyStatus.VERIFIED,
                    severity=Severity.INFO,
                    message="Image 'python:3.12-slim' verified.",
                ),
            ],
        ):
            response = client.post(
                "/v1/verify/dockerfile",
                json={
                    "images": [{"image": "python", "tag": "3.12-slim"}],
                },
            )

        assert response.status_code == 200
        data = response.json()
        assert data["verified"] == 1
        assert data["failed"] == 0

    def test_verify_dockerfile_not_found(
        self, client: TestClient
    ) -> None:
        """Dockerfile with non-existent tag returns failed count."""
        with patch.object(
            DockerVerifyService,
            "verify_images",
            new_callable=AsyncMock,
            return_value=[
                DockerImageResult(
                    image="python",
                    tag="99.99",
                    status=VerifyStatus.NOT_FOUND,
                    severity=Severity.BLOCK,
                    message="Tag '99.99' not found for 'python'.",
                ),
            ],
        ):
            response = client.post(
                "/v1/verify/dockerfile",
                json={
                    "images": [{"image": "python", "tag": "99.99"}],
                },
            )

        assert response.status_code == 200
        data = response.json()
        assert data["failed"] == 1

    def test_verify_dockerfile_empty_images_returns_422(
        self, client: TestClient
    ) -> None:
        """Empty images list returns 422."""
        response = client.post(
            "/v1/verify/dockerfile",
            json={"images": []},
        )
        assert response.status_code == 422


# --- Deep Scan ---


class TestDeepScan:
    """Tests for POST /v1/scan/deep."""

    def test_deep_scan_static_only(self, client: TestClient) -> None:
        """Deep scan with only static analysis."""
        response = client.post(
            "/v1/scan/deep",
            json={
                "code": "x = 1\ny = 2\n",
                "filename": "clean.py",
                "verify_imports": False,
                "verify_docker": False,
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["overall_verdict"] == "PASS"
        assert data["static_scan"] is not None
        assert data["import_verification"] is None
        assert data["docker_verification"] is None

    def test_deep_scan_with_block_finding(self, client: TestClient) -> None:
        """Deep scan with blocking static finding returns BLOCK verdict."""
        response = client.post(
            "/v1/scan/deep",
            json={
                "code": "result = eval('2+2')\n",
                "filename": "bad.py",
                "verify_imports": False,
                "verify_docker": False,
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["overall_verdict"] == "BLOCK"

    def test_deep_scan_missing_code_returns_422(
        self, client: TestClient
    ) -> None:
        """Missing code field returns 422."""
        response = client.post(
            "/v1/scan/deep",
            json={"filename": "test.py"},
        )
        assert response.status_code == 422

    @patch.object(RegistryService, "verify_packages", new_callable=AsyncMock)
    def test_deep_scan_with_imports(
        self, mock_verify: AsyncMock, client: TestClient
    ) -> None:
        """Deep scan includes import verification when requested."""
        mock_verify.return_value = [
            PackageResult(
                package="fastapi",
                registry=Registry.PYPI,
                status=VerifyStatus.VERIFIED,
                severity=Severity.INFO,
                latest_version="0.115.0",
                message="Package exists on PyPI",
            ),
        ]
        response = client.post(
            "/v1/scan/deep",
            json={
                "code": "import fastapi\n",
                "filename": "app.py",
                "language": "python",
                "verify_imports": True,
                "verify_docker": False,
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["import_verification"] is not None
        assert data["import_verification"]["verified"] == 1

    @patch.object(DockerVerifyService, "verify_images", new_callable=AsyncMock)
    def test_deep_scan_with_docker(
        self, mock_verify: AsyncMock, client: TestClient
    ) -> None:
        """Deep scan includes Docker verification when requested."""
        mock_verify.return_value = [
            DockerImageResult(
                image="python",
                tag="3.12-slim",
                status=VerifyStatus.VERIFIED,
                severity=Severity.INFO,
                message="Image tag verified",
            ),
        ]
        response = client.post(
            "/v1/scan/deep",
            json={
                "code": "x = 1\n",
                "filename": "app.py",
                "verify_imports": False,
                "verify_docker": True,
                "dockerfile_content": "FROM python:3.12-slim\n",
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["docker_verification"] is not None
        assert data["docker_verification"]["verified"] == 1

    @patch.object(RegistryService, "verify_packages", new_callable=AsyncMock)
    def test_deep_scan_failed_import_blocks(
        self, mock_verify: AsyncMock, client: TestClient
    ) -> None:
        """Deep scan with failed imports returns BLOCK verdict."""
        mock_verify.return_value = [
            PackageResult(
                package="nonexistent",
                registry=Registry.PYPI,
                status=VerifyStatus.NOT_FOUND,
                severity=Severity.BLOCK,
                message="Package not found",
            ),
        ]
        response = client.post(
            "/v1/scan/deep",
            json={
                "code": "import nonexistent\n",
                "filename": "app.py",
                "language": "python",
                "verify_imports": True,
                "verify_docker": False,
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["overall_verdict"] == "BLOCK"
        assert data["import_verification"]["failed"] == 1
