"""Tests for SBOM generation service and API endpoint."""

import json

import fakeredis.aioredis
import httpx
import pytest
from fastapi.testclient import TestClient

from src.api import app
from src.config import settings
from src.models.enums import Language
from src.services.ast_analyzer import AstAnalyzer
from src.services.auth import AuthService
from src.services.billing import BillingService
from src.services.cache import CacheService
from src.services.docker_verify import DockerVerifyService
from src.services.registry import RegistryService
from src.services.sandbox import SandboxService
from src.services.sbom import SbomService
from src.services.static_analyzer import StaticAnalyzer


@pytest.fixture()
def _setup_app_state() -> None:
    """Set up app.state dependencies for endpoint tests."""
    cache = CacheService("redis://localhost:6379")
    cache._client = fakeredis.aioredis.FakeRedis(decode_responses=True)

    original_api_key = settings.api_key
    settings.api_key = ""

    http_client = httpx.AsyncClient(timeout=5.0)
    app.state.cache = cache
    app.state.http_client = http_client
    app.state.registry = RegistryService(cache, http_client)
    app.state.docker = DockerVerifyService(cache, http_client)
    app.state.analyzer = StaticAnalyzer()
    app.state.ast_analyzer = AstAnalyzer()
    app.state.sandbox = SandboxService()
    app.state.db = None
    app.state.billing = BillingService()
    app.state.auth = AuthService(http_client)
    app.state.rate_limiter = None

    yield

    settings.api_key = original_api_key


class TestSbomService:
    """Validate CycloneDX and SPDX document generation."""

    def test_generate_builds_both_formats(self) -> None:
        """Service returns both CycloneDX and SPDX JSON documents."""
        service = SbomService()
        result = service.generate(
            language=Language.PYTHON,
            packages=["fastapi", "httpx"],
            versions={"fastapi": "0.115.0", "httpx": "0.27.0"},
            document_name="codetrust-api",
        )

        assert result.component_count == 2
        cyclonedx = json.loads(result.cyclonedx_json)
        spdx = json.loads(result.spdx_json)

        assert cyclonedx["bomFormat"] == "CycloneDX"
        assert cyclonedx["specVersion"] == "1.5"
        assert len(cyclonedx["components"]) == 2

        assert spdx["spdxVersion"] == "SPDX-2.3"
        assert spdx["name"] == "codetrust-api"
        assert len(spdx["packages"]) == 2

    def test_generate_defaults_unknown_version(self) -> None:
        """Packages missing version metadata fall back to 'unknown'."""
        service = SbomService()
        result = service.generate(
            language=Language.JAVASCRIPT,
            packages=["react"],
            versions={},
            document_name="frontend",
        )

        cyclonedx = json.loads(result.cyclonedx_json)
        assert cyclonedx["components"][0]["version"] == "unknown"


class TestSbomEndpoint:
    """Validate the /v1/sbom/generate API contract."""

    @pytest.fixture()
    def client(self, _setup_app_state: None) -> TestClient:
        """Create TestClient with initialized app state."""
        return TestClient(app, raise_server_exceptions=False)

    def test_sbom_endpoint_returns_documents(self, client: TestClient) -> None:
        """Endpoint responds with CycloneDX and SPDX payload strings."""
        response = client.post(
            "/v1/sbom/generate",
            json={
                "language": "python",
                "packages": ["fastapi", "httpx"],
                "versions": {"fastapi": "0.115.0", "httpx": "0.27.0"},
                "document_name": "backend-sbom",
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["ecosystem"] == "pypi"
        assert data["component_count"] == 2

        cyclonedx = json.loads(data["cyclonedx_json"])
        spdx = json.loads(data["spdx_json"])
        assert cyclonedx["bomFormat"] == "CycloneDX"
        assert spdx["spdxVersion"] == "SPDX-2.3"

    def test_sbom_endpoint_rejects_empty_package_list(self, client: TestClient) -> None:
        """Validation error is returned for empty package input."""
        response = client.post(
            "/v1/sbom/generate",
            json={
                "language": "python",
                "packages": [],
                "document_name": "invalid",
            },
        )

        assert response.status_code == 422
