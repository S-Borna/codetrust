"""Tests for unified session token governance endpoints."""

from http import HTTPStatus
from unittest.mock import MagicMock

import httpx
import pytest
from fastapi.testclient import TestClient

from src.api import app
from src.config import settings
from src.services.auth import AuthService
from src.services.billing import BillingService
from src.services.cache import CacheService
from src.services.docker_verify import DockerVerifyService
from src.services.registry import RegistryService
from src.services.sandbox import SandboxService
from src.services.static_analyzer import StaticAnalyzer
from src.services.ast_analyzer import AstAnalyzer
from src.services.unified_session import UnifiedSessionStore


@pytest.fixture()
def _setup_app_state() -> None:
    """Set up app.state with test dependencies."""
    import fakeredis.aioredis

    cache = CacheService("redis://localhost:6379")
    cache._client = fakeredis.aioredis.FakeRedis(decode_responses=True)

    original_api_setting = settings.api_key
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
    app.state.billing = MagicMock(spec=BillingService)
    app.state.auth = AuthService(http_client)
    app.state.rate_limiter = None
    app.state.session_store = UnifiedSessionStore()

    yield

    settings.api_key = original_api_setting


@pytest.fixture()
def client(_setup_app_state: None) -> TestClient:
    """Create a TestClient with mocked app state."""
    return TestClient(app, raise_server_exceptions=False)


class TestGovernanceSessionToken:
    """Tests for POST /v1/governance/session-token."""

    def test_issue_session_token(self, client: TestClient) -> None:
        """Issue a unified session token with multiple surfaces."""
        response = client.post(
            "/v1/governance/session-token",
            json={
                "surfaces": ["ide", "cli", "api"],
                "agent_id": "claude",
                "workspace_id": "ws-main",
                "ttl_minutes": 30,
            },
        )
        assert response.status_code == HTTPStatus.OK
        data = response.json()
        assert "session_token" in data
        assert len(data["session_token"]) > 0
        assert data["surfaces"] == ["api", "cli", "ide"]
        assert data["agent_id"] == "claude"
        assert data["workspace_id"] == "ws-main"
        assert data["audit_chain_id"].startswith("chain-")
        assert data["expires_at"] > data["issued_at"]

    def test_issue_filters_invalid_surfaces(self, client: TestClient) -> None:
        """Invalid surface names are filtered out."""
        response = client.post(
            "/v1/governance/session-token",
            json={
                "surfaces": ["ide", "invalid_surface"],
                "agent_id": "copilot",
            },
        )
        assert response.status_code == HTTPStatus.OK
        data = response.json()
        assert data["surfaces"] == ["ide"]

    def test_issue_fallback_to_api(self, client: TestClient) -> None:
        """When all surfaces are invalid, falls back to api."""
        response = client.post(
            "/v1/governance/session-token",
            json={
                "surfaces": ["bogus"],
            },
        )
        assert response.status_code == HTTPStatus.OK
        data = response.json()
        assert data["surfaces"] == ["api"]


class TestGovernanceValidateSessionToken:
    """Tests for GET /v1/governance/session-token/{token}."""

    def test_validate_valid_token(self, client: TestClient) -> None:
        """Validate an existing session token."""
        # Issue first
        issue_resp = client.post(
            "/v1/governance/session-token",
            json={"surfaces": ["ide", "cli"]},
        )
        token = issue_resp.json()["session_token"]

        # Validate
        response = client.get(f"/v1/governance/session-token/{token}")
        assert response.status_code == HTTPStatus.OK
        data = response.json()
        assert data["valid"] is True
        assert data["session_token"] == token
        assert data["remaining_seconds"] > 0

    def test_validate_unknown_token(self, client: TestClient) -> None:
        """Returns 404 for an unknown token."""
        response = client.get("/v1/governance/session-token/nonexistent-token")
        assert response.status_code == HTTPStatus.NOT_FOUND


class TestGovernanceRevokeSessionToken:
    """Tests for DELETE /v1/governance/session-token/{token}."""

    def test_revoke_valid_token(self, client: TestClient) -> None:
        """Revoke an existing session token."""
        # Issue first
        issue_resp = client.post(
            "/v1/governance/session-token",
            json={"surfaces": ["api"]},
        )
        token = issue_resp.json()["session_token"]

        # Revoke
        response = client.delete(f"/v1/governance/session-token/{token}")
        assert response.status_code == HTTPStatus.OK
        assert response.json()["status"] == "revoked"

        # Validate should fail now
        validate_resp = client.get(f"/v1/governance/session-token/{token}")
        assert validate_resp.status_code == HTTPStatus.NOT_FOUND

    def test_revoke_unknown_token(self, client: TestClient) -> None:
        """Returns 404 for unknown token."""
        response = client.delete("/v1/governance/session-token/nonexistent")
        assert response.status_code == HTTPStatus.NOT_FOUND

    def test_audit_chain_id_is_unique(self, client: TestClient) -> None:
        """Each issued token has a unique audit chain ID."""
        resp1 = client.post(
            "/v1/governance/session-token",
            json={"surfaces": ["ide"]},
        )
        resp2 = client.post(
            "/v1/governance/session-token",
            json={"surfaces": ["ide"]},
        )
        chain1 = resp1.json()["audit_chain_id"]
        chain2 = resp2.json()["audit_chain_id"]
        assert chain1 != chain2
