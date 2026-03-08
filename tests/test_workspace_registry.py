"""Tests for multi-workspace governance endpoints."""

from http import HTTPStatus
from unittest.mock import MagicMock, patch

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
from src.services.workspace_registry import WorkspaceRegistry


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
    app.state.workspace_registry = WorkspaceRegistry()

    yield

    settings.api_key = original_api_setting


@pytest.fixture()
def client(_setup_app_state: None) -> TestClient:
    """Create a TestClient with mocked app state."""
    return TestClient(app, raise_server_exceptions=False)


class TestGovernanceWorkspaces:
    """Tests for GET /v1/governance/workspaces."""

    def test_list_workspaces_empty(self, client: TestClient) -> None:
        """Empty aggregate when no workspaces registered."""
        response = client.get("/v1/governance/workspaces")
        assert response.status_code == HTTPStatus.OK
        data = response.json()
        assert data["total_workspaces"] == 0
        assert data["workspaces"] == []
        assert data["healthy_count"] == 0
        assert data["drifted_count"] == 0
        assert data["disabled_count"] == 0

    def test_register_workspace(self, client: TestClient) -> None:
        """Register a new workspace and verify it appears."""
        response = client.post(
            "/v1/governance/workspaces",
            json={
                "workspace_id": "ws-001",
                "workspace_name": "My Project",
                "agent_id": "claude",
                "posture": {
                    "enabled": True,
                    "mode": "enforce",
                    "control_plane_ready": True,
                    "drift_count": 0,
                },
            },
        )
        assert response.status_code == HTTPStatus.OK
        data = response.json()
        assert data["workspace_id"] == "ws-001"
        assert data["workspace_name"] == "My Project"
        assert data["enabled"] is True
        assert data["mode"] == "enforce"
        assert data["drift_count"] == 0

    def test_register_and_list_workspaces(self, client: TestClient) -> None:
        """Register workspaces and verify aggregate stats."""
        # Register healthy workspace
        client.post(
            "/v1/governance/workspaces",
            json={
                "workspace_id": "ws-healthy",
                "workspace_name": "Healthy Project",
                "posture": {"enabled": True, "drift_count": 0},
            },
        )
        # Register drifted workspace
        client.post(
            "/v1/governance/workspaces",
            json={
                "workspace_id": "ws-drifted",
                "workspace_name": "Drifted Project",
                "posture": {"enabled": True, "drift_count": 3},
            },
        )
        # Register disabled workspace
        client.post(
            "/v1/governance/workspaces",
            json={
                "workspace_id": "ws-disabled",
                "workspace_name": "Disabled Project",
                "posture": {"enabled": False},
            },
        )

        response = client.get("/v1/governance/workspaces")
        assert response.status_code == HTTPStatus.OK
        data = response.json()
        assert data["total_workspaces"] == 3
        assert data["healthy_count"] == 1
        assert data["drifted_count"] == 1
        assert data["disabled_count"] == 1
        assert len(data["workspaces"]) == 3

    def test_update_existing_workspace(self, client: TestClient) -> None:
        """Re-registering updates an existing workspace."""
        client.post(
            "/v1/governance/workspaces",
            json={
                "workspace_id": "ws-update",
                "workspace_name": "Old Name",
                "posture": {"enabled": False},
            },
        )
        response = client.post(
            "/v1/governance/workspaces",
            json={
                "workspace_id": "ws-update",
                "workspace_name": "New Name",
                "posture": {"enabled": True, "drift_count": 2},
            },
        )
        assert response.status_code == HTTPStatus.OK
        data = response.json()
        assert data["workspace_name"] == "New Name"
        assert data["enabled"] is True
        assert data["drift_count"] == 2

        # Only one workspace in aggregate
        agg = client.get("/v1/governance/workspaces").json()
        assert agg["total_workspaces"] == 1

    def test_unregister_workspace(self, client: TestClient) -> None:
        """Delete removes a workspace."""
        client.post(
            "/v1/governance/workspaces",
            json={
                "workspace_id": "ws-remove",
                "workspace_name": "To Remove",
            },
        )
        response = client.delete("/v1/governance/workspaces/ws-remove")
        assert response.status_code == HTTPStatus.OK
        assert response.json()["status"] == "removed"

        # Verify it is gone
        agg = client.get("/v1/governance/workspaces").json()
        assert agg["total_workspaces"] == 0

    def test_unregister_not_found(self, client: TestClient) -> None:
        """Delete returns 404 for unknown workspace."""
        response = client.delete("/v1/governance/workspaces/nonexistent")
        assert response.status_code == HTTPStatus.NOT_FOUND
