"""Tests for governance approval/exception API endpoints."""

from http import HTTPStatus
from unittest.mock import MagicMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient

from src.api import app
from src.config import settings
from src.gateway.approvals import (
    ApprovalExceptionStore,
    GovernanceException,
    PendingApproval,
)
from src.services.ast_analyzer import AstAnalyzer
from src.services.auth import AuthService
from src.services.billing import BillingService
from src.services.cache import CacheService
from src.services.docker_verify import DockerVerifyService
from src.services.registry import RegistryService
from src.services.sandbox import SandboxService
from src.services.static_analyzer import StaticAnalyzer

MOCK_PENDING = PendingApproval(
    request_id="apr_test001",
    rule_id="gateway_heredoc",
    action_type="terminal_command",
    original_action="echo test-command",
    action_fingerprint="fp_abc123",
    requested_at=1700000000.0,
    expires_at=1700003600.0,
    session_id="sess-test",
    agent_id="claude",
)

MOCK_EXCEPTION = GovernanceException(
    exception_id="gex_test001",
    rule_id="gateway_heredoc",
    action_type="terminal_command",
    action_fingerprint="fp_abc123",
    reason="Approved for deployment",
    approver="admin",
    approver_role="owner",
    created_at=1700000000.0,
    expires_at=1700003600.0,
    session_id="sess-test",
    agent_id="claude",
)


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

    yield

    settings.api_key = original_api_setting


@pytest.fixture()
def client(_setup_app_state: None) -> TestClient:
    """Create a TestClient with mocked app state."""
    return TestClient(app, raise_server_exceptions=False)


class TestGovernanceApprovals:
    """Tests for GET /v1/governance/approvals."""

    @patch("src.api._get_approval_store")
    def test_list_approvals_returns_list(
        self, mock_store_fn: MagicMock, client: TestClient
    ) -> None:
        """List approvals returns pending items."""
        store = MagicMock(spec=ApprovalExceptionStore)
        store.list_pending.return_value = [MOCK_PENDING]
        mock_store_fn.return_value = store

        response = client.get("/v1/governance/approvals")
        assert response.status_code == HTTPStatus.OK
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["request_id"] == "apr_test001"
        assert data[0]["rule_id"] == "gateway_heredoc"

    @patch("src.api._get_approval_store")
    def test_list_approvals_empty(
        self, mock_store_fn: MagicMock, client: TestClient
    ) -> None:
        """Empty list when no pending approvals."""
        store = MagicMock(spec=ApprovalExceptionStore)
        store.list_pending.return_value = []
        mock_store_fn.return_value = store

        response = client.get("/v1/governance/approvals")
        assert response.status_code == HTTPStatus.OK
        assert response.json() == []


class TestGovernanceApproveAction:
    """Tests for POST /v1/governance/approvals/{request_id}/approve."""

    @patch("src.api._get_approval_store")
    def test_approve_action_success(
        self, mock_store_fn: MagicMock, client: TestClient
    ) -> None:
        """Approve returns exception details on success."""
        store = MagicMock(spec=ApprovalExceptionStore)
        store.approve.return_value = MOCK_EXCEPTION
        mock_store_fn.return_value = store

        response = client.post(
            "/v1/governance/approvals/apr_test001/approve",
            json={
                "approver": "admin",
                "approver_role": "owner",
                "reason": "Approved for test purposes",
            },
        )
        assert response.status_code == HTTPStatus.OK
        data = response.json()
        assert data["approved"] is True
        assert data["exception_id"] == "gex_test001"

    @patch("src.api._get_approval_store")
    def test_approve_action_not_found(
        self, mock_store_fn: MagicMock, client: TestClient
    ) -> None:
        """Approve returns 404 when pending approval not found."""
        store = MagicMock(spec=ApprovalExceptionStore)
        store.approve.return_value = None
        mock_store_fn.return_value = store

        response = client.post(
            "/v1/governance/approvals/nonexistent/approve",
            json={
                "approver": "admin",
                "approver_role": "owner",
                "reason": "Approved for test purposes",
            },
        )
        assert response.status_code == HTTPStatus.NOT_FOUND

    @patch("src.api._get_approval_store")
    def test_approve_action_with_ttl(
        self, mock_store_fn: MagicMock, client: TestClient
    ) -> None:
        """Approve passes ttl_minutes to store."""
        store = MagicMock(spec=ApprovalExceptionStore)
        store.approve.return_value = MOCK_EXCEPTION
        mock_store_fn.return_value = store

        response = client.post(
            "/v1/governance/approvals/apr_test001/approve",
            json={
                "approver": "admin",
                "approver_role": "owner",
                "reason": "Approved for test purposes",
                "ttl_minutes": 120,
            },
        )
        assert response.status_code == HTTPStatus.OK
        store.approve.assert_called_once()
        call_kwargs = store.approve.call_args.kwargs
        assert call_kwargs["ttl_minutes"] == 120


class TestGovernanceExceptions:
    """Tests for GET /v1/governance/exceptions."""

    @patch("src.api._get_approval_store")
    def test_list_exceptions_returns_active(
        self, mock_store_fn: MagicMock, client: TestClient
    ) -> None:
        """List exceptions includes active items."""
        store = MagicMock(spec=ApprovalExceptionStore)
        store.list_active_exceptions.return_value = [MOCK_EXCEPTION]
        mock_store_fn.return_value = store

        response = client.get("/v1/governance/exceptions")
        assert response.status_code == HTTPStatus.OK
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["exception_id"] == "gex_test001"
        assert data[0]["approver"] == "admin"

    @patch("src.api._get_approval_store")
    def test_list_exceptions_empty(
        self, mock_store_fn: MagicMock, client: TestClient
    ) -> None:
        """Empty list when no active exceptions."""
        store = MagicMock(spec=ApprovalExceptionStore)
        store.list_active_exceptions.return_value = []
        mock_store_fn.return_value = store

        response = client.get("/v1/governance/exceptions")
        assert response.status_code == HTTPStatus.OK
        assert response.json() == []


class TestGovernanceRevokeException:
    """Tests for DELETE /v1/governance/exceptions/{exception_id}."""

    @patch("src.api._get_approval_store")
    def test_revoke_exception_success(
        self, mock_store_fn: MagicMock, client: TestClient
    ) -> None:
        """Revoke returns status on success."""
        store = MagicMock(spec=ApprovalExceptionStore)
        store.revoke.return_value = True
        mock_store_fn.return_value = store

        response = client.delete("/v1/governance/exceptions/gex_test001")
        assert response.status_code == HTTPStatus.OK
        data = response.json()
        assert data["status"] == "revoked"

    @patch("src.api._get_approval_store")
    def test_revoke_exception_not_found(
        self, mock_store_fn: MagicMock, client: TestClient
    ) -> None:
        """Revoke returns 404 when exception not found."""
        store = MagicMock(spec=ApprovalExceptionStore)
        store.revoke.return_value = False
        mock_store_fn.return_value = store

        response = client.delete("/v1/governance/exceptions/nonexistent")
        assert response.status_code == HTTPStatus.NOT_FOUND
