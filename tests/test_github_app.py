"""Tests for GitHub App webhook scanning and PR comment integration."""

import base64
import hmac
from hashlib import sha256
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient

from src.api import app
from src.services.github_app import GitHubAppEventResult, GitHubAppService
from src.services.static_analyzer import StaticAnalyzer


@pytest.fixture()
def github_app_service() -> GitHubAppService:
    """Create a GitHubAppService with a shared async client."""
    return GitHubAppService(httpx.AsyncClient(), StaticAnalyzer())


class TestGitHubAppService:
    """Unit tests for GitHub App service behavior."""

    def test_verify_webhook_signature_accepts_valid_hmac(
        self,
        github_app_service: GitHubAppService,
    ) -> None:
        """Valid signatures are accepted when app settings are configured."""
        payload = b'{"hello":"world"}'
        with (
            patch("src.services.github_app.settings.github_app_id", "12345"),
            patch("src.services.github_app.settings.github_app_private_key", "k"),
            patch("src.services.github_app.settings.github_app_webhook_secret", "secret"),
        ):
            header = "sha256=" + hmac.new(b"secret", payload, sha256).hexdigest()
            assert github_app_service.verify_webhook_signature(payload, header)

    @pytest.mark.asyncio
    async def test_handle_webhook_event_posts_new_comment(
        self,
        github_app_service: GitHubAppService,
        httpx_mock: pytest.fixture,
    ) -> None:
        """pull_request opened event scans changed files and creates a sticky comment."""
        content = "print('hello')\n"
        encoded = base64.b64encode(content.encode("utf-8")).decode("utf-8")

        with (
            patch("src.services.github_app.settings.github_app_id", "123"),
            patch("src.services.github_app.settings.github_app_private_key", "pem"),
            patch("src.services.github_app.settings.github_app_webhook_secret", "secret"),
            patch("src.services.github_app.settings.github_app_api_url", "https://api.github.com"),
            patch.object(github_app_service, "_build_app_jwt", return_value="app_jwt"),
        ):
            httpx_mock.add_response(
                method="POST",
                url="https://api.github.com/app/installations/77/access_tokens",
                json={"token": "install_token"},
            )
            httpx_mock.add_response(
                method="GET",
                url="https://api.github.com/repos/acme/repo/pulls/5/files?per_page=50",
                json=[{"filename": "src/app.py"}],
            )
            httpx_mock.add_response(
                method="GET",
                url="https://api.github.com/repos/acme/repo/contents/src/app.py",
                match_params={"ref": "abc123"},
                json={"content": encoded},
            )
            httpx_mock.add_response(
                method="GET",
                url="https://api.github.com/repos/acme/repo/issues/5/comments?per_page=100",
                json=[],
            )
            httpx_mock.add_response(
                method="POST",
                url="https://api.github.com/repos/acme/repo/issues/5/comments",
                json={"html_url": "https://github.com/acme/repo/pull/5#issuecomment-1"},
            )

            result = await github_app_service.handle_webhook_event(
                event="pull_request",
                payload={
                    "action": "opened",
                    "installation": {"id": 77},
                    "repository": {
                        "name": "repo",
                        "owner": {"login": "acme"},
                    },
                    "pull_request": {
                        "number": 5,
                        "head": {"sha": "abc123"},
                    },
                },
            )

        assert result.processed is True
        assert result.comment_url.endswith("issuecomment-1")
        assert result.total_findings >= 1


class TestGitHubAppWebhookEndpoint:
    """Endpoint tests for /v1/github/app/webhook."""

    @pytest.fixture()
    def client(self) -> TestClient:
        """Create TestClient with mocked GitHub app service on app state."""
        app.state.github_app = GitHubAppService(httpx.AsyncClient(), StaticAnalyzer())
        return TestClient(app, raise_server_exceptions=False)

    def test_webhook_rejects_bad_signature(self, client: TestClient) -> None:
        """Invalid signature returns 401."""
        app.state.github_app.verify_webhook_signature = lambda _payload, _sig: False

        response = client.post(
            "/v1/github/app/webhook",
            headers={"X-Hub-Signature-256": "sha256=bad", "X-GitHub-Event": "pull_request"},
            content='{"action":"opened"}',
        )

        assert response.status_code == 401

    def test_webhook_returns_processed_payload(self, client: TestClient) -> None:
        """Valid webhook returns normalized processing result."""
        app.state.github_app.verify_webhook_signature = lambda _payload, _sig: True
        app.state.github_app.handle_webhook_event = AsyncMock(
            return_value=GitHubAppEventResult(
                processed=True,
                event="pull_request",
                action="opened",
                reason="processed",
                comment_url="https://github.com/acme/repo/pull/1#issuecomment-2",
                total_findings=3,
                blocks=1,
                warnings=1,
                infos=1,
            ),
        )

        response = client.post(
            "/v1/github/app/webhook",
            headers={"X-Hub-Signature-256": "sha256=ok", "X-GitHub-Event": "pull_request"},
            content='{"action":"opened"}',
        )

        assert response.status_code == 200
        data = response.json()
        assert data["processed"] is True
        assert data["comment_url"].endswith("issuecomment-2")
        assert data["blocks"] == 1
