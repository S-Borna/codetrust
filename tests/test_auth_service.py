"""Tests for AuthService — GitHub OAuth and JWT token management."""

import datetime
from unittest.mock import AsyncMock, patch

import httpx
import jwt
import pytest

from src.config import settings
from src.services.auth import AuthService


@pytest.fixture()
def auth_service() -> AuthService:
    """Create an AuthService with a mock HTTP client."""
    client = httpx.AsyncClient()
    return AuthService(client)


# --- Configuration checks ---


class TestAuthConfiguration:
    """Test AuthService configuration detection."""

    def test_not_configured_by_default(self, auth_service: AuthService) -> None:
        """OAuth not configured when client_id/secret are empty."""
        assert not auth_service.is_configured()

    def test_jwt_not_configured_by_default(self, auth_service: AuthService) -> None:
        """JWT not configured when jwt_secret is empty."""
        assert not auth_service.jwt_configured()

    def test_configured_when_credentials_set(self) -> None:
        """OAuth configured when both client_id and secret are set."""
        with (
            patch.object(settings, "github_client_id", "test_id"),
            patch.object(settings, "github_client_secret", "test_secret"),
        ):
            svc = AuthService(httpx.AsyncClient())
            assert svc.is_configured()

    def test_jwt_configured_when_secret_set(self) -> None:
        """JWT configured when jwt_secret is set."""
        with patch.object(settings, "jwt_secret", "my_secret"):
            svc = AuthService(httpx.AsyncClient())
            assert svc.jwt_configured()


# --- JWT creation and decoding ---


class TestJwtOperations:
    """Test JWT token creation and decoding."""

    def test_create_and_decode_jwt(self) -> None:
        """Create a JWT and decode it successfully."""
        with (
            patch.object(settings, "jwt_secret", "test_secret_key"),
            patch.object(settings, "jwt_algorithm", "HS256"),
            patch.object(settings, "jwt_expire_minutes", 60),
        ):
            svc = AuthService(httpx.AsyncClient())
            token = svc.create_jwt("user123", "pro")
            decoded = svc.decode_jwt(token)

            assert decoded is not None
            assert decoded["user_id"] == "user123"
            assert decoded["plan"] == "pro"

    def test_decode_expired_jwt(self) -> None:
        """Expired JWT returns None."""
        with (
            patch.object(settings, "jwt_secret", "test_secret_key"),
            patch.object(settings, "jwt_algorithm", "HS256"),
        ):
            svc = AuthService(httpx.AsyncClient())
            payload = {
                "sub": "user123",
                "plan": "pro",
                "iat": datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=2),
                "exp": datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=1),
            }
            token = jwt.encode(payload, "test_secret_key", algorithm="HS256")
            decoded = svc.decode_jwt(token)
            assert decoded is None

    def test_decode_invalid_jwt(self) -> None:
        """Invalid JWT returns None."""
        with patch.object(settings, "jwt_secret", "test_secret_key"):
            svc = AuthService(httpx.AsyncClient())
            decoded = svc.decode_jwt("not.a.valid.jwt")
            assert decoded is None

    def test_decode_wrong_secret(self) -> None:
        """JWT signed with different secret returns None."""
        with (
            patch.object(settings, "jwt_secret", "secret_a"),
            patch.object(settings, "jwt_algorithm", "HS256"),
            patch.object(settings, "jwt_expire_minutes", 60),
        ):
            svc_a = AuthService(httpx.AsyncClient())
            token = svc_a.create_jwt("user123", "free")

        with (
            patch.object(settings, "jwt_secret", "secret_b"),
            patch.object(settings, "jwt_algorithm", "HS256"),
        ):
            svc_b = AuthService(httpx.AsyncClient())
            decoded = svc_b.decode_jwt(token)
            assert decoded is None

    def test_jwt_contains_plan(self) -> None:
        """JWT payload contains plan information."""
        with (
            patch.object(settings, "jwt_secret", "test_key"),
            patch.object(settings, "jwt_algorithm", "HS256"),
            patch.object(settings, "jwt_expire_minutes", 60),
        ):
            svc = AuthService(httpx.AsyncClient())
            token = svc.create_jwt("u1", "enterprise")
            decoded = svc.decode_jwt(token)
            assert decoded is not None
            assert decoded["plan"] == "enterprise"


# --- GitHub OAuth ---


class TestGithubOauth:
    """Test GitHub OAuth code exchange flow."""

    async def test_exchange_not_configured(self, auth_service: AuthService) -> None:
        """Returns empty dict when OAuth not configured."""
        result = await auth_service.exchange_github_code("some_code")
        assert result == {}

    async def test_exchange_success(self, httpx_mock: pytest.fixture) -> None:
        """Successful GitHub OAuth exchange returns user info."""
        with (
            patch.object(settings, "github_client_id", "cid"),
            patch.object(settings, "github_client_secret", "csec"),
            patch.object(
                settings, "github_token_url",
                "https://github.com/login/oauth/access_token",
            ),
            patch.object(
                settings, "github_user_url",
                "https://api.github.com/user",
            ),
        ):
            svc = AuthService(httpx.AsyncClient())

            httpx_mock.add_response(
                url="https://github.com/login/oauth/access_token",
                json={"access_token": "gho_test123"},
            )
            httpx_mock.add_response(
                url="https://api.github.com/user",
                json={
                    "id": 12345,
                    "email": "user@example.com",
                    "name": "Test User",
                    "avatar_url": "https://avatars.github.com/u/12345",
                },
            )

            result = await svc.exchange_github_code("valid_code")
            assert result["github_id"] == "12345"
            assert result["email"] == "user@example.com"
            assert result["name"] == "Test User"

    async def test_exchange_no_token(self, httpx_mock: pytest.fixture) -> None:
        """Returns empty dict when GitHub doesn't return access_token."""
        with (
            patch.object(settings, "github_client_id", "cid"),
            patch.object(settings, "github_client_secret", "csec"),
            patch.object(
                settings, "github_token_url",
                "https://github.com/login/oauth/access_token",
            ),
        ):
            svc = AuthService(httpx.AsyncClient())

            httpx_mock.add_response(
                url="https://github.com/login/oauth/access_token",
                json={"error": "bad_verification_code"},
            )

            result = await svc.exchange_github_code("bad_code")
            assert result == {}

    async def test_exchange_http_error(self) -> None:
        """Returns empty dict on HTTP error during token exchange."""
        with (
            patch.object(settings, "github_client_id", "cid"),
            patch.object(settings, "github_client_secret", "csec"),
            patch.object(
                settings, "github_token_url",
                "https://github.com/login/oauth/access_token",
            ),
        ):
            mock_client = AsyncMock(spec=httpx.AsyncClient)
            mock_client.post.side_effect = httpx.ConnectError("timeout")
            svc = AuthService(mock_client)

            result = await svc.exchange_github_code("code")
            assert result == {}

    async def test_fetch_user_http_error(self) -> None:
        """Returns empty dict on HTTP error during user fetch."""
        with patch.object(settings, "github_user_url", "https://api.github.com/user"):
            mock_client = AsyncMock(spec=httpx.AsyncClient)
            mock_client.get.side_effect = httpx.ConnectError("timeout")
            svc = AuthService(mock_client)

            result = await svc._fetch_github_user("token123")
            assert result == {}

    async def test_fetch_user_null_fields(self, httpx_mock: pytest.fixture) -> None:
        """Handles GitHub API returning null for optional fields."""
        with patch.object(settings, "github_user_url", "https://api.github.com/user"):
            svc = AuthService(httpx.AsyncClient())

            httpx_mock.add_response(
                url="https://api.github.com/user",
                json={
                    "id": 99999,  # noqa: magic_number
                    "email": None,
                    "name": None,
                    "avatar_url": None,
                },
            )

            result = await svc._fetch_github_user("token123")
            assert result["github_id"] == "99999"
            assert result["email"] == ""
            assert result["name"] == ""
            assert result["avatar_url"] == ""
