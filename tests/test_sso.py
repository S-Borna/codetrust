"""Tests for SSO/OIDC authentication service."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import jwt
import pytest

from src.services.sso import OIDCConfig, OIDCService, OIDCUser

OIDC_TEST_VALUE = "test-client-value"

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def oidc_config() -> OIDCConfig:
    return OIDCConfig(
        enabled=True,
        issuer="https://login.microsoftonline.com/tenant-id/v2.0",
        client_id="test-client-id",
        client_secret=OIDC_TEST_VALUE,
        redirect_uri="https://app.codetrust.ai/auth/callback/oidc",
        scopes=["openid", "profile", "email"],
    )


@pytest.fixture
def mock_http() -> AsyncMock:
    return AsyncMock()


@pytest.fixture
def oidc_service(oidc_config: OIDCConfig, mock_http: AsyncMock) -> OIDCService:
    return OIDCService(oidc_config, mock_http)


# ---------------------------------------------------------------------------
# OIDCConfig tests
# ---------------------------------------------------------------------------

class TestOIDCConfig:
    def test_defaults(self) -> None:
        cfg = OIDCConfig()
        assert cfg.enabled is False
        assert cfg.issuer == ""
        assert cfg.scopes == ["openid", "profile", "email"]
        assert cfg.role_claim == "roles"
        assert cfg.admin_roles == ["admin", "codetrust_admin"]
        assert cfg.allowed_domains == []

    def test_custom_config(self) -> None:
        cfg = OIDCConfig(
            enabled=True,
            issuer="https://accounts.google.com",
            client_id="google-id",
            allowed_domains=["example.com"],
        )
        assert cfg.enabled is True
        assert cfg.client_id == "google-id"
        assert cfg.allowed_domains == ["example.com"]


# ---------------------------------------------------------------------------
# OIDCUser tests
# ---------------------------------------------------------------------------

class TestOIDCUser:
    def test_basic_user(self) -> None:
        user = OIDCUser(sub="123", email="a@b.com", name="Test")
        assert user.sub == "123"
        assert user.email == "a@b.com"
        assert user.is_admin is False

    def test_admin_user(self) -> None:
        user = OIDCUser(sub="123", roles=["admin"])
        assert user.is_admin is True

    def test_codetrust_admin(self) -> None:
        user = OIDCUser(sub="123", roles=["codetrust_admin"])
        assert user.is_admin is True

    def test_non_admin_roles(self) -> None:
        user = OIDCUser(sub="123", roles=["viewer", "editor"])
        assert user.is_admin is False

    def test_empty_roles(self) -> None:
        user = OIDCUser(sub="123")
        assert user.roles == []
        assert user.is_admin is False


# ---------------------------------------------------------------------------
# OIDCService — Discovery
# ---------------------------------------------------------------------------

class TestOIDCDiscovery:
    @pytest.mark.asyncio
    async def test_successful_discovery(
        self, oidc_service: OIDCService, mock_http: AsyncMock,
    ) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "authorization_endpoint": "https://login.microsoftonline.com/auth",
            "token_endpoint": "https://login.microsoftonline.com/token",
            "userinfo_endpoint": "https://graph.microsoft.com/oidc/userinfo",
            "jwks_uri": "https://login.microsoftonline.com/keys",
        }
        mock_http.get.return_value = mock_resp

        result = await oidc_service.discover()

        assert result is True
        assert "auth" in oidc_service.config.authorization_endpoint
        assert "token" in oidc_service.config.token_endpoint
        assert "userinfo" in oidc_service.config.userinfo_endpoint

    @pytest.mark.asyncio
    async def test_discovery_failure(
        self, oidc_service: OIDCService, mock_http: AsyncMock,
    ) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_http.get.return_value = mock_resp

        result = await oidc_service.discover()
        assert result is False

    @pytest.mark.asyncio
    async def test_discovery_no_issuer(self, mock_http: AsyncMock) -> None:
        cfg = OIDCConfig(enabled=True, issuer="")
        svc = OIDCService(cfg, mock_http)
        result = await svc.discover()
        assert result is False

    @pytest.mark.asyncio
    async def test_discovery_network_error(
        self, oidc_service: OIDCService, mock_http: AsyncMock,
    ) -> None:
        mock_http.get.side_effect = Exception("network error")
        result = await oidc_service.discover()
        assert result is False


# ---------------------------------------------------------------------------
# OIDCService — Auth URL
# ---------------------------------------------------------------------------

class TestBuildAuthURL:
    def test_build_auth_url(self, oidc_service: OIDCService) -> None:
        oidc_service._config.authorization_endpoint = "https://idp.example.com/auth"
        url = oidc_service.build_auth_url(state="csrf-token", nonce="n123")

        assert "https://idp.example.com/auth?" in url
        assert "response_type=code" in url
        assert "client_id=test-client-id" in url
        assert "state=csrf-token" in url
        assert "nonce=n123" in url
        assert "scope=openid+profile+email" in url

    def test_auth_url_without_nonce(self, oidc_service: OIDCService) -> None:
        oidc_service._config.authorization_endpoint = "https://idp.example.com/auth"
        url = oidc_service.build_auth_url(state="s1")
        assert "nonce" not in url

    def test_auth_url_no_discovery(self, oidc_service: OIDCService) -> None:
        with pytest.raises(RuntimeError, match="OIDC not discovered"):
            oidc_service.build_auth_url(state="s1")


# ---------------------------------------------------------------------------
# OIDCService — Token Exchange
# ---------------------------------------------------------------------------

class TestExchangeCode:
    @pytest.mark.asyncio
    async def test_exchange_with_id_token(
        self, oidc_service: OIDCService, mock_http: AsyncMock,
    ) -> None:
        oidc_service._config.token_endpoint = "https://idp.example.com/token"

        # Create a fake ID token
        id_token = jwt.encode(
            {"sub": "user-1", "email": "u@e.com", "name": "User One", "roles": ["admin"]},
            "secret",
            algorithm="HS256",
        )

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"id_token": id_token, "access_token": "at"}
        mock_http.post.return_value = mock_resp

        user = await oidc_service.exchange_code("auth-code-123")

        assert user is not None
        assert user.sub == "user-1"
        assert user.email == "u@e.com"
        assert user.is_admin is True

    @pytest.mark.asyncio
    async def test_exchange_with_access_token_only(
        self, oidc_service: OIDCService, mock_http: AsyncMock,
    ) -> None:
        oidc_service._config.token_endpoint = "https://idp.example.com/token"
        oidc_service._config.userinfo_endpoint = "https://idp.example.com/userinfo"

        # Token endpoint returns only access_token
        token_resp = MagicMock()
        token_resp.status_code = 200
        token_resp.json.return_value = {"access_token": "at-123"}

        # Userinfo returns profile
        userinfo_resp = MagicMock()
        userinfo_resp.status_code = 200
        userinfo_resp.json.return_value = {"sub": "u2", "email": "x@y.com", "name": "X Y"}

        mock_http.post.return_value = token_resp
        mock_http.get.return_value = userinfo_resp

        user = await oidc_service.exchange_code("code-456")

        assert user is not None
        assert user.sub == "u2"
        assert user.email == "x@y.com"

    @pytest.mark.asyncio
    async def test_exchange_failure(
        self, oidc_service: OIDCService, mock_http: AsyncMock,
    ) -> None:
        oidc_service._config.token_endpoint = "https://idp.example.com/token"
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.text = "invalid_grant"
        mock_http.post.return_value = mock_resp

        user = await oidc_service.exchange_code("bad-code")
        assert user is None

    @pytest.mark.asyncio
    async def test_exchange_no_token_endpoint(
        self, oidc_service: OIDCService,
    ) -> None:
        user = await oidc_service.exchange_code("code")
        assert user is None

    @pytest.mark.asyncio
    async def test_exchange_network_error(
        self, oidc_service: OIDCService, mock_http: AsyncMock,
    ) -> None:
        oidc_service._config.token_endpoint = "https://idp.example.com/token"
        mock_http.post.side_effect = Exception("timeout")
        user = await oidc_service.exchange_code("code")
        assert user is None

    @pytest.mark.asyncio
    async def test_exchange_no_tokens_in_response(
        self, oidc_service: OIDCService, mock_http: AsyncMock,
    ) -> None:
        oidc_service._config.token_endpoint = "https://idp.example.com/token"
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {}  # No tokens
        mock_http.post.return_value = mock_resp

        user = await oidc_service.exchange_code("code")
        assert user is None


# ---------------------------------------------------------------------------
# OIDCService — Provider Detection
# ---------------------------------------------------------------------------

class TestProviderDetection:
    @pytest.mark.parametrize(
        ("issuer", "expected"),
        [
            ("https://login.microsoftonline.com/tenant/v2.0", "azure_ad"),
            ("https://dev-123.okta.com", "okta"),
            ("https://myapp.us.auth0.com", "auth0"),
            ("https://accounts.google.com", "google"),
            ("https://keycloak.example.com/realms/main", "keycloak"),
            ("https://custom-idp.example.com", "oidc"),
        ],
    )
    def test_detect_provider(
        self, oidc_service: OIDCService, issuer: str, expected: str,
    ) -> None:
        oidc_service._config.issuer = issuer
        assert oidc_service._detect_provider() == expected


# ---------------------------------------------------------------------------
# OIDCService — Domain Validation
# ---------------------------------------------------------------------------

class TestDomainValidation:
    def test_no_restrictions(self, oidc_service: OIDCService) -> None:
        assert oidc_service.validate_domain("anyone@any.com") is True

    def test_allowed_domain(self, oidc_service: OIDCService) -> None:
        oidc_service._config.allowed_domains = ["acme.com"]
        assert oidc_service.validate_domain("user@acme.com") is True

    def test_blocked_domain(self, oidc_service: OIDCService) -> None:
        oidc_service._config.allowed_domains = ["acme.com"]
        assert oidc_service.validate_domain("user@evil.com") is False

    def test_case_insensitive_domain(self, oidc_service: OIDCService) -> None:
        oidc_service._config.allowed_domains = ["ACME.COM"]
        assert oidc_service.validate_domain("user@acme.com") is True

    def test_no_at_symbol(self, oidc_service: OIDCService) -> None:
        oidc_service._config.allowed_domains = ["acme.com"]
        assert oidc_service.validate_domain("noemail") is False


# ---------------------------------------------------------------------------
# OIDCService — Properties
# ---------------------------------------------------------------------------

class TestServiceProperties:
    def test_enabled(self, oidc_service: OIDCService) -> None:
        assert oidc_service.enabled is True

    def test_disabled_no_issuer(self, mock_http: AsyncMock) -> None:
        cfg = OIDCConfig(enabled=True, issuer="")
        svc = OIDCService(cfg, mock_http)
        assert svc.enabled is False

    def test_disabled_flag(self, mock_http: AsyncMock) -> None:
        cfg = OIDCConfig(enabled=False, issuer="https://x.com")
        svc = OIDCService(cfg, mock_http)
        assert svc.enabled is False

    def test_config_property(self, oidc_service: OIDCService) -> None:
        assert oidc_service.config.client_id == "test-client-id"


# ---------------------------------------------------------------------------
# OIDCService — Userinfo fetch
# ---------------------------------------------------------------------------

class TestFetchUserinfo:
    @pytest.mark.asyncio
    async def test_fetch_userinfo_success(
        self, oidc_service: OIDCService, mock_http: AsyncMock,
    ) -> None:
        oidc_service._config.userinfo_endpoint = "https://idp.example.com/userinfo"
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "sub": "u3",
            "email": "a@b.com",
            "name": "AB",
            "picture": "https://pic.example.com/ab.png",
        }
        mock_http.get.return_value = mock_resp

        user = await oidc_service._fetch_userinfo("access-token-1")
        assert user is not None
        assert user.sub == "u3"
        assert user.picture == "https://pic.example.com/ab.png"

    @pytest.mark.asyncio
    async def test_fetch_userinfo_no_endpoint(
        self, oidc_service: OIDCService,
    ) -> None:
        user = await oidc_service._fetch_userinfo("at")
        assert user is None

    @pytest.mark.asyncio
    async def test_fetch_userinfo_error(
        self, oidc_service: OIDCService, mock_http: AsyncMock,
    ) -> None:
        oidc_service._config.userinfo_endpoint = "https://idp.example.com/userinfo"
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_http.get.return_value = mock_resp

        user = await oidc_service._fetch_userinfo("bad-token")
        assert user is None

    @pytest.mark.asyncio
    async def test_fetch_userinfo_exception(
        self, oidc_service: OIDCService, mock_http: AsyncMock,
    ) -> None:
        oidc_service._config.userinfo_endpoint = "https://idp.example.com/userinfo"
        mock_http.get.side_effect = Exception("boom")
        user = await oidc_service._fetch_userinfo("at")
        assert user is None


# ---------------------------------------------------------------------------
# OIDCService — ID Token parsing
# ---------------------------------------------------------------------------

class TestParseIdToken:
    def test_parse_roles_as_list(self, oidc_service: OIDCService) -> None:
        token = jwt.encode(
            {"sub": "u1", "email": "a@b.com", "roles": ["admin", "user"]},
            "secret",
            algorithm="HS256",
        )
        user = oidc_service._parse_id_token(token)
        assert user.roles == ["admin", "user"]
        assert user.is_admin is True

    def test_parse_roles_as_string(self, oidc_service: OIDCService) -> None:
        token = jwt.encode(
            {"sub": "u2", "roles": "viewer"},
            "secret",
            algorithm="HS256",
        )
        user = oidc_service._parse_id_token(token)
        assert user.roles == ["viewer"]

    def test_parse_no_roles(self, oidc_service: OIDCService) -> None:
        token = jwt.encode({"sub": "u3"}, "secret", algorithm="HS256")
        user = oidc_service._parse_id_token(token)
        assert user.roles == []

    def test_raw_claims_preserved(self, oidc_service: OIDCService) -> None:
        token = jwt.encode(
            {"sub": "u4", "custom": "value"},
            "secret",
            algorithm="HS256",
        )
        user = oidc_service._parse_id_token(token)
        assert user.raw_claims["custom"] == "value"
