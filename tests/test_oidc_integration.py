"""OIDC integration test — tests the full OAuth2 Authorization Code Flow
against a mock OIDC provider implemented as an HTTP mock transport.

Unlike unit tests that mock individual methods, this test validates:
1. Discovery of .well-known/openid-configuration
2. Authorization URL construction
3. Token exchange with authorization code
4. ID token parsing and user extraction
5. Domain validation
"""

from __future__ import annotations

import time
from http import HTTPStatus
from typing import Any

import httpx
import jwt
import pytest

from src.services.sso import OIDCConfig, OIDCService, OIDCUser

# ---------------------------------------------------------------------------
# Mock OIDC Provider
# ---------------------------------------------------------------------------

ISSUER = "https://idp.example.com"
CLIENT_ID = "test-client-id"
OIDC_TEST_VALUE = "test-client-value"
REDIRECT_URI = "https://app.codetrust.ai/auth/callback/oidc"

# RSA-less: we use HS256 for test simplicity (symmetric key = client_secret)
SIGNING_KEY = OIDC_TEST_VALUE


def _make_id_token(claims: dict[str, Any] | None = None) -> str:
    """Create a signed JWT ID token."""
    payload = {
        "iss": ISSUER,
        "sub": "user-12345",
        "aud": CLIENT_ID,
        "exp": int(time.time()) + 3600,  # noqa: magic_number
        "iat": int(time.time()),
        "email": "alice@codetrust.ai",
        "name": "Alice Tester",
        "picture": "https://example.com/avatar.jpg",
        "roles": ["developer", "admin"],
    }
    if claims:
        payload.update(claims)
    return jwt.encode(payload, SIGNING_KEY, algorithm="HS256")


class MockOIDCTransport(httpx.AsyncBaseTransport):
    """Mock HTTP transport that simulates an OIDC provider."""

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)

        # Discovery endpoint
        if "/.well-known/openid-configuration" in url:
            return httpx.Response(
                HTTPStatus.OK,
                json={
                    "issuer": ISSUER,
                    "authorization_endpoint": f"{ISSUER}/authorize",
                    "token_endpoint": f"{ISSUER}/token",
                    "userinfo_endpoint": f"{ISSUER}/userinfo",
                    "jwks_uri": f"{ISSUER}/.well-known/jwks.json",
                    "response_types_supported": ["code"],
                    "subject_types_supported": ["public"],
                    "id_token_signing_alg_values_supported": ["RS256", "HS256"],
                },
            )

        # Token endpoint
        if url.endswith("/token"):
            body = request.content.decode()
            if "code=valid_code" in body:
                return httpx.Response(
                    HTTPStatus.OK,
                    json={
                        "access_token": "mock-access-token",
                        "token_type": "Bearer",
                        "expires_in": 3600,  # noqa: magic_number
                        "id_token": _make_id_token(),
                    },
                )
            if "code=no_tokens" in body:
                return httpx.Response(
                    HTTPStatus.OK,
                    json={"error": "no tokens returned"},
                )
            if "code=access_only" in body:
                return httpx.Response(
                    HTTPStatus.OK,
                    json={
                        "access_token": "mock-access-token",
                        "token_type": "Bearer",
                        "expires_in": 3600,  # noqa: magic_number
                    },
                )
            return httpx.Response(HTTPStatus.BAD_REQUEST, json={"error": "invalid_grant"})

        # Userinfo endpoint
        if url.endswith("/userinfo"):
            auth = request.headers.get("authorization", "")
            if "mock-access-token" in auth:
                return httpx.Response(
                    HTTPStatus.OK,
                    json={
                        "sub": "user-12345",
                        "email": "alice@codetrust.ai",
                        "name": "Alice Tester",
                        "picture": "https://example.com/avatar.jpg",
                    },
                )
            return httpx.Response(HTTPStatus.UNAUTHORIZED, json={"error": "unauthorized"})

        return httpx.Response(HTTPStatus.NOT_FOUND, json={"error": "not_found"})


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def oidc_config() -> OIDCConfig:
    """Standard OIDC config for testing."""
    return OIDCConfig(
        enabled=True,
        issuer=ISSUER,
        client_id=CLIENT_ID,
        client_secret=OIDC_TEST_VALUE,
        redirect_uri=REDIRECT_URI,
        scopes=["openid", "profile", "email"],
        allowed_domains=["codetrust.ai"],
    )


@pytest.fixture()
async def oidc_service(oidc_config: OIDCConfig) -> OIDCService:
    """OIDCService wired to mock transport (full integration)."""
    http_client = httpx.AsyncClient(transport=MockOIDCTransport())
    service = OIDCService(oidc_config, http_client)
    return service


# ---------------------------------------------------------------------------
# Integration tests — full OIDC flow
# ---------------------------------------------------------------------------


class TestOIDCDiscovery:
    @pytest.mark.asyncio()
    async def test_discover_succeeds(self, oidc_service: OIDCService) -> None:
        result = await oidc_service.discover()
        assert result is True
        assert oidc_service.config.authorization_endpoint == f"{ISSUER}/authorize"
        assert oidc_service.config.token_endpoint == f"{ISSUER}/token"
        assert oidc_service.config.userinfo_endpoint == f"{ISSUER}/userinfo"
        assert oidc_service.config.jwks_uri == f"{ISSUER}/.well-known/jwks.json"

    @pytest.mark.asyncio()
    async def test_discover_no_issuer(self) -> None:
        config = OIDCConfig(enabled=True, issuer="")
        http = httpx.AsyncClient(transport=MockOIDCTransport())
        svc = OIDCService(config, http)
        result = await svc.discover()
        assert result is False

    @pytest.mark.asyncio()
    async def test_discover_bad_status(self) -> None:
        """Discovery fails on non-200 responses."""

        class BadTransport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, req):
                return httpx.Response(503, text="down")

        config = OIDCConfig(enabled=True, issuer="https://down.example.com")
        http = httpx.AsyncClient(transport=BadTransport())
        svc = OIDCService(config, http)
        assert await svc.discover() is False


class TestOIDCAuthURL:
    @pytest.mark.asyncio()
    async def test_build_auth_url(self, oidc_service: OIDCService) -> None:
        await oidc_service.discover()
        url = oidc_service.build_auth_url(state="csrf-token", nonce="nonce-123")
        assert f"{ISSUER}/authorize" in url
        assert f"client_id={CLIENT_ID}" in url
        assert "state=csrf-token" in url
        assert "nonce=nonce-123" in url
        assert "scope=openid+profile+email" in url

    @pytest.mark.asyncio()
    async def test_build_auth_url_without_discovery_raises(
        self, oidc_service: OIDCService,
    ) -> None:
        with pytest.raises(RuntimeError, match="not discovered"):
            oidc_service.build_auth_url(state="x")


class TestOIDCTokenExchange:
    @pytest.mark.asyncio()
    async def test_exchange_valid_code(self, oidc_service: OIDCService) -> None:
        await oidc_service.discover()
        user = await oidc_service.exchange_code("valid_code")
        assert user is not None
        assert user.sub == "user-12345"
        assert user.email == "alice@codetrust.ai"
        assert user.name == "Alice Tester"
        assert "admin" in user.roles

    @pytest.mark.asyncio()
    async def test_exchange_invalid_code(self, oidc_service: OIDCService) -> None:
        await oidc_service.discover()
        user = await oidc_service.exchange_code("invalid_code")
        assert user is None

    @pytest.mark.asyncio()
    async def test_exchange_no_tokens(self, oidc_service: OIDCService) -> None:
        await oidc_service.discover()
        user = await oidc_service.exchange_code("no_tokens")
        assert user is None

    @pytest.mark.asyncio()
    async def test_exchange_access_token_only(self, oidc_service: OIDCService) -> None:
        """Falls back to userinfo endpoint when no id_token."""
        await oidc_service.discover()
        user = await oidc_service.exchange_code("access_only")
        assert user is not None
        assert user.email == "alice@codetrust.ai"

    @pytest.mark.asyncio()
    async def test_exchange_no_token_endpoint(self, oidc_service: OIDCService) -> None:
        # Don't discover — token_endpoint is empty
        user = await oidc_service.exchange_code("valid_code")
        assert user is None


class TestOIDCDomainValidation:
    def test_allowed_domain(self, oidc_service: OIDCService) -> None:
        assert oidc_service.validate_domain("alice@codetrust.ai") is True

    def test_blocked_domain(self, oidc_service: OIDCService) -> None:
        assert oidc_service.validate_domain("alice@evil.com") is False

    def test_empty_allowed_domains_accepts_all(self) -> None:
        config = OIDCConfig(enabled=True, issuer=ISSUER, allowed_domains=[])
        http = httpx.AsyncClient(transport=MockOIDCTransport())
        svc = OIDCService(config, http)
        assert svc.validate_domain("any@domain.com") is True

    def test_no_at_sign(self, oidc_service: OIDCService) -> None:
        assert oidc_service.validate_domain("no-at-sign") is False


class TestOIDCProviderDetection:
    def _make_service(self, issuer: str) -> OIDCService:
        config = OIDCConfig(enabled=True, issuer=issuer)
        http = httpx.AsyncClient(transport=MockOIDCTransport())
        return OIDCService(config, http)

    def test_azure(self) -> None:
        svc = self._make_service("https://login.microsoftonline.com/tenant/v2.0")
        assert svc._detect_provider() == "azure_ad"

    def test_okta(self) -> None:
        svc = self._make_service("https://dev-123.okta.com")
        assert svc._detect_provider() == "okta"

    def test_auth0(self) -> None:
        svc = self._make_service("https://myapp.auth0.com")
        assert svc._detect_provider() == "auth0"

    def test_google(self) -> None:
        svc = self._make_service("https://accounts.google.com")
        assert svc._detect_provider() == "google"

    def test_keycloak(self) -> None:
        svc = self._make_service("https://keycloak.example.com/realms/main")
        assert svc._detect_provider() == "keycloak"

    def test_generic(self) -> None:
        svc = self._make_service("https://idp.custom.com")
        assert svc._detect_provider() == "oidc"


class TestOIDCUserModel:
    def test_is_admin_true(self) -> None:
        user = OIDCUser(sub="1", email="a@b.com", roles=["admin", "dev"])
        assert user.is_admin is True

    def test_is_admin_false(self) -> None:
        user = OIDCUser(sub="1", email="a@b.com", roles=["viewer"])
        assert user.is_admin is False

    def test_is_admin_empty(self) -> None:
        user = OIDCUser(sub="1", email="a@b.com")
        assert user.is_admin is False

    def test_enabled_property(self) -> None:
        config = OIDCConfig(enabled=True, issuer="https://x.com")
        http = httpx.AsyncClient(transport=MockOIDCTransport())
        svc = OIDCService(config, http)
        assert svc.enabled is True

    def test_disabled_property(self) -> None:
        config = OIDCConfig(enabled=False, issuer="https://x.com")
        http = httpx.AsyncClient(transport=MockOIDCTransport())
        svc = OIDCService(config, http)
        assert svc.enabled is False
