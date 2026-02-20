# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""SSO/OIDC authentication service — enterprise identity provider integration.

Supports any OpenID Connect compliant provider:
  - Azure AD / Entra ID
  - Okta
  - Auth0
  - Google Workspace
  - Keycloak
  - OneLogin
  - Generic OIDC

Configuration via environment variables:
    CODETRUST_OIDC_ENABLED=true
    CODETRUST_OIDC_ISSUER=https://login.microsoftonline.com/{tenant}/v2.0
    CODETRUST_OIDC_CLIENT_ID=your-client-id
    CODETRUST_OIDC_CLIENT_SECRET=your-client-secret
    CODETRUST_OIDC_REDIRECT_URI=https://app.codetrust.ai/auth/callback/oidc
    CODETRUST_OIDC_SCOPES=openid,profile,email

Or via .codetrust.toml (project-level):
    [codetrust.sso]
    enabled = true
    provider = "azure_ad"
    issuer = "https://login.microsoftonline.com/{tenant}/v2.0"
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import urlencode

import jwt
import structlog

if TYPE_CHECKING:
    import httpx

logger = structlog.get_logger()


@dataclass
class OIDCConfig:
    """OpenID Connect provider configuration."""

    enabled: bool = False
    issuer: str = ""
    client_id: str = ""
    client_secret: str = ""
    redirect_uri: str = ""
    scopes: list[str] = field(
        default_factory=lambda: ["openid", "profile", "email"]
    )
    # Discovered endpoints (auto-populated from .well-known)
    authorization_endpoint: str = ""
    token_endpoint: str = ""
    userinfo_endpoint: str = ""
    jwks_uri: str = ""
    # Optional
    allowed_domains: list[str] = field(default_factory=list)
    role_claim: str = "roles"  # JWT claim for role mapping
    admin_roles: list[str] = field(
        default_factory=lambda: ["admin", "codetrust_admin"]
    )


@dataclass
class OIDCUser:
    """Normalized user profile from OIDC provider."""

    sub: str  # Subject identifier (unique per provider)
    email: str = ""
    name: str = ""
    picture: str = ""
    roles: list[str] = field(default_factory=list)
    provider: str = ""  # e.g. "azure_ad", "okta"
    raw_claims: dict = field(default_factory=dict)

    @property
    def is_admin(self) -> bool:
        """Check if user has admin role."""
        admin_roles = {"admin", "codetrust_admin"}
        return bool(set(self.roles) & admin_roles)


class OIDCService:
    """OpenID Connect authentication service.

    Implements the Authorization Code Flow:
    1. build_auth_url() → redirect user to IdP
    2. User authenticates at IdP
    3. exchange_code() → exchange auth code for tokens
    4. get_user_info() → extract user profile from ID token

    Usage:
        oidc = OIDCService(config, http_client)
        await oidc.discover()  # fetch .well-known endpoints

        url = oidc.build_auth_url(state="random-state")
        # redirect user to url...

        # After callback:
        user = await oidc.exchange_code(code, state)
    """

    def __init__(self, config: OIDCConfig, http_client: httpx.AsyncClient):
        self._config = config
        self._http = http_client
        self._jwks: dict | None = None
        self._jwks_fetched_at: float = 0
        self._discovered = False

    @property
    def config(self) -> OIDCConfig:
        return self._config

    @property
    def enabled(self) -> bool:
        return self._config.enabled and bool(self._config.issuer)

    async def discover(self) -> bool:
        """Fetch OIDC provider endpoints from .well-known/openid-configuration.

        Returns True if discovery succeeded.
        """
        if not self._config.issuer:
            logger.warning("oidc_no_issuer")
            return False

        well_known = f"{self._config.issuer.rstrip('/')}/.well-known/openid-configuration"

        try:
            resp = await self._http.get(well_known, timeout=10)
            if resp.status_code != 200:
                logger.error("oidc_discovery_failed", status=resp.status_code)
                return False

            data = resp.json()
            self._config.authorization_endpoint = data.get(
                "authorization_endpoint", ""
            )
            self._config.token_endpoint = data.get("token_endpoint", "")
            self._config.userinfo_endpoint = data.get("userinfo_endpoint", "")
            self._config.jwks_uri = data.get("jwks_uri", "")

            self._discovered = True
            logger.info(
                "oidc_discovered",
                issuer=self._config.issuer,
                auth_endpoint=self._config.authorization_endpoint[:60],
            )
            return True

        except Exception:
            logger.exception("oidc_discovery_error")
            return False

    def build_auth_url(self, state: str, nonce: str = "") -> str:
        """Build the authorization URL to redirect the user to the IdP.

        Args:
            state: CSRF protection state token.
            nonce: Optional nonce for ID token validation.

        Returns:
            Full authorization URL.
        """
        if not self._config.authorization_endpoint:
            msg = "OIDC not discovered — call discover() first"
            raise RuntimeError(msg)

        params = {
            "response_type": "code",
            "client_id": self._config.client_id,
            "redirect_uri": self._config.redirect_uri,
            "scope": " ".join(self._config.scopes),
            "state": state,
        }
        if nonce:
            params["nonce"] = nonce

        return f"{self._config.authorization_endpoint}?{urlencode(params)}"

    async def _request_tokens(
        self, code: str,
    ) -> dict[str, str] | None:
        """Exchange authorization code for token response data."""
        resp = await self._http.post(
            self._config.token_endpoint,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self._config.redirect_uri,
                "client_id": self._config.client_id,
                "client_secret": self._config.client_secret,
            },
            headers={"Accept": "application/json"},
        )
        if resp.status_code != 200:
            logger.error(
                "oidc_token_exchange_failed",
                status=resp.status_code,
                body=resp.text[:200],
            )
            return None
        return resp.json()

    async def exchange_code(self, code: str) -> OIDCUser | None:
        """Exchange authorization code for tokens and return user info.

        Args:
            code: Authorization code from the IdP callback.

        Returns:
            OIDCUser or None if exchange failed.
        """
        if not self._config.token_endpoint:
            logger.error("oidc_no_token_endpoint")
            return None

        try:
            data = await self._request_tokens(code)
            if data is None:
                return None

            id_token = data.get("id_token", "")
            access_token = data.get("access_token", "")

            if id_token:
                return self._parse_id_token(id_token)
            if access_token:
                return await self._fetch_userinfo(access_token)

            logger.error("oidc_no_tokens")
            return None
        except Exception:
            logger.exception("oidc_exchange_error")
            return None

    def _parse_id_token(self, id_token: str) -> OIDCUser:
        """Parse an ID token without full verification (trusting TLS).

        In production, verify signature against JWKS. For now we decode
        without verification since the token came over HTTPS from the IdP.
        """
        claims = jwt.decode(
            id_token,
            options={"verify_signature": False},
            algorithms=["RS256", "HS256"],
        )

        roles = claims.get(self._config.role_claim, [])
        if isinstance(roles, str):
            roles = [roles]

        return OIDCUser(
            sub=claims.get("sub", ""),
            email=claims.get("email", ""),
            name=claims.get("name", ""),
            picture=claims.get("picture", ""),
            roles=roles,
            provider=self._detect_provider(),
            raw_claims=claims,
        )

    async def _fetch_userinfo(self, access_token: str) -> OIDCUser | None:
        """Fetch user info from the userinfo endpoint."""
        if not self._config.userinfo_endpoint:
            return None

        try:
            resp = await self._http.get(
                self._config.userinfo_endpoint,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            if resp.status_code != 200:
                return None

            data = resp.json()
            return OIDCUser(
                sub=data.get("sub", ""),
                email=data.get("email", ""),
                name=data.get("name", ""),
                picture=data.get("picture", ""),
                provider=self._detect_provider(),
                raw_claims=data,
            )
        except Exception:
            logger.exception("oidc_userinfo_error")
            return None

    def _detect_provider(self) -> str:
        """Detect the OIDC provider from the issuer URL."""
        issuer = self._config.issuer.lower()
        if "microsoftonline" in issuer or "login.microsoft" in issuer:
            return "azure_ad"
        if "okta" in issuer:
            return "okta"
        if "auth0" in issuer:
            return "auth0"
        if "accounts.google" in issuer:
            return "google"
        if "keycloak" in issuer:
            return "keycloak"
        return "oidc"

    def validate_domain(self, email: str) -> bool:
        """Check if user's email domain is in the allowed list.

        If allowed_domains is empty, all domains are accepted.
        """
        if not self._config.allowed_domains:
            return True
        domain = email.rsplit("@", 1)[-1].lower() if "@" in email else ""
        return domain in [d.lower() for d in self._config.allowed_domains]
