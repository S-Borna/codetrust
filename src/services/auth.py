# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Authentication service for GitHub OAuth and JWT token management."""

import datetime
import hashlib

import httpx
import jwt
import structlog

from src.config import settings

logger = structlog.get_logger()

JWT_REVOKE_PREFIX: str = "jwt:revoked:"
JWT_REVOKE_TTL_SECS: int = settings.jwt_expire_minutes * 60 + 60  # token TTL + margin


class AuthService:
    """Handles GitHub OAuth flow and JWT token lifecycle."""

    def __init__(
        self,
        http_client: httpx.AsyncClient,
        cache: object | None = None,
    ) -> None:
        """Initialize with shared HTTP client and optional cache for revocation."""
        self._http = http_client
        self._cache = cache  # CacheService instance (optional)
        self._configured = bool(
            settings.github_client_id and settings.github_client_secret,
        )

    def is_configured(self) -> bool:
        """Check if GitHub OAuth credentials are set."""
        return self._configured

    def jwt_configured(self) -> bool:
        """Check if JWT secret is set for token operations."""
        return bool(settings.jwt_secret)

    async def exchange_github_code(self, code: str) -> dict[str, str]:
        """Exchange GitHub OAuth code for user info.

        Returns dict with github_id, email, name, avatar_url.
        Returns empty dict on failure.
        """
        if not self._configured:
            logger.error("oauth_not_configured")
            return {}

        token = await self._fetch_access_token(code)
        if not token:
            return {}

        return await self._fetch_github_user(token)

    async def _fetch_access_token(self, code: str) -> str:
        """Exchange OAuth code for GitHub access token."""
        try:
            resp = await self._http.post(
                settings.github_token_url,
                json={
                    "client_id": settings.github_client_id,
                    "client_secret": settings.github_client_secret,
                    "code": code,
                },
                headers={"Accept": "application/json"},
            )
            data = resp.json()
            token = data.get("access_token", "")
            if not token:
                logger.error("oauth_no_token", error=data.get("error", ""))
            return token
        except (httpx.HTTPError, ValueError) as exc:
            logger.error("oauth_token_exchange_failed", error=str(exc))
            return ""

    async def _fetch_github_user(self, access_token: str) -> dict[str, str]:
        """Fetch GitHub user profile with access token."""
        try:
            resp = await self._http.get(
                settings.github_user_url,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            data = resp.json()
            return {
                "github_id": str(data.get("id", "")),
                "email": data.get("email", "") or "",
                "name": data.get("name", "") or "",
                "avatar_url": data.get("avatar_url", "") or "",
            }
        except (httpx.HTTPError, ValueError) as exc:
            logger.error("oauth_user_fetch_failed", error=str(exc))
            return {}

    def create_jwt(self, user_id: str, plan: str) -> str:
        """Create a signed JWT token for dashboard sessions.

        Args:
            user_id: The user's database ID.
            plan: The user's plan tier (free/pro/enterprise).

        Returns:
            Encoded JWT string.
        """
        now = datetime.datetime.now(datetime.UTC)
        payload = {
            "sub": user_id,
            "plan": plan,
            "iat": now,
            "exp": now + datetime.timedelta(minutes=settings.jwt_expire_minutes),
        }
        return jwt.encode(
            payload, settings.jwt_secret, algorithm=settings.jwt_algorithm,
        )

    async def revoke_jwt(self, token: str) -> bool:
        """Revoke a JWT token by adding its hash to the Redis blacklist.

        Returns True if revoked successfully, False if cache unavailable.
        """
        if self._cache is None:
            logger.warning("jwt_revoke_no_cache", message="Cannot revoke — no cache available")
            return False
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        try:
            await self._cache.set(
                f"{JWT_REVOKE_PREFIX}{token_hash}", "1", JWT_REVOKE_TTL_SECS,
            )
            logger.info("jwt_revoked", token_hash=token_hash[:12])
            return True
        except Exception as exc:
            logger.error("jwt_revoke_failed", error=str(exc))
            return False

    async def is_token_revoked(self, token: str) -> bool:
        """Check if a JWT token has been revoked."""
        if self._cache is None:
            return False
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        try:
            result = await self._cache.get(f"{JWT_REVOKE_PREFIX}{token_hash}")
            return result is not None
        except Exception:
            return False

    def decode_jwt(self, token: str) -> dict[str, str] | None:
        """Decode and validate a JWT token.

        Returns dict with user_id and plan, or None if invalid.
        """
        try:
            payload = jwt.decode(
                token,
                settings.jwt_secret,
                algorithms=[settings.jwt_algorithm],
            )
            return {
                "user_id": payload.get("sub", ""),
                "plan": payload.get("plan", "free"),
            }
        except jwt.ExpiredSignatureError:
            logger.warning("jwt_expired")
            return None
        except jwt.InvalidTokenError as exc:
            logger.warning("jwt_invalid", error=str(exc))
            return None
