# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Redis-backed cache with TTL support. Gracefully degrades if Redis unavailable."""

import asyncio
import json
from urllib.parse import urlsplit, urlunsplit

import redis.asyncio as redis
import structlog

logger = structlog.get_logger()

REDIS_CONNECT_RETRIES: int = 3
REDIS_RETRY_DELAY_SECONDS: int = 2


class CacheService:
    """Redis-backed cache with TTL support. Gracefully degrades if Redis unavailable."""

    def __init__(self, redis_url: str) -> None:
        """Initialize cache service with Redis URL."""
        self._redis_url = redis_url
        self._client: redis.Redis | None = None

    def _redis_url_candidates(self) -> list[str]:
        """Build prioritized Redis URL candidates for startup connection."""
        candidates: list[str] = [self._redis_url]
        try:
            parsed = urlsplit(self._redis_url)
            is_railway_internal = parsed.hostname == "redis.railway.internal"
            has_credentials = parsed.username is not None or parsed.password is not None
            if is_railway_internal and not has_credentials:
                netloc = f"default:@{parsed.hostname}"
                if parsed.port is not None:
                    netloc = f"{netloc}:{parsed.port}"
                fallback = urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))
                if fallback not in candidates:
                    candidates.append(fallback)
        except Exception:
            # Keep primary URL only if parsing unexpectedly fails.
            return candidates
        return candidates

    async def connect(self) -> None:
        """Initialize Redis connection pool."""
        candidates = self._redis_url_candidates()
        total_attempts = REDIS_CONNECT_RETRIES + 1
        for url in candidates:
            for attempt in range(1, total_attempts + 1):
                try:
                    logger.warning(
                        "redis_connect_attempt",
                        url=url,
                        attempt=attempt,
                        max_attempts=total_attempts,
                    )
                    self._client = redis.from_url(
                        url,
                        decode_responses=True,
                        socket_timeout=5,
                        socket_connect_timeout=5,
                    )
                    await self._client.ping()
                    self._redis_url = url
                    logger.warning("redis_connected", url=url, attempt=attempt)
                    return
                except redis.RedisError as exc:
                    logger.warning(
                        "redis_connect_failed",
                        url=url,
                        attempt=attempt,
                        max_attempts=total_attempts,
                        error=str(exc),
                    )
                    self._client = None
                    if attempt < total_attempts:
                        await asyncio.sleep(REDIS_RETRY_DELAY_SECONDS)
        logger.warning("redis_connection_unavailable", tried_urls=candidates)

    def raw_client(self) -> redis.Redis | None:
        """Return the underlying redis client (or None if unavailable)."""

        return self._client

    async def disconnect(self) -> None:
        """Close Redis connection pool."""
        if self._client is not None:
            try:
                await self._client.aclose()
                logger.info("redis_disconnected")
            except redis.RedisError as exc:
                logger.warning("redis_disconnect_error", error=str(exc))
            finally:
                self._client = None

    async def get(self, key: str) -> str | None:
        """Get cached value. Returns None on miss or Redis error."""
        if self._client is None:
            return None
        try:
            return await self._client.get(key)
        except redis.RedisError as exc:
            logger.warning("redis_get_error", key=key, error=str(exc))
            return None

    async def set(self, key: str, value: str, ttl: int) -> None:
        """Set cached value with TTL. Silently fails if Redis unavailable."""
        if self._client is None:
            return
        try:
            await self._client.set(key, value, ex=ttl)
        except redis.RedisError as exc:
            logger.warning("redis_set_error", key=key, error=str(exc))

    async def get_json(self, key: str) -> dict[str, str | bool | int | float] | None:
        """Get and deserialize JSON. Returns None on miss."""
        raw = await self.get(key)
        if raw is None:
            return None
        try:
            result: dict[str, str | bool | int | float] = json.loads(raw)
            return result
        except (json.JSONDecodeError, TypeError) as exc:
            logger.warning("redis_json_decode_error", key=key, error=str(exc))
            return None

    async def set_json(
        self, key: str, data: dict[str, str | bool | int | float], ttl: int
    ) -> None:
        """Serialize and cache JSON with TTL."""
        try:
            raw = json.dumps(data)
        except (TypeError, ValueError) as exc:
            logger.warning("redis_json_encode_error", key=key, error=str(exc))
            return
        await self.set(key, raw, ttl)

    def _make_key(self, namespace: str, identifier: str) -> str:
        """Build cache key: 'codetrust:{namespace}:{identifier}'."""
        return f"codetrust:{namespace}:{identifier}"

    async def is_connected(self) -> bool:
        """Check if Redis is reachable."""
        if self._client is None:
            return False
        try:
            await self._client.ping()
            return True
        except redis.RedisError:
            return False
