"""Redis-backed cache with TTL support. Gracefully degrades if Redis unavailable."""

import json

import redis.asyncio as redis
import structlog

logger = structlog.get_logger()


class CacheService:
    """Redis-backed cache with TTL support. Gracefully degrades if Redis unavailable."""

    def __init__(self, redis_url: str) -> None:
        """Initialize cache service with Redis URL."""
        self._redis_url = redis_url
        self._client: redis.Redis | None = None

    async def connect(self) -> None:
        """Initialize Redis connection pool."""
        try:
            self._client = redis.from_url(
                self._redis_url,
                decode_responses=True,
                socket_timeout=5,
                socket_connect_timeout=5,
            )
            await self._client.ping()
            logger.info("redis_connected", url=self._redis_url)
        except redis.RedisError as exc:
            logger.warning("redis_connect_failed", error=str(exc))
            self._client = None

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
