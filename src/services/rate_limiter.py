"""Rate limiting service based on plan tiers and daily usage."""

import structlog

from src.services.billing import PLAN_LIMITS
from src.services.database import DatabaseService

logger = structlog.get_logger()


class RateLimiter:
    """Enforces daily scan rate limits based on user plan tier."""

    def __init__(self, db: DatabaseService) -> None:
        """Initialize with database service for usage lookups."""
        self._db = db

    async def check_limit(
        self, user_id: str, plan: str,
    ) -> tuple[bool, int, int]:
        """Check if user is within their daily rate limit.

        Args:
            user_id: The user's database ID.
            plan: The user's plan tier (free/pro/enterprise).

        Returns:
            Tuple of (allowed, current_usage, daily_limit).
        """
        limit = self._get_limit(plan)
        current = await self._db.get_daily_usage(user_id)

        if current >= limit:
            logger.warning(
                "rate_limit_exceeded",
                user_id=user_id,
                plan=plan,
                usage=current,
                limit=limit,
            )
            return False, current, limit

        return True, current, limit

    async def increment(
        self,
        user_id: str,
        findings_count: int = 0,
        latency_ms: int = 0,
    ) -> None:
        """Increment daily usage counter after a scan.

        Args:
            user_id: The user's database ID.
            findings_count: Number of findings from the scan.
            latency_ms: Latency of the scan in milliseconds.
        """
        await self._db.increment_daily_usage(
            user_id, findings_count, latency_ms,
        )

    def _get_limit(self, plan: str) -> int:
        """Look up the daily scan limit for a plan tier."""
        default_limit = PLAN_LIMITS.get("free", 100)
        return PLAN_LIMITS.get(plan, default_limit)
