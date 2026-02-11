"""Tests for RateLimiter — plan-based daily rate limiting."""

from unittest.mock import AsyncMock

import pytest

from src.services.billing import PLAN_LIMITS
from src.services.rate_limiter import RateLimiter


@pytest.fixture()
def mock_db() -> AsyncMock:
    """Create a mock DatabaseService."""
    db = AsyncMock()
    db.get_daily_usage = AsyncMock(return_value=0)
    db.increment_daily_usage = AsyncMock()
    return db


@pytest.fixture()
def rate_limiter(mock_db: AsyncMock) -> RateLimiter:
    """Create a RateLimiter with mock DB."""
    return RateLimiter(mock_db)


# --- Rate limit checks ---


class TestCheckLimit:
    """Test rate limit checking logic."""

    async def test_free_tier_allowed_when_under_limit(
        self, rate_limiter: RateLimiter, mock_db: AsyncMock,
    ) -> None:
        """Free tier user under limit should be allowed."""
        mock_db.get_daily_usage.return_value = 50
        allowed, current, limit = await rate_limiter.check_limit("user1", "free")
        assert allowed is True
        assert current == 50
        assert limit == PLAN_LIMITS["free"]

    async def test_free_tier_blocked_at_limit(
        self, rate_limiter: RateLimiter, mock_db: AsyncMock,
    ) -> None:
        """Free tier user at limit should be blocked."""
        mock_db.get_daily_usage.return_value = 100
        allowed, current, limit = await rate_limiter.check_limit("user1", "free")
        assert allowed is False
        assert current == 100
        assert limit == 100

    async def test_free_tier_blocked_over_limit(
        self, rate_limiter: RateLimiter, mock_db: AsyncMock,
    ) -> None:
        """Free tier user over limit should be blocked."""
        mock_db.get_daily_usage.return_value = 150
        allowed, _current, _limit = await rate_limiter.check_limit("user1", "free")
        assert allowed is False

    async def test_pro_tier_high_limit(
        self, rate_limiter: RateLimiter, mock_db: AsyncMock,
    ) -> None:
        """Pro tier has 10K daily limit."""
        mock_db.get_daily_usage.return_value = 5000
        allowed, _current, limit = await rate_limiter.check_limit("user1", "pro")
        assert allowed is True
        assert limit == PLAN_LIMITS["pro"]

    async def test_pro_tier_blocked_at_limit(
        self, rate_limiter: RateLimiter, mock_db: AsyncMock,
    ) -> None:
        """Pro tier user at limit should be blocked."""
        mock_db.get_daily_usage.return_value = 10_000
        allowed, _current, limit = await rate_limiter.check_limit("user1", "pro")
        assert allowed is False
        assert limit == 10_000

    async def test_enterprise_tier_very_high_limit(
        self, rate_limiter: RateLimiter, mock_db: AsyncMock,
    ) -> None:
        """Enterprise tier has 100K daily limit."""
        mock_db.get_daily_usage.return_value = 50_000
        allowed, _current, limit = await rate_limiter.check_limit("user1", "enterprise")
        assert allowed is True
        assert limit == PLAN_LIMITS["enterprise"]

    async def test_unknown_plan_defaults_to_free(
        self, rate_limiter: RateLimiter, mock_db: AsyncMock,
    ) -> None:
        """Unknown plan defaults to free tier limit."""
        mock_db.get_daily_usage.return_value = 99
        allowed, _current, limit = await rate_limiter.check_limit("user1", "unknown_plan")
        assert allowed is True
        assert limit == PLAN_LIMITS["free"]

    async def test_zero_usage_always_allowed(
        self, rate_limiter: RateLimiter, mock_db: AsyncMock,
    ) -> None:
        """Zero usage is always allowed regardless of plan."""
        mock_db.get_daily_usage.return_value = 0
        allowed, current, _limit = await rate_limiter.check_limit("user1", "free")
        assert allowed is True
        assert current == 0


# --- Usage increment ---


class TestIncrement:
    """Test usage increment operations."""

    async def test_increment_calls_db(
        self, rate_limiter: RateLimiter, mock_db: AsyncMock,
    ) -> None:
        """Increment should call DB increment_daily_usage."""
        await rate_limiter.increment("user1", findings_count=5, latency_ms=100)
        mock_db.increment_daily_usage.assert_called_once_with("user1", 5, 100)

    async def test_increment_default_args(
        self, rate_limiter: RateLimiter, mock_db: AsyncMock,
    ) -> None:
        """Increment with defaults passes zeros."""
        await rate_limiter.increment("user1")
        mock_db.increment_daily_usage.assert_called_once_with("user1", 0, 0)


# --- Plan limits ---


class TestPlanLimits:
    """Test plan limit lookup."""

    def test_free_limit(self, rate_limiter: RateLimiter) -> None:
        """Free tier limit is 100."""
        assert rate_limiter._get_limit("free") == 100

    def test_pro_limit(self, rate_limiter: RateLimiter) -> None:
        """Pro tier limit is 10,000."""
        assert rate_limiter._get_limit("pro") == 10_000

    def test_enterprise_limit(self, rate_limiter: RateLimiter) -> None:
        """Enterprise tier limit is 100,000."""
        assert rate_limiter._get_limit("enterprise") == 100_000

    def test_unknown_plan_defaults(self, rate_limiter: RateLimiter) -> None:
        """Unknown plan defaults to free limit."""
        assert rate_limiter._get_limit("nonexistent") == 100
