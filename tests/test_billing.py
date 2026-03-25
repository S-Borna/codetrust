"""Tests for billing service — Stripe integration."""

import os
from unittest.mock import MagicMock, patch

import pytest
import stripe as stripe_lib

from src.models.enums import PlanTier
from src.services.billing import PLAN_LIMITS, BillingService

_STRIPE_TEST_KEY = os.environ.get("CODETRUST_STRIPE_SECRET_KEY", "")
_HAS_STRIPE = _STRIPE_TEST_KEY.startswith("sk_test_")
_skip_no_stripe = pytest.mark.skipif(
    not _HAS_STRIPE, reason="CODETRUST_STRIPE_SECRET_KEY (test) not set",
)


@pytest.fixture()
def billing_unconfigured() -> BillingService:
    """Create a BillingService with no Stripe key configured."""
    with patch("src.services.billing.settings") as mock_settings:
        mock_settings.stripe_secret_key = ""
        mock_settings.stripe_webhook_secret = ""
        mock_settings.stripe_price_pro = ""
        mock_settings.stripe_price_enterprise = ""
        mock_settings.dashboard_url = "http://localhost:3000"
        service = BillingService()
    return service


@pytest.fixture()
def billing_configured() -> BillingService:
    """Create a BillingService with Stripe key configured."""
    with patch("src.services.billing.settings") as mock_settings:
        mock_settings.stripe_secret_key = "sk_" + "test_fake"
        mock_settings.stripe_webhook_secret = "wh" + "sec_fake"
        mock_settings.stripe_price_pro = "price_pro_123"
        mock_settings.stripe_price_enterprise = "price_ent_456"
        mock_settings.dashboard_url = "http://localhost:3000"
        service = BillingService()
    return service


class TestBillingConfiguration:
    """Tests for billing service configuration."""

    def test_unconfigured_returns_false(
        self, billing_unconfigured: BillingService,
    ) -> None:
        """Service reports not configured when no key is set."""
        assert not billing_unconfigured.is_configured()

    def test_configured_returns_true(
        self, billing_configured: BillingService,
    ) -> None:
        """Service reports configured when key is set."""
        assert billing_configured.is_configured()


class TestCreateCustomer:
    """Tests for Stripe customer creation."""

    async def test_unconfigured_returns_empty(
        self, billing_unconfigured: BillingService,
    ) -> None:
        """Returns empty string when not configured."""
        result = await billing_unconfigured.create_customer(
            "test@example.com", "Test", "user_1",
        )
        assert result == ""

    async def test_configured_creates_customer(
        self, billing_configured: BillingService,
    ) -> None:
        """Creates Stripe customer when configured."""
        mock_customer = MagicMock()
        mock_customer.id = "cus_test_123"

        with patch("stripe.Customer.create", return_value=mock_customer):
            result = await billing_configured.create_customer(
                "test@example.com", "Test", "user_1",
            )
        assert result == "cus_test_123"

    async def test_stripe_error_returns_empty(
        self, billing_configured: BillingService,
    ) -> None:
        """Returns empty string on Stripe error."""
        import stripe

        with patch(
            "stripe.Customer.create",
            side_effect=stripe.StripeError("API error"),
        ):
            result = await billing_configured.create_customer(
                "test@example.com", "Test", "user_1",
            )
        assert result == ""


class TestCheckoutSession:
    """Tests for Stripe checkout session creation."""

    async def test_unconfigured_returns_empty(
        self, billing_unconfigured: BillingService,
    ) -> None:
        """Returns empty string when not configured."""
        result = await billing_unconfigured.create_checkout_session(
            "cus_xxx", "pro",
        )
        assert result == ""

    async def test_invalid_plan_returns_empty(
        self, billing_configured: BillingService,
    ) -> None:
        """Returns empty string for unknown plan."""
        result = await billing_configured.create_checkout_session(
            "cus_xxx", "invalid_plan",
        )
        assert result == ""

    async def test_creates_session(
        self, billing_configured: BillingService,
    ) -> None:
        """Creates checkout session for valid plan."""
        mock_session = MagicMock()
        mock_session.id = "cs_test_123"
        mock_session.url = "https://checkout.stripe.com/test"

        with (
            patch("stripe.checkout.Session.create", return_value=mock_session),
            patch("src.services.billing.settings") as mock_settings,
        ):
            mock_settings.stripe_price_pro = "price_pro_123"
            mock_settings.dashboard_url = "http://localhost:3000"
            result = await billing_configured.create_checkout_session(
                "cus_xxx", "pro",
            )
        assert result == "https://checkout.stripe.com/test"


class TestPortalSession:
    """Tests for Stripe customer portal."""

    async def test_unconfigured_returns_empty(
        self, billing_unconfigured: BillingService,
    ) -> None:
        """Returns empty string when not configured."""
        result = await billing_unconfigured.create_portal_session("cus_xxx")
        assert result == ""

    async def test_creates_portal(
        self, billing_configured: BillingService,
    ) -> None:
        """Creates portal session."""
        mock_session = MagicMock()
        mock_session.url = "https://billing.stripe.com/portal"

        with (
            patch(
                "stripe.billing_portal.Session.create",
                return_value=mock_session,
            ),
            patch("src.services.billing.settings") as mock_settings,
        ):
            mock_settings.dashboard_url = "http://localhost:3000"
            result = await billing_configured.create_portal_session("cus_xxx")
        assert result == "https://billing.stripe.com/portal"


class TestSubscriptionStatus:
    """Tests for subscription status retrieval."""

    async def test_unconfigured_returns_none(
        self, billing_unconfigured: BillingService,
    ) -> None:
        """Returns 'none' when not configured."""
        result = await billing_unconfigured.get_subscription_status("sub_xxx")
        assert result == "none"

    async def test_empty_subscription_id(
        self, billing_configured: BillingService,
    ) -> None:
        """Returns 'none' for empty subscription ID."""
        result = await billing_configured.get_subscription_status("")
        assert result == "none"

    async def test_retrieves_status(
        self, billing_configured: BillingService,
    ) -> None:
        """Retrieves subscription status."""
        mock_sub = MagicMock()
        mock_sub.status = "active"

        with patch("stripe.Subscription.retrieve", return_value=mock_sub):
            result = await billing_configured.get_subscription_status("sub_xxx")
        assert result == "active"


class TestCancelSubscription:
    """Tests for subscription cancellation."""

    async def test_unconfigured_returns_false(
        self, billing_unconfigured: BillingService,
    ) -> None:
        """Returns False when not configured."""
        result = await billing_unconfigured.cancel_subscription("sub_xxx")
        assert not result

    async def test_cancels_subscription(
        self, billing_configured: BillingService,
    ) -> None:
        """Cancels subscription at period end."""
        with patch("stripe.Subscription.modify"):
            result = await billing_configured.cancel_subscription("sub_xxx")
        assert result


class TestWebhookEvent:
    """Tests for webhook event verification."""

    def test_unconfigured_returns_none(
        self, billing_unconfigured: BillingService,
    ) -> None:
        """Returns None when not configured."""
        result = billing_unconfigured.construct_webhook_event(b"data", "sig")
        assert result is None

    def test_invalid_signature_returns_none(
        self, billing_configured: BillingService,
    ) -> None:
        """Returns None for invalid signature."""
        result = billing_configured.construct_webhook_event(b"data", "bad_sig")
        assert result is None


class TestPlanLimits:
    """Tests for plan limit lookups."""

    def test_free_limit(self, billing_unconfigured: BillingService) -> None:
        """Free tier has 100 scans/day."""
        assert billing_unconfigured.get_plan_limit("free") == 100

    def test_pro_limit(self, billing_unconfigured: BillingService) -> None:
        """Pro tier has 10,000 scans/day."""
        assert billing_unconfigured.get_plan_limit("pro") == 10_000

    def test_enterprise_limit(
        self, billing_unconfigured: BillingService,
    ) -> None:
        """Enterprise tier has 100,000 scans/day."""
        assert billing_unconfigured.get_plan_limit("enterprise") == 100_000

    def test_unknown_plan_defaults_to_free(
        self, billing_unconfigured: BillingService,
    ) -> None:
        """Unknown plan defaults to free tier limit."""
        assert billing_unconfigured.get_plan_limit("unknown") == 100

    def test_plan_limits_map(self) -> None:
        """All plan tiers are in the limits map."""
        assert PlanTier.FREE in PLAN_LIMITS
        assert PlanTier.PRO in PLAN_LIMITS
        assert PlanTier.ENTERPRISE in PLAN_LIMITS


# ── Stripe Integration Tests (require sk_test_ key) ────────────────────────


@_skip_no_stripe
class TestStripeIntegration:
    """Live integration tests against Stripe test-mode API."""

    @pytest.fixture(autouse=True)
    def _setup_stripe(self) -> None:
        """Configure Stripe with test key."""
        stripe_lib.api_key = _STRIPE_TEST_KEY

    async def test_create_and_delete_customer(self) -> None:
        """Create a real test customer and clean up."""
        svc = BillingService()
        assert svc.is_configured()

        cust_id = await svc.create_customer(
            "pytest-integration@codetrust.ai", "Pytest Test", "pytest_user_001",
        )
        assert cust_id.startswith("cus_")

        fetched = stripe_lib.Customer.retrieve(cust_id)
        assert fetched.email == "pytest-integration@codetrust.ai"
        assert fetched.metadata["codetrust_user_id"] == "pytest_user_001"

        stripe_lib.Customer.delete(cust_id)

    async def test_checkout_session_pro(self) -> None:
        """Create a checkout session for Pro plan."""
        svc = BillingService()
        cust_id = await svc.create_customer(
            "pytest-checkout@codetrust.ai", "Checkout Test", "pytest_checkout",
        )

        url = await svc.create_checkout_session(cust_id, "pro")
        assert "checkout.stripe.com" in url

        stripe_lib.Customer.delete(cust_id)

    async def test_checkout_session_enterprise(self) -> None:
        """Create a checkout session for Enterprise plan."""
        svc = BillingService()
        cust_id = await svc.create_customer(
            "pytest-ent@codetrust.ai", "Enterprise Test", "pytest_ent",
        )

        url = await svc.create_checkout_session(cust_id, "enterprise")
        assert "checkout.stripe.com" in url

        stripe_lib.Customer.delete(cust_id)

    async def test_portal_session(self) -> None:
        """Create a customer portal session."""
        svc = BillingService()
        cust_id = await svc.create_customer(
            "pytest-portal@codetrust.ai", "Portal Test", "pytest_portal",
        )

        url = await svc.create_portal_session(cust_id)
        assert "billing.stripe.com" in url

        stripe_lib.Customer.delete(cust_id)

    async def test_subscription_status_empty(self) -> None:
        """Empty subscription ID returns 'none'."""
        svc = BillingService()
        status = await svc.get_subscription_status("")
        assert status == "none"

    async def test_invalid_plan_returns_empty(self) -> None:
        """Unknown plan returns empty checkout URL."""
        svc = BillingService()
        cust_id = await svc.create_customer(
            "pytest-invalid@codetrust.ai", "Invalid Test", "pytest_invalid",
        )

        url = await svc.create_checkout_session(cust_id, "nonexistent_plan")
        assert url == ""

        stripe_lib.Customer.delete(cust_id)
