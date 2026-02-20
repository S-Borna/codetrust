# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Stripe billing service for subscription management and usage metering."""

import stripe as stripe_lib
import structlog

from src.config import settings
from src.models.enums import PlanTier

logger = structlog.get_logger()

PLAN_PRICE_MAP: dict[str, str] = {
    PlanTier.PRO: "stripe_price_pro",
    PlanTier.ENTERPRISE: "stripe_price_enterprise",
}

PLAN_LIMITS: dict[str, int] = {
    PlanTier.FREE: 100,
    PlanTier.PRO: 10_000,
    PlanTier.ENTERPRISE: 100_000,
}


class BillingService:
    """Stripe-backed billing for subscriptions and usage tracking."""

    def __init__(self) -> None:
        """Initialize Stripe with the configured secret key."""
        self._configured = bool(settings.stripe_secret_key)
        if self._configured:
            stripe_lib.api_key = settings.stripe_secret_key
        else:
            logger.warning("stripe_not_configured")

    def is_configured(self) -> bool:
        """Check if Stripe is configured."""
        return self._configured

    async def create_customer(
        self, email: str, name: str, user_id: str,
    ) -> str:
        """Create a Stripe customer. Returns the customer ID."""
        if not self._configured:
            return ""
        try:
            customer = stripe_lib.Customer.create(
                email=email,
                name=name,
                metadata={"codetrust_user_id": user_id},
            )
            logger.info("stripe_customer_created", customer_id=customer.id)
            return customer.id
        except stripe_lib.StripeError as exc:
            logger.error("stripe_customer_error", error=str(exc))
            return ""

    async def create_checkout_session(
        self,
        customer_id: str,
        plan: str,
        success_url: str = "",
        cancel_url: str = "",
    ) -> str:
        """Create a Stripe Checkout session. Returns the session URL."""
        if not self._configured:
            return ""

        price_attr = PLAN_PRICE_MAP.get(plan, "")
        price_id = getattr(settings, price_attr, "") if price_attr else ""
        if not price_id:
            logger.error("stripe_no_price", plan=plan)
            return ""

        try:
            session = stripe_lib.checkout.Session.create(
                customer=customer_id,
                mode="subscription",
                line_items=[{"price": price_id, "quantity": 1}],
                success_url=success_url or f"{settings.dashboard_url}/dashboard?upgraded=true",
                cancel_url=cancel_url or f"{settings.dashboard_url}/pricing",
                metadata={"plan": plan},
            )
            logger.info("stripe_checkout_created", session_id=session.id)
            return session.url or ""
        except stripe_lib.StripeError as exc:
            logger.error("stripe_checkout_error", error=str(exc))
            return ""

    async def create_portal_session(self, customer_id: str) -> str:
        """Create a Stripe Customer Portal session for managing subscriptions."""
        if not self._configured:
            return ""
        try:
            session = stripe_lib.billing_portal.Session.create(
                customer=customer_id,
                return_url=f"{settings.dashboard_url}/dashboard/settings",
            )
            return session.url
        except stripe_lib.StripeError as exc:
            logger.error("stripe_portal_error", error=str(exc))
            return ""

    async def get_subscription_status(
        self, subscription_id: str,
    ) -> str:
        """Get the status of a Stripe subscription."""
        if not self._configured or not subscription_id:
            return "none"
        try:
            sub = stripe_lib.Subscription.retrieve(subscription_id)
            return sub.status
        except stripe_lib.StripeError as exc:
            logger.error("stripe_sub_status_error", error=str(exc))
            return "error"

    async def cancel_subscription(
        self, subscription_id: str,
    ) -> bool:
        """Cancel a subscription at period end."""
        if not self._configured or not subscription_id:
            return False
        try:
            stripe_lib.Subscription.modify(
                subscription_id,
                cancel_at_period_end=True,
            )
            logger.info("stripe_sub_cancelled", sub_id=subscription_id)
            return True
        except stripe_lib.StripeError as exc:
            logger.error("stripe_cancel_error", error=str(exc))
            return False

    def construct_webhook_event(
        self, payload: bytes, sig_header: str,
    ) -> stripe_lib.Event | None:
        """Verify and construct a Stripe webhook event."""
        if not self._configured or not settings.stripe_webhook_secret:
            return None
        try:
            return stripe_lib.Webhook.construct_event(
                payload, sig_header, settings.stripe_webhook_secret,
            )
        except (ValueError, stripe_lib.SignatureVerificationError) as exc:
            logger.error("stripe_webhook_invalid", error=str(exc))
            return None

    def get_plan_limit(self, plan: str) -> int:
        """Get the daily scan limit for a plan tier."""
        return PLAN_LIMITS.get(plan, PLAN_LIMITS[PlanTier.FREE])
