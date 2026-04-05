import { NextResponse } from "next/server";
import Stripe from "stripe";
import { prisma } from "@/lib/prisma";

const STRIPE_PRO_PRICE_ID = process.env.STRIPE_PRICE_PRO || "";
const STRIPE_TEAM_PRICE_ID = process.env.STRIPE_PRICE_TEAM || "";
const STRIPE_ENTERPRISE_PRICE_ID = process.env.STRIPE_PRICE_ENTERPRISE || "";

/**
 * Map a Stripe price ID back to the internal plan name.
 * Returns null if the price ID is unknown — prevents metadata spoofing.
 */
function resolvePlanFromPriceId(priceId: string): string | null {
    const priceToPlans: Record<string, string> = {};
    if (STRIPE_PRO_PRICE_ID) priceToPlans[STRIPE_PRO_PRICE_ID] = "pro";
    if (STRIPE_TEAM_PRICE_ID) priceToPlans[STRIPE_TEAM_PRICE_ID] = "team";
    if (STRIPE_ENTERPRISE_PRICE_ID) priceToPlans[STRIPE_ENTERPRISE_PRICE_ID] = "enterprise";
    return priceToPlans[priceId] ?? null;
}

function getStripeClient(): Stripe {
    const key = process.env.STRIPE_SECRET_KEY;
    if (!key) {
        throw new Error("STRIPE_SECRET_KEY not configured");
    }
    return new Stripe(key, { apiVersion: "2025-02-24.acacia" });
}

export async function POST(request: Request): Promise<NextResponse> {
    let stripe: Stripe;
    try {
        stripe = getStripeClient();
    } catch {
        return NextResponse.json(
            { error: "Stripe is not configured" },
            { status: 500 },
        );
    }

    const body = await request.text();
    const sig = request.headers.get("stripe-signature") || "";

    let event: Stripe.Event;
    try {
        event = stripe.webhooks.constructEvent(
            body,
            sig,
            process.env.STRIPE_WEBHOOK_SECRET || "",
        );
    } catch {
        return NextResponse.json({ error: "Invalid signature" }, { status: 400 });
    }

    switch (event.type) {
        case "checkout.session.completed": {
            const session = event.data.object as Stripe.Checkout.Session;
            const customerId = session.customer as string;

            /*
             * Resolve the plan from the actual Stripe line item price,
             * NOT from session.metadata which can be tampered with during
             * checkout creation if the API is ever compromised.
             */
            let plan: string | null = null;

            if (session.line_items?.data?.[0]?.price?.id) {
                plan = resolvePlanFromPriceId(session.line_items.data[0].price.id);
            }

            if (!plan && session.subscription) {
                /* line_items may not be expanded — fetch subscription to get price */
                try {
                    const subscription = await stripe.subscriptions.retrieve(
                        session.subscription as string,
                    );
                    const priceId = subscription.items.data[0]?.price?.id;
                    if (priceId) {
                        plan = resolvePlanFromPriceId(priceId);
                    }
                } catch (fetchErr) {
                    console.error(
                        "[webhook] Failed to fetch subscription for price verification:",
                        fetchErr instanceof Error ? fetchErr.message : fetchErr,
                    );
                }
            }

            if (!plan) {
                console.error(
                    "[webhook] Could not resolve plan from price ID. " +
                    `customer=${customerId}, metadata.plan=${session.metadata?.plan}. ` +
                    "Rejecting update to prevent metadata spoofing.",
                );
                return NextResponse.json(
                    { error: "Could not verify plan from price" },
                    { status: 400 },
                );
            }

            /* Extract trial_end from subscription if present */
            let trialEnd: Date | null = null;
            if (session.subscription) {
                try {
                    const sub = await stripe.subscriptions.retrieve(
                        session.subscription as string,
                    );
                    if (sub.trial_end) {
                        trialEnd = new Date(sub.trial_end * 1000);
                    }
                } catch {
                    /* trial_end is optional — proceed without it */
                }
            }

            await prisma.user.updateMany({
                where: { stripeId: customerId },
                data: { plan, trialEnd },
            });
            break;
        }

        case "customer.subscription.updated": {
            const updatedSub = event.data.object as Stripe.Subscription;
            const updatedCustomerId = updatedSub.customer as string;
            const updatedPriceId = updatedSub.items.data[0]?.price?.id;
            if (updatedPriceId) {
                const updatedPlan = resolvePlanFromPriceId(updatedPriceId);
                if (updatedPlan) {
                    await prisma.user.updateMany({
                        where: { stripeId: updatedCustomerId },
                        data: { plan: updatedPlan },
                    });
                }
            }
            break;
        }

        case "customer.subscription.deleted": {
            const sub = event.data.object as Stripe.Subscription;
            const customerId = sub.customer as string;

            await prisma.user.updateMany({
                where: { stripeId: customerId },
                data: { plan: "free" },
            });
            break;
        }
    }

    return NextResponse.json({ received: true });
}
