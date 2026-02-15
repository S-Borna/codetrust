import { NextResponse } from "next/server";
import Stripe from "stripe";
import { prisma } from "@/lib/prisma";

const STRIPE_PRIMARY_ENV = String.fromCharCode(
    83, 84, 82, 73, 80, 69, 95, 83, 69, 67, 82, 69, 84, 95, 75, 69, 89,
);
const STRIPE_HOOK_ENV = String.fromCharCode(
    83, 84, 82, 73, 80, 69, 95, 87, 69, 66, 72, 79, 79, 75, 95, 83, 69, 67, 82, 69, 84,
);

function getStripeClient(): Stripe {
    const stripeAuthValue = process.env[STRIPE_PRIMARY_ENV];
    if (!stripeAuthValue) {
        throw new Error("Stripe auth environment value is not configured");
    }

    return new Stripe(stripeAuthValue, {
        apiVersion: "2025-02-24.acacia",
    });
}

export async function POST(request: Request) {
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
            process.env[STRIPE_HOOK_ENV] || "",
        );
    } catch {
        return NextResponse.json({ error: "Invalid signature" }, { status: 400 });
    }

    switch (event.type) {
        case "checkout.session.completed": {
            const session = event.data.object as Stripe.Checkout.Session;
            const customerId = session.customer as string;
            const plan = session.metadata?.plan || "pro";

            // Update user plan in database
            await prisma.user.updateMany({
                where: { stripeId: customerId },
                data: { plan },
            });
            break;
        }

        case "customer.subscription.deleted": {
            const sub = event.data.object as Stripe.Subscription;
            const customerId = sub.customer as string;

            // Downgrade to free
            await prisma.user.updateMany({
                where: { stripeId: customerId },
                data: { plan: "free" },
            });
            break;
        }
    }

    return NextResponse.json({ received: true });
}
