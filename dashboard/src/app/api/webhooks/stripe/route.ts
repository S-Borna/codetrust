import { NextResponse } from "next/server";
import Stripe from "stripe";
import { prisma } from "@/lib/prisma";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || "", {
    apiVersion: "2024-12-18.acacia",
});

export async function POST(request: Request) {
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
