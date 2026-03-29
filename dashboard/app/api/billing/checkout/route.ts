import { NextResponse } from "next/server";
import { getServerSession } from "next-auth";
import Stripe from "stripe";
import { authOptions } from "@/lib/auth";
import { prisma } from "@/lib/prisma";

const STRIPE_PRO_PRICE_ID = process.env.STRIPE_PRICE_PRO || "";

function getStripe(): Stripe {
    const key = process.env.STRIPE_SECRET_KEY;
    if (!key) {
        throw new Error("STRIPE_SECRET_KEY not configured");
    }
    return new Stripe(key, { apiVersion: "2025-02-24.acacia" });
}

function toPublicError(err: unknown): { error: string; status: number } {
    const message = err instanceof Error ? err.message : "Unknown error";

    if (message === "STRIPE_SECRET_KEY not configured") {
        return { error: "Billing is temporarily unavailable", status: 503 };
    }

    if (message.includes("Invalid API Key provided")) {
        return { error: "Billing is temporarily unavailable", status: 503 };
    }

    return { error: "Failed to create checkout session", status: 500 };
}

export async function POST(request: Request) {
    try {
        const session = await getServerSession(authOptions);
        if (!session?.user?.id) {
            return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
        }

        const stripe = getStripe();
        const body = await request.json().catch(() => ({}));
        const plan = (body as Record<string, unknown>).plan || "pro";

        if (plan !== "pro" && plan !== "enterprise") {
            return NextResponse.json({ error: "Invalid plan" }, { status: 400 });
        }

        const priceId = plan === "pro" ? STRIPE_PRO_PRICE_ID : process.env.STRIPE_PRICE_ENTERPRISE || "";
        if (!priceId) {
            return NextResponse.json(
                { error: `Price not configured for plan: ${plan}` },
                { status: 503 },
            );
        }

        const dbUser = await prisma.user.findUnique({
            where: { id: session.user.id },
            select: { stripeId: true, email: true, name: true },
        });

        let customerId = dbUser?.stripeId || "";

        if (!customerId) {
            const customer = await stripe.customers.create({
                email: dbUser?.email || session.user.email || "",
                name: dbUser?.name || session.user.name || "",
                metadata: { codetrust_user_id: session.user.id },
            });
            customerId = customer.id;
            await prisma.user.update({
                where: { id: session.user.id },
                data: { stripeId: customerId },
            });
        }

        const baseUrl = process.env.NEXTAUTH_URL || "https://app.codetrust.ai";
        const checkoutSession = await stripe.checkout.sessions.create({
            customer: customerId,
            mode: "subscription",
            line_items: [{ price: priceId, quantity: 1 }],
            success_url: `${baseUrl}/dashboard/settings?upgraded=true`,
            cancel_url: `${baseUrl}/dashboard/settings`,
            metadata: { plan: String(plan) },
        });
        return NextResponse.json({ url: checkoutSession.url });
    } catch (err) {
        console.error("[billing/checkout]", err instanceof Error ? err.message : err);
        const publicError = toPublicError(err);
        return NextResponse.json(
            { error: publicError.error },
            { status: publicError.status },
        );
    }
}
