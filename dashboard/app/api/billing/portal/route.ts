import { NextResponse } from "next/server";
import { getServerSession } from "next-auth";
import Stripe from "stripe";
import { authOptions } from "@/lib/auth";
import { prisma } from "@/lib/prisma";

function getStripe(): Stripe {
    const key = process.env.STRIPE_SECRET_KEY;
    if (!key) {
        throw new Error("STRIPE_SECRET_KEY not configured");
    }
    return new Stripe(key, { apiVersion: "2025-02-24.acacia" });
}

export async function POST() {
    const session = await getServerSession(authOptions);
    if (!session?.user?.id) {
        return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    let stripe: Stripe;
    try {
        stripe = getStripe();
    } catch {
        return NextResponse.json(
            { error: "Stripe is not configured" },
            { status: 503 },
        );
    }

    const dbUser = await prisma.user.findUnique({
        where: { id: session.user.id },
        select: { stripeId: true },
    });

    const customerId = dbUser?.stripeId || "";
    if (!customerId) {
        return NextResponse.json(
            { error: "No billing account found. Please upgrade first." },
            { status: 400 },
        );
    }

    try {
        const baseUrl = process.env.NEXTAUTH_URL || "https://app.codetrust.ai";
        const portalSession = await stripe.billingPortal.sessions.create({
            customer: customerId,
            return_url: `${baseUrl}/dashboard/settings`,
        });
        return NextResponse.json({ url: portalSession.url });
    } catch (err) {
        const message = err instanceof Error ? err.message : "Failed to create portal session";
        return NextResponse.json({ error: message }, { status: 500 });
    }
}
