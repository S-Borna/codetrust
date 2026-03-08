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

function toPublicError(err: unknown): { error: string; status: number } {
    const message = err instanceof Error ? err.message : "Unknown error";

    if (message === "STRIPE_SECRET_KEY not configured") {
        return { error: "Billing is temporarily unavailable", status: 503 };
    }

    if (message.includes("Invalid API Key provided")) {
        return { error: "Billing is temporarily unavailable", status: 503 };
    }

    return { error: "Failed to open billing portal", status: 500 };
}

export async function POST() {
    try {
        const session = await getServerSession(authOptions);
        if (!session?.user?.id) {
            return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
        }

        const stripe = getStripe();
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

        const baseUrl = process.env.NEXTAUTH_URL || "https://app.codetrust.ai";
        const portalSession = await stripe.billingPortal.sessions.create({
            customer: customerId,
            return_url: `${baseUrl}/dashboard/settings`,
        });
        return NextResponse.json({ url: portalSession.url });
    } catch (err) {
        const publicError = toPublicError(err);
        return NextResponse.json(
            { error: publicError.error },
            { status: publicError.status },
        );
    }
}
