import type { NextAuthOptions } from "next-auth";
import GithubProvider from "next-auth/providers/github";
import { PrismaAdapter } from "@next-auth/prisma-adapter";
import { prisma } from "@/lib/prisma";

/** Server-side API URL: prefer internal Railway networking to avoid Cloudflare loop. */
const SERVER_API_URL =
    process.env.CODETRUST_INTERNAL_API_URL ||
    process.env.NEXT_PUBLIC_API_URL ||
    "https://api.codetrust.ai";

interface BootstrapApiKeyResponse {
    user_id: string;
    plan: string;
    api_key: string;
    key_id: string;
    prefix: string;
}

async function bootstrapDashboardApiKey(params: {
    userId: string;
    email?: string | null;
    name?: string | null;
}): Promise<BootstrapApiKeyResponse | null> {
    const masterKey = process.env.CODETRUST_API_KEY || "";
    if (!masterKey) {
        console.error("[bootstrap] CODETRUST_API_KEY is not set");
        return null;
    }

    const url = `${SERVER_API_URL}/v1/admin/dashboard/bootstrap-api-key`;
    try {
        const response = await fetch(url, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-API-Key": masterKey,
                "X-Client-Version": "2.9.0",
            },
            body: JSON.stringify({
                user_id: params.userId,
                github_id: params.userId,
                email: params.email || "",
                name: params.name || "",
            }),
            cache: "no-store",
        });
        if (!response.ok) {
            const body = await response.text().catch(() => "");
            console.error(`[bootstrap] ${response.status} from ${url}: ${body}`);
            return null;
        }
        return await response.json() as BootstrapApiKeyResponse;
    } catch (err) {
        console.error(`[bootstrap] fetch failed for ${url}:`, err);
        return null;
    }
}

declare module "next-auth" {
    interface User {
        plan?: string;
        apiKey?: string;
    }
    interface Session {
        user: {
            id: string;
            name?: string | null;
            email?: string | null;
            image?: string | null;
            plan?: string;
            apiKey?: string;
        };
    }
}

export const authOptions: NextAuthOptions = {
    adapter: PrismaAdapter(prisma),
    providers: [
        GithubProvider({
            clientId: process.env.GITHUB_CLIENT_ID || "",
            clientSecret: process.env.GITHUB_CLIENT_SECRET || "",
        }),
    ],
    pages: {
        signIn: "/login",
    },
    callbacks: {
        async session({ session, user }) {
            if (session.user) {
                session.user.id = user.id;
                // Fetch plan from DB
                const dbUser = await prisma.user.findUnique({
                    where: { id: user.id },
                    select: { plan: true, stripeId: true },
                });
                session.user.plan = dbUser?.plan || "free";
                const bootstrap = await bootstrapDashboardApiKey({
                    userId: user.id,
                    email: session.user.email,
                    name: session.user.name,
                });
                if (bootstrap) {
                    session.user.apiKey = bootstrap.api_key;
                    session.user.plan = bootstrap.plan || session.user.plan;
                } else {
                    session.user.apiKey = "";
                }
            }
            return session;
        },
    },
};
