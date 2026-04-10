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

/** In-memory cache: avoids re-bootstrapping (and rotating) the API key
 *  on every session callback. TTL = 20 minutes. */
const bootstrapCache = new Map<string, { data: BootstrapApiKeyResponse; expiresAt: number }>();
const BOOTSTRAP_TTL_MS = 20 * 60 * 1000;

async function bootstrapDashboardApiKey(params: {
    userId: string;
    email?: string | null;
    name?: string | null;
}): Promise<BootstrapApiKeyResponse | null> {
    const cached = bootstrapCache.get(params.userId);
    if (cached && cached.expiresAt > Date.now()) {
        return cached.data;
    }

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
        const data = await response.json() as BootstrapApiKeyResponse;
        bootstrapCache.set(params.userId, {
            data,
            expiresAt: Date.now() + BOOTSTRAP_TTL_MS,
        });
        return data;
    } catch (err) {
        console.error(`[bootstrap] fetch failed for ${url}:`, err);
        return null;
    }
}

declare module "next-auth" {
    interface User {
        plan?: string;
        apiKey?: string;
        trialEnd?: Date | null;
    }
    interface Session {
        user: {
            id: string;
            name?: string | null;
            email?: string | null;
            image?: string | null;
            plan?: string;
            apiKey?: string;
            trialEnd?: string | null;
        };
    }
}

const IS_PRODUCTION = (process.env.NEXTAUTH_URL || "").startsWith("https://");

export const authOptions: NextAuthOptions = {
    adapter: PrismaAdapter(prisma),
    providers: [
        GithubProvider({
            clientId: process.env.GITHUB_CLIENT_ID || "",
            clientSecret: process.env.GITHUB_CLIENT_SECRET || "",
            // GitHub uses OAuth2, not OpenID Connect. The openid-client
            // library requires an issuer value even for non-OIDC providers.
            // Without this, NextAuth 4.24.8+ throws "issuer must be
            // configured on the issuer" on every OAuth callback.
            issuer: "https://github.com/login/oauth",
            checks: ["state"],
        }),
    ],
    pages: {
        signIn: "/login",
    },
    cookies: {
        sessionToken: {
            name: "next-auth.session-token",
            options: {
                httpOnly: true,
                sameSite: "lax",
                path: "/",
                secure: IS_PRODUCTION,
            },
        },
        csrfToken: {
            name: "next-auth.csrf-token",
            options: {
                httpOnly: true,
                sameSite: "lax",
                path: "/",
                secure: IS_PRODUCTION,
            },
        },
        callbackUrl: {
            name: "next-auth.callback-url",
            options: {
                httpOnly: true,
                sameSite: "lax",
                path: "/",
                secure: IS_PRODUCTION,
            },
        },
    },
    session: {
        /* 24-hour sessions: plan changes and API key revocations
           propagate within a day without forcing constant re-login. */
        maxAge: 24 * 60 * 60,
    },
    callbacks: {
        async session({ session, user }) {
            if (session.user) {
                session.user.id = user.id;
                // Fetch plan from DB
                let dbPlan = "free";
                let dbTrialEnd: string | null = null;
                try {
                    const dbUser = await prisma.user.findUnique({
                        where: { id: user.id },
                        select: { plan: true, trialEnd: true },
                    });
                    dbPlan = dbUser?.plan || "free";
                    dbTrialEnd = dbUser?.trialEnd?.toISOString() || null;
                } catch {
                    const dbUser = await prisma.user.findUnique({
                        where: { id: user.id },
                        select: { plan: true },
                    });
                    dbPlan = dbUser?.plan || "free";
                }
                session.user.plan = dbPlan;
                session.user.trialEnd = dbTrialEnd;
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
