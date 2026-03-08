import type { NextAuthOptions } from "next-auth";
import GithubProvider from "next-auth/providers/github";
import { PrismaAdapter } from "@next-auth/prisma-adapter";
import { prisma } from "@/lib/prisma";

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
                // Use stripeId as API key proxy or generate deterministic key
                // The API key is the user's backend auth credential
                session.user.apiKey = process.env.CODETRUST_API_KEY || dbUser?.stripeId || "";
            }
            return session;
        },
    },
};
