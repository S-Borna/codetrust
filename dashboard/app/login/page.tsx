"use client";

import { signIn } from "next-auth/react";
import Link from "next/link";

const BENEFITS = [
    "100 scans/day on free tier",
    "8 enforcement layers auto-installed",
    "Hallucination detection against 8 registries",
    "AI attribution — know which model wrote what",
    "GitHub Action support for PR gates",
];

export default function LoginPage() {
    return (
        <main className="flex min-h-screen items-center justify-center bg-gray-50 dark:bg-gray-950">
            <div className="mx-auto w-full max-w-md rounded-2xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-8 shadow-lg">
                <div className="text-center">
                    <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
                        Govern your AI agents
                    </h1>
                    <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
                        Block destructive commands, catch hallucinated packages, and track which AI model wrote every line — before damage happens.
                    </p>
                </div>

                <button
                    onClick={() => signIn("github", { callbackUrl: "/dashboard" })}
                    className="mt-8 flex w-full items-center justify-center gap-3 rounded-lg bg-gray-900 dark:bg-white px-4 py-3 font-semibold text-white dark:text-gray-900 hover:bg-gray-800 dark:hover:bg-gray-100 transition"
                >
                    <svg className="h-5 w-5" fill="currentColor" viewBox="0 0 24 24">
                        <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
                    </svg>
                    Continue with GitHub
                </button>

                <div className="mt-8 border-t border-gray-200 dark:border-gray-700 pt-6">
                    <p className="text-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-gray-400 mb-3">
                        What you get immediately
                    </p>
                    <ul className="space-y-2">
                        {BENEFITS.map((b) => (
                            <li
                                key={b}
                                className="flex items-start gap-2 text-sm text-gray-600 dark:text-gray-400"
                            >
                                <span className="text-emerald-500 font-bold mt-0.5">✓</span>
                                {b}
                            </li>
                        ))}
                    </ul>
                </div>

                <div className="mt-6 text-center">
                    <Link
                        href="/pricing"
                        className="text-sm text-brand-600 hover:text-brand-700 transition"
                    >
                        Compare plans →
                    </Link>
                </div>

                <p className="mt-6 text-center text-xs text-gray-500 dark:text-gray-400">
                    By signing in, you agree to our{" "}
                    <a href="https://codetrust.ai/tos" className="underline">Terms of Service</a>{" "}
                    and{" "}
                    <a href="https://codetrust.ai/privacy.html" className="underline">Privacy Policy</a>.
                </p>
            </div>
        </main>
    );
}
