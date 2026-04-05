"use client";

import { useState } from "react";

/** Allowed redirect hosts for billing flows. */
const SAFE_REDIRECT_HOSTS = new Set([
    "checkout.stripe.com",
    "billing.stripe.com",
]);

function isSafeRedirectUrl(url: string): boolean {
    try {
        const parsed = new URL(url);
        if (parsed.protocol !== "https:") return false;
        return SAFE_REDIRECT_HOSTS.has(parsed.hostname);
    } catch {
        return false;
    }
}

interface UserInfo {
    name?: string | null;
    email?: string | null;
    image?: string | null;
    plan?: string;
}

export function SettingsForm({ user, apiKey }: { user?: UserInfo | null; apiKey?: string }) {
    const plan = user?.plan || "free";
    const [upgrading, setUpgrading] = useState(false);
    const [error, setError] = useState("");
    const [keyVisible, setKeyVisible] = useState(false);
    const [copied, setCopied] = useState("");

    function sanitizeErrorMessage(message: string): string {
        const hasStripeSecretLikeToken = /sk_(live|test)_[A-Za-z0-9]+/.test(message);
        if (hasStripeSecretLikeToken) {
            return "Billing is temporarily unavailable. Please try again shortly.";
        }
        return message;
    }

    async function readErrorMessage(res: Response, fallback: string): Promise<string> {
        if (res.status >= 500) {
            return "Billing is temporarily unavailable. Please try again shortly.";
        }
        const contentType = res.headers.get("content-type") || "";
        if (contentType.includes("application/json")) {
            const payload = await res.json().catch(() => ({}));
            const apiError = (payload as { error?: string }).error;
            if (apiError && apiError.length > 0) {
                return sanitizeErrorMessage(apiError);
            }
            return fallback;
        }
        const text = await res.text().catch(() => "");
        if (text.length > 0) {
            return `${fallback} (HTTP ${res.status})`;
        }
        return fallback;
    }

    async function handleUpgrade() {
        setUpgrading(true);
        setError("");
        try {
            const res = await fetch("/api/billing/checkout", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ plan: "pro" }),
            });

            if (!res.ok) {
                const message = await readErrorMessage(res, "Failed to create checkout session");
                setError(message);
                return;
            }
            const data = await res.json();
            if (data.url && isSafeRedirectUrl(data.url)) {
                window.location.href = data.url;
            } else if (data.url) {
                setError("Received an untrusted redirect URL. Checkout aborted.");
            }
        } catch {
            setError("Something went wrong. Please try again.");
        } finally {
            setUpgrading(false);
        }
    }

    async function handleManageBilling() {
        setError("");
        try {
            const res = await fetch("/api/billing/portal", {
                method: "POST",
            });

            if (!res.ok) {
                const message = await readErrorMessage(res, "Failed to open billing portal");
                setError(message);
                return;
            }
            const data = await res.json();
            if (data.url && isSafeRedirectUrl(data.url)) {
                window.location.href = data.url;
            } else if (data.url) {
                setError("Received an untrusted redirect URL. Portal aborted.");
            }
        } catch {
            setError("Something went wrong. Please try again.");
        }
    }

    return (
        <div className="space-y-6">
            {/* Profile */}
            <div className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-6">
                <h3 className="font-semibold text-gray-900 dark:text-white mb-4">
                    Profile
                </h3>
                <div className="space-y-4">
                    <div>
                        <label className="block text-sm font-medium text-gray-500 dark:text-gray-400">
                            Name
                        </label>
                        <p className="mt-1 text-gray-900 dark:text-white">
                            {user?.name || "—"}
                        </p>
                    </div>
                    <div>
                        <label className="block text-sm font-medium text-gray-500 dark:text-gray-400">
                            Email
                        </label>
                        <p className="mt-1 text-gray-900 dark:text-white">
                            {user?.email || "—"}
                        </p>
                    </div>
                </div>
            </div>

            {/* API Key */}
            {apiKey && (
                <div className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-6">
                    <h3 className="font-semibold text-gray-900 dark:text-white mb-4">
                        API Key
                    </h3>
                    <div className="space-y-3">
                        <div className="flex items-center gap-2">
                            <code className="flex-1 rounded-lg bg-gray-100 dark:bg-gray-800 px-3 py-2 text-sm font-mono text-gray-700 dark:text-gray-300">
                                {keyVisible ? apiKey : `${apiKey.slice(0, 12)}${"•".repeat(32)}`}
                            </code>
                            <button
                                onClick={() => setKeyVisible(!keyVisible)}
                                className="rounded-lg border border-gray-300 dark:border-gray-600 px-3 py-2 text-sm text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800 transition"
                            >
                                {keyVisible ? "Hide" : "Show"}
                            </button>
                            <button
                                onClick={() => {
                                    navigator.clipboard.writeText(apiKey).then(
                                        () => { setCopied("key"); setTimeout(() => setCopied(""), 2000); },
                                        () => { setCopied("fail"); setTimeout(() => setCopied(""), 2000); },
                                    );
                                }}
                                className="rounded-lg border border-gray-300 dark:border-gray-600 px-3 py-2 text-sm text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800 transition"
                            >
                                {copied === "key" ? "Copied!" : copied === "fail" ? "Failed" : "Copy"}
                            </button>
                        </div>
                        <div>
                            <p className="text-xs text-gray-500 dark:text-gray-400 mb-1">
                                Connect your CLI:
                            </p>
                            <div className="flex items-center gap-2">
                                <code className="flex-1 rounded-lg bg-gray-100 dark:bg-gray-800 px-3 py-2 text-sm font-mono text-gray-700 dark:text-gray-300">
                                    codetrust login --api-key {apiKey.slice(0, 12)}...
                                </code>
                                <button
                                    onClick={() => {
                                        navigator.clipboard.writeText(`codetrust login --api-key ${apiKey}`).then(
                                            () => { setCopied("cli"); setTimeout(() => setCopied(""), 2000); },
                                            () => { setCopied("fail"); setTimeout(() => setCopied(""), 2000); },
                                        );
                                    }}
                                    className="rounded-lg border border-gray-300 dark:border-gray-600 px-3 py-2 text-sm text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800 transition"
                                >
                                    {copied === "cli" ? "Copied!" : copied === "fail" ? "Failed" : "Copy"}
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* Subscription */}
            <div className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-6">
                <h3 className="font-semibold text-gray-900 dark:text-white mb-4">
                    Subscription
                </h3>
                <div className="flex items-center justify-between">
                    <div>
                        <p className="text-gray-900 dark:text-white">
                            Current plan:{" "}
                            <span className="font-semibold text-brand-600 capitalize">
                                {plan}
                            </span>
                        </p>
                        <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                            {plan === "free"
                                ? "25 scans/day included"
                                : plan === "pro"
                                    ? "10,000 scans/day included"
                                    : "100,000 scans/day included"}
                        </p>
                    </div>
                    <div>
                        {plan === "free" ? (
                            <button
                                onClick={handleUpgrade}
                                disabled={upgrading}
                                className="rounded-lg bg-brand-600 px-4 py-2 text-sm font-semibold text-white hover:bg-brand-700 transition disabled:opacity-50 disabled:cursor-not-allowed"
                            >
                                {upgrading ? "Redirecting…" : "Upgrade to Pro"}
                            </button>
                        ) : (
                            <button
                                onClick={handleManageBilling}
                                className="rounded-lg border border-gray-300 dark:border-gray-600 px-4 py-2 text-sm font-semibold text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800 transition"
                            >
                                Manage billing
                            </button>
                        )}
                    </div>
                </div>
                {error && (
                    <p className="mt-3 text-sm text-red-500">{error}</p>
                )}
            </div>

            {/* Danger zone */}
            <div className="rounded-xl border border-red-200 dark:border-red-800 bg-white dark:bg-gray-900 p-6">
                <h3 className="font-semibold text-red-600 dark:text-red-400 mb-4">
                    Danger zone
                </h3>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                    Deleting your account will revoke all API keys and remove all scan
                    history. This action cannot be undone.
                </p>
                <button className="mt-4 rounded-lg border border-red-300 dark:border-red-700 px-4 py-2 text-sm font-semibold text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950 transition">
                    Delete account
                </button>
            </div>
        </div>
    );
}
