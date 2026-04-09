"use client";

import { useState } from "react";
import type { UserQuota } from "@/lib/dashboard-api";

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

interface SettingsFormProps {
    user?: UserInfo | null;
    apiKey?: string;
    trialEnd?: string | null;
    quota?: UserQuota | null;
}

/**
 * Formats a UTC ISO-8601 timestamp as a short local-time label.
 * Used for the "resets at" line on the quota card.
 */
function formatResetTime(isoTs: string): string {
    try {
        const date = new Date(isoTs);
        if (Number.isNaN(date.getTime())) return "midnight UTC";
        // Show hours until reset when it's imminent, otherwise the
        // absolute local time. Users trust "in 3 hours" more than
        // "at 01:00" when they're staring at a reduced-mode banner.
        const hoursUntil = Math.max(
            0,
            Math.round((date.getTime() - Date.now()) / 3_600_000),
        );
        if (hoursUntil <= 12) {
            return `in ${hoursUntil} hour${hoursUntil === 1 ? "" : "s"}`;
        }
        return date.toLocaleString(undefined, {
            hour: "2-digit",
            minute: "2-digit",
            timeZoneName: "short",
        });
    } catch {
        return "midnight UTC";
    }
}

/**
 * Live scan quota card with reduced-mode awareness.
 *
 * Three states, each with its own visual treatment:
 *
 *   1. Healthy:   used / limit < 80%    — neutral
 *   2. Near:      80% ≤ used / limit < 100% — warning tint
 *   3. Exceeded:  used >= limit          — red tint + "reduced mode"
 *                                          badge + upgrade CTA
 *
 * Never fabricates numbers — if `quota` is null we render nothing
 * (the parent already guards this but double-check for safety).
 */
function ScanQuotaCard({ quota }: { quota: UserQuota }): React.ReactElement | null {
    const limit = Math.max(1, quota.limit);
    const pct = Math.min(100, Math.round((quota.used / limit) * 100));
    const exceeded = quota.exceeded || quota.used >= limit;
    const nearLimit = !exceeded && pct >= 80;

    const barColor = exceeded
        ? "bg-red-500"
        : nearLimit
            ? "bg-yellow-500"
            : "bg-brand-600";

    const borderColor = exceeded
        ? "border-red-200 dark:border-red-800"
        : nearLimit
            ? "border-yellow-200 dark:border-yellow-800"
            : "border-gray-200 dark:border-gray-700";

    return (
        <div
            className={`rounded-xl border ${borderColor} bg-white dark:bg-gray-900 p-6`}
        >
            <div className="flex items-center justify-between mb-4">
                <h3 className="font-semibold text-gray-900 dark:text-white">
                    Scan quota
                </h3>
                {exceeded && (
                    <span className="inline-flex items-center rounded-full bg-yellow-100 dark:bg-yellow-900/40 px-3 py-1 text-xs font-semibold text-yellow-800 dark:text-yellow-300">
                        Reduced mode active
                    </span>
                )}
            </div>

            <div className="space-y-3">
                <div className="flex items-baseline justify-between">
                    <p className="text-2xl font-bold text-gray-900 dark:text-white">
                        {quota.used.toLocaleString()}
                        <span className="text-base font-normal text-gray-500 dark:text-gray-400">
                            {" / "}
                            {quota.limit.toLocaleString()} today
                        </span>
                    </p>
                    <p className="text-sm text-gray-500 dark:text-gray-400 capitalize">
                        {quota.plan} plan
                    </p>
                </div>

                <div className="h-2 w-full overflow-hidden rounded-full bg-gray-100 dark:bg-gray-800">
                    <div
                        className={`h-full rounded-full transition-all ${barColor}`}
                        style={{ width: `${pct}%` }}
                    />
                </div>

                <p className="text-sm text-gray-600 dark:text-gray-400">
                    Resets {formatResetTime(quota.resets_at)}
                </p>

                {exceeded && (
                    <div className="mt-4 rounded-lg bg-yellow-50 dark:bg-yellow-950/30 border border-yellow-200 dark:border-yellow-800 p-4 text-sm">
                        <p className="font-semibold text-yellow-900 dark:text-yellow-200 mb-2">
                            Running in reduced mode
                        </p>
                        <p className="text-yellow-800 dark:text-yellow-300 mb-3">
                            Your daily free scans are used. CodeTrust is still
                            active in real time — gateway hooks block destructive
                            commands and 15 critical safety rules still fire on
                            every scan. Advanced analyses are paused until quota
                            resets:
                        </p>
                        <ul className="list-disc list-inside space-y-1 text-yellow-800 dark:text-yellow-300">
                            <li>Hallucination detection (imports, APIs, sanitizers)</li>
                            <li>PII detection across 16 categories</li>
                            <li>Agent integrity patterns</li>
                            <li>2,913 advanced quality & security rules</li>
                        </ul>
                    </div>
                )}

                {nearLimit && !exceeded && (
                    <p className="text-sm text-yellow-700 dark:text-yellow-400">
                        Approaching daily limit — {limit - quota.used} scan
                        {limit - quota.used === 1 ? "" : "s"} remaining.
                    </p>
                )}
            </div>
        </div>
    );
}

export function SettingsForm({ user, apiKey, trialEnd, quota }: SettingsFormProps) {
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

            {/* Scan quota + reduced mode widget */}
            {quota && <ScanQuotaCard quota={quota} />}

            {/* Subscription */}
            <div className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-6">
                <h3 className="font-semibold text-gray-900 dark:text-white mb-4">
                    Subscription
                </h3>
                {(() => {
                    if (!trialEnd) return null;
                    const trialEndDate = new Date(trialEnd);
                    if (trialEndDate <= new Date()) return null;
                    const daysRemaining = Math.ceil((trialEndDate.getTime() - Date.now()) / 86_400_000);
                    const isEndingSoon = daysRemaining <= 3;
                    return (
                        <div className={`mb-4 rounded-lg px-4 py-3 text-sm ${
                            isEndingSoon
                                ? "bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-300"
                                : "bg-blue-50 dark:bg-blue-950/30 border border-blue-200 dark:border-blue-800 text-blue-700 dark:text-blue-300"
                        }`}>
                            Pro trial: {daysRemaining} days remaining
                            {isEndingSoon && " — add a payment method to keep Pro features"}
                        </div>
                    );
                })()}
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
