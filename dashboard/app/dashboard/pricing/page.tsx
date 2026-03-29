"use client";

import { useState } from "react";
import { useSession } from "next-auth/react";

const PLANS = [
    {
        name: "Free",
        who: "For local testing. No CI enforcement.",
        price: "$0",
        period: "forever",
        features: [
            "25 scans / day",
            "Static analysis (2,924 rules)",
            "MCP server (local)",
            "Registry verification (WARN only)",
            "CLI + VS Code extension",
            "Community support",
        ],
        planKey: "free",
        highlight: false,
    },
    {
        name: "Pro",
        who: "Enforce rules in CI. Block unsafe code before merge.",
        price: "$29",
        period: "/month",
        trial: "14 days free",
        features: [
            "10,000 scans / day",
            "Everything in Free, plus:",
            "Registry verification (BLOCK)",
            "Docker verification",
            "Sandbox execution",
            "GitHub Action PR gate (SARIF)",
            "API key management",
            "Priority support",
        ],
        planKey: "pro",
        highlight: true,
    },
    {
        name: "Team",
        who: "Govern AI usage across teams and repositories.",
        price: "$149",
        period: "/month",
        features: [
            "100,000 scans / day",
            "Everything in Pro, plus:",
            "Shared governance policies",
            "Team visibility & dashboards",
            "PR risk & audit logs",
            "Multi-repo enforcement",
            "Basic RBAC",
        ],
        planKey: "team",
        highlight: false,
    },
    {
        name: "Enterprise",
        who: "Full control, compliance, and custom deployment.",
        price: "Custom",
        period: "",
        features: [
            "Unlimited scans",
            "Everything in Team, plus:",
            "SSO / SAML",
            "Self-hosted deployment option",
            "Custom rules",
            "Compliance & audit export",
            "SLA guarantee",
            "Dedicated support",
        ],
        planKey: "enterprise",
        highlight: false,
    },
];

export default function DashboardPricingPage() {
    const { data: session } = useSession();
    const currentPlan = session?.user?.plan || "free";
    const [loading, setLoading] = useState("");
    const [error, setError] = useState("");

    async function handleCheckout(planKey: string) {
        setLoading(planKey);
        setError("");
        try {
            const res = await fetch("/api/billing/checkout", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ plan: planKey }),
            });
            if (!res.ok) {
                const data = await res.json().catch(() => ({}));
                setError((data as { error?: string }).error || "Failed to start checkout");
                return;
            }
            const data = await res.json();
            if (data.url) {
                window.location.href = data.url;
            }
        } catch {
            setError("Something went wrong. Please try again.");
        } finally {
            setLoading("");
        }
    }

    function ctaLabel(planKey: string): string {
        if (planKey === currentPlan) return "Current plan";
        if (planKey === "free") return "Current plan";
        if (planKey === "pro") return "Start Pro — 14 days free";
        if (planKey === "team") return "Start Team";
        return "Contact sales";
    }

    function isDisabled(planKey: string): boolean {
        return planKey === currentPlan || planKey === "free" || planKey === "enterprise";
    }

    return (
        <div className="space-y-8">
            <div>
                <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
                    Pricing
                </h1>
                <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">
                    Choose the plan that fits your team. Upgrade or downgrade anytime.
                </p>
            </div>

            {error && (
                <div className="rounded-lg border border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-950/30 p-4">
                    <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
                </div>
            )}

            <div className="grid gap-6 lg:grid-cols-4">
                {PLANS.map((plan) => (
                    <div
                        key={plan.name}
                        className={`rounded-2xl border p-8 flex flex-col ${
                            plan.highlight
                                ? "border-brand-600 shadow-lg ring-2 ring-brand-600"
                                : plan.planKey === currentPlan
                                    ? "border-emerald-500 ring-1 ring-emerald-500"
                                    : "border-gray-200 dark:border-gray-700"
                        }`}
                    >
                        <div className="flex items-center gap-2">
                            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                                {plan.name}
                            </h3>
                            {plan.planKey === currentPlan && (
                                <span className="rounded-full bg-emerald-100 dark:bg-emerald-900 px-2 py-0.5 text-xs font-medium text-emerald-700 dark:text-emerald-300">
                                    Current
                                </span>
                            )}
                        </div>
                        <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                            {plan.who}
                        </p>
                        <p className="mt-4">
                            <span className="text-4xl font-bold text-gray-900 dark:text-white">
                                {plan.price}
                            </span>
                            {plan.period && (
                                <span className="text-gray-500 dark:text-gray-400">
                                    {plan.period}
                                </span>
                            )}
                        </p>
                        {"trial" in plan && plan.trial && (
                            <p className="mt-1 text-sm font-medium text-brand-600">
                                {plan.trial}
                            </p>
                        )}
                        <ul className="mt-8 space-y-3 flex-1">
                            {plan.features.map((f) => (
                                <li
                                    key={f}
                                    className={`flex items-start gap-2 text-sm ${
                                        f.endsWith("plus:")
                                            ? "text-gray-500 dark:text-gray-400 font-medium"
                                            : "text-gray-600 dark:text-gray-400"
                                    }`}
                                >
                                    {!f.endsWith("plus:") && (
                                        <span className="text-emerald-500 font-bold mt-0.5">
                                            &#10003;
                                        </span>
                                    )}
                                    {f}
                                </li>
                            ))}
                        </ul>
                        {plan.planKey === "enterprise" ? (
                            <a
                                href="mailto:contact@codetrust.ai"
                                className="mt-8 block w-full rounded-lg border border-gray-300 dark:border-gray-600 py-3 text-center font-semibold text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800 transition"
                            >
                                Contact sales
                            </a>
                        ) : (
                            <button
                                onClick={() => handleCheckout(plan.planKey)}
                                disabled={isDisabled(plan.planKey) || loading === plan.planKey}
                                className={`mt-8 block w-full rounded-lg py-3 text-center font-semibold transition ${
                                    plan.highlight && !isDisabled(plan.planKey)
                                        ? "bg-brand-600 text-white hover:bg-brand-700"
                                        : "border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800"
                                } disabled:opacity-50 disabled:cursor-not-allowed`}
                            >
                                {loading === plan.planKey ? "Redirecting..." : ctaLabel(plan.planKey)}
                            </button>
                        )}
                    </div>
                ))}
            </div>

            <p className="text-center text-sm text-gray-500 dark:text-gray-400">
                All plans use the same 3,006 rule engine. Pro includes a 14-day free trial.
            </p>
        </div>
    );
}