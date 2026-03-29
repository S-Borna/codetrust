import Link from "next/link";

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
        cta: "Get started free",
        href: "/login",
        highlight: false,
    },
    {
        name: "Pro",
        who: "Enforce rules in CI. Block unsafe code before merge.",
        price: "$29",
        period: "/month",
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
        cta: "Start Pro — 14 days free",
        href: "/login?plan=pro",
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
        cta: "Start Team",
        href: "/login?plan=team",
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
        cta: "Contact sales",
        href: "mailto:said@saidborna.com",
        highlight: false,
    },
];

/* Prices marked for manual confirmation — verify against Stripe config before launch */

export default function PricingPage() {
    return (
        <main className="bg-white dark:bg-gray-950 py-24">
            <div className="mx-auto max-w-7xl px-6">
                <h1 className="text-center text-4xl font-bold text-gray-900 dark:text-white">
                    Governance for every team size
                </h1>
                <p className="mx-auto mt-4 max-w-2xl text-center text-gray-600 dark:text-gray-400">
                    Free gets you started with full enforcement. Paid unlocks cloud API,
                    team governance, AI policy, and scale.
                </p>

                <div className="mt-16 grid gap-6 lg:grid-cols-4">
                    {PLANS.map((plan) => (
                        <div
                            key={plan.name}
                            className={`rounded-2xl border p-8 flex flex-col ${plan.highlight
                                ? "border-brand-600 shadow-lg ring-2 ring-brand-600"
                                : "border-gray-200 dark:border-gray-700"
                                }`}
                        >
                            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                                {plan.name}
                            </h3>
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
                            <ul className="mt-8 space-y-3 flex-1">
                                {plan.features.map((f) => (
                                    <li
                                        key={f}
                                        className={`flex items-start gap-2 text-sm ${f.endsWith("plus:")
                                            ? "text-gray-500 dark:text-gray-400 font-medium"
                                            : "text-gray-600 dark:text-gray-400"
                                            }`}
                                    >
                                        {!f.endsWith("plus:") && (
                                            <span className="text-emerald-500 font-bold mt-0.5">✓</span>
                                        )}
                                        {f}
                                    </li>
                                ))}
                            </ul>
                            <Link
                                href={plan.href}
                                className={`mt-8 block w-full rounded-lg py-3 text-center font-semibold transition ${plan.highlight
                                    ? "bg-brand-600 text-white hover:bg-brand-700"
                                    : "border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800"
                                    }`}
                            >
                                {plan.cta}
                            </Link>
                        </div>
                    ))}
                </div>

                <div className="mt-16 text-center">
                    <p className="text-sm text-gray-500 dark:text-gray-400">
                        Free detects locally. Pro enforces in CI. Team governs across repos.
                        <br />
                        All plans use the same 3,006 rule engine.
                    </p>
                    <Link
                        href="https://codetrust.ai"
                        className="mt-4 inline-block text-sm text-brand-600 hover:text-brand-700 transition"
                    >
                        Learn more at codetrust.ai →
                    </Link>
                </div>
            </div>
        </main>
    );
}
