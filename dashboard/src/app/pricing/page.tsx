import Link from "next/link";

const PLANS = [
    {
        name: "Free",
        price: "$0",
        period: "forever",
        features: [
            "100 scans / day",
            "Static analysis (35+ rules)",
            "MCP server (local)",
            "Community support",
        ],
        cta: "Get started",
        href: "/login",
        highlight: false,
    },
    {
        name: "Pro",
        price: "$29",
        period: "/month",
        features: [
            "10,000 scans / day",
            "All analysis layers",
            "Registry verification",
            "Docker verification",
            "Sandbox execution",
            "GitHub Action (SARIF)",
            "API key management",
            "Priority support",
        ],
        cta: "Start free trial",
        href: "/login?plan=pro",
        highlight: true,
    },
    {
        name: "Enterprise",
        price: "$199",
        period: "/month",
        features: [
            "100,000 scans / day",
            "Everything in Pro",
            "Custom rules",
            "Self-hosted option",
            "SSO / SAML",
            "SLA guarantee",
            "Dedicated support",
            "Audit logs",
        ],
        cta: "Contact sales",
        href: "mailto:sales@codetrust.dev",
        highlight: false,
    },
];

export default function PricingPage() {
    return (
        <main className="bg-white dark:bg-gray-950 py-24">
            <div className="mx-auto max-w-6xl px-6">
                <h1 className="text-center text-4xl font-bold text-gray-900 dark:text-white">
                    Simple, transparent pricing
                </h1>
                <p className="mx-auto mt-4 max-w-xl text-center text-gray-600 dark:text-gray-400">
                    Start free, upgrade as your team grows. All plans include the full
                    static analysis engine.
                </p>

                <div className="mt-16 grid gap-8 lg:grid-cols-3">
                    {PLANS.map((plan) => (
                        <div
                            key={plan.name}
                            className={`rounded-2xl border p-8 ${plan.highlight
                                    ? "border-brand-600 shadow-lg ring-2 ring-brand-600"
                                    : "border-gray-200 dark:border-gray-700"
                                }`}
                        >
                            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                                {plan.name}
                            </h3>
                            <p className="mt-4">
                                <span className="text-4xl font-bold text-gray-900 dark:text-white">
                                    {plan.price}
                                </span>
                                <span className="text-gray-500 dark:text-gray-400">
                                    {plan.period}
                                </span>
                            </p>
                            <ul className="mt-8 space-y-3">
                                {plan.features.map((f) => (
                                    <li
                                        key={f}
                                        className="flex items-start gap-2 text-sm text-gray-600 dark:text-gray-400"
                                    >
                                        <span className="text-brand-600 font-bold">✓</span>
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
            </div>
        </main>
    );
}
