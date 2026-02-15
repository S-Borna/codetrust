import Link from "next/link";

const FEATURES = [
    {
        title: "Static Analysis",
        description:
            "35+ anti-pattern rules catch hallucinated code, security issues, and quality problems.",
        icon: "🔍",
    },
    {
        title: "Registry Verification",
        description:
            "Verify packages exist on PyPI, npm, crates.io, and Go Proxy before deploying.",
        icon: "📦",
    },
    {
        title: "Docker Verification",
        description:
            "Confirm Docker base images and tags exist on Docker Hub and GHCR.",
        icon: "🐳",
    },
    {
        title: "AST Deep Analysis",
        description:
            "Tree-sitter powered complexity analysis, unused variables, and unreachable code detection.",
        icon: "🌳",
    },
    {
        title: "Sandbox Execution",
        description:
            "Run code in isolated Docker containers to catch runtime errors static analysis misses.",
        icon: "🏗️",
    },
    {
        title: "GitHub Action",
        description:
            "One-line CI integration with SARIF output for the GitHub Security tab.",
        icon: "⚙️",
    },
];

export default function HomePage() {
    return (
        <main>
            {/* Hero */}
            <section className="relative overflow-hidden bg-white dark:bg-gray-950">
                <div className="mx-auto max-w-6xl px-6 py-24 text-center">
                    <h1 className="text-5xl font-bold tracking-tight text-gray-900 dark:text-white sm:text-6xl">
                        Trust every line of
                        <span className="text-brand-600"> AI-generated code</span>
                    </h1>
                    <p className="mx-auto mt-6 max-w-2xl text-lg text-gray-600 dark:text-gray-400">
                        CodeTrust catches hallucinated packages, broken configs, and code
                        anti-patterns before they reach production. MCP server + Cloud API +
                        GitHub Action.
                    </p>
                    <div className="mt-10 flex items-center justify-center gap-4">
                        <Link
                            href="/login"
                            className="rounded-lg bg-brand-600 px-6 py-3 font-semibold text-white shadow-sm hover:bg-brand-700 transition"
                        >
                            Get started free
                        </Link>
                        <Link
                            href="/pricing"
                            className="rounded-lg border border-gray-300 dark:border-gray-700 px-6 py-3 font-semibold text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800 transition"
                        >
                            View pricing
                        </Link>
                    </div>
                </div>
            </section>

            {/* Features */}
            <section className="bg-gray-50 dark:bg-gray-900 py-20">
                <div className="mx-auto max-w-6xl px-6">
                    <h2 className="text-center text-3xl font-bold text-gray-900 dark:text-white">
                        Everything you need to verify AI code
                    </h2>
                    <div className="mt-12 grid gap-8 md:grid-cols-2 lg:grid-cols-3">
                        {FEATURES.map((f) => (
                            <div
                                key={f.title}
                                className="rounded-xl bg-white dark:bg-gray-800 p-6 shadow-sm border border-gray-200 dark:border-gray-700"
                            >
                                <span className="text-3xl">{f.icon}</span>
                                <h3 className="mt-4 text-lg font-semibold text-gray-900 dark:text-white">
                                    {f.title}
                                </h3>
                                <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
                                    {f.description}
                                </p>
                            </div>
                        ))}
                    </div>
                </div>
            </section>

            {/* CTA */}
            <section className="bg-brand-600 py-16">
                <div className="mx-auto max-w-4xl px-6 text-center">
                    <h2 className="text-3xl font-bold text-white">
                        Start verifying code in under 2 minutes
                    </h2>
                    <p className="mt-4 text-lg text-brand-100">
                        Free tier includes 100 scans/day. No credit card required.
                    </p>
                    <Link
                        href="/login"
                        className="mt-8 inline-block rounded-lg bg-white px-8 py-3 font-semibold text-brand-700 shadow hover:bg-gray-100 transition"
                    >
                        Sign up with GitHub
                    </Link>
                </div>
            </section>
        </main>
    );
}
