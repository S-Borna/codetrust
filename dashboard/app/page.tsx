import Link from "next/link";

const FEATURES = [
    {
        title: "Real-Time Agent Interception",
        description:
            "BASH_ENV guard + PreToolUse hooks block destructive commands before execution. git push, rm -rf, heredoc — all caught before damage.",
        icon: "🛡️",
    },
    {
        title: "AI Attribution",
        description:
            "Per-line model tracking. GPT-5.3, Claude Opus 4.6, Gemini 3, Codex 5.3 — know which AI wrote which line. Shadow AI flagged.",
        icon: "🔍",
    },
    {
        title: "Hallucination Detection",
        description:
            "Live verification against PyPI, npm, crates.io, Go Proxy, Maven, NuGet, RubyGems, and Packagist. Hallucinated packages blocked instantly.",
        icon: "📦",
    },
    {
        title: "AI Policy Engine",
        description:
            "Model allowlist/blocklist. Max AI ratio per commit. Attribution requirements. The CTO decides, CodeTrust enforces.",
        icon: "⚙️",
    },
    {
        title: "Commit & Repo Guards",
        description:
            "Pre-commit hook scans 2,924 rules. BLOCK = rejected. Governance files protected — agents cannot change their own rules.",
        icon: "🔒",
    },
    {
        title: "8 Enforcement Layers",
        description:
            "BASH_ENV, PreToolUse hooks, MCP Gateway, pre-commit, GitHub Action, advisory files, governance config, allow-list audit. All verified by codetrust doctor.",
        icon: "📊",
    },
];

export default function HomePage() {
    return (
        <main>
            {/* Hero */}
            <section className="relative overflow-hidden bg-white dark:bg-gray-950">
                <div className="mx-auto max-w-6xl px-6 py-24 text-center">
                    <h1 className="text-5xl font-bold tracking-tight text-gray-900 dark:text-white sm:text-6xl">
                        Your AI agent just ran
                        <span className="text-brand-600"> git push --force</span>.
                        <br />
                        <span className="text-emerald-500">CodeTrust stopped it before it executed.</span>
                    </h1>
                    <p className="mx-auto mt-6 max-w-2xl text-lg text-gray-600 dark:text-gray-400">
                        AI governance enforcement platform. 3,006 rules, 8 enforcement layers,
                        39 MCP tools. Blocks destructive commands, catches hallucinated packages,
                        tracks which AI model wrote every line — before damage happens.
                    </p>
                    <div className="mt-10 flex items-center justify-center gap-4">
                        <Link
                            href="/login"
                            className="rounded-lg bg-brand-600 px-6 py-3 font-semibold text-white shadow-sm hover:bg-brand-700 transition"
                        >
                            See what your AI would break
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
                        What no other tool does
                    </h2>
                    <p className="mx-auto mt-4 max-w-2xl text-center text-gray-600 dark:text-gray-400">
                        SonarQube checks quality. Snyk checks CVEs. Nobody checks what the AI agent itself is doing.
                    </p>
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
                        Governance active in 30 seconds
                    </h2>
                    <p className="mt-4 text-lg text-brand-100">
                        Free tier: 25 scans/day. Detection only. No credit card.
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
