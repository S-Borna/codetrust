/**
 * Threat Intelligence dashboard page — fleet-wide view.
 *
 * Visualizes the cross-agent threat signal: what CodeTrust is catching across
 * deployments — severity split, impact categories, and top triggered rules.
 * Reads the public stats endpoint (no auth); the same data the live site shows,
 * here rendered as the fleet threat picture.
 */

const API_URL = process.env.NEXT_PUBLIC_API_URL || "https://api.codetrust.ai";

interface CategoryStat {
    label: string;
    count: number;
    last_seen: string | null;
}

interface ThreatStats {
    usage: {
        total_findings: number;
        findings_by_severity: { BLOCK: number; WARN: number; INFO: number };
    };
    impact: {
        categories: Record<string, CategoryStat>;
        top_rules: { rule: string; count: number }[];
    };
}

async function getThreatStats(): Promise<ThreatStats | null> {
    try {
        const res = await fetch(`${API_URL}/v1/stats/public`, {
            next: { revalidate: 60 },
        });
        if (!res.ok) return null;
        const data = await res.json();
        return (data && data.stats) ? (data.stats as ThreatStats) : null;
    } catch {
        return null;
    }
}

function pct(count: number, max: number): number {
    if (max <= 0) return 0;
    return Math.max(2, Math.round((count / max) * 100));
}

export const revalidate = 60;

export default async function ThreatIntelPage() {
    const stats = await getThreatStats();

    if (!stats) {
        return (
            <div className="mx-auto max-w-6xl px-6 py-8">
                <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Threat Intelligence</h1>
                <p className="mt-4 text-gray-500 dark:text-gray-400">
                    Threat data is temporarily unavailable. It builds from agent activity across deployments.
                </p>
            </div>
        );
    }

    const sev = stats.usage.findings_by_severity;
    const categories = Object.entries(stats.impact.categories)
        .map(([key, c]) => ({ key, ...c }))
        .sort((a, b) => b.count - a.count);
    const maxCat = categories.length ? categories[0].count : 0;
    const topRules = (stats.impact.top_rules || []).slice(0, 10);
    const maxRule = topRules.length ? topRules[0].count : 0;

    return (
        <div className="mx-auto max-w-6xl px-6 py-8">
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Threat Intelligence</h1>
            <p className="mt-2 text-gray-500 dark:text-gray-400">
                What CodeTrust is catching across deployments — the fleet threat picture.
                The more agents report, the sharper this gets.
            </p>

            {/* Severity headline */}
            <div className="mt-8 grid grid-cols-1 gap-6 sm:grid-cols-3">
                <div className="rounded-lg border p-6">
                    <p className="text-xs font-medium uppercase tracking-wide text-gray-500 dark:text-gray-400">Total findings</p>
                    <p className="mt-2 text-3xl font-bold text-gray-900 dark:text-white">
                        {stats.usage.total_findings.toLocaleString()}
                    </p>
                </div>
                <div className="rounded-lg border border-red-200 dark:border-red-900 p-6">
                    <p className="text-xs font-medium uppercase tracking-wide text-red-500">Critical (BLOCK)</p>
                    <p className="mt-2 text-3xl font-bold text-red-600 dark:text-red-400">
                        {sev.BLOCK.toLocaleString()}
                    </p>
                </div>
                <div className="rounded-lg border border-amber-200 dark:border-amber-900 p-6">
                    <p className="text-xs font-medium uppercase tracking-wide text-amber-500">Warnings (WARN)</p>
                    <p className="mt-2 text-3xl font-bold text-amber-600 dark:text-amber-400">
                        {sev.WARN.toLocaleString()}
                    </p>
                </div>
            </div>

            {/* Impact categories — horizontal bars */}
            <div className="mt-10">
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Threats by category</h2>
                <div className="mt-4 space-y-3">
                    {categories.map((c) => (
                        <div key={c.key}>
                            <div className="flex items-baseline justify-between text-sm">
                                <span className="font-medium text-gray-700 dark:text-gray-300">{c.label}</span>
                                <span className="tabular-nums text-gray-500 dark:text-gray-400">
                                    {c.count.toLocaleString()}
                                </span>
                            </div>
                            <div className="mt-1 h-2.5 w-full overflow-hidden rounded-full bg-gray-100 dark:bg-gray-800">
                                <div
                                    className="h-full rounded-full bg-brand-500"
                                    style={{ width: `${pct(c.count, maxCat)}%` }}
                                />
                            </div>
                        </div>
                    ))}
                </div>
            </div>

            {/* Top rules */}
            {topRules.length > 0 && (
                <div className="mt-10">
                    <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Top triggered rules</h2>
                    <div className="mt-4 space-y-2">
                        {topRules.map((r) => (
                            <div key={r.rule} className="flex items-center gap-3">
                                <span className="w-56 shrink-0 truncate font-mono text-xs text-gray-600 dark:text-gray-400">
                                    {r.rule}
                                </span>
                                <div className="h-2 flex-1 overflow-hidden rounded-full bg-gray-100 dark:bg-gray-800">
                                    <div
                                        className="h-full rounded-full bg-brand-400"
                                        style={{ width: `${pct(r.count, maxRule)}%` }}
                                    />
                                </div>
                                <span className="w-16 shrink-0 text-right tabular-nums text-xs text-gray-500 dark:text-gray-400">
                                    {r.count.toLocaleString()}
                                </span>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            <p className="mt-10 text-xs text-gray-400 dark:text-gray-500">
                Aggregated, anonymized signal across CodeTrust deployments. Refreshes every 60s.
            </p>
        </div>
    );
}
