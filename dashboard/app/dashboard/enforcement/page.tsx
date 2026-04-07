"use client";

import { useEffect, useState } from "react";

interface EnforcementData {
    layers_active: number;
    total_blocks_24h: number;
    total_warns_24h: number;
    top_blocked_rules: Array<{ rule: string; count: number }>;
}

export default function EnforcementPage() {
    const [data, setData] = useState<EnforcementData | null>(null);

    useEffect(() => {
        async function load() {
            try {
                const apiBase = process.env.NEXT_PUBLIC_API_URL || "";
                const res = await fetch(`${apiBase}/v1/dashboard/overview`, {
                    headers: { "Content-Type": "application/json" },
                });
                if (res.ok) {
                    const json = await res.json();
                    setData(json.enforcement);
                }
            } catch {
                // API not reachable — show fallback
            }
        }
        load();
        const interval = setInterval(load, 30_000);
        return () => clearInterval(interval);
    }, []);

    const layers = data?.layers_active ?? 9;
    const blocks = data?.total_blocks_24h ?? 0;
    const warns = data?.total_warns_24h ?? 0;
    const rules = data?.top_blocked_rules ?? [];

    return (
        <div className="mx-auto max-w-6xl px-6 py-8">
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Enforcement</h1>
            <p className="mt-2 text-gray-500 dark:text-gray-400">
                Real-time governance enforcement (last 24h). Polls every 30 seconds.
            </p>

            <div className="mt-8 grid grid-cols-1 gap-6 sm:grid-cols-3">
                <div className="rounded-lg border p-6 text-center">
                    <p className="text-sm text-gray-500">Layers Active</p>
                    <p className="mt-1 text-3xl font-bold text-green-600">{layers}</p>
                </div>
                <div className="rounded-lg border p-6 text-center">
                    <p className="text-sm text-gray-500">Blocks (24h)</p>
                    <p className={`mt-1 text-3xl font-bold ${blocks > 0 ? "text-red-600" : "text-green-600"}`}>{blocks}</p>
                </div>
                <div className="rounded-lg border p-6 text-center">
                    <p className="text-sm text-gray-500">Warns (24h)</p>
                    <p className={`mt-1 text-3xl font-bold ${warns > 0 ? "text-yellow-600" : "text-green-600"}`}>{warns}</p>
                </div>
            </div>

            <div className="mt-8">
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Top Blocked Rules</h2>
                <div className="mt-4 rounded-lg border overflow-hidden">
                    <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                        <thead className="bg-gray-50 dark:bg-gray-800">
                            <tr>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Rule</th>
                                <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase">Count</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                            {rules.length === 0 ? (
                                <tr><td className="px-6 py-4 text-sm text-gray-400" colSpan={2}>No blocks in the last 24 hours</td></tr>
                            ) : rules.map((r) => (
                                <tr key={r.rule}>
                                    <td className="px-6 py-4 text-sm font-mono text-gray-700 dark:text-gray-300">{r.rule}</td>
                                    <td className="px-6 py-4 text-sm text-right text-gray-900 dark:text-white font-medium">{r.count}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
}
