"use client";

import { useEffect, useState } from "react";

interface CostData {
    current_month_usd: number;
    budget_limit_usd: number;
    budget_pct: number;
    top_developer: { name: string; cost: number };
    top_model: { name: string; cost: number };
    anomalies_24h: number;
}

export default function CostPage() {
    const [data, setData] = useState<CostData | null>(null);

    useEffect(() => {
        async function load() {
            try {
                const apiBase = process.env.NEXT_PUBLIC_API_URL || "";
                const res = await fetch(`${apiBase}/v1/dashboard/overview`, {
                    headers: { "Content-Type": "application/json" },
                });
                if (res.ok) {
                    const json = await res.json();
                    setData(json.cost);
                }
            } catch { /* API not reachable */ }
        }
        load();
        const interval = setInterval(load, 30_000);
        return () => clearInterval(interval);
    }, []);

    const cost = data?.current_month_usd ?? 0;
    const budget = data?.budget_limit_usd ?? 0;
    const pct = data?.budget_pct ?? 0;
    const anomalies = data?.anomalies_24h ?? 0;
    const topDev = data?.top_developer ?? { name: "", cost: 0 };
    const topModel = data?.top_model ?? { name: "", cost: 0 };
    const hasUsage = cost > 0;

    return (
        <div className="mx-auto max-w-6xl px-6 py-8">
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Cost Tracking</h1>
            <p className="mt-2 text-gray-500 dark:text-gray-400">
                LLM cost monitoring per developer, team, and model. Polls every 30s.
            </p>

            <div className="mt-8 grid grid-cols-1 gap-6 sm:grid-cols-3">
                <div className="rounded-lg border p-6 text-center">
                    <p className="text-sm text-gray-500">This Month</p>
                    <p className="mt-1 text-3xl font-bold text-gray-900 dark:text-white">${cost.toFixed(2)}</p>
                </div>
                <div className="rounded-lg border p-6 text-center">
                    <p className="text-sm text-gray-500">Budget</p>
                    {budget > 0 ? (
                        <>
                            <p className="mt-1 text-3xl font-bold text-gray-900 dark:text-white">{pct.toFixed(0)}%</p>
                            <div className="mt-2 h-2 w-full rounded-full bg-gray-200 dark:bg-gray-700">
                                <div
                                    className={`h-2 rounded-full ${pct > 95 ? "bg-red-500" : pct > 80 ? "bg-yellow-500" : "bg-green-500"}`}
                                    style={{ width: `${Math.min(pct, 100)}%` }}
                                />
                            </div>
                            <p className="mt-1 text-xs text-gray-400">${cost.toFixed(2)} / ${budget.toFixed(0)}</p>
                        </>
                    ) : (
                        <p className="mt-1 text-lg text-gray-400">Not configured</p>
                    )}
                </div>
                <div className="rounded-lg border p-6 text-center">
                    <p className="text-sm text-gray-500">Anomalies (24h)</p>
                    <p className={`mt-1 text-3xl font-bold ${anomalies > 0 ? "text-red-600" : "text-green-600"}`}>
                        {anomalies}
                    </p>
                </div>
            </div>

            <div className="mt-8 grid grid-cols-1 gap-6 sm:grid-cols-2">
                <div className="rounded-lg border p-6">
                    <p className="text-sm text-gray-500">Top Developer</p>
                    {hasUsage && topDev.name ? (
                        <>
                            <p className="mt-1 text-xl font-bold text-gray-900 dark:text-white">{topDev.name}</p>
                            <p className="text-sm text-gray-400">${topDev.cost.toFixed(2)}</p>
                        </>
                    ) : (
                        <p className="mt-1 text-sm text-gray-400">No usage tracked yet</p>
                    )}
                </div>
                <div className="rounded-lg border p-6">
                    <p className="text-sm text-gray-500">Top Model</p>
                    {hasUsage && topModel.name ? (
                        <>
                            <p className="mt-1 text-xl font-bold text-gray-900 dark:text-white">{topModel.name}</p>
                            <p className="text-sm text-gray-400">${topModel.cost.toFixed(2)}</p>
                        </>
                    ) : (
                        <p className="mt-1 text-sm text-gray-400">No usage tracked yet</p>
                    )}
                </div>
            </div>

            <div className="mt-8">
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Supported Models + Pricing</h2>
                <div className="mt-4 rounded-lg border overflow-hidden">
                    <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                        <thead className="bg-gray-50 dark:bg-gray-800">
                            <tr>
                                <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Model</th>
                                <th className="px-4 py-2 text-right text-xs font-medium text-gray-500 uppercase">Input/1M</th>
                                <th className="px-4 py-2 text-right text-xs font-medium text-gray-500 uppercase">Output/1M</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-gray-200 dark:divide-gray-700 text-sm">
                            {[
                                ["Claude Opus 4.6", "$15.00", "$75.00"],
                                ["Claude Sonnet 4.6", "$3.00", "$15.00"],
                                ["Claude Haiku 4.5", "$0.80", "$4.00"],
                                ["GPT-4.1", "$2.00", "$8.00"],
                                ["GPT-4o", "$2.50", "$10.00"],
                                ["o3-mini / o4-mini", "$1.10", "$4.40"],
                                ["Gemini 2.5 Pro", "$1.25", "$10.00"],
                                ["Gemini 2.5 Flash", "$0.15", "$0.60"],
                            ].map(([model, inp, out]) => (
                                <tr key={model}>
                                    <td className="px-4 py-2 text-gray-700 dark:text-gray-300">{model}</td>
                                    <td className="px-4 py-2 text-right text-gray-500">{inp}</td>
                                    <td className="px-4 py-2 text-right text-gray-500">{out}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
}
