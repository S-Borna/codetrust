"use client";

import { useState, useEffect } from "react";

interface AuditEntry {
    timestamp: number;
    action_type: string;
    verdict: string;
    rule_id: string;
    original_action: string;
    message: string;
    agent_id: string;
    session_id: string;
}

interface AuditStats {
    total: number;
    by_verdict: Record<string, number>;
    by_action_type: Record<string, number>;
    top_rules: { rule_id: string; count: number }[];
}

function VerdictBadge({ verdict }: { verdict: string }) {
    const colors: Record<string, string> = {
        BLOCK: "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400",
        WARN: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400",
        ALLOW: "bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400",
    };
    return (
        <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${colors[verdict] || "bg-gray-100 text-gray-800"}`}>
            {verdict}
        </span>
    );
}

function StatCard({ label, value, color }: { label: string; value: number; color?: string }) {
    return (
        <div className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-6">
            <p className="text-sm text-gray-500 dark:text-gray-400">{label}</p>
            <p className={`mt-2 text-3xl font-bold ${color || "text-gray-900 dark:text-white"}`}>
                {value}
            </p>
        </div>
    );
}

export function GovernanceAuditView({ entries, stats }: { entries: AuditEntry[]; stats: AuditStats }) {
    const [filter, setFilter] = useState<string>("");

    const filtered = filter
        ? entries.filter((e) => e.verdict === filter)
        : entries;

    return (
        <div className="space-y-8">
            {/* Stats cards */}
            <div className="grid gap-4 sm:grid-cols-4">
                <StatCard label="Total actions" value={stats.total} />
                <StatCard
                    label="Blocked"
                    value={stats.by_verdict?.BLOCK || 0}
                    color="text-red-600"
                />
                <StatCard
                    label="Warned"
                    value={stats.by_verdict?.WARN || 0}
                    color="text-yellow-600"
                />
                <StatCard
                    label="Allowed"
                    value={stats.by_verdict?.ALLOW || 0}
                    color="text-green-600"
                />
            </div>

            {/* Top rules */}
            {stats.top_rules && stats.top_rules.length > 0 && (
                <div className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-6">
                    <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-4">
                        Most Triggered Rules
                    </h3>
                    <div className="space-y-2">
                        {stats.top_rules.slice(0, 5).map((rule) => (
                            <div key={rule.rule_id} className="flex items-center justify-between">
                                <code className="text-sm text-gray-700 dark:text-gray-300">{rule.rule_id}</code>
                                <span className="text-sm font-medium text-gray-900 dark:text-white">
                                    {rule.count}×
                                </span>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Filter + table */}
            <div className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900">
                <div className="flex items-center justify-between border-b border-gray-200 dark:border-gray-700 px-6 py-4">
                    <h3 className="text-sm font-medium text-gray-900 dark:text-white">
                        Audit Log ({filtered.length} entries)
                    </h3>
                    <div className="flex gap-2">
                        {["", "BLOCK", "WARN", "ALLOW"].map((v) => (
                            <button
                                key={v}
                                onClick={() => setFilter(v)}
                                className={`rounded-lg px-3 py-1.5 text-xs font-medium transition ${filter === v
                                    ? "bg-brand-100 dark:bg-brand-900 text-brand-700 dark:text-brand-300"
                                    : "text-gray-500 hover:bg-gray-100 dark:hover:bg-gray-800"
                                    }`}
                            >
                                {v || "All"}
                            </button>
                        ))}
                    </div>
                </div>

                <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                        <thead>
                            <tr className="border-b border-gray-100 dark:border-gray-800">
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Time</th>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Agent</th>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Verdict</th>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Rule</th>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Action</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-gray-100 dark:divide-gray-800">
                            {filtered.map((entry, i) => (
                                <tr key={i} className="hover:bg-gray-50 dark:hover:bg-gray-800/50">
                                    <td className="whitespace-nowrap px-6 py-3 text-gray-500 dark:text-gray-400">
                                        {new Date(entry.timestamp * 1000).toLocaleTimeString()}
                                    </td>
                                    <td className="whitespace-nowrap px-6 py-3 text-gray-700 dark:text-gray-300">
                                        {entry.agent_id || "—"}
                                    </td>
                                    <td className="whitespace-nowrap px-6 py-3">
                                        <VerdictBadge verdict={entry.verdict} />
                                    </td>
                                    <td className="whitespace-nowrap px-6 py-3">
                                        <code className="text-xs text-gray-600 dark:text-gray-400">
                                            {entry.rule_id || "—"}
                                        </code>
                                    </td>
                                    <td className="max-w-xs truncate px-6 py-3 text-gray-700 dark:text-gray-300">
                                        {entry.original_action}
                                    </td>
                                </tr>
                            ))}
                            {filtered.length === 0 && (
                                <tr>
                                    <td colSpan={5} className="px-6 py-8 text-center text-gray-500">
                                        No audit entries found.
                                    </td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
}
