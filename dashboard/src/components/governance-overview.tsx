"use client";

import { useEffect, useState } from "react";
import Link from "next/link";

interface DashboardData {
    enforcement: {
        layers_active: number;
        total_blocks_24h: number;
        total_warns_24h: number;
        top_blocked_rules: Array<{ rule: string; count: number }>;
    };
    compliance: {
        owasp_asi: { status: string; full: number; total: number };
        eu_ai_act: { status: string; full: number; total: number };
        nist_rmf: { status: string; full: number; total: number };
    };
    pii: {
        scans_24h: number;
        findings_24h: number;
        blocks_24h: number;
    };
    classification: {
        files_classified: number;
        by_level: Record<string, number>;
    };
    cost: {
        current_month_usd: number;
        budget_limit_usd: number;
        budget_pct: number;
        top_model: { name: string; cost: number };
        anomalies_24h: number;
    };
    integrity: {
        sessions_analyzed: number;
        trustworthy: number;
        questionable: number;
        unreliable: number;
    };
}

const POLL_INTERVAL_MS = 30_000;

function StatusBadge({ status }: { status: string }) {
    const color = status === "COMPLIANT"
        ? "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"
        : "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200";
    return (
        <span className={`inline-block rounded-full px-2 py-0.5 text-xs font-medium ${color}`}>
            {status}
        </span>
    );
}

function Card({
    title, value, subtitle, href, borderColor,
}: {
    title: string; value: string | number; subtitle: string; href: string; borderColor: string;
}) {
    return (
        <Link href={href} className="block">
            <div className={`rounded-lg border border-l-4 ${borderColor} p-4 transition hover:shadow-md bg-white dark:bg-gray-900`}>
                <p className="text-sm font-medium text-gray-500 dark:text-gray-400">{title}</p>
                <p className="mt-1 text-2xl font-bold text-gray-900 dark:text-white">{value}</p>
                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">{subtitle}</p>
            </div>
        </Link>
    );
}

export function GovernanceOverview({ apiKey }: { apiKey: string }) {
    const [data, setData] = useState<DashboardData | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [lastUpdated, setLastUpdated] = useState<string>("");

    useEffect(() => {
        let active = true;

        async function fetchData() {
            try {
                const apiBase = process.env.NEXT_PUBLIC_API_URL || "";
                const res = await fetch(`${apiBase}/v1/dashboard/overview`, {
                    headers: {
                        "X-API-Key": apiKey,
                        "Content-Type": "application/json",
                    },
                });
                if (!res.ok) {
                    if (res.status === 401 || res.status === 403) {
                        setError("Authentication required");
                    } else {
                        setError(`API error: ${res.status}`);
                    }
                    return;
                }
                const json = await res.json();
                if (active) {
                    setData(json);
                    setError(null);
                    setLastUpdated(new Date().toLocaleTimeString());
                }
            } catch (err) {
                if (active) {
                    setError("Failed to connect to API");
                }
            }
        }

        fetchData();
        const interval = setInterval(fetchData, POLL_INTERVAL_MS);
        return () => { active = false; clearInterval(interval); };
    }, [apiKey]);

    if (error && !data) {
        return (
            <div className="rounded-lg border border-yellow-200 bg-yellow-50 dark:bg-yellow-950/20 p-4">
                <p className="text-sm text-yellow-800 dark:text-yellow-200">
                    Governance overview unavailable: {error}
                </p>
                <p className="mt-1 text-xs text-yellow-600">
                    The governance dashboard requires a running CodeTrust API.
                    Data will appear once the API is accessible.
                </p>
            </div>
        );
    }

    if (!data) {
        return (
            <div className="grid gap-4 sm:grid-cols-3 lg:grid-cols-6">
                {Array.from({ length: 6 }).map((_, i) => (
                    <div key={i} className="h-28 animate-pulse rounded-lg border bg-gray-100 dark:bg-gray-800" />
                ))}
            </div>
        );
    }

    const complianceTotal = data.compliance.owasp_asi.full + data.compliance.eu_ai_act.full + data.compliance.nist_rmf.full;
    const complianceMax = data.compliance.owasp_asi.total + data.compliance.eu_ai_act.total + data.compliance.nist_rmf.total;
    const allCompliant = complianceTotal === complianceMax;

    return (
        <div>
            <div className="flex items-center justify-between mb-4">
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                    Governance Overview
                </h2>
                <span className="text-xs text-gray-400">
                    {error
                        ? `Retrying — ${error}`
                        : lastUpdated
                            ? `Updated ${lastUpdated} (polls every 30s)`
                            : "Loading..."}
                </span>
            </div>

            {/* Core — what every user needs */}
            <div className="grid gap-4 sm:grid-cols-3">
                <Card
                    title="Threats Blocked"
                    value={data.enforcement.total_blocks_24h}
                    subtitle={`${data.enforcement.layers_active} enforcement layers active, ${data.enforcement.total_warns_24h} warnings (24h)`}
                    href="/dashboard/enforcement"
                    borderColor={data.enforcement.total_blocks_24h > 0 ? "border-l-red-500" : "border-l-green-500"}
                />
                <Card
                    title="PII Detection"
                    value={`${data.pii.blocks_24h} blocks`}
                    subtitle={`${data.pii.scans_24h} scans, ${data.pii.findings_24h} findings (24h)`}
                    href="/dashboard/pii"
                    borderColor={data.pii.blocks_24h > 0 ? "border-l-red-500" : "border-l-green-500"}
                />
                <Card
                    title="Agent Integrity"
                    value={data.integrity.sessions_analyzed > 0
                        ? `${data.integrity.trustworthy}/${data.integrity.sessions_analyzed} trusted`
                        : "No sessions yet"}
                    subtitle={data.integrity.unreliable > 0
                        ? `${data.integrity.unreliable} unreliable sessions detected`
                        : data.integrity.questionable > 0
                            ? `${data.integrity.questionable} questionable`
                            : "All sessions healthy"}
                    href="/dashboard/integrity"
                    borderColor={data.integrity.unreliable > 0 ? "border-l-red-500" : "border-l-green-500"}
                />
            </div>

            {/* Pro — governance & operations */}
            <div className="mt-6">
                <p className="text-xs font-medium text-gray-400 dark:text-gray-500 uppercase tracking-wider mb-3">Pro</p>
                <div className="grid gap-4 sm:grid-cols-3">
                    <Card
                        title="LLM Cost"
                        value={`$${data.cost.current_month_usd.toFixed(2)}`}
                        subtitle={data.cost.budget_limit_usd > 0
                            ? `${data.cost.budget_pct.toFixed(0)}% of budget`
                            : `Top model: ${data.cost.top_model.name}`}
                        href="/dashboard/cost"
                        borderColor={data.cost.budget_pct > 95 ? "border-l-red-500" : data.cost.budget_pct > 80 ? "border-l-yellow-500" : "border-l-green-500"}
                    />
                    <Card
                        title="Classification"
                        value={`${data.classification.files_classified} files`}
                        subtitle={Object.entries(data.classification.by_level).map(([k, v]) => `${v} ${k}`).join(", ") || "No files classified yet"}
                        href="/dashboard/classification"
                        borderColor="border-l-blue-500"
                    />
                    <Card
                        title="Compliance Mapping"
                        value={`${complianceTotal}/${complianceMax}`}
                        subtitle={allCompliant ? "All frameworks mapped" : "Coverage gaps detected"}
                        href="/dashboard/compliance"
                        borderColor={allCompliant ? "border-l-green-500" : "border-l-yellow-500"}
                    />
                </div>
            </div>

            {/* Top blocked rules */}
            {data.enforcement.top_blocked_rules.length > 0 && (
                <div className="mt-6">
                    <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">
                        Top Blocked Rules (24h)
                    </h3>
                    <div className="flex flex-wrap gap-2">
                        {data.enforcement.top_blocked_rules.slice(0, 5).map((r) => (
                            <span key={r.rule} className="rounded-full bg-red-50 dark:bg-red-950/30 px-3 py-1 text-xs text-red-700 dark:text-red-300">
                                {r.rule} ({r.count})
                            </span>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );
}
