"use client";

import type { GovernancePosture } from "@/lib/api";

interface DriftCheck {
    label: string;
    expected: boolean;
    actual: boolean;
    severity: "critical" | "warning";
}

function buildDriftChecks(posture: GovernancePosture): DriftCheck[] {
    return [
        {
            label: "Governance engine enabled",
            expected: true,
            actual: posture.enabled,
            severity: "critical",
        },
        {
            label: "Trusted execution mode",
            expected: true,
            actual: posture.trusted_execution_mode,
            severity: "critical",
        },
        {
            label: "Deny native tool execution",
            expected: true,
            actual: posture.deny_native_execution,
            severity: "critical",
        },
        {
            label: "Require allow reason",
            expected: true,
            actual: posture.require_allow_reason,
            severity: "warning",
        },
        {
            label: "Session binding enforced",
            expected: true,
            actual: posture.session_binding_enforced,
            severity: "warning",
        },
        {
            label: "Anti-bypass checks",
            expected: true,
            actual: posture.anti_bypass_enabled,
            severity: "warning",
        },
        {
            label: "Policy integrity passing",
            expected: true,
            actual: posture.policy_integrity.verdict === "ALLOW",
            severity: "critical",
        },
    ];
}

export function DriftAlerts({
    posture,
}: {
    posture: GovernancePosture | null;
}) {
    if (!posture) {
        return null;
    }

    const checks = buildDriftChecks(posture);
    const drifted = checks.filter((c) => c.actual !== c.expected);
    const criticalDrifts = drifted.filter((d) => d.severity === "critical");
    const warningDrifts = drifted.filter((d) => d.severity === "warning");

    if (drifted.length === 0) {
        return (
            <div className="rounded-xl border border-green-200 dark:border-green-800 bg-green-50 dark:bg-green-900/20 p-4">
                <div className="flex items-center gap-2">
                    <span className="inline-block h-2.5 w-2.5 rounded-full bg-green-500" />
                    <p className="text-sm font-medium text-green-800 dark:text-green-400">
                        No drift detected — all governance gates match expected
                        baseline.
                    </p>
                </div>
            </div>
        );
    }

    return (
        <div className="space-y-4">
            {criticalDrifts.length > 0 && (
                <div className="rounded-xl border border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/20 p-4">
                    <div className="flex items-center gap-2 mb-3">
                        <span className="inline-block h-2.5 w-2.5 rounded-full bg-red-500 animate-pulse" />
                        <p className="text-sm font-semibold text-red-800 dark:text-red-400">
                            Critical Drift ({criticalDrifts.length})
                        </p>
                    </div>
                    <ul className="space-y-2">
                        {criticalDrifts.map((d) => (
                            <li
                                key={d.label}
                                className="flex items-center gap-2 text-sm text-red-700 dark:text-red-300"
                            >
                                <span className="font-mono text-xs bg-red-100 dark:bg-red-900/30 px-1.5 py-0.5 rounded">
                                    DRIFT
                                </span>
                                {d.label} — expected{" "}
                                <strong>
                                    {d.expected ? "ON" : "OFF"}
                                </strong>
                                , got{" "}
                                <strong>
                                    {d.actual ? "ON" : "OFF"}
                                </strong>
                            </li>
                        ))}
                    </ul>
                </div>
            )}

            {warningDrifts.length > 0 && (
                <div className="rounded-xl border border-yellow-200 dark:border-yellow-800 bg-yellow-50 dark:bg-yellow-900/20 p-4">
                    <div className="flex items-center gap-2 mb-3">
                        <span className="inline-block h-2.5 w-2.5 rounded-full bg-yellow-500" />
                        <p className="text-sm font-semibold text-yellow-800 dark:text-yellow-400">
                            Warning Drift ({warningDrifts.length})
                        </p>
                    </div>
                    <ul className="space-y-2">
                        {warningDrifts.map((d) => (
                            <li
                                key={d.label}
                                className="flex items-center gap-2 text-sm text-yellow-700 dark:text-yellow-300"
                            >
                                <span className="font-mono text-xs bg-yellow-100 dark:bg-yellow-900/30 px-1.5 py-0.5 rounded">
                                    WARN
                                </span>
                                {d.label} — expected{" "}
                                <strong>
                                    {d.expected ? "ON" : "OFF"}
                                </strong>
                                , got{" "}
                                <strong>
                                    {d.actual ? "ON" : "OFF"}
                                </strong>
                            </li>
                        ))}
                    </ul>
                </div>
            )}
        </div>
    );
}
