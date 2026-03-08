"use client";

import type { GovernancePosture } from "@/lib/api";

function StatusIndicator({ active, label }: { active: boolean; label: string }) {
    return (
        <div className="flex items-center gap-2">
            <span
                className={`inline-block h-2.5 w-2.5 rounded-full ${
                    active
                        ? "bg-green-500 shadow-sm shadow-green-500/50"
                        : "bg-gray-300 dark:bg-gray-600"
                }`}
            />
            <span className="text-sm text-gray-700 dark:text-gray-300">
                {label}
            </span>
            <span
                className={`ml-auto text-xs font-medium ${
                    active ? "text-green-600" : "text-gray-400"
                }`}
            >
                {active ? "Active" : "Off"}
            </span>
        </div>
    );
}

function IntegrityBadge({ verdict }: { verdict: string }) {
    const colors: Record<string, string> = {
        ALLOW: "bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400",
        WARN: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400",
        BLOCK: "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400",
    };
    return (
        <span
            className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${
                colors[verdict] || "bg-gray-100 text-gray-800"
            }`}
        >
            {verdict}
        </span>
    );
}

export function GovernancePostureView({
    posture,
}: {
    posture: GovernancePosture | null;
}) {
    if (!posture) {
        return (
            <div className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-6">
                <p className="text-sm text-gray-500 dark:text-gray-400">
                    Governance posture unavailable. Connect to the API to view
                    live status.
                </p>
            </div>
        );
    }

    return (
        <div className="space-y-6">
            {/* Control plane readiness */}
            <div className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-6">
                <div className="flex items-center justify-between mb-4">
                    <h3 className="text-sm font-medium text-gray-900 dark:text-white">
                        Control Plane
                    </h3>
                    <span
                        className={`inline-flex items-center rounded-full px-3 py-1 text-xs font-semibold ${
                            posture.control_plane_ready
                                ? "bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400"
                                : "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400"
                        }`}
                    >
                        {posture.control_plane_ready ? "Ready" : "Partial"}
                    </span>
                </div>

                <div className="grid gap-4 sm:grid-cols-2 mb-4">
                    <div>
                        <p className="text-xs text-gray-500 dark:text-gray-400">
                            Mode
                        </p>
                        <p className="text-sm font-medium text-gray-900 dark:text-white capitalize">
                            {posture.mode}
                        </p>
                    </div>
                    <div>
                        <p className="text-xs text-gray-500 dark:text-gray-400">
                            Agent
                        </p>
                        <p className="text-sm font-mono text-gray-900 dark:text-white">
                            {posture.agent_id}
                        </p>
                    </div>
                    <div>
                        <p className="text-xs text-gray-500 dark:text-gray-400">
                            Session
                        </p>
                        <p className="text-sm font-mono text-gray-700 dark:text-gray-300 truncate">
                            {posture.session_id}
                        </p>
                    </div>
                    <div>
                        <p className="text-xs text-gray-500 dark:text-gray-400">
                            Policy integrity
                        </p>
                        <IntegrityBadge
                            verdict={posture.policy_integrity.verdict}
                        />
                    </div>
                </div>
            </div>

            {/* Enforcement toggles */}
            <div className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-6">
                <h3 className="text-sm font-medium text-gray-900 dark:text-white mb-4">
                    Enforcement Gates
                </h3>
                <div className="space-y-3">
                    <StatusIndicator
                        active={posture.enabled}
                        label="Governance engine"
                    />
                    <StatusIndicator
                        active={posture.trusted_execution_mode}
                        label="Trusted execution mode"
                    />
                    <StatusIndicator
                        active={posture.deny_native_execution}
                        label="Deny native tool execution"
                    />
                    <StatusIndicator
                        active={posture.require_allow_reason}
                        label="Require allow reason"
                    />
                    <StatusIndicator
                        active={posture.session_binding_enforced}
                        label="Session binding"
                    />
                    <StatusIndicator
                        active={posture.anti_bypass_enabled}
                        label="Anti-bypass checks"
                    />
                </div>
            </div>

            {/* Active counts */}
            <div className="grid gap-4 sm:grid-cols-2">
                <div className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-6">
                    <p className="text-sm text-gray-500 dark:text-gray-400">
                        Pending approvals
                    </p>
                    <p className="mt-2 text-3xl font-bold text-yellow-600">
                        {posture.pending_approvals}
                    </p>
                </div>
                <div className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-6">
                    <p className="text-sm text-gray-500 dark:text-gray-400">
                        Active exceptions
                    </p>
                    <p className="mt-2 text-3xl font-bold text-blue-600">
                        {posture.active_exceptions}
                    </p>
                </div>
            </div>

            {/* Policy hash */}
            <div className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-6">
                <h3 className="text-sm font-medium text-gray-900 dark:text-white mb-2">
                    Policy Hash
                </h3>
                <p className="font-mono text-xs text-gray-600 dark:text-gray-400 break-all">
                    {posture.policy_integrity.policy_hash || "\u2014"}
                </p>
                <p className="text-xs text-gray-400 mt-1">
                    Rule: {posture.policy_integrity.rule_id}
                </p>
            </div>
        </div>
    );
}
