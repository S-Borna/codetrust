"use client";

import type { GovernanceWorkspaceAggregate, GovernanceWorkspacePosture } from "@/lib/api";

const STATUS_COLORS = {
    healthy: "bg-green-500",
    drifted: "bg-red-500",
    disabled: "bg-gray-400",
} as const;

function classifyWorkspace(
    ws: GovernanceWorkspacePosture,
): "healthy" | "drifted" | "disabled" {
    if (!ws.enabled) return "disabled";
    if (ws.drift_count > 0) return "drifted";
    return "healthy";
}

function formatTimestamp(ts: number): string {
    if (ts === 0) return "Never";
    const date = new Date(ts * 1000);
    return date.toLocaleString();
}

function AggregateBar({
    healthy,
    drifted,
    disabled,
    total,
}: {
    healthy: number;
    drifted: number;
    disabled: number;
    total: number;
}) {
    if (total === 0) return null;
    const healthyPct = (healthy / total) * 100;
    const driftedPct = (drifted / total) * 100;
    const disabledPct = (disabled / total) * 100;

    return (
        <div className="w-full h-3 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden flex">
            {healthyPct > 0 && (
                <div
                    className="bg-green-500 h-full"
                    style={{ width: `${healthyPct}%` }}
                    title={`Healthy: ${healthy}`}
                />
            )}
            {driftedPct > 0 && (
                <div
                    className="bg-red-500 h-full"
                    style={{ width: `${driftedPct}%` }}
                    title={`Drifted: ${drifted}`}
                />
            )}
            {disabledPct > 0 && (
                <div
                    className="bg-gray-400 h-full"
                    style={{ width: `${disabledPct}%` }}
                    title={`Disabled: ${disabled}`}
                />
            )}
        </div>
    );
}

function WorkspaceRow({ ws }: { ws: GovernanceWorkspacePosture }) {
    const status = classifyWorkspace(ws);
    const statusColor = STATUS_COLORS[status];

    return (
        <tr className="border-b border-gray-100 dark:border-gray-800">
            <td className="py-3 pr-4">
                <div className="flex items-center gap-2">
                    <span
                        className={`inline-block h-2.5 w-2.5 rounded-full ${statusColor}`}
                    />
                    <span className="font-medium text-gray-900 dark:text-white text-sm">
                        {ws.workspace_name}
                    </span>
                </div>
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5 ml-4">
                    {ws.workspace_id}
                </p>
            </td>
            <td className="py-3 px-4 text-sm text-gray-700 dark:text-gray-300">
                {ws.agent_id}
            </td>
            <td className="py-3 px-4 text-sm">
                <span
                    className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${
                        ws.enabled
                            ? "bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400"
                            : "bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400"
                    }`}
                >
                    {ws.mode}
                </span>
            </td>
            <td className="py-3 px-4 text-sm">
                {ws.drift_count > 0 ? (
                    <span className="text-red-600 dark:text-red-400 font-medium">
                        {ws.drift_count} drift{ws.drift_count > 1 ? "s" : ""}
                    </span>
                ) : (
                    <span className="text-green-600 dark:text-green-400">
                        Clean
                    </span>
                )}
            </td>
            <td className="py-3 px-4 text-sm text-gray-600 dark:text-gray-400">
                {ws.policy_verdict === "ALLOW" ? (
                    <span className="text-green-600 dark:text-green-400">PASS</span>
                ) : (
                    <span className="text-red-600 dark:text-red-400">{ws.policy_verdict}</span>
                )}
            </td>
            <td className="py-3 px-4 text-sm tabular-nums text-gray-600 dark:text-gray-400">
                {ws.pending_approvals}
            </td>
            <td className="py-3 pl-4 text-sm text-gray-500 dark:text-gray-400">
                {formatTimestamp(ws.last_seen_at)}
            </td>
        </tr>
    );
}

/**
 * Multi-workspace governance view — bird's-eye aggregate
 * of all registered workspaces with health indicators,
 * drift counts, and policy integrity status.
 */
export function MultiWorkspaceView({
    aggregate,
}: {
    aggregate: GovernanceWorkspaceAggregate | null;
}) {
    if (!aggregate || aggregate.total_workspaces === 0) {
        return (
            <div className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-6">
                <h3 className="text-sm font-medium text-gray-900 dark:text-white mb-2">
                    Multi-Workspace Overview
                </h3>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                    No workspaces registered yet. Gateway instances will
                    auto-register when they report posture.
                </p>
                <div className="mt-3 font-mono text-xs text-gray-500 dark:text-gray-400 bg-gray-50 dark:bg-gray-800 rounded-lg p-3">
                    <p>POST /v1/governance/workspaces</p>
                    <p className="text-gray-400">
                        # Register a workspace for aggregation
                    </p>
                </div>
            </div>
        );
    }

    return (
        <div className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-6">
            <div className="flex items-center justify-between mb-4">
                <h3 className="text-sm font-medium text-gray-900 dark:text-white">
                    Multi-Workspace Overview
                </h3>
                <span className="text-xs text-gray-500 dark:text-gray-400">
                    {aggregate.total_workspaces} workspace
                    {aggregate.total_workspaces !== 1 ? "s" : ""}
                </span>
            </div>

            {/* Aggregate stats bar */}
            <div className="mb-4">
                <AggregateBar
                    healthy={aggregate.healthy_count}
                    drifted={aggregate.drifted_count}
                    disabled={aggregate.disabled_count}
                    total={aggregate.total_workspaces}
                />
                <div className="flex justify-between mt-2 text-xs text-gray-500 dark:text-gray-400">
                    <span className="flex items-center gap-1">
                        <span className="inline-block h-2 w-2 rounded-full bg-green-500" />
                        Healthy: {aggregate.healthy_count}
                    </span>
                    <span className="flex items-center gap-1">
                        <span className="inline-block h-2 w-2 rounded-full bg-red-500" />
                        Drifted: {aggregate.drifted_count}
                    </span>
                    <span className="flex items-center gap-1">
                        <span className="inline-block h-2 w-2 rounded-full bg-gray-400" />
                        Disabled: {aggregate.disabled_count}
                    </span>
                </div>
            </div>

            {/* Summary counters */}
            <div className="grid grid-cols-2 gap-4 mb-6">
                <div className="rounded-lg bg-gray-50 dark:bg-gray-800 p-3">
                    <p className="text-xs text-gray-500 dark:text-gray-400">
                        Pending Approvals
                    </p>
                    <p className="text-lg font-semibold text-gray-900 dark:text-white">
                        {aggregate.total_pending_approvals}
                    </p>
                </div>
                <div className="rounded-lg bg-gray-50 dark:bg-gray-800 p-3">
                    <p className="text-xs text-gray-500 dark:text-gray-400">
                        Active Exceptions
                    </p>
                    <p className="text-lg font-semibold text-gray-900 dark:text-white">
                        {aggregate.total_active_exceptions}
                    </p>
                </div>
            </div>

            {/* Workspace table */}
            <div className="overflow-x-auto">
                <table className="w-full text-left">
                    <thead>
                        <tr className="border-b border-gray-200 dark:border-gray-700 text-xs text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                            <th className="pb-2 pr-4 font-medium">Workspace</th>
                            <th className="pb-2 px-4 font-medium">Agent</th>
                            <th className="pb-2 px-4 font-medium">Mode</th>
                            <th className="pb-2 px-4 font-medium">Drift</th>
                            <th className="pb-2 px-4 font-medium">Policy</th>
                            <th className="pb-2 px-4 font-medium">Pending</th>
                            <th className="pb-2 pl-4 font-medium">Last Seen</th>
                        </tr>
                    </thead>
                    <tbody>
                        {aggregate.workspaces.map((ws) => (
                            <WorkspaceRow key={ws.workspace_id} ws={ws} />
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}
