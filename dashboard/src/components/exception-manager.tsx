"use client";

import { useState } from "react";
import type {
    GovernancePendingApproval,
    GovernanceException,
} from "@/lib/api";
import { governanceClient } from "@/lib/api";

const VALID_APPROVAL_ROLES = ["owner", "admin", "security"] as const;
type ApprovalRole = typeof VALID_APPROVAL_ROLES[number];

function TimeAgo({ timestamp }: { timestamp: number }) {
    const seconds = Math.floor(Date.now() / 1000 - timestamp);
    if (seconds < 60) return <span>{seconds}s ago</span>;
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return <span>{minutes}m ago</span>;
    const hours = Math.floor(minutes / 60);
    return <span>{hours}h ago</span>;
}

function TimeRemaining({ expiresAt }: { expiresAt: number }) {
    const remaining = Math.max(0, Math.floor(expiresAt - Date.now() / 1000));
    if (remaining <= 0) return <span className="text-red-500">Expired</span>;
    const minutes = Math.floor(remaining / 60);
    if (minutes < 60) return <span>{minutes}m remaining</span>;
    const hours = Math.floor(minutes / 60);
    return <span>{hours}h {minutes % 60}m remaining</span>;
}

function VerdictBadge({ verdict }: { verdict: string }) {
    const colors: Record<string, string> = {
        pending: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400",
        active: "bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400",
        revoked: "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400",
    };
    return (
        <span
            className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${
                colors[verdict] || "bg-gray-100 text-gray-800"
            }`}
        >
            {verdict}
        </span>
    );
}

function ApproveDialog({
    approval,
    apiKey,
    onClose,
    onApproved,
}: {
    approval: GovernancePendingApproval;
    apiKey: string;
    onClose: () => void;
    onApproved: () => void;
}) {
    const [reason, setReason] = useState("");
    const [approver, setApprover] = useState("");
    const [role, setRole] = useState<ApprovalRole>("owner");
    const [ttl, setTtl] = useState(60);
    const [submitting, setSubmitting] = useState(false);

    async function handleApprove() {
        if (reason.length < 12 || !approver) return;
        if (!VALID_APPROVAL_ROLES.includes(role)) return;
        setSubmitting(true);
        const result = await governanceClient.approveAction(
            apiKey,
            approval.request_id,
            approver,
            reason,
            role,
            ttl,
        );
        setSubmitting(false);
        if (result?.approved) {
            onApproved();
        }
    }

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
            <div className="bg-white dark:bg-gray-900 rounded-xl p-6 w-full max-w-md shadow-xl">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
                    Approve Action
                </h3>
                <div className="space-y-3">
                    <div>
                        <p className="text-xs text-gray-500 dark:text-gray-400">
                            Rule
                        </p>
                        <p className="text-sm font-mono">{approval.rule_id}</p>
                    </div>
                    <div>
                        <p className="text-xs text-gray-500 dark:text-gray-400">
                            Action
                        </p>
                        <p className="text-sm font-mono truncate">
                            {approval.original_action}
                        </p>
                    </div>
                    <div>
                        <label className="block text-xs text-gray-500 dark:text-gray-400 mb-1">
                            Approver name
                        </label>
                        <input
                            type="text"
                            value={approver}
                            onChange={(e) => setApprover(e.target.value)}
                            className="w-full rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2 text-sm"
                            placeholder="Your name"
                        />
                    </div>
                    <div>
                        <label className="block text-xs text-gray-500 dark:text-gray-400 mb-1">
                            Role
                        </label>
                        <select
                            value={role}
                            onChange={(e) => {
                                const value = e.target.value;
                                if (VALID_APPROVAL_ROLES.includes(value as ApprovalRole)) {
                                    setRole(value as ApprovalRole);
                                }
                            }}
                            className="w-full rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2 text-sm"
                        >
                            {VALID_APPROVAL_ROLES.map((r) => (
                                <option key={r} value={r}>{r.charAt(0).toUpperCase() + r.slice(1)}</option>
                            ))}
                        </select>
                    </div>
                    <div>
                        <label className="block text-xs text-gray-500 dark:text-gray-400 mb-1">
                            Reason (min 12 chars)
                        </label>
                        <textarea
                            value={reason}
                            onChange={(e) => setReason(e.target.value)}
                            rows={3}
                            className="w-full rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2 text-sm"
                            placeholder="Explain why this action should be allowed..."
                        />
                    </div>
                    <div>
                        <label className="block text-xs text-gray-500 dark:text-gray-400 mb-1">
                            TTL (minutes)
                        </label>
                        <input
                            type="number"
                            value={ttl}
                            onChange={(e) =>
                                setTtl(Math.max(1, parseInt(e.target.value) || 1))
                            }
                            min={1}
                            max={1440}
                            className="w-full rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2 text-sm"
                        />
                    </div>
                </div>
                <div className="flex gap-3 mt-6">
                    <button
                        onClick={onClose}
                        className="flex-1 rounded-lg border border-gray-300 dark:border-gray-600 px-4 py-2 text-sm text-gray-700 dark:text-gray-300"
                    >
                        Cancel
                    </button>
                    <button
                        onClick={handleApprove}
                        disabled={reason.length < 12 || !approver || submitting}
                        className="flex-1 rounded-lg bg-green-600 px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
                    >
                        {submitting ? "Approving..." : "Approve"}
                    </button>
                </div>
            </div>
        </div>
    );
}

export function ExceptionManager({
    approvals,
    exceptions,
    apiKey,
    onRefresh,
}: {
    approvals: GovernancePendingApproval[];
    exceptions: GovernanceException[];
    apiKey: string;
    onRefresh: () => void;
}) {
    const [approving, setApproving] =
        useState<GovernancePendingApproval | null>(null);
    const [revoking, setRevoking] = useState<string | null>(null);

    async function handleRevoke(exceptionId: string) {
        setRevoking(exceptionId);
        await governanceClient.revokeException(apiKey, exceptionId);
        setRevoking(null);
        onRefresh();
    }

    return (
        <div className="space-y-8">
            {/* Pending approvals */}
            <div className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-6">
                <h3 className="text-sm font-medium text-gray-900 dark:text-white mb-4">
                    Pending Approvals ({approvals.length})
                </h3>
                {approvals.length === 0 ? (
                    <p className="text-sm text-gray-500 dark:text-gray-400">
                        No pending approval requests.
                    </p>
                ) : (
                    <div className="divide-y divide-gray-200 dark:divide-gray-700">
                        {approvals.map((a) => (
                            <div
                                key={a.request_id}
                                className="py-3 flex items-center gap-4"
                            >
                                <div className="flex-1 min-w-0">
                                    <div className="flex items-center gap-2">
                                        <VerdictBadge verdict="pending" />
                                        <span className="text-xs font-mono text-gray-500">
                                            {a.rule_id}
                                        </span>
                                    </div>
                                    <p className="text-sm text-gray-700 dark:text-gray-300 truncate mt-1">
                                        {a.original_action}
                                    </p>
                                    <p className="text-xs text-gray-400 mt-0.5">
                                        <TimeAgo timestamp={a.requested_at} />{" "}
                                        &middot; agent: {a.agent_id} &middot;{" "}
                                        <TimeRemaining
                                            expiresAt={a.expires_at}
                                        />
                                    </p>
                                </div>
                                <button
                                    onClick={() => setApproving(a)}
                                    className="shrink-0 rounded-lg bg-green-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-green-700"
                                >
                                    Approve
                                </button>
                            </div>
                        ))}
                    </div>
                )}
            </div>

            {/* Active exceptions */}
            <div className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-6">
                <h3 className="text-sm font-medium text-gray-900 dark:text-white mb-4">
                    Active Exceptions ({exceptions.length})
                </h3>
                {exceptions.length === 0 ? (
                    <p className="text-sm text-gray-500 dark:text-gray-400">
                        No active exceptions.
                    </p>
                ) : (
                    <div className="divide-y divide-gray-200 dark:divide-gray-700">
                        {exceptions.map((exc) => (
                            <div
                                key={exc.exception_id}
                                className="py-3 flex items-center gap-4"
                            >
                                <div className="flex-1 min-w-0">
                                    <div className="flex items-center gap-2">
                                        <VerdictBadge
                                            verdict={
                                                exc.revoked_at > 0
                                                    ? "revoked"
                                                    : "active"
                                            }
                                        />
                                        <span className="text-xs font-mono text-gray-500">
                                            {exc.rule_id}
                                        </span>
                                    </div>
                                    <p className="text-sm text-gray-700 dark:text-gray-300 mt-1">
                                        {exc.reason}
                                    </p>
                                    <p className="text-xs text-gray-400 mt-0.5">
                                        Approved by {exc.approver} (
                                        {exc.approver_role}) &middot;{" "}
                                        <TimeRemaining
                                            expiresAt={exc.expires_at}
                                        />
                                    </p>
                                </div>
                                {exc.revoked_at <= 0 && (
                                    <button
                                        onClick={() =>
                                            handleRevoke(exc.exception_id)
                                        }
                                        disabled={revoking === exc.exception_id}
                                        className="shrink-0 rounded-lg border border-red-300 dark:border-red-700 px-3 py-1.5 text-xs font-medium text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20 disabled:opacity-50"
                                    >
                                        {revoking === exc.exception_id
                                            ? "Revoking..."
                                            : "Revoke"}
                                    </button>
                                )}
                            </div>
                        ))}
                    </div>
                )}
            </div>

            {/* Approve dialog */}
            {approving && (
                <ApproveDialog
                    approval={approving}
                    apiKey={apiKey}
                    onClose={() => setApproving(null)}
                    onApproved={() => {
                        setApproving(null);
                        onRefresh();
                    }}
                />
            )}
        </div>
    );
}
