import { getServerSession } from "next-auth";
import { authOptions } from "@/lib/auth";
import { governanceClient } from "@/lib/api";
import { GovernanceAuditView } from "@/components/governance-audit";
import { GovernanceLive } from "@/components/governance-live";
import { MultiWorkspaceView } from "@/components/multi-workspace-view";
import { GovernanceAnalytics } from "@/components/governance-analytics";
import { BackendAuthRequired } from "@/components/backend-auth-required";
import { PlanGate } from "@/components/plan-gate";

/**
 * Governance page — live dashboard with posture, drift alerts,
 * audit log, multi-workspace overview, and exception/approval management.
 *
 * Server component fetches initial data; interactive parts are
 * delegated to GovernanceLive (client component).
 */
export default async function GovernancePage() {
    const session = await getServerSession(authOptions);
    let plan = "free";
    if (session && session.user && session.user.plan) {
        plan = session.user.plan.toLowerCase();
    }
    const isFree = plan === "free";
    let apiKey = "";
    if (
        session
        && session.user
        && typeof session.user.apiKey === "string"
    ) {
        apiKey = session.user.apiKey;
    }
    if (!apiKey) {
        return <BackendAuthRequired />;
    }

    if (isFree) {
        return (
            <PlanGate
                currentPlan={plan}
                requiredPlan="pro"
                title="Pro Feature"
                description="Governance dashboard is available on Pro. Upgrade for drift detection, audit logs, and posture monitoring."
            />
        );
    }

    const [audit, posture, approvals, exceptions, workspaces] = await Promise.all([
        governanceClient.getAudit(apiKey),
        governanceClient.getPosture(apiKey),
        governanceClient.listApprovals(apiKey),
        governanceClient.listExceptions(apiKey),
        governanceClient.getWorkspaces(apiKey),
    ]);

    return (
        <div className="space-y-8">
            <div>
                <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
                    Governance
                </h1>
                <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">
                    AI agent governance — posture, drift detection, audit log,
                    and exception management.
                </p>
            </div>

            {/* Live interactive section: posture, drift, exceptions */}
            <GovernanceLive
                initialPosture={posture}
                initialApprovals={approvals}
                initialExceptions={exceptions}
                apiKey={apiKey}
            />

            <GovernanceAnalytics
                auditEntries={audit.entries}
                workspaces={workspaces}
            />

            {/* Audit log (display-only) */}
            <div>
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
                    Audit Log
                </h2>
                <GovernanceAuditView
                    entries={audit.entries}
                    stats={audit.stats}
                />
            </div>

            {/* Multi-workspace overview */}
            <div>
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
                    Workspaces
                </h2>
                <MultiWorkspaceView aggregate={workspaces} />
            </div>

            <div className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-6">
                <h3 className="text-sm font-medium text-gray-900 dark:text-white mb-2">
                    Query Audit Log
                </h3>
                <p className="text-sm text-gray-600 dark:text-gray-400 mb-3">
                    Use the CLI or MCP tools to query the full audit log:
                </p>
                <div className="space-y-2 font-mono text-sm text-gray-700 dark:text-gray-300 bg-gray-50 dark:bg-gray-800 rounded-lg p-4">
                    <p>$ codetrust audit --hours 24</p>
                    <p>$ codetrust audit --verdict BLOCK --stats</p>
                    <p className="text-gray-400"># Or via MCP: mcp_codetrust-gat_codetrust_audit_history</p>
                </div>
            </div>
        </div>
    );
}
