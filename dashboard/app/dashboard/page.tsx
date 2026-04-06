import { getServerSession } from "next-auth";
import { authOptions } from "@/lib/auth";
import { ScanHistoryTable } from "@/components/scan-history";
import { UsageChart } from "@/components/usage-chart";
import { GovernanceOverview } from "@/components/governance-overview";
import { apiClient } from "@/lib/api";
import { BackendAuthRequired } from "@/components/backend-auth-required";
import { PlanGate } from "@/components/plan-gate";

export default async function DashboardPage() {
    const session = await getServerSession(authOptions);
    let apiKey = "";
    if (session && session.user && session.user.apiKey) {
        apiKey = session.user.apiKey;
    }
    let plan = "free";
    if (session && session.user && session.user.plan) {
        plan = session.user.plan.toLowerCase();
    }
    const historyLimit = plan === "free" ? 10 : 5;

    if (!apiKey) {
        return <BackendAuthRequired />;
    }

    const [history, usage] = await Promise.all([
        apiClient.getScanHistory(apiKey, 1, historyLimit),
        apiClient.getUsageStats(apiKey, 30),
    ]);

    return (
        <div className="space-y-8">
            <div>
                <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
                    Your AI agents are governed.
                </h1>
                <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">
                    {usage.total_scans} scans in the last 30 days &middot; Plan: <span className="font-medium text-brand-600 capitalize">{plan}</span>
                </p>
            </div>

            {/* Governance overview — polls /v1/dashboard/overview every 30s */}
            <GovernanceOverview apiKey={apiKey} />

            <PlanGate
                currentPlan={plan}
                requiredPlan="pro"
                title="Unlock Pro Features"
                description="Get trust score trending, deep scan insights, vulnerability scanning, and license compliance checks."
            >
                <UsageChart days={usage.days} />
            </PlanGate>

            {/* Recent scans */}
            <ScanHistoryTable scans={history.scans} />
        </div>
    );
}
