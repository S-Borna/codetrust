import { getServerSession } from "next-auth";
import { authOptions } from "@/lib/auth";
import { ScanHistoryTable } from "@/components/scan-history";
import { UsageChart } from "@/components/usage-chart";
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
                    Dashboard
                </h1>
                <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">
                    Overview of your recent scans and usage
                </p>
            </div>

            {/* Stats cards */}
            <div className="grid gap-4 sm:grid-cols-3">
                <div className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-6">
                    <p className="text-sm text-gray-500 dark:text-gray-400">
                        Total scans (30d)
                    </p>
                    <p className="mt-2 text-3xl font-bold text-gray-900 dark:text-white">
                        {usage.total_scans}
                    </p>
                </div>
                <div className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-6">
                    <p className="text-sm text-gray-500 dark:text-gray-400">
                        Recent scans
                    </p>
                    <p className="mt-2 text-3xl font-bold text-gray-900 dark:text-white">
                        {history.total}
                    </p>
                </div>
                <div className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-6">
                    <p className="text-sm text-gray-500 dark:text-gray-400">Plan</p>
                    <p className="mt-2 text-3xl font-bold text-brand-600 capitalize">
                        {plan}
                    </p>
                </div>
            </div>

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
