import { getServerSession } from "next-auth";
import { authOptions } from "@/lib/auth";
import { ScanHistoryTable } from "@/components/scan-history";
import { UsageChart } from "@/components/usage-chart";
import { apiClient } from "@/lib/api";

export default async function DashboardPage() {
    const session = await getServerSession(authOptions);
    const apiKey = session?.user?.apiKey || "";

    const [history, usage] = await Promise.all([
        apiClient.getScanHistory(apiKey, 1, 5),
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
                        {session?.user?.plan || "free"}
                    </p>
                </div>
            </div>

            {/* Usage chart */}
            <UsageChart days={usage.days} />

            {/* Recent scans */}
            <ScanHistoryTable scans={history.scans} />
        </div>
    );
}
