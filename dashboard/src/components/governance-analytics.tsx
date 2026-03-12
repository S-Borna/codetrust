import type {
    GovernanceAuditEntry,
    GovernanceWorkspaceAggregate,
} from "@/lib/api";

interface GovernanceAnalyticsProps {
    auditEntries: GovernanceAuditEntry[];
    workspaces: GovernanceWorkspaceAggregate;
}

interface HourBucket {
    hourLabel: string;
    total: number;
    blocked: number;
}

const HOURS_WINDOW = 24;
const COMPLIANCE_MAX = 100;
const BLOCK_PENALTY = 40;
const DRIFT_PENALTY = 35;
const EXCEPTION_PENALTY = 25;

function clampScore(score: number): number {
    if (score < 0) {
        return 0;
    }
    if (score > COMPLIANCE_MAX) {
        return COMPLIANCE_MAX;
    }
    return Math.round(score);
}

function buildHourlyBuckets(entries: GovernanceAuditEntry[]): HourBucket[] {
    const now = Date.now();
    const buckets: HourBucket[] = [];

    for (let i = HOURS_WINDOW - 1; i >= 0; i -= 1) {
        const start = now - (i + 1) * 3600 * 1000;
        const end = now - i * 3600 * 1000;
        let total = 0;
        let blocked = 0;

        for (const entry of entries) {
            const tsMs = entry.timestamp * 1000;
            if (tsMs >= start && tsMs < end) {
                total += 1;
                if (entry.verdict.toUpperCase() === "BLOCK") {
                    blocked += 1;
                }
            }
        }

        const labelDate = new Date(end);
        const hourLabel = `${String(labelDate.getHours()).padStart(2, "0")}:00`;
        buckets.push({ hourLabel, total, blocked });
    }

    return buckets;
}

export function GovernanceAnalytics({
    auditEntries,
    workspaces,
}: GovernanceAnalyticsProps) {
    const totalAudit = auditEntries.length;
    const blockedAudit = auditEntries.filter(
        (entry) => entry.verdict.toUpperCase() === "BLOCK",
    ).length;

    const blockRate = totalAudit > 0 ? blockedAudit / totalAudit : 0;
    const driftRate = workspaces.total_workspaces > 0
        ? workspaces.drifted_count / workspaces.total_workspaces
        : 0;
    const exceptionRate = workspaces.total_workspaces > 0
        ? workspaces.total_active_exceptions / workspaces.total_workspaces
        : 0;

    const complianceScore = clampScore(
        COMPLIANCE_MAX
        - blockRate * BLOCK_PENALTY
        - driftRate * DRIFT_PENALTY
        - exceptionRate * EXCEPTION_PENALTY,
    );

    const hourly = buildHourlyBuckets(auditEntries);
    const peakHourVolume = hourly.reduce(
        (peak, hour) => (hour.total > peak ? hour.total : peak),
        1,
    );

    return (
        <section className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-6">
            <div className="mb-4">
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                    Governance Analytics
                </h2>
                <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">
                    Compliance score, drift risk, and 24h governance trend.
                </p>
            </div>

            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                <div className="rounded-lg border border-gray-200 dark:border-gray-700 p-4">
                    <p className="text-xs uppercase tracking-wide text-gray-500 dark:text-gray-400">Compliance Score</p>
                    <p className="mt-2 text-2xl font-bold text-gray-900 dark:text-white">
                        {complianceScore}
                    </p>
                </div>
                <div className="rounded-lg border border-gray-200 dark:border-gray-700 p-4">
                    <p className="text-xs uppercase tracking-wide text-gray-500 dark:text-gray-400">Block Rate (24h)</p>
                    <p className="mt-2 text-2xl font-bold text-gray-900 dark:text-white">
                        {(blockRate * 100).toFixed(1)}%
                    </p>
                </div>
                <div className="rounded-lg border border-gray-200 dark:border-gray-700 p-4">
                    <p className="text-xs uppercase tracking-wide text-gray-500 dark:text-gray-400">Drifted Workspaces</p>
                    <p className="mt-2 text-2xl font-bold text-gray-900 dark:text-white">
                        {workspaces.drifted_count}/{workspaces.total_workspaces}
                    </p>
                </div>
                <div className="rounded-lg border border-gray-200 dark:border-gray-700 p-4">
                    <p className="text-xs uppercase tracking-wide text-gray-500 dark:text-gray-400">Active Exceptions</p>
                    <p className="mt-2 text-2xl font-bold text-gray-900 dark:text-white">
                        {workspaces.total_active_exceptions}
                    </p>
                </div>
            </div>

            <div className="mt-6">
                <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">24h Trend</h3>
                <div className="space-y-2">
                    {hourly.map((bucket) => {
                        const width = `${Math.max(4, (bucket.total / peakHourVolume) * 100)}%`;
                        return (
                            <div key={bucket.hourLabel} className="grid grid-cols-[56px_1fr_72px] items-center gap-3">
                                <span className="text-xs text-gray-500 dark:text-gray-400">{bucket.hourLabel}</span>
                                <div className="h-2 rounded-full bg-gray-200 dark:bg-gray-800 overflow-hidden">
                                    <div className="h-full bg-brand-600" style={{ width }} />
                                </div>
                                <span className="text-xs text-gray-600 dark:text-gray-400 text-right">
                                    {bucket.blocked}/{bucket.total}
                                </span>
                            </div>
                        );
                    })}
                </div>
            </div>
        </section>
    );
}
