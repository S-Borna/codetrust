"use client";

import type { UsageDay } from "@/lib/api";

export function UsageChart({ days }: { days: UsageDay[] }) {
    if (days.length === 0) {
        return (
            <div className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-8 text-center">
                <p className="text-sm text-gray-500 dark:text-gray-400">
                    No usage data yet
                </p>
            </div>
        );
    }

    const maxScans = Math.max(...days.map((d) => d.scan_count), 1);

    return (
        <div className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-6">
            <h3 className="font-semibold text-gray-900 dark:text-white mb-4">
                Daily usage (last {days.length} days)
            </h3>
            <div className="flex items-end gap-1 h-32">
                {days
                    .slice()
                    .reverse()
                    .map((day) => {
                        const height = (day.scan_count / maxScans) * 100;
                        return (
                            <div
                                key={day.date}
                                className="flex-1 group relative"
                                title={`${day.date}: ${day.scan_count} scans`}
                            >
                                <div
                                    className="w-full bg-brand-500 rounded-t transition-all hover:bg-brand-400"
                                    style={{ height: `${Math.max(height, 2)}%` }}
                                />
                                <div className="hidden group-hover:block absolute bottom-full left-1/2 -translate-x-1/2 mb-1 px-2 py-1 bg-gray-900 text-white text-xs rounded whitespace-nowrap z-10">
                                    {day.date}: {day.scan_count} scans
                                </div>
                            </div>
                        );
                    })}
            </div>
        </div>
    );
}
