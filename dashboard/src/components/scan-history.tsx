"use client";

import type { ScanLog } from "@/lib/api";

const VERDICT_COLORS: Record<string, string> = {
    PASS: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300",
    WARN: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300",
    BLOCK: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300",
};

export function ScanHistoryTable({ scans }: { scans: ScanLog[] }) {
    if (scans.length === 0) {
        return (
            <div className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-8 text-center">
                <p className="text-sm text-gray-500 dark:text-gray-400">
                    No scans yet. Run your first scan to see history here.
                </p>
            </div>
        );
    }

    return (
        <div className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 overflow-hidden">
            <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
                <h3 className="font-semibold text-gray-900 dark:text-white">
                    Recent scans
                </h3>
            </div>
            <table className="w-full text-sm">
                <thead className="bg-gray-50 dark:bg-gray-800">
                    <tr>
                        <th className="px-6 py-3 text-left font-medium text-gray-500 dark:text-gray-400">
                            Type
                        </th>
                        <th className="px-6 py-3 text-left font-medium text-gray-500 dark:text-gray-400">
                            Verdict
                        </th>
                        <th className="px-6 py-3 text-left font-medium text-gray-500 dark:text-gray-400">
                            Findings
                        </th>
                        <th className="px-6 py-3 text-left font-medium text-gray-500 dark:text-gray-400">
                            File
                        </th>
                        <th className="px-6 py-3 text-left font-medium text-gray-500 dark:text-gray-400">
                            Latency
                        </th>
                        <th className="px-6 py-3 text-left font-medium text-gray-500 dark:text-gray-400">
                            Date
                        </th>
                    </tr>
                </thead>
                <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                    {scans.map((scan) => (
                        <tr
                            key={scan.id}
                            className="hover:bg-gray-50 dark:hover:bg-gray-800"
                        >
                            <td className="px-6 py-4 text-gray-900 dark:text-white capitalize">
                                {scan.scan_type}
                            </td>
                            <td className="px-6 py-4">
                                <span
                                    className={`inline-block rounded-full px-2.5 py-0.5 text-xs font-semibold ${VERDICT_COLORS[scan.verdict] || "bg-gray-100 text-gray-800"
                                        }`}
                                >
                                    {scan.verdict}
                                </span>
                            </td>
                            <td className="px-6 py-4 text-gray-600 dark:text-gray-400">
                                {scan.findings_count}
                            </td>
                            <td className="px-6 py-4 text-gray-600 dark:text-gray-400 truncate max-w-[200px]">
                                {scan.filename || "—"}
                            </td>
                            <td className="px-6 py-4 text-gray-600 dark:text-gray-400">
                                {scan.latency_ms}ms
                            </td>
                            <td className="px-6 py-4 text-gray-600 dark:text-gray-400">
                                {new Date(scan.created_at).toLocaleDateString()}
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}
