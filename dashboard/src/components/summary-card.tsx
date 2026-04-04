/**
 * Summary card for the governance dashboard overview.
 * Displays a metric with label, value, status color, and optional link.
 */

import Link from "next/link";

interface SummaryCardProps {
    title: string;
    value: string | number;
    subtitle: string;
    href: string;
    status: "green" | "yellow" | "red" | "gray";
}

const statusColors: Record<string, string> = {
    green: "border-l-green-500 bg-green-50 dark:bg-green-950/20",
    yellow: "border-l-yellow-500 bg-yellow-50 dark:bg-yellow-950/20",
    red: "border-l-red-500 bg-red-50 dark:bg-red-950/20",
    gray: "border-l-gray-400 bg-gray-50 dark:bg-gray-800/50",
};

export function SummaryCard({ title, value, subtitle, href, status }: SummaryCardProps) {
    return (
        <Link href={href} className="block">
            <div
                className={`rounded-lg border border-l-4 p-4 transition hover:shadow-md ${statusColors[status]}`}
            >
                <p className="text-sm font-medium text-gray-500 dark:text-gray-400">
                    {title}
                </p>
                <p className="mt-1 text-2xl font-bold text-gray-900 dark:text-white">
                    {value}
                </p>
                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                    {subtitle}
                </p>
            </div>
        </Link>
    );
}
