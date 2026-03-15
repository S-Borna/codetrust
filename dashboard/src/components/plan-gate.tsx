import type { ReactNode } from "react";

interface PlanGateProps {
    currentPlan: string;
    requiredPlan: "pro" | "enterprise";
    children?: ReactNode;
    title: string;
    description: string;
}

const PLAN_ORDER: Record<string, number> = {
    free: 0,
    pro: 1,
    enterprise: 2,
};

function hasRequiredPlan(currentPlan: string, requiredPlan: "pro" | "enterprise"): boolean {
    const current = PLAN_ORDER[currentPlan] ?? 0;
    const required = PLAN_ORDER[requiredPlan] ?? 2;
    return current >= required;
}

export function PlanGate(props: PlanGateProps) {
    const normalized = props.currentPlan.toLowerCase();
    if (hasRequiredPlan(normalized, props.requiredPlan)) {
        return <>{props.children ?? null}</>;
    }

    return (
        <div className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 p-6">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                {props.title}
            </h2>
            <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
                {props.description}
            </p>
            <a
                href="/dashboard/settings"
                className="mt-4 inline-flex rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-700"
            >
                Upgrade Plan
            </a>
        </div>
    );
}
