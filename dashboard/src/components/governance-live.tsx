"use client";

import { useState, useCallback } from "react";
import { governanceClient } from "@/lib/api";
import type {
    GovernancePosture,
    GovernancePendingApproval,
    GovernanceException,
} from "@/lib/api";
import { GovernancePostureView } from "@/components/governance-posture";
import { DriftAlerts } from "@/components/drift-alerts";
import { ExceptionManager } from "@/components/exception-manager";
import { GovernanceRolloutControls } from "@/components/governance-rollout-controls";

/**
 * Client wrapper for interactive governance components.
 * Handles client-side refresh after approve/revoke mutations.
 */
export function GovernanceLive({
    initialPosture,
    initialApprovals,
    initialExceptions,
    apiKey,
}: {
    initialPosture: GovernancePosture | null;
    initialApprovals: GovernancePendingApproval[];
    initialExceptions: GovernanceException[];
    apiKey: string;
}) {
    const [posture, setPosture] = useState(initialPosture);
    const [approvals, setApprovals] = useState(initialApprovals);
    const [exceptions, setExceptions] = useState(initialExceptions);

    const refresh = useCallback(async () => {
        const [newPosture, newApprovals, newExceptions] = await Promise.all([
            governanceClient.getPosture(apiKey),
            governanceClient.listApprovals(apiKey),
            governanceClient.listExceptions(apiKey),
        ]);
        setPosture(newPosture);
        setApprovals(newApprovals);
        setExceptions(newExceptions);
    }, [apiKey]);

    return (
        <div className="space-y-8">
            {/* Drift alerts — critical warnings at top */}
            <DriftAlerts posture={posture} />

            {/* Posture overview */}
            <div>
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
                    Posture
                </h2>
                <GovernancePostureView posture={posture} />
            </div>

            {/* Exception workflow */}
            <div>
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
                    Approvals &amp; Exceptions
                </h2>
                <ExceptionManager
                    approvals={approvals}
                    exceptions={exceptions}
                    apiKey={apiKey}
                    onRefresh={refresh}
                />
            </div>

            <GovernanceRolloutControls apiKey={apiKey} />
        </div>
    );
}
