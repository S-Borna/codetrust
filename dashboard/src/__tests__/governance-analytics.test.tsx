import React from "react";
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { GovernanceAnalytics } from "@/components/governance-analytics";
import type { GovernanceAuditEntry, GovernanceWorkspaceAggregate } from "@/lib/api";

const nowSec = Math.floor(Date.now() / 1000);

const auditEntries: GovernanceAuditEntry[] = [
    {
        timestamp: nowSec - 600,
        action_type: "command",
        verdict: "BLOCK",
        rule_id: "block_eval",
        original_action: "blocked-command",
        message: "Blocked",
        agent_id: "claude",
        session_id: "s1",
    },
    {
        timestamp: nowSec - 300,
        action_type: "command",
        verdict: "ALLOW",
        rule_id: "allow_echo",
        original_action: "echo ok",
        message: "Allowed",
        agent_id: "claude",
        session_id: "s1",
    },
];

const workspaceAggregate: GovernanceWorkspaceAggregate = {
    total_workspaces: 4,
    healthy_count: 3,
    drifted_count: 1,
    disabled_count: 0,
    total_pending_approvals: 2,
    total_active_exceptions: 1,
    workspaces: [],
};

describe("GovernanceAnalytics", () => {
    it("renders analytics cards", () => {
        render(
            <GovernanceAnalytics
                auditEntries={auditEntries}
                workspaces={workspaceAggregate}
            />,
        );

        expect(screen.getByText("Governance Analytics")).toBeInTheDocument();
        expect(screen.getByText("Compliance Score")).toBeInTheDocument();
        expect(screen.getByText("Block Rate (24h)")).toBeInTheDocument();
        expect(screen.getByText("Drifted Workspaces")).toBeInTheDocument();
        expect(screen.getByText("Active Exceptions")).toBeInTheDocument();
    });

    it("renders derived rates and ratios", () => {
        render(
            <GovernanceAnalytics
                auditEntries={auditEntries}
                workspaces={workspaceAggregate}
            />,
        );

        expect(screen.getByText("50.0%")).toBeInTheDocument();
        expect(screen.getByText("1/4")).toBeInTheDocument();
    });
});
