import React from "react";
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { MultiWorkspaceView } from "@/components/multi-workspace-view";
import type { GovernanceWorkspaceAggregate } from "@/lib/api";

const mockAggregate: GovernanceWorkspaceAggregate = {
    total_workspaces: 3,
    healthy_count: 2,
    drifted_count: 1,
    disabled_count: 0,
    total_pending_approvals: 5,
    total_active_exceptions: 2,
    workspaces: [
        {
            workspace_id: "ws-frontend",
            workspace_name: "Frontend App",
            agent_id: "claude",
            enabled: true,
            mode: "enforce",
            control_plane_ready: true,
            policy_hash: "abc123",
            policy_verdict: "ALLOW",
            pending_approvals: 2,
            active_exceptions: 1,
            drift_count: 0,
            last_seen_at: Date.now() / 1000 - 60,
        },
        {
            workspace_id: "ws-backend",
            workspace_name: "Backend API",
            agent_id: "copilot",
            enabled: true,
            mode: "enforce",
            control_plane_ready: true,
            policy_hash: "def456",
            policy_verdict: "BLOCK",
            pending_approvals: 3,
            active_exceptions: 1,
            drift_count: 2,
            last_seen_at: Date.now() / 1000 - 300,
        },
        {
            workspace_id: "ws-infra",
            workspace_name: "Infra Config",
            agent_id: "claude",
            enabled: false,
            mode: "audit",
            control_plane_ready: false,
            policy_hash: "",
            policy_verdict: "ALLOW",
            pending_approvals: 0,
            active_exceptions: 0,
            drift_count: 0,
            last_seen_at: 0,
        },
    ],
};

describe("MultiWorkspaceView", () => {
    it("renders empty state when aggregate is null", () => {
        render(<MultiWorkspaceView aggregate={null} />);
        expect(
            screen.getByText(/no workspaces registered/i)
        ).toBeInTheDocument();
    });

    it("renders empty state when total is 0", () => {
        const emptyAggregate: GovernanceWorkspaceAggregate = {
            total_workspaces: 0,
            healthy_count: 0,
            drifted_count: 0,
            disabled_count: 0,
            total_pending_approvals: 0,
            total_active_exceptions: 0,
            workspaces: [],
        };
        render(<MultiWorkspaceView aggregate={emptyAggregate} />);
        expect(
            screen.getByText(/no workspaces registered/i)
        ).toBeInTheDocument();
    });

    it("renders overview heading with workspace count", () => {
        render(<MultiWorkspaceView aggregate={mockAggregate} />);
        expect(
            screen.getByText("Multi-Workspace Overview")
        ).toBeInTheDocument();
        expect(screen.getByText("3 workspaces")).toBeInTheDocument();
    });

    it("shows aggregate health stats", () => {
        render(<MultiWorkspaceView aggregate={mockAggregate} />);
        expect(screen.getByText(/Healthy: 2/)).toBeInTheDocument();
        expect(screen.getByText(/Drifted: 1/)).toBeInTheDocument();
        expect(screen.getByText(/Disabled: 0/)).toBeInTheDocument();
    });

    it("shows pending approvals and active exceptions", () => {
        render(<MultiWorkspaceView aggregate={mockAggregate} />);
        expect(screen.getByText("Pending Approvals")).toBeInTheDocument();
        expect(screen.getByText("Active Exceptions")).toBeInTheDocument();
        // Check the counters exist next to labels (5 pending, 2 exceptions)
        const pendingSection = screen.getByText("Pending Approvals").closest("div");
        expect(pendingSection?.textContent).toContain("5");
        const exceptionsSection = screen.getByText("Active Exceptions").closest("div");
        expect(exceptionsSection?.textContent).toContain("2");
    });

    it("renders workspace names in table", () => {
        render(<MultiWorkspaceView aggregate={mockAggregate} />);
        expect(screen.getByText("Frontend App")).toBeInTheDocument();
        expect(screen.getByText("Backend API")).toBeInTheDocument();
        expect(screen.getByText("Infra Config")).toBeInTheDocument();
    });

    it("shows drift count for drifted workspace", () => {
        render(<MultiWorkspaceView aggregate={mockAggregate} />);
        expect(screen.getByText("2 drifts")).toBeInTheDocument();
    });

    it("shows Clean for workspace with zero drift", () => {
        render(<MultiWorkspaceView aggregate={mockAggregate} />);
        const cleanElements = screen.getAllByText("Clean");
        expect(cleanElements.length).toBeGreaterThanOrEqual(1);
    });

    it("displays table column headers", () => {
        render(<MultiWorkspaceView aggregate={mockAggregate} />);
        expect(screen.getByText("Workspace")).toBeInTheDocument();
        expect(screen.getByText("Agent")).toBeInTheDocument();
        expect(screen.getByText("Mode")).toBeInTheDocument();
        expect(screen.getByText("Drift")).toBeInTheDocument();
        expect(screen.getByText("Policy")).toBeInTheDocument();
        expect(screen.getByText("Pending")).toBeInTheDocument();
        expect(screen.getByText("Last Seen")).toBeInTheDocument();
    });
});
