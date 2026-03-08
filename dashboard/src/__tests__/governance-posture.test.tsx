import React from "react";
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { GovernancePostureView } from "@/components/governance-posture";
import type { GovernancePosture } from "@/lib/api";

const fullPosture: GovernancePosture = {
    enabled: true,
    mode: "enforce",
    agent_id: "claude",
    session_id: "gateway-1700000000",
    control_plane_ready: true,
    trusted_execution_mode: true,
    deny_native_execution: true,
    require_allow_reason: true,
    session_binding_enforced: true,
    anti_bypass_enabled: true,
    pending_approvals: 2,
    active_exceptions: 1,
    policy_integrity: {
        verdict: "ALLOW",
        rule_id: "policy_integrity",
        policy_hash: "abc123def456",
    },
};

describe("GovernancePostureView", () => {
    it("renders unavailable message when posture is null", () => {
        render(<GovernancePostureView posture={null} />);
        expect(
            screen.getByText(/governance posture unavailable/i)
        ).toBeInTheDocument();
    });

    it("renders control plane section", () => {
        render(<GovernancePostureView posture={fullPosture} />);
        expect(screen.getByText("Control Plane")).toBeInTheDocument();
        expect(screen.getByText("Ready")).toBeInTheDocument();
    });

    it("renders mode and agent", () => {
        render(<GovernancePostureView posture={fullPosture} />);
        expect(screen.getByText("enforce")).toBeInTheDocument();
        expect(screen.getByText("claude")).toBeInTheDocument();
    });

    it("renders enforcement gate labels", () => {
        render(<GovernancePostureView posture={fullPosture} />);
        expect(
            screen.getByText("Governance engine")
        ).toBeInTheDocument();
        expect(
            screen.getByText("Trusted execution mode")
        ).toBeInTheDocument();
        expect(
            screen.getByText("Deny native tool execution")
        ).toBeInTheDocument();
    });

    it("renders pending and exception counts", () => {
        render(<GovernancePostureView posture={fullPosture} />);
        expect(screen.getByText("2")).toBeInTheDocument();
        expect(screen.getByText("1")).toBeInTheDocument();
    });

    it("renders policy hash", () => {
        render(<GovernancePostureView posture={fullPosture} />);
        expect(screen.getByText("abc123def456")).toBeInTheDocument();
    });

    it("renders partial status when control_plane_ready is false", () => {
        const partial = { ...fullPosture, control_plane_ready: false };
        render(<GovernancePostureView posture={partial} />);
        expect(screen.getByText("Partial")).toBeInTheDocument();
    });

    it("renders integrity badge", () => {
        render(<GovernancePostureView posture={fullPosture} />);
        expect(screen.getByText("ALLOW")).toBeInTheDocument();
    });
});
