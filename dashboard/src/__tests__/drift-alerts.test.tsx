import React from "react";
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { DriftAlerts } from "@/components/drift-alerts";
import type { GovernancePosture } from "@/lib/api";

const basePosture: GovernancePosture = {
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
    pending_approvals: 0,
    active_exceptions: 0,
    policy_integrity: {
        verdict: "ALLOW",
        rule_id: "policy_integrity",
        policy_hash: "abc123",
    },
};

describe("DriftAlerts", () => {
    it("returns null when posture is null", () => {
        const { container } = render(<DriftAlerts posture={null} />);
        expect(container.innerHTML).toBe("");
    });

    it("shows no-drift message when all gates match baseline", () => {
        render(<DriftAlerts posture={basePosture} />);
        expect(
            screen.getByText(/no drift detected/i)
        ).toBeInTheDocument();
    });

    it("shows critical drift when governance engine is disabled", () => {
        const drifted = { ...basePosture, enabled: false };
        render(<DriftAlerts posture={drifted} />);
        expect(screen.getByText(/critical drift/i)).toBeInTheDocument();
        expect(
            screen.getByText(/governance engine enabled/i)
        ).toBeInTheDocument();
    });

    it("shows critical drift when trusted execution is off", () => {
        const drifted = { ...basePosture, trusted_execution_mode: false };
        render(<DriftAlerts posture={drifted} />);
        expect(screen.getByText(/critical drift/i)).toBeInTheDocument();
    });

    it("shows warning drift when require_allow_reason is off", () => {
        const drifted = { ...basePosture, require_allow_reason: false };
        render(<DriftAlerts posture={drifted} />);
        expect(screen.getByText(/warning drift/i)).toBeInTheDocument();
    });

    it("shows critical drift when policy integrity fails", () => {
        const drifted = {
            ...basePosture,
            policy_integrity: {
                verdict: "BLOCK",
                rule_id: "policy_integrity",
                policy_hash: "abc123",
            },
        };
        render(<DriftAlerts posture={drifted} />);
        expect(screen.getByText(/critical drift/i)).toBeInTheDocument();
    });

    it("shows both critical and warning sections when multiple drifts", () => {
        const drifted = {
            ...basePosture,
            enabled: false,
            require_allow_reason: false,
        };
        render(<DriftAlerts posture={drifted} />);
        expect(screen.getByText(/critical drift/i)).toBeInTheDocument();
        expect(screen.getByText(/warning drift/i)).toBeInTheDocument();
    });

    it("displays expected ON/OFF values in drift items", () => {
        const drifted = { ...basePosture, deny_native_execution: false };
        render(<DriftAlerts posture={drifted} />);
        // Should show "expected ON, got OFF" pattern
        const onLabels = screen.getAllByText("ON");
        const offLabels = screen.getAllByText("OFF");
        expect(onLabels.length).toBeGreaterThanOrEqual(1);
        expect(offLabels.length).toBeGreaterThanOrEqual(1);
    });
});
