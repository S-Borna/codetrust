import React from "react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { GovernanceRolloutControls } from "@/components/governance-rollout-controls";
import { governanceClient } from "@/lib/api";

vi.mock("@/lib/api", async () => {
    const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
    return {
        ...actual,
        governanceClient: {
            ...actual.governanceClient,
            listPolicyBundles: vi.fn().mockResolvedValue([
                {
                    bundle_id: "startup",
                    name: "Startup Baseline",
                    target_tier: "startup",
                    description: "Starter",
                    policy: {},
                    signature: "sig1",
                    issued_at: "2026-03-12T00:00:00Z",
                    version: "2.9.0",
                },
            ]),
            simulatePolicy: vi.fn().mockResolvedValue({
                bundle_id: "startup",
                outcomes: [
                    {
                        command: "git push",
                        verdict: "BLOCK",
                        rule_id: "block_git_push",
                        message: "blocked",
                    },
                ],
            }),
        },
    };
});

describe("GovernanceRolloutControls", () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    it("loads policy bundles", async () => {
        render(<GovernanceRolloutControls apiKey="" />);

        await waitFor(() => {
            expect(governanceClient.listPolicyBundles).toHaveBeenCalled();
        });
        expect(screen.getByText("Policy Rollout Controls")).toBeInTheDocument();
    });

    it("runs simulation and shows result", async () => {
        render(<GovernanceRolloutControls apiKey="" />);

        fireEvent.click(screen.getByText("Run Simulation"));

        await waitFor(() => {
            expect(governanceClient.simulatePolicy).toHaveBeenCalled();
        });
        expect(screen.getByText("block_git_push")).toBeInTheDocument();
    });
});
