import React from "react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { TeamDashboard } from "@/components/team-dashboard";
import { apiClient } from "@/lib/api";

const TEST_API_KEY = "";

vi.mock("@/lib/api", async () => {
    const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
    return {
        ...actual,
        apiClient: {
            ...actual.apiClient,
            listOrganizationMembers: vi.fn().mockResolvedValue([]),
            getOrganizationPolicy: vi.fn().mockResolvedValue({
                max_severity_allowed: "BLOCK",
                require_license_compliance: false,
                blocked_licenses: [],
                require_vuln_scan: false,
                max_critical_vulns: 0,
                max_high_vulns: 0,
            }),
            createOrganization: vi.fn().mockResolvedValue({
                id: "org-2",
                name: "Team Two",
                slug: "team-two",
                plan: "free",
                owner_id: "u-1",
                member_count: 1,
                created_at: "2026-03-12T00:00:00Z",
            }),
            addOrganizationMember: vi.fn().mockResolvedValue(null),
            updateOrganizationMemberRole: vi.fn().mockResolvedValue(true),
            removeOrganizationMember: vi.fn().mockResolvedValue(true),
            updateOrganizationPolicy: vi.fn().mockResolvedValue(true),
        },
    };
});

describe("TeamDashboard", () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    it("renders initial org and member/policy sections", async () => {
        render(
            <TeamDashboard
                apiKey={TEST_API_KEY}
                initialOrgs={[
                    {
                        id: "org-1",
                        name: "Team One",
                        slug: "team-one",
                        plan: "free",
                        owner_id: "u-1",
                        member_count: 1,
                        created_at: "2026-03-12T00:00:00Z",
                    },
                ]}
            />,
        );

        expect(screen.getByText("Organizations")).toBeInTheDocument();
        expect(screen.getByText("Members")).toBeInTheDocument();
        expect(screen.getByText("Policy")).toBeInTheDocument();

        await waitFor(() => {
            expect(apiClient.listOrganizationMembers).toHaveBeenCalled();
            expect(apiClient.getOrganizationPolicy).toHaveBeenCalled();
        });
    });

    it("creates organization from form", async () => {
        render(
            <TeamDashboard
                apiKey={TEST_API_KEY}
                initialOrgs={[]}
            />,
        );

        const input = screen.getByPlaceholderText("New organization name");
        fireEvent.change(input, { target: { value: "Team Two" } });
        fireEvent.click(screen.getByText("Create"));

        await waitFor(() => {
            expect(apiClient.createOrganization).toHaveBeenCalledWith(TEST_API_KEY, "Team Two");
        });

        expect(screen.getAllByText(/Team Two/).length).toBeGreaterThan(0);
    });
});
