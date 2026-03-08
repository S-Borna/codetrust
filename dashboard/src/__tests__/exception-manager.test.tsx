import React from "react";
import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { ExceptionManager } from "@/components/exception-manager";
import type {
    GovernancePendingApproval,
    GovernanceException,
} from "@/lib/api";

const PLACEHOLDER_CREDENTIAL = "";

const mockApprovals: GovernancePendingApproval[] = [
    {
        request_id: "req-001",
        rule_id: "gateway_heredoc",
        action_type: "terminal_command",
        original_action: "echo blocked-action",
        action_fingerprint: "fp-001",
        requested_at: Date.now() / 1000 - 120,
        expires_at: Date.now() / 1000 + 600,
        session_id: "sess-1",
        agent_id: "claude",
    },
];

const mockExceptions: GovernanceException[] = [
    {
        exception_id: "exc-001",
        rule_id: "gateway_heredoc",
        action_type: "terminal_command",
        action_fingerprint: "fp-001",
        reason: "Needed for deployment script",
        approver: "Admin User",
        approver_role: "admin",
        created_at: Date.now() / 1000 - 300,
        expires_at: Date.now() / 1000 + 3300,
        revoked_at: 0,
        revoked_by: "",
        session_id: "sess-1",
        agent_id: "claude",
    },
];

describe("ExceptionManager", () => {
    const onRefresh = vi.fn();

    it("renders pending approvals heading", () => {
        render(
            <ExceptionManager
                approvals={mockApprovals}
                exceptions={[]}
                apiKey={PLACEHOLDER_CREDENTIAL}
                onRefresh={onRefresh}
            />
        );
        expect(
            screen.getByText(/pending approvals/i)
        ).toBeInTheDocument();
    });

    it("renders pending approval count", () => {
        render(
            <ExceptionManager
                approvals={mockApprovals}
                exceptions={[]}
                apiKey={PLACEHOLDER_CREDENTIAL}
                onRefresh={onRefresh}
            />
        );
        expect(screen.getByText("Pending Approvals (1)")).toBeInTheDocument();
    });

    it("renders approval rule_id", () => {
        render(
            <ExceptionManager
                approvals={mockApprovals}
                exceptions={[]}
                apiKey={PLACEHOLDER_CREDENTIAL}
                onRefresh={onRefresh}
            />
        );
        expect(screen.getByText("gateway_heredoc")).toBeInTheDocument();
    });

    it("renders approve button for pending items", () => {
        render(
            <ExceptionManager
                approvals={mockApprovals}
                exceptions={[]}
                apiKey={PLACEHOLDER_CREDENTIAL}
                onRefresh={onRefresh}
            />
        );
        expect(screen.getByText("Approve")).toBeInTheDocument();
    });

    it("shows approve dialog when clicking Approve", () => {
        render(
            <ExceptionManager
                approvals={mockApprovals}
                exceptions={[]}
                apiKey={PLACEHOLDER_CREDENTIAL}
                onRefresh={onRefresh}
            />
        );
        fireEvent.click(screen.getByText("Approve"));
        expect(screen.getByText("Approve Action")).toBeInTheDocument();
        expect(
            screen.getByPlaceholderText("Your name")
        ).toBeInTheDocument();
    });

    it("renders empty state for no pending approvals", () => {
        render(
            <ExceptionManager
                approvals={[]}
                exceptions={[]}
                apiKey={PLACEHOLDER_CREDENTIAL}
                onRefresh={onRefresh}
            />
        );
        expect(
            screen.getByText(/no pending approval requests/i)
        ).toBeInTheDocument();
    });

    it("renders active exceptions section", () => {
        render(
            <ExceptionManager
                approvals={[]}
                exceptions={mockExceptions}
                apiKey={PLACEHOLDER_CREDENTIAL}
                onRefresh={onRefresh}
            />
        );
        expect(
            screen.getByText("Active Exceptions (1)")
        ).toBeInTheDocument();
    });

    it("renders exception details", () => {
        render(
            <ExceptionManager
                approvals={[]}
                exceptions={mockExceptions}
                apiKey={PLACEHOLDER_CREDENTIAL}
                onRefresh={onRefresh}
            />
        );
        expect(
            screen.getByText("Needed for deployment script")
        ).toBeInTheDocument();
        expect(
            screen.getByText(/admin user/i)
        ).toBeInTheDocument();
    });

    it("renders Revoke button for active exceptions", () => {
        render(
            <ExceptionManager
                approvals={[]}
                exceptions={mockExceptions}
                apiKey={PLACEHOLDER_CREDENTIAL}
                onRefresh={onRefresh}
            />
        );
        expect(screen.getByText("Revoke")).toBeInTheDocument();
    });

    it("renders empty state for no exceptions", () => {
        render(
            <ExceptionManager
                approvals={[]}
                exceptions={[]}
                apiKey={PLACEHOLDER_CREDENTIAL}
                onRefresh={onRefresh}
            />
        );
        expect(
            screen.getByText(/no active exceptions/i)
        ).toBeInTheDocument();
    });

    it("does not render Revoke for revoked exceptions", () => {
        const revoked: GovernanceException[] = [
            {
                ...mockExceptions[0],
                revoked_at: Date.now() / 1000 - 60,
                revoked_by: "admin",
            },
        ];
        render(
            <ExceptionManager
                approvals={[]}
                exceptions={revoked}
                apiKey={PLACEHOLDER_CREDENTIAL}
                onRefresh={onRefresh}
            />
        );
        expect(screen.queryByText("Revoke")).not.toBeInTheDocument();
    });
});
