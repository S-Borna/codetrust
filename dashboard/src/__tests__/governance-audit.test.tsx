import React from "react";
import { describe, it, expect } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { GovernanceAuditView } from "@/components/governance-audit";

const mockEntries = [
    {
        timestamp: 1700000000,
        action_type: "terminal_command",
        verdict: "BLOCK",
        rule_id: "gateway_rm_rf",
        original_action: "rm -rf /",
        message: "Blocked dangerous command",
        agent_id: "copilot",
        session_id: "sess-1",
    },
    {
        timestamp: 1700000100,
        action_type: "file_write",
        verdict: "ALLOW",
        rule_id: "",
        original_action: "write main.py",
        message: "File write allowed",
        agent_id: "claude",
        session_id: "sess-2",
    },
    {
        timestamp: 1700000200,
        action_type: "package_install",
        verdict: "WARN",
        rule_id: "unverified_pkg",
        original_action: "pip install foo",
        message: "Unverified package",
        agent_id: "copilot",
        session_id: "sess-3",
    },
];

const mockStats = {
    total: 3,
    by_verdict: { BLOCK: 1, WARN: 1, ALLOW: 1 },
    by_action_type: {
        terminal_command: 1,
        file_write: 1,
        package_install: 1,
    },
    top_rules: [
        { rule_id: "gateway_rm_rf", count: 1 },
        { rule_id: "unverified_pkg", count: 1 },
    ],
};

describe("GovernanceAuditView", () => {
    it("renders stat cards", () => {
        render(
            <GovernanceAuditView entries={mockEntries} stats={mockStats} />
        );
        expect(screen.getByText("Total actions")).toBeInTheDocument();
        expect(screen.getByText("Blocked")).toBeInTheDocument();
        expect(screen.getByText("Warned")).toBeInTheDocument();
        expect(screen.getByText("Allowed")).toBeInTheDocument();
    });

    it("renders stat values", () => {
        render(
            <GovernanceAuditView entries={mockEntries} stats={mockStats} />
        );
        // Total actions = 3
        expect(screen.getByText("3")).toBeInTheDocument();
    });

    it("renders top rules section", () => {
        render(
            <GovernanceAuditView entries={mockEntries} stats={mockStats} />
        );
        expect(
            screen.getByText("Most Triggered Rules")
        ).toBeInTheDocument();
        // gateway_rm_rf appears in top rules and in the entries table
        const ruleTexts = screen.getAllByText("gateway_rm_rf");
        expect(ruleTexts.length).toBeGreaterThanOrEqual(1);
    });

    it("renders audit entries in table", () => {
        render(
            <GovernanceAuditView entries={mockEntries} stats={mockStats} />
        );
        // Entries show original_action in the table
        expect(screen.getByText("rm -rf /")).toBeInTheDocument();
        expect(screen.getByText("write main.py")).toBeInTheDocument();
    });

    it("renders verdict badges", () => {
        render(
            <GovernanceAuditView entries={mockEntries} stats={mockStats} />
        );
        // BLOCK appears in verdict badges + filter button
        const blocks = screen.getAllByText("BLOCK");
        expect(blocks.length).toBeGreaterThanOrEqual(1);
    });

    it("renders with empty stats", () => {
        const emptyStats = {
            total: 0,
            by_verdict: {},
            by_action_type: {},
            top_rules: [],
        };
        render(
            <GovernanceAuditView entries={[]} stats={emptyStats} />
        );
        expect(screen.getByText("Total actions")).toBeInTheDocument();
        // Multiple stat cards show 0 — just verify at least one exists
        const zeros = screen.getAllByText("0");
        expect(zeros.length).toBeGreaterThanOrEqual(1);
    });
});
