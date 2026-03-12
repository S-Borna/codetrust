import React from "react";
import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";

// Mock next/navigation
vi.mock("next/navigation", () => ({
    usePathname: () => "/dashboard",
}));

// Mock next-auth/react
vi.mock("next-auth/react", () => ({
    signOut: vi.fn(),
}));

import { DashboardNav } from "@/components/dashboard-nav";

describe("DashboardNav", () => {
    it("renders CodeTrust brand", () => {
        render(<DashboardNav />);
        expect(screen.getByText("CodeTrust")).toBeInTheDocument();
    });

    it("renders nav items", () => {
        render(<DashboardNav />);
        expect(screen.getByText("Overview")).toBeInTheDocument();
        expect(screen.getByText("Team")).toBeInTheDocument();
        expect(screen.getByText("API Keys")).toBeInTheDocument();
        expect(screen.getByText("Governance")).toBeInTheDocument();
        expect(screen.getByText("Settings")).toBeInTheDocument();
    });

    it("renders user info when provided", () => {
        const user = { name: "John Doe", email: "john@example.com" };
        render(<DashboardNav user={user} />);
        expect(screen.getByText("John Doe")).toBeInTheDocument();
    });

    it("renders without user", () => {
        render(<DashboardNav />);
        // Should not crash
        expect(screen.getByText("CodeTrust")).toBeInTheDocument();
    });

    it("highlights active nav item", () => {
        render(<DashboardNav />);
        // The Overview link should have the active class since pathname is /dashboard
        const overviewLink = screen.getByText("Overview");
        expect(overviewLink.closest("a")).toHaveAttribute("href", "/dashboard");
    });
});
