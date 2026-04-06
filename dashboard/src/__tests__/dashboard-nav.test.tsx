import React from "react";
import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";

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

    it("renders core and pro nav items", () => {
        render(<DashboardNav />);
        // Core links
        expect(screen.getByText("Overview")).toBeInTheDocument();
        expect(screen.getByText("Enforcement")).toBeInTheDocument();
        expect(screen.getByText("PII")).toBeInTheDocument();
        expect(screen.getByText("Integrity")).toBeInTheDocument();
        expect(screen.getByText("Settings")).toBeInTheDocument();
        // Pro links
        expect(screen.getByText("Cost")).toBeInTheDocument();
        expect(screen.getByText("Team")).toBeInTheDocument();
        expect(screen.getByText("Governance")).toBeInTheDocument();
    });

    it("renders user info when provided", () => {
        const user = { name: "John Doe", email: "john@example.com" };
        render(<DashboardNav user={user} />);
        expect(screen.getByText("John Doe")).toBeInTheDocument();
    });

    it("renders without user", () => {
        render(<DashboardNav />);
        expect(screen.getByText("CodeTrust")).toBeInTheDocument();
    });

    it("highlights active nav item", () => {
        render(<DashboardNav />);
        const overviewLink = screen.getByText("Overview");
        expect(overviewLink.closest("a")).toHaveAttribute("href", "/dashboard");
    });

    it("toggles mobile menu on hamburger click", () => {
        render(<DashboardNav />);
        const toggle = screen.getByLabelText("Open menu");
        expect(toggle).toHaveAttribute("aria-expanded", "false");

        fireEvent.click(toggle);
        expect(toggle).toHaveAttribute("aria-expanded", "true");
        expect(screen.getByLabelText("Close menu")).toBeInTheDocument();
    });

    it("closes mobile menu when a nav link is clicked", () => {
        render(<DashboardNav />);
        const toggle = screen.getByLabelText("Open menu");
        fireEvent.click(toggle);

        // Mobile menu should be open — find a link inside the mobile nav
        const mobileLinks = screen.getAllByText("Settings");
        // Click the last one (mobile menu instance)
        fireEvent.click(mobileLinks[mobileLinks.length - 1]);

        // Menu should close
        expect(screen.getByLabelText("Open menu")).toHaveAttribute("aria-expanded", "false");
    });
});
