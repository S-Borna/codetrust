import React from "react";
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { ScanHistoryTable } from "@/components/scan-history";

const mockScans = [
    {
        id: "1",
        scan_type: "static",
        verdict: "PASS",
        findings_count: 0,
        language: "python",
        filename: "main.py",
        latency_ms: 42,
        created_at: "2024-01-15T10:00:00Z",
    },
    {
        id: "2",
        scan_type: "deep",
        verdict: "BLOCK",
        findings_count: 3,
        language: "javascript",
        filename: "app.js",
        latency_ms: 120,
        created_at: "2024-01-15T11:00:00Z",
    },
    {
        id: "3",
        scan_type: "static",
        verdict: "WARN",
        findings_count: 1,
        language: "python",
        filename: "utils.py",
        latency_ms: 55,
        created_at: "2024-01-15T12:00:00Z",
    },
];

describe("ScanHistoryTable", () => {
    it("renders empty state when no scans", () => {
        render(<ScanHistoryTable scans={[]} />);
        expect(
            screen.getByText(/no scans yet/i)
        ).toBeInTheDocument();
    });

    it("renders table headers", () => {
        render(<ScanHistoryTable scans={mockScans} />);
        expect(screen.getByText("Type")).toBeInTheDocument();
        expect(screen.getByText("Verdict")).toBeInTheDocument();
        expect(screen.getByText("Findings")).toBeInTheDocument();
        expect(screen.getByText("File")).toBeInTheDocument();
        expect(screen.getByText("Latency")).toBeInTheDocument();
        expect(screen.getByText("Date")).toBeInTheDocument();
    });

    it("renders scan rows", () => {
        render(<ScanHistoryTable scans={mockScans} />);
        expect(screen.getByText("PASS")).toBeInTheDocument();
        expect(screen.getByText("BLOCK")).toBeInTheDocument();
        expect(screen.getByText("WARN")).toBeInTheDocument();
    });

    it("renders filenames", () => {
        render(<ScanHistoryTable scans={mockScans} />);
        expect(screen.getByText("main.py")).toBeInTheDocument();
        expect(screen.getByText("app.js")).toBeInTheDocument();
        expect(screen.getByText("utils.py")).toBeInTheDocument();
    });

    it("renders latency with ms suffix", () => {
        render(<ScanHistoryTable scans={mockScans} />);
        expect(screen.getByText("42ms")).toBeInTheDocument();
        expect(screen.getByText("120ms")).toBeInTheDocument();
    });

    it("renders findings count", () => {
        render(<ScanHistoryTable scans={mockScans} />);
        expect(screen.getByText("0")).toBeInTheDocument();
        expect(screen.getByText("3")).toBeInTheDocument();
    });

    it("renders section title", () => {
        render(<ScanHistoryTable scans={mockScans} />);
        expect(screen.getByText("Recent scans")).toBeInTheDocument();
    });
});
