// Copyright (c) 2026 Said Borna. All rights reserved.
// Proprietary — see LICENSE for terms.
/**
 * Status bar component for the CodeTrust VS Code extension.
 *
 * Design: consistent enterprise branding across all states.
 * The shield icon and "CodeTrust" text remain constant.
 * Scan results are communicated via tooltip and the VS Code Problems panel.
 */

import * as vscode from "vscode";

/** Verdict display configuration. */
interface VerdictDisplay {
    icon: string;
    text: string;
    color: string | vscode.ThemeColor;
    tooltip: string;
}

/** Status bar text — always "CodeTrust" for brand consistency. */
const BRAND_TEXT = "CodeTrust";

/** Verdict display presets — enterprise-grade: consistent icon, neutral colors. */
const VERDICT_DISPLAY: Record<string, VerdictDisplay> = {
    PASS: {
        icon: "$(shield)",
        text: BRAND_TEXT,
        color: new vscode.ThemeColor("statusBar.foreground"),
        tooltip: "CodeTrust — All checks passed",
    },
    WARN: {
        icon: "$(shield)",
        text: BRAND_TEXT,
        color: new vscode.ThemeColor("statusBar.foreground"),
        tooltip: "CodeTrust — Warnings found, review suggested",
    },
    BLOCK: {
        icon: "$(shield)",
        text: BRAND_TEXT,
        color: new vscode.ThemeColor("statusBar.foreground"),
        tooltip: "CodeTrust — Blocking issues found, action required",
    },
    SCANNING: {
        icon: "$(loading~spin)",
        text: BRAND_TEXT,
        color: new vscode.ThemeColor("statusBar.foreground"),
        tooltip: "CodeTrust — Scan in progress",
    },
    ERROR: {
        icon: "$(shield)",
        text: BRAND_TEXT,
        color: new vscode.ThemeColor("statusBar.foreground"),
        tooltip: "CodeTrust — Scan failed",
    },
    IDLE: {
        icon: "$(shield)",
        text: BRAND_TEXT,
        color: new vscode.ThemeColor("statusBar.foreground"),
        tooltip: "CodeTrust — Click to scan current file",
    },
};

/** Manages the status bar item for scan results. */
export class StatusBarManager {
    private readonly item: vscode.StatusBarItem;
    private isOffline = false;

    constructor() {
        this.item = vscode.window.createStatusBarItem(
            vscode.StatusBarAlignment.Left,
            100,
        );
        this.item.command = "codetrust.scanFile";
        this.setIdle();
        this.item.show();
    }

    /** Set status to idle (no recent scan). */
    setIdle(): void {
        this.applyDisplay(VERDICT_DISPLAY.IDLE);
    }

    /** Set status to scanning (in progress). */
    setScanning(): void {
        this.applyDisplay(VERDICT_DISPLAY.SCANNING);
    }

    /** Set status to a scan verdict. */
    setVerdict(verdict: string, findingsCount: number, offline = false): void {
        this.isOffline = offline;
        const key = verdict.toUpperCase();
        const display = VERDICT_DISPLAY[key] ?? VERDICT_DISPLAY.IDLE;

        const modeLabel = offline ? "Embedded scanner" : "Full scan";
        const countSuffix =
            findingsCount > 0
                ? ` · ${findingsCount} finding${findingsCount !== 1 ? "s" : ""}`
                : "";
        const tooltip = `${display.tooltip}${countSuffix} (${modeLabel})`;

        this.applyDisplay({ ...display, tooltip });
    }

    /** Set status to error. */
    setError(message: string): void {
        this.applyDisplay({
            ...VERDICT_DISPLAY.ERROR,
            tooltip: `CodeTrust — ${message}`,
        });
    }

    /** Apply a display configuration to the status bar item. */
    private applyDisplay(display: VerdictDisplay): void {
        this.item.text = `${display.icon} ${display.text}`;
        this.item.color = display.color;
        this.item.tooltip = display.tooltip;
    }

    /** Dispose the status bar item. */
    dispose(): void {
        this.item.dispose();
    }
}
