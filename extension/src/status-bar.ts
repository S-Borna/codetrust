/**
 * Status bar component for the CodeTrust VS Code extension.
 * Shows the last scan verdict and provides quick access to scan commands.
 */

import * as vscode from "vscode";

/** Verdict display configuration. */
interface VerdictDisplay {
  icon: string;
  text: string;
  color: string | vscode.ThemeColor;
  tooltip: string;
}

/** Verdict display presets. */
const VERDICT_DISPLAY: Record<string, VerdictDisplay> = {
  PASS: {
    icon: "$(check)",
    text: "PASS",
    color: new vscode.ThemeColor("testing.iconPassed"),
    tooltip: "CodeTrust: All checks passed",
  },
  WARN: {
    icon: "$(warning)",
    text: "WARN",
    color: new vscode.ThemeColor("editorWarning.foreground"),
    tooltip: "CodeTrust: Warnings found — review suggested",
  },
  BLOCK: {
    icon: "$(error)",
    text: "BLOCK",
    color: new vscode.ThemeColor("editorError.foreground"),
    tooltip: "CodeTrust: Blocking issues found — action required",
  },
  SCANNING: {
    icon: "$(sync~spin)",
    text: "Scanning...",
    color: new vscode.ThemeColor("statusBar.foreground"),
    tooltip: "CodeTrust: Scan in progress",
  },
  ERROR: {
    icon: "$(alert)",
    text: "Error",
    color: new vscode.ThemeColor("errorForeground"),
    tooltip: "CodeTrust: Scan failed",
  },
  IDLE: {
    icon: "$(shield)",
    text: "CodeTrust",
    color: new vscode.ThemeColor("statusBar.foreground"),
    tooltip: "CodeTrust: Click to scan current file",
  },
};

/** Manages the status bar item for scan results. */
export class StatusBarManager {
  private readonly item: vscode.StatusBarItem;

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
  setVerdict(verdict: string, findingsCount: number): void {
    const key = verdict.toUpperCase();
    const display = VERDICT_DISPLAY[key] ?? VERDICT_DISPLAY.IDLE;

    const tooltip =
      findingsCount > 0
        ? `${display.tooltip} (${findingsCount} finding${findingsCount !== 1 ? "s" : ""})`
        : display.tooltip;

    this.applyDisplay({ ...display, tooltip });
  }

  /** Set status to error. */
  setError(message: string): void {
    this.applyDisplay({
      ...VERDICT_DISPLAY.ERROR,
      tooltip: `CodeTrust: ${message}`,
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
