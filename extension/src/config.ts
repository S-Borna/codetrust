/**
 * Configuration helper for the CodeTrust VS Code extension.
 * Reads settings from VS Code workspace configuration.
 */

import * as vscode from "vscode";
import type { ExtensionConfig, Language, ScanType, SeverityThreshold } from "./types";

/** Read the current extension configuration. */
export function getConfig(): ExtensionConfig {
    const config = vscode.workspace.getConfiguration("codetrust");

    return {
        apiUrl: config.get<string>("apiUrl", "http://localhost:8000"),
        apiKey: config.get<string>("apiKey", ""),
        scanOnSave: config.get<boolean>("scanOnSave", true),
        severityThreshold: config.get<SeverityThreshold>("severityThreshold", "INFO"),
        enabledLanguages: config.get<Language[]>("enabledLanguages", [
            "python", "javascript", "typescript", "go", "rust",
        ]),
        scanType: config.get<ScanType>("scanType", "static"),
        verifyImportsOnSave: config.get<boolean>("verifyImportsOnSave", false),
        timeout: config.get<number>("timeout", 15000),
    };
}
