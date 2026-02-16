/**
 * Configuration helper for the CodeTrust VS Code extension.
 * Reads settings from VS Code workspace configuration.
 */

import * as vscode from "vscode";
import type { ExtensionConfig, GovernanceMode, Language, ScanType, SeverityThreshold } from "./types";

/** Read the current extension configuration. */
export function getConfig(): ExtensionConfig {
    const config = vscode.workspace.getConfiguration("codetrust");

    return {
        apiUrl: config.get<string>("apiUrl", "https://codetrust-api.saidborna.com"),
        apiKey: config.get<string>("apiKey", ""),
        scanOnSave: config.get<boolean>("scanOnSave", true),
        scanOnType: config.get<boolean>("scanOnType", false),
        scanOnTypeDebounceMs: config.get<number>("scanOnTypeDebounceMs", 600),
        severityThreshold: config.get<SeverityThreshold>("severityThreshold", "INFO"),
        enabledLanguages: config.get<Language[]>("enabledLanguages", [
            "python", "javascript", "typescript", "go", "rust",
        ]),
        scanType: config.get<ScanType>("scanType", "static"),
        verifyImportsOnSave: config.get<boolean>("verifyImportsOnSave", false),
        timeout: config.get<number>("timeout", 15000),
        telemetry: config.get<boolean>("telemetry", true),
        governance: {
            enabled: config.get<boolean>("governance.enabled", true),
            mode: config.get<GovernanceMode>("governance.mode", "enforce"),
            blockHeredoc: config.get<boolean>("governance.blockHeredoc", true),
            blockEval: config.get<boolean>("governance.blockEval", true),
            blockGitPush: config.get<boolean>("governance.blockGitPush", true),
            protectedPaths: config.get<string[]>("governance.protectedPaths", [
                "LICENSE", ".env", ".env.production",
            ]),
        },
    };
}
