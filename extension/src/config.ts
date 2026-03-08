// Copyright (c) Said Borna. All rights reserved.
// Proprietary — see LICENSE for terms.
/**
 * Configuration helper for the CodeTrust VS Code extension.
 * Reads settings from VS Code workspace configuration.
 */

import * as vscode from "vscode";
import type { ExtensionConfig, GovernanceMode, Language, ScanType, SeverityThreshold } from "./types";

const DEFAULT_REQUEST_TIMEOUT_MS = 15000;
const DEFAULT_SCAN_ON_TYPE_DEBOUNCE_MS = 600;

/** Read the current extension configuration. */
export function getConfig(): ExtensionConfig {
    const config = vscode.workspace.getConfiguration("codetrust");

    return {
        apiUrl: config.get<string>("apiUrl", "https://api.codetrust.ai"),
        apiKey: config.get<string>("apiKey", ""),
        scanOnSave: config.get<boolean>("scanOnSave", true),
        scanOnType: config.get<boolean>("scanOnType", false),
        scanOnTypeDebounceMs: config.get<number>("scanOnTypeDebounceMs", DEFAULT_SCAN_ON_TYPE_DEBOUNCE_MS),
        severityThreshold: config.get<SeverityThreshold>("severityThreshold", "INFO"),
        enabledLanguages: config.get<Language[]>("enabledLanguages", [
            "python", "javascript", "typescript", "go", "rust", "sql", "yaml",
            "java", "csharp", "cpp", "shell", "html", "terraform",
        ]),
        scanType: config.get<ScanType>("scanType", "static"),
        verifyImportsOnSave: config.get<boolean>("verifyImportsOnSave", false),
        timeout: config.get<number>("timeout", DEFAULT_REQUEST_TIMEOUT_MS),
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
