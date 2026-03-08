// Copyright (c) Said Borna. All rights reserved.
// Proprietary — see LICENSE for terms.
/**
 * Command handlers for the CodeTrust VS Code extension.
 * Implements scan, verify, and diagnostic management commands.
 */

import * as vscode from "vscode";
import { ApiClient, ApiError } from "./api-client";
import type { RateLimitInfo } from "./api-client";
import { DiagnosticProvider } from "./diagnostics";
import { StatusBarManager } from "./status-bar";
import { scanCodeOffline } from "./embedded-scanner";
import { extractImports, extractDockerImages } from "./parsers";
import { getConfig } from "./config";
import { getApiKeySecret, storeApiKeySecret } from "./secrets";
import type { VerificationCache } from "./verification-cache";
import type {
    Language,
    SeverityThreshold,
    Finding,
} from "./types";
import { LANGUAGE_MAP, DOCKERFILE_LANGUAGE_IDS } from "./types";

/** Command handler dependencies. */
export interface CommandDeps {
    client: ApiClient;
    diagnostics: DiagnosticProvider;
    statusBar: StatusBarManager;
    outputChannel: vscode.OutputChannel;
    cache: VerificationCache;
    telemetry: (eventType: string, payload: Record<string, unknown>) => void;
}

let lastScannableDocumentUri: vscode.Uri | null = null;
let lastScanAtIso: string | null = null;
let lastScanTarget: string | null = null;

const TRUNCATE_BODY_MAX_LEN = 240;
const FILE_SCAN_LIMIT = 500;

/** Register all extension commands. */
export function registerCommands(
    context: vscode.ExtensionContext,
    deps: CommandDeps,
): void {
    const commands: Array<[string, () => Promise<void>]> = [
        ["codetrust.scanFile", (): Promise<void> => scanCurrentFile(deps)],
        [
            "codetrust.guidedOnboarding",
            (): Promise<void> => guidedOnboardingCommand(context, deps),
        ],
        ["codetrust.createProfile", (): Promise<void> => createProfileCommand(deps)],
        ["codetrust.applyProfile", (): Promise<void> => applyProfileCommand(deps)],
        ["codetrust.healthCheck", (): Promise<void> => healthCheckCommand(deps)],
        ["codetrust.verifyImports", (): Promise<void> => verifyImportsCommand(deps)],
        ["codetrust.verifyDockerfile", (): Promise<void> => verifyDockerfileCommand(deps)],
        ["codetrust.deepScan", (): Promise<void> => deepScanCommand(deps)],
        ["codetrust.clearDiagnostics", (): Promise<void> => clearDiagnosticsCommand(deps)],
        ["codetrust.scanWorkspace", (): Promise<void> => scanWorkspaceCommand(deps)],
        ["codetrust.governanceStatus", (): Promise<void> => governanceStatusCommand(deps)],
    ];

    for (const [id, handler] of commands) {
        context.subscriptions.push(
            vscode.commands.registerCommand(id, handler),
        );
    }
}

const API_URL_CHOICES = [
    "Use Cloud API (recommended)",
    "Set custom API URL",
    "Skip (offline only)",
] as const;

type ApiUrlChoice = (typeof API_URL_CHOICES)[number];

async function guidedOnboardingCommand(
    context: vscode.ExtensionContext,
    deps: CommandDeps,
): Promise<void> {
    deps.outputChannel.appendLine(`[${timestamp()}] Guided onboarding`);

    const key = "codetrust.guidedOnboardingCompleted.v1";
    const existing = context.globalState.get<boolean | null>(key, null);
    if (existing === true) {
        const again = await vscode.window.showInformationMessage(
            "CodeTrust onboarding was already completed. Run it again?",
            "Run again",
            "Cancel",
        );
        if (again !== "Run again") {
            return;
        }
    }

    const cfg = vscode.workspace.getConfiguration("codetrust");
    const current = getConfig();
    const currentSecretKey = await getApiKeySecret(context);

    const apiUrlChoice = (await vscode.window.showQuickPick(
        API_URL_CHOICES,
        {
            title: "CodeTrust setup",
            placeHolder: "Choose API mode",
            ignoreFocusOut: true,
        },
    )) as ApiUrlChoice | undefined;

    if (apiUrlChoice === undefined) {
        deps.outputChannel.appendLine("  Cancelled at API mode step.");
        return;
    }

    if (apiUrlChoice === "Use Cloud API (recommended)") {
        await cfg.update(
            "apiUrl",
            "https://api.codetrust.ai",
            vscode.ConfigurationTarget.Global,
        );
        deps.outputChannel.appendLine("  Set apiUrl to cloud default.");
    }

    if (apiUrlChoice === "Set custom API URL") {
        const url = await vscode.window.showInputBox({
            title: "CodeTrust setup",
            prompt: "Enter your CodeTrust API URL (http/https)",
            value: current.apiUrl,
            ignoreFocusOut: true,
            validateInput: (value: string): string | null => {
                const trimmed = value.trim();
                if (trimmed.length === 0) {
                    return "API URL is required.";
                }
                try {
                    const parsed = new URL(trimmed);
                    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
                        return "URL must start with http:// or https://";
                    }
                    return null;
                } catch {
                    return "Invalid URL.";
                }
            },
        });

        if (!url) {
            deps.outputChannel.appendLine("  Cancelled at API URL input.");
            return;
        }

        await cfg.update("apiUrl", url.trim(), vscode.ConfigurationTarget.Global);
        deps.outputChannel.appendLine("  Updated apiUrl.");
    }

    if (apiUrlChoice !== "Skip (offline only)") {
        const apiKey = await vscode.window.showInputBox({
            title: "CodeTrust setup",
            prompt: "Enter API key (stored in VS Code Secret Storage)",
            password: true,
            ignoreFocusOut: true,
            value: currentSecretKey.length > 0 ? "" : "",
        });

        if (apiKey === undefined) {
            deps.outputChannel.appendLine("  Cancelled at API key step.");
            return;
        }

        const trimmedKey = apiKey.trim();
        await storeApiKeySecret(context, trimmedKey);
        const updatedBase = getConfig();
        deps.client.updateConfig({ ...updatedBase, apiKey: trimmedKey });
        deps.outputChannel.appendLine(
            trimmedKey.length > 0
                ? "  API key saved to Secret Storage."
                : "  API key left empty (offline usage only).",
        );
    }

    const runHealth = await vscode.window.showInformationMessage(
        "Run CodeTrust Health Check now?",
        "Run Health Check",
        "Skip",
    );
    if (runHealth === "Run Health Check") {
        await vscode.commands.executeCommand("codetrust.healthCheck");
    }

    const firstScan = await vscode.window.showInformationMessage(
        "Run your first scan now?",
        "Scan Workspace",
        "Scan Current File",
        "Not now",
    );

    if (firstScan === "Scan Workspace") {
        await vscode.commands.executeCommand("codetrust.scanWorkspace");
    }
    if (firstScan === "Scan Current File") {
        await vscode.commands.executeCommand("codetrust.scanFile");
    }

    await context.globalState.update(key, true);
    vscode.window.showInformationMessage(
        "CodeTrust is active. Your code is now protected.",
    );
}

async function createProfileCommand(deps: CommandDeps): Promise<void> {
    deps.outputChannel.appendLine(`[${timestamp()}] Create CodeTrust Profile`);

    const ok = await applyProfileSettings(deps, {
        promptTitle: "Create & apply CodeTrust Profile",
        promptBody:
            "This will apply CodeTrust recommended settings to the current VS Code Profile. " +
            "You can create/switch profiles using VS Code Profiles UI.",
    });
    if (!ok) {
        return;
    }

    // Best-effort: trigger VS Code's built-in Profile creation UI when available.
    // Command IDs are not part of the stable API surface, so try a small set.
    const candidateCommands = [
        "workbench.profiles.actions.createProfile",
        "workbench.profiles.actions.manageProfiles",
        "workbench.profiles.actions.switchProfile",
    ];

    for (const cmd of candidateCommands) {
        try {
            // eslint-disable-next-line no-await-in-loop
            await vscode.commands.executeCommand(cmd);
            deps.outputChannel.appendLine(`  Triggered VS Code Profiles UI: ${cmd}`);
            return;
        } catch {
            // Try next
        }
    }

    deps.outputChannel.appendLine("  VS Code Profiles UI command not available in this build.");
    vscode.window.showInformationMessage(
        "CodeTrust: Settings applied to current profile. Create/switch profiles via: Settings (Profiles).",
    );
}

async function applyProfileCommand(deps: CommandDeps): Promise<void> {
    deps.outputChannel.appendLine(`[${timestamp()}] Apply CodeTrust Profile`);
    await applyProfileSettings(deps, {
        promptTitle: "Apply CodeTrust Profile",
        promptBody: "Apply CodeTrust recommended settings to the current VS Code Profile?",
    });
}

type ProfilePrompt = {
    promptTitle: string;
    promptBody: string;
};

async function applyProfileSettings(deps: CommandDeps, prompt: ProfilePrompt): Promise<boolean> {
    const choice = await vscode.window.showInformationMessage(
        prompt.promptBody,
        { modal: true, detail: "This updates profile-scoped User settings for CodeTrust." },
        "Apply",
        "Cancel",
    );

    if (choice !== "Apply") {
        deps.outputChannel.appendLine("  Cancelled.");
        return false;
    }

    const cfg = vscode.workspace.getConfiguration("codetrust");
    const target = vscode.ConfigurationTarget.Global;

    // Recommended baseline for a dedicated CodeTrust profile
    await cfg.update("scanOnSave", true, target);
    await cfg.update("scanOnType", false, target);
    await cfg.update("scanType", "static", target);
    await cfg.update("severityThreshold", "INFO", target);
    await cfg.update("governance.enabled", true, target);
    await cfg.update("governance.mode", "enforce", target);
    await cfg.update("governance.blockHeredoc", true, target);
    await cfg.update("governance.blockEval", true, target);
    await cfg.update("governance.blockGitPush", true, target);

    deps.outputChannel.appendLine("  Applied recommended CodeTrust profile settings.");
    vscode.window.showInformationMessage("CodeTrust: Profile settings applied.");
    return true;
}

/** Scan the currently active file. */
async function scanCurrentFile(deps: CommandDeps): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        if (lastScannableDocumentUri) {
            deps.outputChannel.appendLine(
                `[${timestamp()}] No active editor — scanning last saved file`,
            );
            const doc = await vscode.workspace.openTextDocument(lastScannableDocumentUri);
            const language = LANGUAGE_MAP[doc.languageId];
            if (!language) {
                vscode.window.showWarningMessage(
                    "CodeTrust: No active file to scan, and last saved file is not supported.",
                );
                return;
            }
            const config = getConfig();
            if (!config.enabledLanguages.includes(language)) {
                vscode.window.showInformationMessage(
                    `CodeTrust: ${language} scanning is disabled in settings.`,
                );
                return;
            }
            if (config.scanType === "deep") {
                await runDeepScan(deps, doc, language);
            } else {
                await runStaticScan(deps, doc, language);
            }
            return;
        }
        vscode.window.showWarningMessage("CodeTrust: No active file to scan.");
        return;
    }

    const document = editor.document;
    const config = getConfig();
    const language = LANGUAGE_MAP[document.languageId];

    if (!language) {
        // Check if it's a Dockerfile
        if (DOCKERFILE_LANGUAGE_IDS.has(document.languageId)) {
            await verifyDockerfileDocument(deps, document);
            return;
        }
        vscode.window.showInformationMessage(
            `CodeTrust: Language '${document.languageId}' is not supported.`,
        );
        return;
    }

    if (!config.enabledLanguages.includes(language)) {
        vscode.window.showInformationMessage(
            `CodeTrust: ${language} scanning is disabled in settings.`,
        );
        return;
    }

    if (config.scanType === "deep") {
        await runDeepScan(deps, document, language);
    } else {
        await runStaticScan(deps, document, language);
    }
}

/** Run static scan on a document. */
async function runStaticScan(
    deps: CommandDeps,
    document: vscode.TextDocument,
    language: Language,
): Promise<void> {
    const config = getConfig();
    const startedAtMs = Date.now();
    deps.statusBar.setScanning();
    deps.outputChannel.appendLine(
        `[${timestamp()}] Static scan: ${document.fileName}`,
    );

    lastScanAtIso = new Date().toISOString();
    lastScanTarget = document.fileName;
    lastScannableDocumentUri = document.uri;

    try {
        const response = await deps.client.staticScan(
            document.getText(),
            document.fileName,
            language,
        );

        deps.diagnostics.setFindingsDiagnostics(
            document.uri,
            response.findings,
            config.severityThreshold,
        );

        deps.statusBar.setVerdict(response.verdict, response.total_findings, false);
        logScanResult(deps.outputChannel, "Static", response.verdict, response.findings);

        deps.telemetry("scan_completed", {
            scan_type: "static",
            language,
            verdict: response.verdict,
            files_scanned: 1,
            total_findings: response.total_findings,
            findings_by_severity: {
                BLOCK: response.blocks,
                WARN: response.warnings,
                INFO: response.infos,
            },
            offline_used: false,
            duration_ms: Date.now() - startedAtMs,
        });

        // Check rate limit headers and warn if near limit
        checkRateLimitWarning(deps, deps.client.lastRateLimit);
    } catch (err) {
        logApiError(deps, err);
        if (err instanceof ApiError && err.statusCode === 429) {
            showRateLimitBlockedNotification();
        }
        // Fallback to embedded offline scanner when API is unavailable
        deps.outputChannel.appendLine(
            `  API unavailable — using embedded scanner (49 rules)`,
        );
        const response = scanCodeOffline(document.getText(), document.fileName);
        deps.diagnostics.setFindingsDiagnostics(
            document.uri,
            response.findings,
            config.severityThreshold,
        );
        deps.statusBar.setVerdict(response.verdict, response.total_findings, true);
        logScanResult(deps.outputChannel, "Static (offline)", response.verdict, response.findings);

        deps.telemetry("scan_completed", {
            scan_type: "static",
            language,
            verdict: response.verdict,
            files_scanned: 1,
            total_findings: response.total_findings,
            findings_by_severity: {
                BLOCK: response.blocks,
                WARN: response.warnings,
                INFO: response.infos,
            },
            offline_used: true,
            duration_ms: Date.now() - startedAtMs,
        });
    }
}

/** Run deep scan on a document. */
async function runDeepScan(
    deps: CommandDeps,
    document: vscode.TextDocument,
    language: Language,
): Promise<void> {
    const config = getConfig();
    const startedAtMs = Date.now();
    deps.statusBar.setScanning();
    deps.outputChannel.appendLine(
        `[${timestamp()}] Deep scan: ${document.fileName}`,
    );

    lastScanAtIso = new Date().toISOString();
    lastScanTarget = document.fileName;
    lastScannableDocumentUri = document.uri;

    try {
        const response = await deps.client.deepScan(
            document.getText(),
            document.fileName,
            language,
        );

        // Combine all findings
        const allFindings: Finding[] = [
            ...response.static_findings,
            ...response.ast_findings,
        ];

        deps.diagnostics.setFindingsDiagnostics(
            document.uri,
            allFindings,
            config.severityThreshold,
        );

        // Add import results if present
        if (response.import_results.length > 0) {
            deps.diagnostics.appendImportDiagnostics(
                document.uri,
                document,
                response.import_results,
                config.severityThreshold,
            );
        }

        deps.statusBar.setVerdict(response.verdict, response.total_findings, false);
        deps.outputChannel.appendLine(
            `  Verdict: ${response.verdict} | ` +
            `${response.total_findings} findings | ` +
            `${response.latency_ms}ms`,
        );

        deps.telemetry("scan_completed", {
            scan_type: "deep",
            language,
            verdict: response.verdict,
            files_scanned: 1,
            total_findings: response.total_findings,
            findings_by_severity: {
                BLOCK: response.blocks,
                WARN: response.warnings,
                INFO: response.infos,
            },
            offline_used: false,
            duration_ms: Date.now() - startedAtMs,
            api_latency_ms: response.latency_ms,
            import_results_count: response.import_results.length,
        });

        // Check rate limit headers and warn if near limit
        checkRateLimitWarning(deps, deps.client.lastRateLimit);
    } catch (err) {
        logApiError(deps, err);
        if (err instanceof ApiError && err.statusCode === 429) {
            showRateLimitBlockedNotification();
        }
        // Fallback to embedded offline scanner when API is unavailable
        deps.outputChannel.appendLine(
            `  API unavailable — falling back to embedded scanner (49 rules)`,
        );
        const response = scanCodeOffline(document.getText(), document.fileName);
        deps.diagnostics.setFindingsDiagnostics(
            document.uri,
            response.findings,
            config.severityThreshold,
        );
        deps.statusBar.setVerdict(response.verdict, response.total_findings, true);
        logScanResult(deps.outputChannel, "Deep (offline)", response.verdict, response.findings);

        deps.telemetry("scan_completed", {
            scan_type: "deep",
            language,
            verdict: response.verdict,
            files_scanned: 1,
            total_findings: response.total_findings,
            findings_by_severity: {
                BLOCK: response.blocks,
                WARN: response.warnings,
                INFO: response.infos,
            },
            offline_used: true,
            duration_ms: Date.now() - startedAtMs,
        });
    }
}

/** Deep scan command (always uses deep scan regardless of settings). */
async function deepScanCommand(deps: CommandDeps): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showWarningMessage("CodeTrust: No active file to scan.");
        return;
    }

    const language = LANGUAGE_MAP[editor.document.languageId];
    if (!language) {
        vscode.window.showInformationMessage(
            `CodeTrust: Language '${editor.document.languageId}' is not supported.`,
        );
        return;
    }

    await runDeepScan(deps, editor.document, language);
}

/** Show health diagnostics for the extension + API connectivity. */
async function healthCheckCommand(deps: CommandDeps): Promise<void> {
    const config = getConfig();
    const cacheStats = deps.cache.getStats();

    deps.outputChannel.appendLine(`[${timestamp()}] Health Check`);
    deps.outputChannel.appendLine(`  API URL: ${config.apiUrl}`);
    deps.outputChannel.appendLine(`  API key configured: ${config.apiKey ? "yes" : "no"}`);
    deps.outputChannel.appendLine(
        `  Mode: scanOnSave=${config.scanOnSave} scanType=${config.scanType} threshold=${config.severityThreshold}`,
    );
    deps.outputChannel.appendLine(
        `  Governance: enabled=${config.governance.enabled} mode=${config.governance.mode}`,
    );
    deps.outputChannel.appendLine(
        `  Cache: imports=${cacheStats.imports} docker=${cacheStats.docker}`,
    );
    deps.outputChannel.appendLine(
        `  Last scan: ${lastScanAtIso ? lastScanAtIso : "never"}${lastScanTarget ? ` | ${lastScanTarget}` : ""}`,
    );

    try {
        const health = await deps.client.checkHealth();
        deps.outputChannel.appendLine(`  API status: ok (v${health.version})`);
        vscode.window.showInformationMessage(
            `CodeTrust: API ok (v${health.version}) — ${config.apiUrl}`,
        );
    } catch (err) {
        logApiError(deps, err);
        vscode.window.showWarningMessage(
            "CodeTrust: API not reachable — extension will use offline scanner where possible.",
        );
    }
}

function logApiError(deps: CommandDeps, err: unknown): void {
    if (err instanceof ApiError) {
        const hint = apiErrorHint(err.statusCode);
        deps.outputChannel.appendLine(
            `  API error (${err.statusCode}): ${hint}${err.body ? ` | ${truncate(err.body, TRUNCATE_BODY_MAX_LEN)}` : ""}`,
        );
        return;
    }
    const msg = err instanceof Error ? err.message : "Unknown error";
    deps.outputChannel.appendLine(`  API error: ${msg}`);
}

function apiErrorHint(statusCode: number): string {
    if (statusCode === 401) {
        return "Unauthorized — run 'CodeTrust: Guided Onboarding' to set API key (Secret Storage), or sign in (JWT)";
    }
    if (statusCode === 403) {
        return "Forbidden — credentials are valid but lack access";
    }
    if (statusCode === 429) {
        return "Rate limited — daily scan limit exceeded";
    }
    if (statusCode >= 500) {
        return "Server error — try again or switch to offline scan";
    }
    if (statusCode === 0) {
        return "Network error/timeout — check codetrust.apiUrl";
    }
    return "Request failed";
}

const UPGRADE_URL = "https://app.codetrust.ai/dashboard/settings";
const RATE_LIMIT_WARNING_THRESHOLD = 0.8;
let rateLimitWarningShown = false;

/** Show upgrade notification when rate limit is near or exceeded. */
function checkRateLimitWarning(
    deps: CommandDeps,
    rateLimit: RateLimitInfo | null,
): void {
    if (!rateLimit || rateLimit.limit === 0) {
        return;
    }
    const usageRatio = rateLimit.used / rateLimit.limit;
    if (usageRatio >= RATE_LIMIT_WARNING_THRESHOLD && !rateLimitWarningShown) {
        rateLimitWarningShown = true;
        const remaining = rateLimit.remaining;
        const msg = remaining > 0
            ? `CodeTrust: ${remaining} scans remaining today (${rateLimit.used}/${rateLimit.limit}). Upgrade for more.`
            : `CodeTrust: Daily scan limit reached (${rateLimit.limit}). Upgrade for more scans.`;
        vscode.window.showWarningMessage(msg, "Upgrade to Pro").then((choice) => {
            if (choice === "Upgrade to Pro") {
                vscode.env.openExternal(vscode.Uri.parse(UPGRADE_URL));
            }
        });
        deps.outputChannel.appendLine(`  Rate limit warning: ${rateLimit.used}/${rateLimit.limit} scans used today`);
    }
    // Reset warning flag at start of new day (when used resets to low)
    if (usageRatio < RATE_LIMIT_WARNING_THRESHOLD) {
        rateLimitWarningShown = false;
    }
}

/** Show clickable upgrade notification on 429 rate limit error. */
function showRateLimitBlockedNotification(): void {
    vscode.window.showErrorMessage(
        "CodeTrust: Daily scan limit exceeded. Upgrade to Pro for 10,000 scans/day.",
        "Upgrade to Pro",
    ).then((choice) => {
        if (choice === "Upgrade to Pro") {
            vscode.env.openExternal(vscode.Uri.parse(UPGRADE_URL));
        }
    });
}

function truncate(text: string, maxLen: number): string {
    if (text.length <= maxLen) {
        return text;
    }
    return `${text.slice(0, Math.max(0, maxLen - 1))}…`;
}

/** Verify imports in the current file. */
async function verifyImportsCommand(deps: CommandDeps): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showWarningMessage("CodeTrust: No active file.");
        return;
    }

    const document = editor.document;
    const language = LANGUAGE_MAP[document.languageId];
    if (!language) {
        vscode.window.showInformationMessage(
            `CodeTrust: Cannot verify imports for '${document.languageId}'.`,
        );
        return;
    }

    const config = getConfig();
    const code = document.getText();
    const imports = extractImports(code, language);

    if (imports.length === 0) {
        vscode.window.showInformationMessage("CodeTrust: No imports found.");
        return;
    }

    deps.statusBar.setScanning();
    const startedAtMs = Date.now();
    deps.outputChannel.appendLine(
        `[${timestamp()}] Verify imports: ${imports.length} packages in ${document.fileName}`,
    );

    try {
        // Check cache first — serve cached results for known packages
        const { cached, missing } = deps.cache.getImportResults(language, imports);
        let response;

        if (missing.length === 0) {
            // All imports are cached
            deps.outputChannel.appendLine(`  All ${imports.length} packages served from cache`);
            const verified = cached.filter((r) => r.status === "VERIFIED").length;
            const failed = cached.filter((r) => r.severity === "BLOCK").length;
            const warnings = cached.filter((r) => r.severity === "WARN").length;
            response = { verified, failed, warnings, results: cached, latency_ms: 0, cached_ratio: 1.0 };
        } else {
            // Fetch missing from API, merge with cached
            response = await deps.client.verifyImports(language, missing);
            // Cache the new results
            deps.cache.setImportResults(language, response.results);
            // Merge with cached results
            response.results = [...cached, ...response.results];
            response.verified += cached.filter((r) => r.status === "VERIFIED").length;
            deps.outputChannel.appendLine(
                `  ${cached.length} cached, ${missing.length} fetched from API`,
            );
        }

        deps.diagnostics.appendImportDiagnostics(
            document.uri,
            document,
            response.results,
            config.severityThreshold,
        );

        const summary =
            `Imports: ${response.verified} verified, ` +
            `${response.failed} failed, ` +
            `${response.warnings} warnings (${response.latency_ms}ms)`;

        deps.outputChannel.appendLine(`  ${summary}`);

        if (response.failed > 0) {
            deps.statusBar.setVerdict("BLOCK", response.failed);
            vscode.window.showWarningMessage(`CodeTrust: ${summary}`);
        } else if (response.warnings > 0) {
            deps.statusBar.setVerdict("WARN", response.warnings);
        } else {
            deps.statusBar.setVerdict("PASS", 0);
            vscode.window.showInformationMessage(`CodeTrust: ${summary}`);
        }

        deps.telemetry("import_verified", {
            language,
            total_imports_checked: imports.length,
            hallucinations_caught: response.failed,
            offline_used: false,
            duration_ms: Date.now() - startedAtMs,
            api_latency_ms: response.latency_ms,
            cached_ratio: response.cached_ratio,
        });
    } catch (err) {
        if (err instanceof ApiError && err.statusCode === 0) {
            // Serve cached results if available when offline
            const { cached } = deps.cache.getImportResults(language, imports);
            if (cached.length > 0) {
                deps.outputChannel.appendLine(
                    `  API offline — serving ${cached.length} cached import results`,
                );
                deps.diagnostics.appendImportDiagnostics(
                    document.uri,
                    document,
                    cached,
                    config.severityThreshold,
                );
                deps.statusBar.setVerdict("PASS", 0, true);
                vscode.window.showInformationMessage(
                    `CodeTrust: ${cached.length} imports verified from cache (offline)`,
                );

                deps.telemetry("import_verified", {
                    language,
                    total_imports_checked: imports.length,
                    cached_results_count: cached.length,
                    offline_used: true,
                    duration_ms: Date.now() - startedAtMs,
                });
            } else {
                deps.statusBar.setError("API offline");
                deps.outputChannel.appendLine(
                    `  Import verification skipped — API offline, no cached results.`,
                );
                vscode.window.showWarningMessage(
                    "CodeTrust: Import verification requires the API server. Run with: uvicorn src.server:app",
                );
            }
        } else {
            handleScanError(deps, err);
        }
    }
}

/** Verify Dockerfile in the current file. */
async function verifyDockerfileCommand(deps: CommandDeps): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showWarningMessage("CodeTrust: No active file.");
        return;
    }

    await verifyDockerfileDocument(deps, editor.document);
}

/** Verify Docker images in a document. */
async function verifyDockerfileDocument(
    deps: CommandDeps,
    document: vscode.TextDocument,
): Promise<void> {
    const config = getConfig();
    const startedAtMs = Date.now();
    const content = document.getText();
    const images = extractDockerImages(content);

    if (images.length === 0) {
        vscode.window.showInformationMessage(
            "CodeTrust: No Docker images found in file.",
        );
        return;
    }

    deps.statusBar.setScanning();
    deps.outputChannel.appendLine(
        `[${timestamp()}] Verify Dockerfile: ${images.length} images in ${document.fileName}`,
    );

    try {
        // Check cache for known-good images
        const cachedResults = [];
        const missingImages = [];
        for (const img of images) {
            const cached = deps.cache.getDockerResult(img.image, img.tag);
            if (cached) {
                cachedResults.push(cached);
            } else {
                missingImages.push(img);
            }
        }

        let response;
        if (missingImages.length === 0) {
            deps.outputChannel.appendLine(`  All ${images.length} images served from cache`);
            const verified = cachedResults.filter((r) => r.status === "VERIFIED").length;
            const failed = cachedResults.filter((r) => r.severity === "BLOCK").length;
            response = { verified, failed, results: cachedResults, latency_ms: 0 };
        } else {
            response = await deps.client.verifyDockerfile(missingImages);
            deps.cache.setDockerResults(response.results);
            response.results = [...cachedResults, ...response.results];
            response.verified += cachedResults.filter((r) => r.status === "VERIFIED").length;
            deps.outputChannel.appendLine(
                `  ${cachedResults.length} cached, ${missingImages.length} fetched from API`,
            );
        }

        deps.diagnostics.appendDockerDiagnostics(
            document.uri,
            document,
            response.results,
            config.severityThreshold,
        );

        const summary =
            `Docker: ${response.verified} verified, ${response.failed} failed (${response.latency_ms}ms)`;

        deps.outputChannel.appendLine(`  ${summary}`);

        if (response.failed > 0) {
            deps.statusBar.setVerdict("BLOCK", response.failed);
            vscode.window.showWarningMessage(`CodeTrust: ${summary}`);
        } else {
            deps.statusBar.setVerdict("PASS", 0);
            vscode.window.showInformationMessage(`CodeTrust: ${summary}`);
        }

        deps.telemetry("docker_verified", {
            images_checked: images.length,
            offline_used: false,
            duration_ms: Date.now() - startedAtMs,
            api_latency_ms: response.latency_ms,
        });
    } catch (err) {
        if (err instanceof ApiError && err.statusCode === 0) {
            // Serve cached Docker results when offline
            const cachedResults = images
                .map((img) => deps.cache.getDockerResult(img.image, img.tag))
                .filter((r): r is NonNullable<typeof r> => r !== undefined);
            if (cachedResults.length > 0) {
                deps.outputChannel.appendLine(
                    `  API offline — serving ${cachedResults.length} cached Docker results`,
                );
                deps.diagnostics.appendDockerDiagnostics(
                    document.uri,
                    document,
                    cachedResults,
                    config.severityThreshold,
                );
                deps.statusBar.setVerdict("PASS", 0, true);

                deps.telemetry("docker_verified", {
                    images_checked: images.length,
                    cached_results_count: cachedResults.length,
                    offline_used: true,
                    duration_ms: Date.now() - startedAtMs,
                });
            } else {
                deps.statusBar.setError("API offline");
                deps.outputChannel.appendLine(
                    `  Docker verification skipped — API offline, no cached results.`,
                );
            }
        } else {
            handleScanError(deps, err);
        }
    }
}

/** Scan all supported files in the workspace. */
async function scanWorkspaceCommand(deps: CommandDeps): Promise<void> {
    const folders = vscode.workspace.workspaceFolders;
    if (!folders || folders.length === 0) {
        vscode.window.showWarningMessage("CodeTrust: No workspace folder open.");
        return;
    }

    const config = getConfig();
    const supportedExts = ["py", "js", "ts", "tsx", "jsx", "go", "rs", "sql", "yaml", "yml"];
    const globPattern = `**/*.{${supportedExts.join(",")}}`;
    const excludePattern = "{**/node_modules/**,**/.venv/**,**/dist/**,**/build/**,**/__pycache__/**,**/out/**,**/.next/**,**/coverage/**}";

    deps.statusBar.setScanning();
    const startedAtMs = Date.now();
    deps.outputChannel.appendLine(`[${timestamp()}] Workspace scan started`);

    const files = await vscode.workspace.findFiles(globPattern, excludePattern, FILE_SCAN_LIMIT);
    deps.outputChannel.appendLine(`  Found ${files.length} files to scan`);

    let totalFindings = 0;
    let filesScanned = 0;
    let blocks = 0;

    await vscode.window.withProgress(
        {
            location: vscode.ProgressLocation.Notification,
            title: "CodeTrust: Scanning workspace",
            cancellable: true,
        },
        async (progress, token) => {
            for (let i = 0; i < files.length; i++) {
                if (token.isCancellationRequested) {
                    break;
                }

                const uri = files[i];
                progress.report({
                    increment: (100 / files.length),
                    message: `${i + 1}/${files.length}`,
                });

                try {
                    const doc = await vscode.workspace.openTextDocument(uri);
                    const language = LANGUAGE_MAP[doc.languageId];
                    if (!language) {
                        continue;
                    }

                    const response = scanCodeOffline(doc.getText(), doc.fileName);
                    if (response.findings.length > 0) {
                        deps.diagnostics.setFindingsDiagnostics(
                            doc.uri,
                            response.findings,
                            config.severityThreshold,
                        );
                        totalFindings += response.findings.length;
                        blocks += response.findings.filter(
                            (f) => f.severity === "BLOCK",
                        ).length;
                    }
                    filesScanned++;
                } catch {
                    // Skip files that can't be opened
                }
            }
        },
    );

    const verdict = blocks > 0 ? "BLOCK" : totalFindings > 0 ? "WARN" : "PASS";
    deps.statusBar.setVerdict(verdict, totalFindings, true);
    deps.outputChannel.appendLine(
        `  Workspace scan complete: ${filesScanned} files, ${totalFindings} findings, ${blocks} blocks`,
    );
    vscode.window.showInformationMessage(
        `CodeTrust: Scanned ${filesScanned} files — ${totalFindings} findings (${blocks} blocks)`,
    );

    deps.telemetry("scan_completed", {
        scan_type: "workspace_offline",
        files_scanned: filesScanned,
        total_findings: totalFindings,
        findings_by_severity: {
            BLOCK: blocks,
            WARN: Math.max(0, totalFindings - blocks),
            INFO: 0,
        },
        blocks,
        verdict,
        offline_used: true,
        duration_ms: Date.now() - startedAtMs,
    });
}

/** Clear all CodeTrust diagnostics. */
async function clearDiagnosticsCommand(deps: CommandDeps): Promise<void> {
    deps.diagnostics.clear();
    deps.statusBar.setIdle();
    deps.outputChannel.appendLine(`[${timestamp()}] Diagnostics cleared.`);
}

/** Handle scan errors uniformly. */
function handleScanError(deps: CommandDeps, err: unknown): void {
    const isConnectionError = err instanceof ApiError && err.statusCode === 0;
    const message = err instanceof ApiError
        ? `API error (${err.statusCode}): ${err.message}`
        : err instanceof Error
            ? err.message
            : "Unknown error";

    deps.statusBar.setError(isConnectionError ? "API offline" : message);
    deps.outputChannel.appendLine(`  ERROR: ${message}`);

    // Only show intrusive error popup for real API errors, not connection failures
    if (!isConnectionError) {
        vscode.window.showErrorMessage(`CodeTrust: ${message}`);
    }
}

/** Log scan result to output channel. */
function logScanResult(
    channel: vscode.OutputChannel,
    scanType: string,
    verdict: string,
    findings: Finding[],
): void {
    channel.appendLine(
        `  ${scanType}: ${verdict} | ${findings.length} findings`,
    );
    for (const f of findings.slice(0, 10)) {
        channel.appendLine(
            `    [${f.severity}] ${f.rule_id}: ${f.message}${f.line > 0 ? ` (line ${f.line})` : ""}`,
        );
    }
    if (findings.length > 10) {
        channel.appendLine(`    ... and ${findings.length - 10} more`);
    }
}

/** Handle scan on save for a document. */
export async function handleScanOnSave(
    deps: CommandDeps,
    document: vscode.TextDocument,
): Promise<void> {
    const config = getConfig();

    // Skip non-file schemes (e.g. output panels, git diffs)
    if (document.uri.scheme !== "file") {
        return;
    }

    // Check if it's a Dockerfile
    if (DOCKERFILE_LANGUAGE_IDS.has(document.languageId)) {
        await verifyDockerfileDocument(deps, document);
        return;
    }

    const language = LANGUAGE_MAP[document.languageId];
    if (!language || !config.enabledLanguages.includes(language)) {
        return;
    }

    // Run the configured scan type
    if (config.scanType === "deep") {
        await runDeepScan(deps, document, language);
    } else {
        await runStaticScan(deps, document, language);
    }

    // Optionally verify imports too
    if (config.verifyImportsOnSave) {
        const code = document.getText();
        const imports = extractImports(code, language);
        if (imports.length > 0) {
            try {
                const response = await deps.client.verifyImports(language, imports);
                deps.diagnostics.appendImportDiagnostics(
                    document.uri,
                    document,
                    response.results,
                    config.severityThreshold as SeverityThreshold,
                );
            } catch (err) {
                deps.outputChannel.appendLine(
                    `[${timestamp()}] Import verification failed: ${err instanceof Error ? err.message : "Unknown error"}`,
                );
            }
        }
    }
}

/**
 * Display the current CodeTrust governance status in the output channel.
 *
 * Shows the active governance mode, injection state of Copilot instructions,
 * and a reminder of mandatory pre-action validation steps.
 */
async function governanceStatusCommand(deps: CommandDeps): Promise<void> {
    deps.outputChannel.show(true);
    deps.outputChannel.appendLine(`[${timestamp()}] === CodeTrust Governance Status ===`);

    const cfg = vscode.workspace.getConfiguration("codetrust");
    const governanceEnabled = cfg.get<boolean>("governance.enabled", false);
    const governanceMode = cfg.get<string>("governance.mode", "audit");
    deps.outputChannel.appendLine(`Governance enabled : ${governanceEnabled}`);
    deps.outputChannel.appendLine(`Governance mode    : ${governanceMode}`);

    const copilotCfg = vscode.workspace.getConfiguration("github.copilot.chat");
    const copilotInstructions = copilotCfg.get<Array<{ text?: string; file?: string }>>(
        "codeGeneration.instructions",
        [],
    );
    const injected = copilotInstructions.some(
        (e) => e.text?.includes("[codetrust-governance-v1]"),
    );
    deps.outputChannel.appendLine(`Copilot rules injected: ${injected ? "YES ✓" : "NO — run 'CodeTrust: Inject Copilot Instructions'"}`);
    deps.outputChannel.appendLine("");
    deps.outputChannel.appendLine("Mandatory validation sequence:");
    deps.outputChannel.appendLine("  1. codetrust_validate_command  → before run_in_terminal");
    deps.outputChannel.appendLine("  2. codetrust_validate_file_write → before create_file / replace_string_in_file");
    deps.outputChannel.appendLine("  3. codetrust_validate_package  → before installing packages");
    deps.outputChannel.appendLine("  4. codetrust_validate_file_delete → before file deletion");
    deps.outputChannel.appendLine("Audit log: .codetrust/audit.jsonl");

    await vscode.window.showInformationMessage(
        `CodeTrust governance: ${governanceMode.toUpperCase()} | Copilot rules: ${injected ? "injected ✓" : "NOT injected ✗"}`,
    );
}

/** Format current timestamp for logging. */
function timestamp(): string {
    return new Date().toISOString().slice(11, 19);
}
