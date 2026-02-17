/**
 * CodeTrust VS Code Extension — Main entry point.
 *
 * Activates on supported languages, provides:
 * - Scan on save (configurable)
 * - Command palette: Scan File, Deep Scan, Verify Imports, Verify Dockerfile
 * - Inline diagnostics (squiggly lines) with severity mapping
 * - Quick-fix code actions from scan findings
 * - Status bar showing last scan verdict
 */

import * as vscode from "vscode";
import { ApiClient } from "./api-client";
import { DiagnosticProvider } from "./diagnostics";
import { StatusBarManager } from "./status-bar";
import { CodeTrustCodeActionProvider } from "./code-actions";
import { registerCommands, handleScanOnSave } from "./commands";
import type { CommandDeps } from "./commands";
import { getConfig } from "./config";
import { LANGUAGE_MAP, DOCKERFILE_LANGUAGE_IDS } from "./types";
import { VerificationCache } from "./verification-cache";
import { scanCodeOffline } from "./embedded-scanner";
import { getApiKeySecret, migrateApiKeySettingToSecretIfNeeded } from "./secrets";
import { sendTelemetry } from "./telemetry";

/** Extension activation — called when a supported file is opened. */
export async function activate(context: vscode.ExtensionContext): Promise<void> {
    const baseConfig = getConfig();
    const diagnostics = new DiagnosticProvider();
    const statusBar = new StatusBarManager();
    const outputChannel = vscode.window.createOutputChannel("CodeTrust");
    const cache = new VerificationCache(context.globalState);

    await migrateApiKeySettingToSecretIfNeeded(context, outputChannel);
    const apiKey = await getApiKeySecret(context);

    const config = { ...baseConfig, apiKey };
    const client = new ApiClient(config);

    void sendTelemetry(context, "client_activated", {
        api_url_default: config.apiUrl.replace(/\/+$/, "") === "https://codetrust-api.saidborna.com",
        api_key_configured: config.apiKey.trim().length > 0,
        scan_on_save: config.scanOnSave,
        scan_type: config.scanType,
        enabled_languages_count: config.enabledLanguages.length,
    });

    const stats = cache.getStats();
    outputChannel.appendLine(
        `CodeTrust extension activated | API: ${config.apiUrl} | Cache: ${stats.imports} imports, ${stats.docker} images`,
    );

    void maybePromptAlwaysOn(context, outputChannel);
    void maybePromptGuidedOnboarding(context, outputChannel);

    const deps: CommandDeps = {
        client,
        diagnostics,
        statusBar,
        outputChannel,
        cache,
        telemetry: (eventType: string, payload: Record<string, unknown>): void => {
            void sendTelemetry(context, eventType, payload);
        },
    };

    // Register commands
    registerCommands(context, deps);

    // Register code action provider for all supported languages
    const languageSelectors = buildLanguageSelectors();
    context.subscriptions.push(
        vscode.languages.registerCodeActionsProvider(
            languageSelectors,
            new CodeTrustCodeActionProvider(),
            { providedCodeActionKinds: CodeTrustCodeActionProvider.providedCodeActionKinds },
        ),
    );

    // Scan on save
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument((document) => {
            handleScanOnSave(deps, document).catch((err: unknown) => {
                const msg = err instanceof Error ? err.message : "Unknown error";
                outputChannel.appendLine(`Save-scan error: ${msg}`);
            });
        }),
    );

    // Scan on type (debounced, offline only)
    const debounceTimers = new Map<string, NodeJS.Timeout>();
    context.subscriptions.push(
        vscode.workspace.onDidChangeTextDocument((event) => {
            const cfg = getConfig();
            if (!cfg.scanOnType) {
                return;
            }

            const doc = event.document;
            if (doc.uri.scheme !== "file") {
                return;
            }

            if (DOCKERFILE_LANGUAGE_IDS.has(doc.languageId)) {
                return;
            }

            const language = LANGUAGE_MAP[doc.languageId];
            if (!language || !cfg.enabledLanguages.includes(language)) {
                return;
            }

            const key = doc.uri.toString();
            const existing = debounceTimers.get(key);
            if (existing) {
                clearTimeout(existing);
            }

            const timeout = setTimeout(() => {
                try {
                    const response = scanCodeOffline(doc.getText(), doc.fileName);
                    diagnostics.setFindingsDiagnostics(
                        doc.uri,
                        response.findings,
                        cfg.severityThreshold,
                    );
                } catch {
                    // Best-effort only — never disrupt typing
                }
            }, cfg.scanOnTypeDebounceMs);

            debounceTimers.set(key, timeout);
        }),
    );

    // Scan on open — always active, CodeTrust is never idle
    context.subscriptions.push(
        vscode.workspace.onDidOpenTextDocument((document) => {
            handleScanOnSave(deps, document).catch((err: unknown) => {
                const msg = err instanceof Error ? err.message : "Unknown error";
                outputChannel.appendLine(`Open-scan error: ${msg}`);
            });
        }),
    );

    // Scan the active editor immediately on activation
    const activeEditor = vscode.window.activeTextEditor;
    if (activeEditor) {
        handleScanOnSave(deps, activeEditor.document).catch(() => { });
    }

    // Scan all already-open documents on activation
    for (const document of vscode.workspace.textDocuments) {
        if (document.uri.toString() !== activeEditor?.document.uri.toString()) {
            handleScanOnSave(deps, document).catch(() => { });
        }
    }

    // Clear diagnostics when a file is closed
    context.subscriptions.push(
        vscode.workspace.onDidCloseTextDocument((document) => {
            const key = document.uri.toString();
            const existing = debounceTimers.get(key);
            if (existing) {
                clearTimeout(existing);
                debounceTimers.delete(key);
            }
            diagnostics.clearForDocument(document.uri);
        }),
    );

    // Update client config when settings change
    context.subscriptions.push(
        vscode.workspace.onDidChangeConfiguration((event) => {
            if (event.affectsConfiguration("codetrust")) {
                void (async (): Promise<void> => {
                    const updatedBase = getConfig();
                    const updatedKey = await getApiKeySecret(context);
                    const updated = { ...updatedBase, apiKey: updatedKey };
                    client.updateConfig(updated);
                    outputChannel.appendLine(
                        `Configuration updated | API: ${updated.apiUrl}`,
                    );
                })();
            }
        }),
    );

    // Register disposables
    context.subscriptions.push(diagnostics.diagnosticCollection);
    context.subscriptions.push(statusBar);
    context.subscriptions.push(outputChannel);
}

async function maybePromptGuidedOnboarding(
    context: vscode.ExtensionContext,
    outputChannel: vscode.OutputChannel,
): Promise<void> {
    const key = "codetrust.guidedOnboardingPrompted.v3";
    const existing = context.globalState.get<boolean | null>(key, null);
    if (existing !== null) {
        return;
    }

    // Silently apply safe global defaults on first activation — no prompts
    const cfg = vscode.workspace.getConfiguration("codetrust");
    const target = vscode.ConfigurationTarget.Global;
    await cfg.update("scanOnSave", true, target);
    await context.globalState.update(key, true);
    outputChannel.appendLine("CodeTrust: global defaults applied (scanOnSave=true).");
}

async function maybePromptAlwaysOn(
    context: vscode.ExtensionContext,
    outputChannel: vscode.OutputChannel,
): Promise<void> {
    const key = "codetrust.alwaysOnConsent.v3";
    const existing = context.globalState.get<boolean | null>(key, null);
    if (existing !== null) {
        return;
    }

    // Silently enable CodeTrust everywhere — no prompts
    const cfg = vscode.workspace.getConfiguration("codetrust");
    const target = vscode.ConfigurationTarget.Global;
    await cfg.update("scanOnSave", true, target);
    await cfg.update("governance.enabled", true, target);
    await cfg.update("governance.mode", "enforce", target);
    await context.globalState.update(key, true);
    outputChannel.appendLine(
        "CodeTrust enabled globally: scanOnSave, governance.enabled, governance.mode=enforce.",
    );
}

/** Extension deactivation — cleanup. */
export function deactivate(): void {
    // All disposables are cleaned up via context.subscriptions
}

/** Build language selectors for code action registration. */
function buildLanguageSelectors(): vscode.DocumentSelector {
    const selectors: vscode.DocumentFilter[] = [];

    for (const langId of Object.keys(LANGUAGE_MAP)) {
        selectors.push({ language: langId, scheme: "file" });
    }

    for (const langId of DOCKERFILE_LANGUAGE_IDS) {
        selectors.push({ language: langId, scheme: "file" });
    }

    return selectors;
}
