/**
 * Command handlers for the CodeTrust VS Code extension.
 * Implements scan, verify, and diagnostic management commands.
 */

import * as vscode from "vscode";
import { ApiClient, ApiError } from "./api-client";
import { DiagnosticProvider } from "./diagnostics";
import { StatusBarManager } from "./status-bar";
import { scanCodeOffline } from "./embedded-scanner";
import { extractImports, extractDockerImages } from "./parsers";
import { getConfig } from "./config";
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
}

/** Register all extension commands. */
export function registerCommands(
    context: vscode.ExtensionContext,
    deps: CommandDeps,
): void {
    const commands: Array<[string, () => Promise<void>]> = [
        ["codetrust.scanFile", () => scanCurrentFile(deps)],
        ["codetrust.verifyImports", () => verifyImportsCommand(deps)],
        ["codetrust.verifyDockerfile", () => verifyDockerfileCommand(deps)],
        ["codetrust.deepScan", () => deepScanCommand(deps)],
        ["codetrust.clearDiagnostics", () => clearDiagnosticsCommand(deps)],
    ];

    for (const [id, handler] of commands) {
        context.subscriptions.push(
            vscode.commands.registerCommand(id, handler),
        );
    }
}

/** Scan the currently active file. */
async function scanCurrentFile(deps: CommandDeps): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
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
    deps.statusBar.setScanning();
    deps.outputChannel.appendLine(
        `[${timestamp()}] Static scan: ${document.fileName}`,
    );

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

        deps.statusBar.setVerdict(response.verdict, response.total_findings);
        logScanResult(deps.outputChannel, "Static", response.verdict, response.findings);
    } catch (err) {
        // Fallback to embedded offline scanner when API is unavailable
        deps.outputChannel.appendLine(
            `  API unavailable — using embedded scanner`,
        );
        const response = scanCodeOffline(document.getText(), document.fileName);
        deps.diagnostics.setFindingsDiagnostics(
            document.uri,
            response.findings,
            config.severityThreshold,
        );
        deps.statusBar.setVerdict(
            `${response.verdict} (offline)`,
            response.total_findings,
        );
        logScanResult(deps.outputChannel, "Static (offline)", response.verdict, response.findings);
    }
}

/** Run deep scan on a document. */
async function runDeepScan(
    deps: CommandDeps,
    document: vscode.TextDocument,
    language: Language,
): Promise<void> {
    const config = getConfig();
    deps.statusBar.setScanning();
    deps.outputChannel.appendLine(
        `[${timestamp()}] Deep scan: ${document.fileName}`,
    );

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

        deps.statusBar.setVerdict(response.verdict, response.total_findings);
        deps.outputChannel.appendLine(
            `  Verdict: ${response.verdict} | ` +
            `${response.total_findings} findings | ` +
            `${response.latency_ms}ms`,
        );
    } catch (err) {
        handleScanError(deps, err);
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
    deps.outputChannel.appendLine(
        `[${timestamp()}] Verify imports: ${imports.length} packages in ${document.fileName}`,
    );

    try {
        const response = await deps.client.verifyImports(language, imports);

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
    } catch (err) {
        handleScanError(deps, err);
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
        const response = await deps.client.verifyDockerfile(images);

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
    } catch (err) {
        handleScanError(deps, err);
    }
}

/** Clear all CodeTrust diagnostics. */
async function clearDiagnosticsCommand(deps: CommandDeps): Promise<void> {
    deps.diagnostics.clear();
    deps.statusBar.setIdle();
    deps.outputChannel.appendLine(`[${timestamp()}] Diagnostics cleared.`);
}

/** Handle scan errors uniformly. */
function handleScanError(deps: CommandDeps, err: unknown): void {
    const message = err instanceof ApiError
        ? `API error (${err.statusCode}): ${err.message}`
        : err instanceof Error
            ? err.message
            : "Unknown error";

    deps.statusBar.setError(message);
    deps.outputChannel.appendLine(`  ERROR: ${message}`);
    vscode.window.showErrorMessage(`CodeTrust: ${message}`);
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

    if (!config.scanOnSave) {
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

/** Format current timestamp for logging. */
function timestamp(): string {
    return new Date().toISOString().slice(11, 19);
}
