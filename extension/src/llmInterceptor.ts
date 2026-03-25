// Copyright (c) Said Borna. All rights reserved.
// Proprietary — see LICENSE for terms.
/**
 * LLM Attribution via VS Code Language Model API.
 *
 * Uses vscode.lm (Language Model API, stable since VS Code 1.90) to enumerate
 * available AI models, and onDidChangeTextDocument to detect AI-generated
 * code insertions. Records provider, model, file, and timestamp — without
 * capturing prompts, responses, or source code.
 *
 * Privacy: Only metadata is recorded. No code content. No prompts. No responses.
 */

import * as vscode from "vscode";
import * as path from "path";
import * as fs from "fs";

// ─────────────────────────────────────────────────────────────────
//  Known AI extensions — used to identify which tool generated code
// ─────────────────────────────────────────────────────────────────

interface AIExtensionDef {
    id: string;
    displayName: string;
    provider: string;
}

const KNOWN_AI_EXTENSIONS: AIExtensionDef[] = [
    { id: "github.copilot", displayName: "GitHub Copilot", provider: "github_copilot" },
    { id: "github.copilot-chat", displayName: "GitHub Copilot Chat", provider: "github_copilot" },
    { id: "anthropic.claude-code", displayName: "Claude Code", provider: "anthropic" },
    { id: "saoudrizwan.claude-dev", displayName: "Cline", provider: "cline" },
    { id: "continue.continue", displayName: "Continue", provider: "continue" },
    { id: "codeium.codeium", displayName: "Codeium", provider: "codeium" },
    { id: "codeium.windsurf", displayName: "Windsurf", provider: "codeium" },
    { id: "sourcegraph.cody-ai", displayName: "Cody", provider: "sourcegraph" },
    { id: "tabnine.tabnine-vscode", displayName: "Tabnine", provider: "tabnine" },
    { id: "amazonwebservices.aws-toolkit-vscode", displayName: "Amazon Q", provider: "amazon_q" },
    { id: "cursor.cursor", displayName: "Cursor", provider: "cursor" },
];

// ─────────────────────────────────────────────────────────────────
//  Types
// ─────────────────────────────────────────────────────────────────

export interface LLMEvent {
    timestamp: string;
    provider: string;
    model: string;
    model_vendor: string;
    model_family: string;
    active_file: string;
    workspace: string;
    source_extension: string;
    event_type: "model_available" | "ai_edit_detected" | "chat_model_invoked";
}

interface CachedModel {
    id: string;
    vendor: string;
    family: string;
    version: string;
    name: string;
}

// ─────────────────────────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────────────────────────

function getWorkspaceRoot(): string {
    const folders = vscode.workspace.workspaceFolders;
    if (folders && folders.length > 0) {
        return folders[0].uri.fsPath;
    }
    return "";
}

function getActiveAIExtensions(): AIExtensionDef[] {
    return KNOWN_AI_EXTENSIONS.filter((ext) => {
        const extension = vscode.extensions.getExtension(ext.id);
        return extension !== undefined && extension.isActive;
    });
}

// ─────────────────────────────────────────────────────────────────
//  Event recording
// ─────────────────────────────────────────────────────────────────

const ATTRIBUTION_FILENAME = "attribution.jsonl";
const CODETRUST_DIR = ".codetrust";
const MAX_EVENTS_PER_MINUTE = 60;

/** Minimum inserted characters to consider as AI-generated (not typing). */
const MIN_AI_INSERT_CHARS = 20;

/** Minimum lines inserted to consider as AI-generated. */
const MIN_AI_INSERT_LINES = 2;

let eventCountThisMinute = 0;
let lastMinuteReset = Date.now();

function shouldRecord(): boolean {
    const now = Date.now();
    const MINUTE_MS = 60_000;
    if (now - lastMinuteReset > MINUTE_MS) {
        eventCountThisMinute = 0;
        lastMinuteReset = now;
    }
    if (eventCountThisMinute >= MAX_EVENTS_PER_MINUTE) {
        return false;
    }
    eventCountThisMinute++;
    return true;
}

function recordEvent(event: LLMEvent, outputChannel: vscode.OutputChannel): void {
    if (!shouldRecord()) {
        return;
    }

    const workspace = event.workspace || getWorkspaceRoot();
    if (!workspace) {
        return;
    }

    const dir = path.join(workspace, CODETRUST_DIR);
    const filepath = path.join(dir, ATTRIBUTION_FILENAME);

    try {
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
        const line = JSON.stringify(event) + "\n";
        fs.appendFileSync(filepath, line, "utf-8");
        outputChannel.appendLine(
            `CodeTrust Attribution: ${event.event_type} | ${event.provider}/${event.model} → ${event.active_file || "(no file)"}`,
        );
    } catch {
        // Silent — don't break user workflow for attribution failure
    }
}

// ─────────────────────────────────────────────────────────────────
//  Model enumeration via vscode.lm API
// ─────────────────────────────────────────────────────────────────

let cachedModels: CachedModel[] = [];

async function enumerateModels(outputChannel: vscode.OutputChannel): Promise<void> {
    try {
        const models = await vscode.lm.selectChatModels();
        cachedModels = models.map((m) => ({
            id: m.id,
            vendor: m.vendor,
            family: m.family,
            version: m.version,
            name: m.name,
        }));

        if (cachedModels.length > 0) {
            outputChannel.appendLine(
                `CodeTrust Attribution: discovered ${cachedModels.length} LLM model(s):`,
            );
            for (const model of cachedModels) {
                outputChannel.appendLine(
                    `  → ${model.vendor}/${model.family} (${model.id})`,
                );

                // Record each model discovery
                recordEvent({
                    timestamp: new Date().toISOString(),
                    provider: model.vendor,
                    model: model.family,
                    model_vendor: model.vendor,
                    model_family: model.family,
                    active_file: "",
                    workspace: getWorkspaceRoot(),
                    source_extension: "vscode.lm",
                    event_type: "model_available",
                }, outputChannel);
            }
        } else {
            outputChannel.appendLine(
                "CodeTrust Attribution: no LLM models registered (no AI extensions active yet).",
            );
        }
    } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        outputChannel.appendLine(
            `CodeTrust Attribution: vscode.lm.selectChatModels() failed — ${msg}`,
        );
    }
}

/**
 * Resolve the most likely model for a given provider.
 *
 * If only one model from that provider is registered, return it.
 * Otherwise return the first match or "unknown".
 */
function resolveModelForProvider(provider: string): CachedModel | null {
    const matching = cachedModels.filter(
        (m) => m.vendor.toLowerCase().includes(provider.toLowerCase())
            || provider.toLowerCase().includes(m.vendor.toLowerCase()),
    );
    if (matching.length >= 1) {
        return matching[0];
    }
    return cachedModels.length === 1 ? cachedModels[0] : null;
}

// ─────────────────────────────────────────────────────────────────
//  AI edit detection via onDidChangeTextDocument
// ─────────────────────────────────────────────────────────────────

/**
 * Determine if a text change looks AI-generated rather than human-typed.
 *
 * Heuristic: multi-line insertions or large single-line pastes that happen
 * while an AI extension is active are likely AI-generated.
 */
function isLikelyAIGenerated(change: vscode.TextDocumentContentChangeEvent): boolean {
    const text = change.text;

    // Deletions or empty changes — not AI
    if (text.length === 0) {
        return false;
    }

    const lineCount = text.split("\n").length;

    // Multi-line insertion (2+ lines with enough content)
    if (lineCount >= MIN_AI_INSERT_LINES && text.length >= MIN_AI_INSERT_CHARS) {
        return true;
    }

    // Large single-line insertion (likely inline completion)
    if (lineCount === 1 && text.length >= MIN_AI_INSERT_CHARS) {
        // Exclude common non-AI patterns: pasting a URL, auto-bracket
        const isAutoClose = text.length <= 2 && /^[\])}>'"` ]$/.test(text);
        return !isAutoClose;
    }

    return false;
}

// ─────────────────────────────────────────────────────────────────
//  Activation / Deactivation
// ─────────────────────────────────────────────────────────────────

let isInterceptorActive = false;
const disposables: vscode.Disposable[] = [];

export function activateInterceptor(
    context: vscode.ExtensionContext,
    outputChannel: vscode.OutputChannel,
): void {
    // Check config
    const config = vscode.workspace.getConfiguration("codetrust");
    const enabled = config.get<boolean>("attribution.enabled", true);

    if (!enabled) {
        outputChannel.appendLine("CodeTrust Attribution: disabled by config.");
        return;
    }

    if (isInterceptorActive) {
        return;
    }

    // 1. Enumerate available models at startup
    void enumerateModels(outputChannel);

    // 2. Re-enumerate when models change (extensions activate/deactivate)
    if (vscode.lm.onDidChangeChatModels) {
        const modelWatcher = vscode.lm.onDidChangeChatModels(() => {
            void enumerateModels(outputChannel);
        });
        disposables.push(modelWatcher);
        context.subscriptions.push(modelWatcher);
    }

    // 3. Detect AI-generated edits
    const editWatcher = vscode.workspace.onDidChangeTextDocument((event) => {
        // Skip non-file documents (output panels, settings, etc.)
        if (event.document.uri.scheme !== "file") {
            return;
        }

        // Only process if AI extensions are active
        const activeAI = getActiveAIExtensions();
        if (activeAI.length === 0) {
            return;
        }

        for (const change of event.contentChanges) {
            if (isLikelyAIGenerated(change)) {
                // Determine source extension — if only one AI ext is active, it's unambiguous
                const sourceExt = activeAI.length === 1
                    ? activeAI[0]
                    : activeAI[0]; // Best guess: first active

                const resolvedModel = resolveModelForProvider(sourceExt.provider);

                const llmEvent: LLMEvent = {
                    timestamp: new Date().toISOString(),
                    provider: sourceExt.provider,
                    model: resolvedModel ? resolvedModel.family : "unknown",
                    model_vendor: resolvedModel ? resolvedModel.vendor : sourceExt.provider,
                    model_family: resolvedModel ? resolvedModel.family : "unknown",
                    active_file: path.relative(
                        getWorkspaceRoot() || "",
                        event.document.uri.fsPath,
                    ),
                    workspace: getWorkspaceRoot(),
                    source_extension: sourceExt.id,
                    event_type: "ai_edit_detected",
                };

                recordEvent(llmEvent, outputChannel);

                // One event per document change is enough
                break;
            }
        }
    });
    disposables.push(editWatcher);
    context.subscriptions.push(editWatcher);

    // 4. Log active AI extensions
    const activeAI = getActiveAIExtensions();
    const activeNames = activeAI.map((e) => e.displayName).join(", ") || "none yet";

    isInterceptorActive = true;
    outputChannel.appendLine(
        `CodeTrust Attribution: active — using vscode.lm API. Active AI extensions: ${activeNames}`,
    );

    // 5. Watch for config changes
    const configWatcher = vscode.workspace.onDidChangeConfiguration((e) => {
        if (e.affectsConfiguration("codetrust.attribution.enabled")) {
            const nowEnabled = vscode.workspace
                .getConfiguration("codetrust")
                .get<boolean>("attribution.enabled", true);
            if (!nowEnabled && isInterceptorActive) {
                deactivateInterceptor(outputChannel);
            }
        }
    });
    disposables.push(configWatcher);
    context.subscriptions.push(configWatcher);
}

export function deactivateInterceptor(outputChannel: vscode.OutputChannel): void {
    if (!isInterceptorActive) {
        return;
    }
    for (const d of disposables) {
        d.dispose();
    }
    disposables.length = 0;
    cachedModels = [];
    isInterceptorActive = false;
    outputChannel.appendLine("CodeTrust Attribution: deactivated.");
}
