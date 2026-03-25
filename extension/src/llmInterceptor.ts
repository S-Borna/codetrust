// Copyright (c) Said Borna. All rights reserved.
// Proprietary — see LICENSE for terms.
/**
 * LLM API Call Interceptor — AI Observability Foundation.
 *
 * Monitors VS Code's outgoing HTTPS requests to known LLM API endpoints.
 * Records which model is being used, when, and on which file — without
 * capturing prompts, responses, or source code.
 *
 * Privacy: Only metadata is recorded. No code content. No prompts. No responses.
 */

import * as vscode from "vscode";
import * as https from "https";
import * as http from "http";
import * as path from "path";
import * as fs from "fs";

// ─────────────────────────────────────────────────────────────────
//  Known LLM API endpoints
// ─────────────────────────────────────────────────────────────────

const LLM_ENDPOINTS: Record<string, string> = {
    "api.openai.com": "openai",
    "api.anthropic.com": "anthropic",
    "generativelanguage.googleapis.com": "google",
    "api.fireworks.ai": "fireworks",
    "openrouter.ai": "openrouter",
    "api.together.xyz": "together",
    "api.mistral.ai": "mistral",
    "api.cohere.com": "cohere",
    "api.groq.com": "groq",
    "api.deepseek.com": "deepseek",
    "api.perplexity.ai": "perplexity",
};

/** Partial hostname matches (for services with variable subdomains). */
const LLM_PARTIAL_ENDPOINTS: Record<string, string> = {
    "bedrock-runtime": "aws_bedrock",
    "aiplatform.googleapis.com": "google_vertex",
};

// ─────────────────────────────────────────────────────────────────
//  Types
// ─────────────────────────────────────────────────────────────────

export interface LLMEvent {
    timestamp: string;
    provider: string;
    model: string;
    active_file: string;
    workspace: string;
    source_extension: string;
    request_url: string;
}

// ─────────────────────────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────────────────────────

function getHostname(options: string | URL | https.RequestOptions): string {
    if (typeof options === "string") {
        try {
            return new URL(options).hostname;
        } catch {
            return "";
        }
    }
    if (options instanceof URL) {
        return options.hostname;
    }
    return (options.hostname || options.host || "").replace(/:\d+$/, "");
}

function getRequestUrl(options: string | URL | https.RequestOptions): string {
    if (typeof options === "string") {
        return options;
    }
    if (options instanceof URL) {
        return options.toString();
    }
    const proto = "https";
    const host = options.hostname || options.host || "unknown";
    const urlPath = options.path || "/";
    return `${proto}://${host}${urlPath}`;
}

function matchProvider(hostname: string): string | null {
    // Exact match first
    const exact = LLM_ENDPOINTS[hostname];
    if (exact) {
        return exact;
    }
    // Partial match
    for (const [partial, provider] of Object.entries(LLM_PARTIAL_ENDPOINTS)) {
        if (hostname.includes(partial)) {
            return provider;
        }
    }
    return null;
}

function extractModelFromBody(body: string, provider: string, url: string): string {
    try {
        const parsed = JSON.parse(body);
        // Most providers use body.model
        if (parsed.model && typeof parsed.model === "string") {
            return parsed.model;
        }
        // Google Vertex: model in URL path
        if (provider === "google" || provider === "google_vertex") {
            const modelMatch = url.match(/models\/([^/:]+)/);
            if (modelMatch) {
                return modelMatch[1];
            }
        }
        // AWS Bedrock: modelId in body or URL
        if (provider === "aws_bedrock") {
            if (parsed.modelId) {
                return parsed.modelId;
            }
            const modelMatch = url.match(/model\/([^/]+)/);
            if (modelMatch) {
                return decodeURIComponent(modelMatch[1]);
            }
        }
    } catch {
        // Non-JSON body — skip
    }
    return "unknown";
}

function getActiveFilePath(): string {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        return "";
    }
    const workspaceFolder = vscode.workspace.getWorkspaceFolder(editor.document.uri);
    if (workspaceFolder) {
        return path.relative(workspaceFolder.uri.fsPath, editor.document.uri.fsPath);
    }
    return editor.document.uri.fsPath;
}

function getWorkspaceRoot(): string {
    const folders = vscode.workspace.workspaceFolders;
    if (folders && folders.length > 0) {
        return folders[0].uri.fsPath;
    }
    return "";
}

function getCallingExtension(): string {
    // Attempt to derive from Error stack trace
    try {
        const stack = new Error().stack || "";
        const lines = stack.split("\n");
        for (const line of lines) {
            // VS Code extension paths contain the extension ID
            const extMatch = line.match(/extensions\/([^/]+)\//);
            if (extMatch) {
                const extId = extMatch[1];
                // Skip ourselves
                if (!extId.includes("codetrust")) {
                    return extId;
                }
            }
        }
    } catch {
        // Stack trace unavailable
    }
    return "unknown";
}

// ─────────────────────────────────────────────────────────────────
//  Event recording
// ─────────────────────────────────────────────────────────────────

const ATTRIBUTION_FILENAME = "attribution.jsonl";
const CODETRUST_DIR = ".codetrust";
const MAX_EVENTS_PER_MINUTE = 60;

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
            `CodeTrust Attribution: ${event.provider}/${event.model} → ${event.active_file || "(no file)"}`,
        );
    } catch {
        // Silent — don't break user workflow for telemetry failure
    }
}

// ─────────────────────────────────────────────────────────────────
//  HTTPS interception
// ─────────────────────────────────────────────────────────────────

let isInterceptorActive = false;
let originalHttpsRequest: typeof https.request | null = null;
let originalHttpsGet: typeof https.get | null = null;

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

    // Respect VS Code global telemetry opt-out
    const isTelemetryOff = vscode.env.isTelemetryEnabled === false;
    if (isTelemetryOff) {
        outputChannel.appendLine("CodeTrust Attribution: disabled (VS Code telemetry off).");
        return;
    }

    if (isInterceptorActive) {
        return;
    }

    originalHttpsRequest = https.request;
    originalHttpsGet = https.get;

    const patchedRequest = function (
        this: unknown,
        ...args: Parameters<typeof https.request>
    ): http.ClientRequest {
        const options = args[0];
        const hostname = getHostname(options);
        const provider = matchProvider(hostname);

        if (provider && originalHttpsRequest) {
            const url = getRequestUrl(options);
            const callback = typeof args[1] === "function" ? args[1] : args[2];
            const req = originalHttpsRequest.call(https, ...args);

            // Intercept write to extract model from request body
            const originalWrite = req.write.bind(req);
            let bodyChunks: Buffer[] = [];

            req.write = function (
                chunk: string | Buffer | Uint8Array,
                ...writeArgs: unknown[]
            ): boolean {
                if (chunk) {
                    const buf = typeof chunk === "string"
                        ? Buffer.from(chunk, "utf-8")
                        : Buffer.from(chunk);
                    bodyChunks.push(buf);
                }
                return (originalWrite as Function)(chunk, ...writeArgs);
            };

            // Intercept end to capture full body
            const originalEnd = req.end.bind(req);
            req.end = function (...endArgs: unknown[]): http.ClientRequest {
                // First arg to end() can also be data
                if (endArgs[0] && typeof endArgs[0] !== "function") {
                    const chunk = endArgs[0];
                    const buf = typeof chunk === "string"
                        ? Buffer.from(chunk, "utf-8")
                        : Buffer.from(chunk as Uint8Array);
                    bodyChunks.push(buf);
                }

                const fullBody = Buffer.concat(bodyChunks).toString("utf-8");
                const model = extractModelFromBody(fullBody, provider, url);

                const event: LLMEvent = {
                    timestamp: new Date().toISOString(),
                    provider,
                    model,
                    active_file: getActiveFilePath(),
                    workspace: getWorkspaceRoot(),
                    source_extension: getCallingExtension(),
                    request_url: `${hostname}${url.replace(/^https?:\/\/[^/]+/, "").split("?")[0]}`,
                };

                recordEvent(event, outputChannel);
                bodyChunks = [];

                return (originalEnd as Function)(...endArgs);
            };

            return req;
        }

        return originalHttpsRequest!.call(https, ...args);
    };

    // Patch https.request
    (https as { request: typeof https.request }).request = patchedRequest as typeof https.request;

    // Patch https.get (calls request internally, but patch for safety)
    (https as { get: typeof https.get }).get = function (
        this: unknown,
        ...args: Parameters<typeof https.get>
    ): http.ClientRequest {
        const req = patchedRequest.call(this, ...args as Parameters<typeof https.request>);
        req.end();
        return req;
    } as typeof https.get;

    isInterceptorActive = true;
    outputChannel.appendLine(
        `CodeTrust Attribution: active — monitoring ${Object.keys(LLM_ENDPOINTS).length + Object.keys(LLM_PARTIAL_ENDPOINTS).length} LLM endpoints.`,
    );

    // Watch for config changes
    context.subscriptions.push(
        vscode.workspace.onDidChangeConfiguration((e) => {
            if (e.affectsConfiguration("codetrust.attribution.enabled")) {
                const nowEnabled = vscode.workspace
                    .getConfiguration("codetrust")
                    .get<boolean>("attribution.enabled", true);
                if (!nowEnabled && isInterceptorActive) {
                    deactivateInterceptor(outputChannel);
                }
            }
        }),
    );
}

export function deactivateInterceptor(outputChannel: vscode.OutputChannel): void {
    if (!isInterceptorActive) {
        return;
    }
    if (originalHttpsRequest) {
        (https as { request: typeof https.request }).request = originalHttpsRequest;
    }
    if (originalHttpsGet) {
        (https as { get: typeof https.get }).get = originalHttpsGet;
    }
    isInterceptorActive = false;
    originalHttpsRequest = null;
    originalHttpsGet = null;
    outputChannel.appendLine("CodeTrust Attribution: deactivated.");
}
