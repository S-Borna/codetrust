// Copyright (c) Said Borna. All rights reserved.
// Proprietary — see LICENSE for terms.
/**
 * Anonymous telemetry emitter for the CodeTrust VS Code extension.
 *
 * Goals:
 * - Never blocks core functionality
 * - Best-effort only
 * - No code, filenames, paths, repo URLs, users, IPs, or secrets
 */

import * as http from "http";
import * as https from "https";
import * as vscode from "vscode";
import { URL } from "url";
import { randomUUID } from "crypto";

import { getConfig } from "./config";

const INSTALL_ID_STORAGE_KEY = "codetrust-install-id";
const TELEMETRY_TIMEOUT_MS = 3000;

async function getInstallationId(context: vscode.ExtensionContext): Promise<string> {
    const fromSecret = await context.secrets.get(INSTALL_ID_STORAGE_KEY);
    if (fromSecret && fromSecret.trim().length > 0) {
        return fromSecret;
    }

    const fromState = context.globalState.get<string>(INSTALL_ID_STORAGE_KEY);
    if (fromState && fromState.trim().length > 0) {
        await context.secrets.store(INSTALL_ID_STORAGE_KEY, fromState);
        return fromState;
    }

    const id = randomUUID();
    await context.secrets.store(INSTALL_ID_STORAGE_KEY, id);
    await context.globalState.update(INSTALL_ID_STORAGE_KEY, id);
    return id;
}

function postJson(url: string, body: Record<string, unknown>): void {
    try {
        const parsed = new URL(url);
        const isHttps = parsed.protocol === "https:";
        const transport = isHttps ? https : http;
        let port = 80;
        if (isHttps) {
            port = 443;
        }
        if (parsed.port) {
            port = Number(parsed.port);
        }

        const payload = JSON.stringify(body);
        const req = transport.request(
            {
                method: "POST",
                hostname: parsed.hostname,
                port,
                path: parsed.pathname,
                headers: {
                    "Content-Type": "application/json",
                    "Content-Length": Buffer.byteLength(payload).toString(),
                },
                timeout: TELEMETRY_TIMEOUT_MS,
            },
            (res) => {
                res.on("data", () => undefined);
            },
        );
        req.on("error", () => undefined);
        req.on("timeout", () => {
            try {
                req.destroy();
            } catch {
                // ignore
            }
        });
        req.write(payload);
        req.end();
    } catch {
        // ignore
    }
}

export async function sendTelemetry(
    context: vscode.ExtensionContext,
    eventType: string,
    payload: Record<string, unknown>,
): Promise<void> {
    try {
        const cfg = getConfig();
        const baseUrl = cfg.apiUrl.replace(/\/+$/, "");
        const installId = await getInstallationId(context);
        const ext = vscode.extensions.getExtension("SaidBorna.codetrust");
        let version = "unknown";
        if (ext && ext.packageJSON) {
            const pkg = ext.packageJSON as { version?: string };
            if (typeof pkg.version === "string" && pkg.version.length > 0) {
                version = pkg.version;
            }
        }

        postJson(`${baseUrl}/v1/telemetry`, {
            event_type: eventType,
            source: "vscode",
            installation_id: installId,
            version,
            payload,
        });
    } catch {
        // never block extension
    }
}
