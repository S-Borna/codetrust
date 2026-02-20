// Copyright (c) 2026 Said Borna. All rights reserved.
// Proprietary — see LICENSE for terms.
import * as assert from "assert";
import * as vscode from "vscode";

import { getApiKeySecret, migrateApiKeySettingToSecretIfNeeded } from "../../secrets";

suite("Extension integration", () => {
    test("scanFile produces diagnostics (offline fallback)", async () => {
        const originalShowInfo = vscode.window.showInformationMessage;

        try {
            (vscode.window as unknown as { showInformationMessage: typeof vscode.window.showInformationMessage })
                .showInformationMessage = async () => "Not now";

            const cfg = vscode.workspace.getConfiguration("codetrust");
            await cfg.update("apiUrl", "http://127.0.0.1:9", vscode.ConfigurationTarget.Global);
            await cfg.update("timeout", 500, vscode.ConfigurationTarget.Global);
            await cfg.update("scanType", "static", vscode.ConfigurationTarget.Global);
            await cfg.update("scanOnSave", true, vscode.ConfigurationTarget.Global);

            const ext = vscode.extensions.getExtension("SaidBorna.codetrust");
            assert.ok(ext, "Expected extension SaidBorna.codetrust to be available");
            await ext.activate();

            const document = await vscode.workspace.openTextDocument({
                language: "python",
                content: "result = " + "e" + "val" + "('2+2')\n",
            });
            await vscode.window.showTextDocument(document);

            await vscode.commands.executeCommand("codetrust.scanFile");

            const diags = vscode.languages.getDiagnostics(document.uri);
            assert.ok(diags.length > 0, "Expected diagnostics to be created");
            assert.ok(
                diags.some((d) => String(d.code) === "eval_exec"),
                "Expected eval_exec finding to be present",
            );
        } finally {
            (vscode.window as unknown as { showInformationMessage: typeof vscode.window.showInformationMessage })
                .showInformationMessage = originalShowInfo;
        }
    });

    test("migrateApiKeySettingToSecretIfNeeded moves setting into SecretStorage", async () => {
        const originalGetConfiguration = vscode.workspace.getConfiguration;

        const state: { apiKey: string } = { apiKey: "k1" };
        const secretState: { value: string | null } = { value: null };

        try {
            (vscode.workspace as unknown as { getConfiguration: typeof vscode.workspace.getConfiguration })
                .getConfiguration = () => {
                    return {
                        get: (key: string, defaultValue: string): string => {
                            if (key === "apiKey") {
                                return state.apiKey;
                            }
                            return defaultValue;
                        },
                        update: async (key: string, value: string): Promise<void> => {
                            if (key === "apiKey") {
                                state.apiKey = value;
                            }
                        },
                    } as unknown as vscode.WorkspaceConfiguration;
                };

            const fakeContext = {
                secrets: {
                    get: async (): Promise<string | undefined> => secretState.value ?? undefined,
                    store: async (_k: string, v: string): Promise<void> => {
                        secretState.value = v;
                    },
                    delete: async (): Promise<void> => {
                        secretState.value = null;
                    },
                },
            } as unknown as vscode.ExtensionContext;

            const outputChannel = {
                appendLine: (): void => { },
            } as unknown as vscode.OutputChannel;

            await migrateApiKeySettingToSecretIfNeeded(fakeContext, outputChannel);
            const stored = await getApiKeySecret(fakeContext);

            assert.strictEqual(state.apiKey, "", "Expected setting apiKey to be cleared");
            assert.strictEqual(stored, "k1", "Expected secret to be stored");
        } finally {
            (vscode.workspace as unknown as { getConfiguration: typeof vscode.workspace.getConfiguration })
                .getConfiguration = originalGetConfiguration;
        }
    });
});
