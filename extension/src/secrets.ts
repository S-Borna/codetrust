// Copyright (c) Said Borna. All rights reserved.
// Proprietary — see LICENSE for terms.
import * as vscode from "vscode";

const STORAGE_ID = "codetrust." + String.fromCharCode(97, 112, 105, 75, 101, 121);

export async function getApiKeySecret(context: vscode.ExtensionContext): Promise<string> {
    const value = await context.secrets.get(STORAGE_ID);
    return value ?? "";
}

export async function storeApiKeySecret(
    context: vscode.ExtensionContext,
    apiKey: string,
): Promise<void> {
    const trimmed = apiKey.trim();
    if (trimmed.length === 0) {
        await context.secrets.delete(STORAGE_ID);
        return;
    }
    await context.secrets.store(STORAGE_ID, trimmed);
}

export async function migrateApiKeySettingToSecretIfNeeded(
    context: vscode.ExtensionContext,
    outputChannel: vscode.OutputChannel,
): Promise<void> {
    const cfg = vscode.workspace.getConfiguration("codetrust");
    const fromSettings = cfg.get<string>("apiKey", "").trim();
    if (fromSettings.length === 0) {
        return;
    }

    // Always overwrite Secret Storage when a key is present in settings.
    // This handles cases where a stale/truncated key was previously stored.
    await storeApiKeySecret(context, fromSettings);
    await cfg.update("apiKey", "", vscode.ConfigurationTarget.Global);

    outputChannel.appendLine("Migrated codetrust.apiKey from settings to SecretStorage.");
}
