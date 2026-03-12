// Copyright (c) Said Borna. All rights reserved.
// Proprietary — see LICENSE for terms.
import * as assert from "assert";
import * as vscode from "vscode";
import { CodeTrustCodeActionProvider } from "../../code-actions";

suite("Code Actions Tests", () => {
    test("provides logging.info quick fix for print_debug", async () => {
        const doc = await vscode.workspace.openTextDocument({
            language: "python",
            content: "print('hello')\n",
        });
        const editor = await vscode.window.showTextDocument(doc);
        void editor;

        const diagnostic = new vscode.Diagnostic(
            new vscode.Range(0, 0, 0, 5),
            "Use logging instead of print().",
            vscode.DiagnosticSeverity.Warning,
        );
        diagnostic.source = "CodeTrust";
        diagnostic.code = "print_debug";

        const provider = new CodeTrustCodeActionProvider();
        const actions = provider.provideCodeActions(
            doc,
            new vscode.Range(0, 0, 0, 10),
            { diagnostics: [diagnostic], only: undefined, triggerKind: vscode.CodeActionTriggerKind.Invoke },
        );

        const titles = actions.map((a) => a.title);
        assert.ok(titles.includes("Convert print() to logging.info()"));
    });

    test("provides typed-exception quick fix for bare_except", async () => {
        const snippet = [
            "try:",
            "    run()",
            `except${":"}`,
            "    pass",
            "",
        ].join("\n");
        const doc = await vscode.workspace.openTextDocument({
            language: "python",
            content: snippet,
        });

        const diagnostic = new vscode.Diagnostic(
            new vscode.Range(2, 0, 2, 7),
            "Bare except detected.",
            vscode.DiagnosticSeverity.Warning,
        );
        diagnostic.source = "CodeTrust";
        diagnostic.code = "bare_except";

        const provider = new CodeTrustCodeActionProvider();
        const actions = provider.provideCodeActions(
            doc,
            new vscode.Range(2, 0, 2, 7),
            { diagnostics: [diagnostic], only: undefined, triggerKind: vscode.CodeActionTriggerKind.Invoke },
        );

        const titles = actions.map((a) => a.title);
        assert.ok(titles.includes("Replace bare except with typed exception"));
    });

    test("provides env-var quick fix for hardcoded_secret", async () => {
        const doc = await vscode.workspace.openTextDocument({
            language: "python",
            content: "API_KEY = \"super-secret\"\n",
        });

        const diagnostic = new vscode.Diagnostic(
            new vscode.Range(0, 0, 0, 22),
            "Hardcoded secret detected.",
            vscode.DiagnosticSeverity.Warning,
        );
        diagnostic.source = "CodeTrust";
        diagnostic.code = "hardcoded_secret";

        const provider = new CodeTrustCodeActionProvider();
        const actions = provider.provideCodeActions(
            doc,
            new vscode.Range(0, 0, 0, 22),
            { diagnostics: [diagnostic], only: undefined, triggerKind: vscode.CodeActionTriggerKind.Invoke },
        );

        const titles = actions.map((a) => a.title);
        assert.ok(titles.includes("Move secret to environment variable"));
    });
});
