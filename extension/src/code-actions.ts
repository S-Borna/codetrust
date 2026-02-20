// Copyright (c) 2026 Said Borna. All rights reserved.
// Proprietary — see LICENSE for terms.
/**
 * Code action provider for the CodeTrust VS Code extension.
 * Provides quick-fix suggestions from diagnostics.
 */

import * as vscode from "vscode";

/** Code action provider that generates quick-fix actions from CodeTrust diagnostics. */
export class CodeTrustCodeActionProvider implements vscode.CodeActionProvider {
    public static readonly providedCodeActionKinds = [
        vscode.CodeActionKind.QuickFix,
    ];

    /** Provide code actions for CodeTrust diagnostics. */
    provideCodeActions(
        document: vscode.TextDocument,
        range: vscode.Range | vscode.Selection,
        context: vscode.CodeActionContext,
    ): vscode.CodeAction[] {
        const actions: vscode.CodeAction[] = [];

        for (const diagnostic of context.diagnostics) {
            if (diagnostic.source !== "CodeTrust") {
                continue;
            }

            const suggestionActions = this.createActionsForDiagnostic(
                document,
                diagnostic,
            );
            actions.push(...suggestionActions);
        }

        return actions;
    }

    /** Create code actions for a single CodeTrust diagnostic. */
    private createActionsForDiagnostic(
        document: vscode.TextDocument,
        diagnostic: vscode.Diagnostic,
    ): vscode.CodeAction[] {
        const actions: vscode.CodeAction[] = [];
        const ruleId = typeof diagnostic.code === "string" ? diagnostic.code : "";
        const message = diagnostic.message;

        // Extract suggestion from the message (after " → ")
        const suggestionMatch = message.match(/→\s*(.+)$/);
        const suggestion = suggestionMatch?.[1] ?? "";

        // Action: Suppress for this line (add noqa/eslint-disable comment)
        const suppressAction = this.createSuppressAction(
            document,
            diagnostic,
            ruleId,
        );
        if (suppressAction) {
            actions.push(suppressAction);
        }

        // Rule-specific deterministic quick fixes
        actions.push(...this.createRuleSpecificActions(document, diagnostic, ruleId));

        // Action: Apply suggestion if it looks like a replacement
        if (suggestion) {
            const applyAction = this.createApplySuggestionAction(
                document,
                diagnostic,
                suggestion,
                ruleId,
            );
            if (applyAction) {
                actions.push(applyAction);
            }
        }

        // Action: Delete the problematic line (for some anti-patterns)
        if (this.isDeletableRule(ruleId)) {
            const deleteAction = this.createDeleteLineAction(document, diagnostic);
            actions.push(deleteAction);
        }

        return actions;
    }

    private createRuleSpecificActions(
        document: vscode.TextDocument,
        diagnostic: vscode.Diagnostic,
        ruleId: string,
    ): vscode.CodeAction[] {
        if (ruleId !== "print_debug") {
            return [];
        }

        if (document.languageId !== "python") {
            return [];
        }

        const line = diagnostic.range.start.line;
        const lineText = document.lineAt(line).text;
        const match = lineText.match(/\bprint\s*\((.*)\)\s*$/);
        if (!match) {
            return [];
        }

        const expr = match[1] ?? "";
        const action = new vscode.CodeAction(
            "Convert print() to logging.info()",
            vscode.CodeActionKind.QuickFix,
        );

        const edit = new vscode.WorkspaceEdit();

        // Replace the print(...) call with logging.info(...)
        const startIdx = lineText.indexOf("print");
        if (startIdx >= 0) {
            const replaceRange = new vscode.Range(
                line,
                startIdx,
                line,
                lineText.length,
            );
            edit.replace(document.uri, replaceRange, `logging.info(${expr})`);
        }

        // Ensure `import logging` exists near the top
        const hasImport = document.getText().split("\n").some((ln) => ln.trim() === "import logging");
        if (!hasImport) {
            const insertAt = this.findPythonImportInsertLine(document);
            edit.insert(document.uri, new vscode.Position(insertAt, 0), "import logging\n");
        }

        action.edit = edit;
        action.diagnostics = [diagnostic];
        action.isPreferred = true;
        return [action];
    }

    private findPythonImportInsertLine(document: vscode.TextDocument): number {
        // Insert after shebang and module docstring if present.
        const lines = document.getText().split("\n");
        let i = 0;
        if (lines[0]?.startsWith("#!")) {
            i = 1;
        }

        // Skip encoding comment
        if (lines[i]?.includes("coding")) {
            i += 1;
        }

        // Skip module docstring
        const first = (lines[i] ?? "").trim();
        const triple = first.startsWith('"""') || first.startsWith("'''");
        if (triple) {
            const quote = first.startsWith('"""') ? '"""' : "'''";
            // If the opener also closes on same line, just advance one line
            if (first.slice(3).includes(quote)) {
                return Math.min(i + 1, lines.length);
            }
            for (let j = i + 1; j < lines.length; j++) {
                if ((lines[j] ?? "").includes(quote)) {
                    return Math.min(j + 1, lines.length);
                }
            }
        }

        return Math.min(i, lines.length);
    }

    /** Create a suppress action that adds a disable comment. */
    private createSuppressAction(
        document: vscode.TextDocument,
        diagnostic: vscode.Diagnostic,
        ruleId: string,
    ): vscode.CodeAction | null {
        if (!ruleId) {
            return null;
        }

        const lang = document.languageId;
        const comment = this.buildSuppressComment(lang, ruleId);
        if (!comment) {
            return null;
        }

        const action = new vscode.CodeAction(
            `Suppress CodeTrust: ${ruleId}`,
            vscode.CodeActionKind.QuickFix,
        );

        const line = diagnostic.range.start.line;
        const lineText = document.lineAt(line).text;
        const indent = lineText.match(/^\s*/)?.[0] ?? "";

        const edit = new vscode.WorkspaceEdit();
        edit.insert(
            document.uri,
            new vscode.Position(line, 0),
            `${indent}${comment}\n`,
        );
        action.edit = edit;
        action.diagnostics = [diagnostic];
        action.isPreferred = false;

        return action;
    }

    /** Build a language-appropriate suppress comment. */
    private buildSuppressComment(lang: string, ruleId: string): string | null {
        switch (lang) {
            case "python":
                return `# noqa: ${ruleId}  # codetrust-suppress`;
            case "javascript":
            case "typescript":
            case "typescriptreact":
            case "javascriptreact":
                return `// eslint-disable-next-line ${ruleId} -- codetrust-suppress`;
            case "go":
                return `//nolint:${ruleId} // codetrust-suppress`;
            case "rust":
                return `#[allow(${ruleId})] // codetrust-suppress`;
            default:
                return null;
        }
    }

    /** Create an action to apply a suggestion. */
    private createApplySuggestionAction(
        document: vscode.TextDocument,
        diagnostic: vscode.Diagnostic,
        suggestion: string,
        ruleId: string,
    ): vscode.CodeAction | null {
        // Only create apply action for suggestions that look like replacements
        const replaceMatch = suggestion.match(
            /^[Uu]se\s+[`']?(.+?)[`']?\s+instead$/,
        );
        if (!replaceMatch) {
            // Show suggestion as an informational action
            const infoAction = new vscode.CodeAction(
                `💡 ${suggestion}`,
                vscode.CodeActionKind.QuickFix,
            );
            infoAction.diagnostics = [diagnostic];
            infoAction.isPreferred = false;
            infoAction.command = {
                title: "Open CodeTrust Documentation",
                command: "vscode.open",
                arguments: [
                    vscode.Uri.parse(
                        `https://codetrust.ai/rules/${ruleId}`,
                    ),
                ],
            };
            return infoAction;
        }

        const replacement = replaceMatch[1];
        const action = new vscode.CodeAction(
            `Replace with ${replacement}`,
            vscode.CodeActionKind.QuickFix,
        );

        const edit = new vscode.WorkspaceEdit();
        const lineText = document.lineAt(diagnostic.range.start.line).text;

        // Try to find what needs replacing based on the rule
        const oldText = this.findReplacementTarget(lineText, ruleId);
        if (oldText) {
            const startIdx = lineText.indexOf(oldText);
            if (startIdx >= 0) {
                const range = new vscode.Range(
                    diagnostic.range.start.line,
                    startIdx,
                    diagnostic.range.start.line,
                    startIdx + oldText.length,
                );
                edit.replace(document.uri, range, replacement);
                action.edit = edit;
            }
        }

        action.diagnostics = [diagnostic];
        action.isPreferred = true;

        return action;
    }

    /** Find the text to replace based on the rule ID. */
    private findReplacementTarget(lineText: string, ruleId: string): string | null {
        switch (ruleId) {
            case "console_log":
                return lineText.match(/console\.log\([^)]*\)/)?.[0] ?? null;
            case "print_debug":
                return lineText.match(/print\([^)]*\)/)?.[0] ?? null;
            case "eval_exec":
                return lineText.match(/\b(eval|exec)\([^)]*\)/)?.[0] ?? null;
            default:
                return null;
        }
    }

    /** Create an action to delete a problematic line. */
    private createDeleteLineAction(
        document: vscode.TextDocument,
        diagnostic: vscode.Diagnostic,
    ): vscode.CodeAction {
        const action = new vscode.CodeAction(
            "Remove this line",
            vscode.CodeActionKind.QuickFix,
        );

        const edit = new vscode.WorkspaceEdit();
        const line = diagnostic.range.start.line;
        const range = new vscode.Range(line, 0, line + 1, 0);
        edit.delete(document.uri, range);
        action.edit = edit;
        action.diagnostics = [diagnostic];
        action.isPreferred = false;

        return action;
    }

    /** Check if a rule's line can be safely deleted. */
    private isDeletableRule(ruleId: string): boolean {
        const deletable = new Set([
            "console_log",
            "todo_marker",
            "print_debug",
        ]);
        return deletable.has(ruleId);
    }
}
