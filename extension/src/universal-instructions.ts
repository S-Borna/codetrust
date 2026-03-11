// Copyright (c) Said Borna. All rights reserved.
// Proprietary — see LICENSE for terms.
/**
 * Universal governance rule injection across all AI coding platforms.
 *
 * Writes CodeTrust governance rules to the global configuration files for
 * every major AI IDE — Claude Code, Cursor, Windsurf, and GitHub Copilot.
 * Activated once on extension startup; idempotent on subsequent activations.
 *
 * Target files (all in user home directory — global scope, not per-workspace):
 *   ~/.claude/CLAUDE.md           — Claude Code
 *   ~/.cursor/rules/codetrust.mdc — Cursor global rules
 *   ~/.codeium/windsurf/memories/global_rules.md — Windsurf global memory
 *
 * GitHub Copilot injection is handled separately via VS Code settings API
 * in extension.ts using ConfigurationTarget.Global.
 */

import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as vscode from "vscode";

/** Unique marker used to detect existing injections. Must not contain eval/exec. */
const MARKER = "[codetrust-governance-v1]";

/** Rules content — describes the outcome and prohibited behaviours, not the mechanism. */
const RULES_BLOCK = `
## CodeTrust Governance — Mandatory Rules ${MARKER}

> Enforced by CodeTrust v2.5.2+. Active in every session, every workspace.
> All actions are logged to \`.codetrust/audit.jsonl\` (append-only).

### Proxy Validation — Two-Step Workflow

Before calling any native tool, call the corresponding CodeTrust proxy first:

| Native Tool              | Call This First                                  |
|--------------------------|--------------------------------------------------|
| run_in_terminal          | mcp_codetrust-gat_codetrust_validate_command     |
| run_in_terminal          | mcp_codetrust-gat_codetrust_run_in_terminal      |

Response handling:
- \`status: APPROVED\` → proceed with native tool using EXACT same parameters
- \`status: BLOCKED\`  → STOP. Do NOT proceed. Use the suggestion instead.
- \`status: WARN\`     → acknowledge, then proceed.

For package installs: call \`mcp_codetrust-gat_codetrust_validate_package\` — BLOCKED = do not install.
For file deletions:   call \`mcp_codetrust-gat_codetrust_validate_file_delete\` — BLOCKED = do not delete.

### Absolute Prohibitions

- NEVER run \`git push\` — user pushes manually, always
- NEVER use heredoc (\`<< EOF\`) — use the create_file tool instead
- NEVER write hardcoded secrets, API keys, or passwords — use environment variables
- NEVER use wildcard imports (import all-symbol forms) — import explicitly
- NEVER use \`Any\` type annotation — use explicit types always
- NEVER skip CodeTrust validation to save time — zero exceptions
- NEVER use bare \`except:\` — always catch specific exception types
- NEVER use \`print()\` in production code — use structured logging
- NEVER use magic numbers inline — extract to named constants

### Code Quality Requirements

- Full type annotations on all function parameters and return types
- Docstring on every public function and class
- Max ~40 lines per function — split by responsibility if longer
- Every external call wrapped in try/except with specific exception types
- No TODO/HACK/FIXME in committed code — resolve or open an issue
`;

/** Describes one platform target to inject rules into. */
interface PlatformTarget {
    /** Human-readable name shown in output channel. */
    name: string;
    /** Absolute path to the global config file. */
    filePath: string;
    /**
     * Build the content to write. Receives existing file content (or empty string)
     * and returns the new full file content.
     */
    buildContent: (existing: string) => string;
}

/** Returns true if the file already contains our marker. */
function alreadyInjected(content: string): boolean {
    return content.includes(MARKER);
}

/** Append rules block to the end of an existing file, with a separator. */
function appendToFile(existing: string, separator: string = "\n---\n"): string {
    const trimmed = existing.trimEnd();
    if (trimmed.length > 0) {
        return `${trimmed}${separator}${RULES_BLOCK.trimStart()}\n`;
    }
    return `${RULES_BLOCK.trimStart()}\n`;
}

/** Build the list of platform targets for the current user's home directory. */
function buildTargets(): PlatformTarget[] {
    const home = os.homedir();

    return [
        {
            name: "Claude Code (~/.claude/CLAUDE.md)",
            filePath: path.join(home, ".claude", "CLAUDE.md"),
            buildContent: (existing) => appendToFile(existing),
        },
        {
            name: "Cursor (~/.cursor/rules/codetrust.mdc)",
            filePath: path.join(home, ".cursor", "rules", "codetrust.mdc"),
            buildContent: (_existing) =>
                `---\ndescription: CodeTrust governance rules — mandatory for all sessions\nalwaysApply: true\n---\n${RULES_BLOCK.trimStart()}\n`,
        },
        {
            name: "Windsurf (~/.codeium/windsurf/memories/global_rules.md)",
            filePath: path.join(home, ".codeium", "windsurf", "memories", "global_rules.md"),
            buildContent: (existing) => appendToFile(existing),
        },
    ];
}

/**
 * Inject CodeTrust governance rules into every supported AI IDE's global config.
 *
 * Idempotent: skips files that already contain the marker.
 * Best-effort: a failure for one platform does not stop the others.
 * Shows a VS Code information notification listing the IDEs that were updated
 * on first injection, so users have visibility during onboarding.
 *
 * @returns Names of platforms where rules were freshly injected this run.
 */
export async function injectUniversalInstructions(
    outputChannel: vscode.OutputChannel,
): Promise<string[]> {
    const targets = buildTargets();
    const injectedNames: string[] = [];

    for (const target of targets) {
        try {
            const dir = path.dirname(target.filePath);

            // Skip if the parent directory doesn't exist — IDE is not installed
            if (!fs.existsSync(dir)) {
                outputChannel.appendLine(
                    `CodeTrust: Skipping ${target.name} — directory not found (IDE not installed).`,
                );
                continue;
            }

            const existing = fs.existsSync(target.filePath)
                ? fs.readFileSync(target.filePath, "utf8")
                : "";

            if (alreadyInjected(existing)) {
                outputChannel.appendLine(
                    `CodeTrust: ${target.name} — already injected, skipping.`,
                );
                continue;
            }

            const newContent = target.buildContent(existing);
            fs.writeFileSync(target.filePath, newContent, "utf8");
            outputChannel.appendLine(
                `CodeTrust: Governance rules injected → ${target.name}`,
            );
            injectedNames.push(target.name);
        } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            outputChannel.appendLine(
                `CodeTrust: Failed to inject ${target.name}: ${msg}`,
            );
        }
    }

    if (injectedNames.length > 0) {
        const list = injectedNames
            .map((n) => n.split(" ")[0]) // e.g. "Claude Code", "Cursor", "Windsurf"
            .join(", ");
        void vscode.window.showInformationMessage(
            `CodeTrust: Governance rules injected into ${list}. ` +
            `Every new AI session starts rule-aware — no further setup required.`,
        );
    }

    return injectedNames;
}

/**
 * Remove CodeTrust governance rules from all global AI IDE config files.
 *
 * Called on extension deactivation for a clean uninstall path.
 * For Claude Code and Windsurf, removes only the injected block.
 * For Cursor, removes the entire codetrust.mdc file (it is CodeTrust-owned).
 */
export function removeUniversalInstructions(outputChannel: vscode.OutputChannel): void {
    const targets = buildTargets();

    for (const target of targets) {
        try {
            if (!fs.existsSync(target.filePath)) {
                continue;
            }

            const existing = fs.readFileSync(target.filePath, "utf8");
            if (!alreadyInjected(existing)) {
                continue;
            }

            // Cursor file is fully CodeTrust-owned — delete entirely
            if (target.filePath.includes("codetrust.mdc")) {
                fs.unlinkSync(target.filePath);
                outputChannel.appendLine(`CodeTrust: Removed ${target.name}`);
                continue;
            }

            // For shared files, strip only the injected block
            const separatorPattern = /\n---\n## CodeTrust Governance[\s\S]*?\[codetrust-governance-v1\][\s\S]*$/;
            const cleaned = existing.replace(separatorPattern, "\n").trimEnd();
            fs.writeFileSync(target.filePath, cleaned + "\n", "utf8");
            outputChannel.appendLine(`CodeTrust: Rules removed from ${target.name}`);
        } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            outputChannel.appendLine(
                `CodeTrust: Failed to remove from ${target.name}: ${msg}`,
            );
        }
    }
}

/** Action label shown in re-injection warning notifications. */
const ACTION_REINJECT = "Re-inject Now";

/**
 * Returns display name from a PlatformTarget name string.
 * e.g. "Claude Code (~/.claude/CLAUDE.md)" → "Claude Code"
 */
function displayName(target: PlatformTarget): string {
    return target.name.split(" (")[0];
}

/**
 * Watch injected governance files and installed IDE directories for disruptions.
 *
 * Two protection layers:
 *
 * 1. File watchers — if an IDE update overwrites a file and removes the
 *    CodeTrust marker, a warning notification appears immediately with a
 *    "Re-inject Now" action that restores the rules.
 *
 * 2. Window-focus check — each time VS Code regains focus, detects IDEs
 *    whose config directory now exists but whose rules file is absent or
 *    no longer contains the marker (e.g. IDE installed after CodeTrust).
 *    Offers a "Inject Now" action.
 *
 * Returns VS Code disposables that should be pushed to context.subscriptions.
 */
export function watchForGovernanceDisruption(
    outputChannel: vscode.OutputChannel,
): vscode.Disposable[] {
    const disposables: vscode.Disposable[] = [];
    const targets = buildTargets();

    // ── Layer 1: watch existing injected files for overwrites ──────────────────
    for (const target of targets) {
        if (!fs.existsSync(target.filePath)) {
            continue; // File doesn't exist yet — covered by Layer 2
        }

        const dir = vscode.Uri.file(path.dirname(target.filePath));
        const base = path.basename(target.filePath);
        const pattern = new vscode.RelativePattern(dir, base);
        const watcher = vscode.workspace.createFileSystemWatcher(pattern);

        const handleChange = (): void => {
            try {
                if (!fs.existsSync(target.filePath)) {
                    return; // Deletion handled below
                }
                const content = fs.readFileSync(target.filePath, "utf8");
                if (alreadyInjected(content)) {
                    return; // Still intact
                }
                outputChannel.appendLine(
                    `CodeTrust: Governance rules overwritten in ${target.name} — showing recovery prompt.`,
                );
                void vscode.window
                    .showWarningMessage(
                        `CodeTrust: Governance rules were removed from ${displayName(target)} ` +
                        `(possibly overwritten by an IDE update). Re-inject to restore enforcement?`,
                        ACTION_REINJECT,
                        "Dismiss",
                    )
                    .then((action) => {
                        if (action === ACTION_REINJECT) {
                            void injectUniversalInstructions(outputChannel);
                        }
                    });
            } catch (err: unknown) {
                const msg = err instanceof Error ? err.message : String(err);
                outputChannel.appendLine(`CodeTrust: Watch error for ${target.name}: ${msg}`);
            }
        };

        const handleDelete = (): void => {
            outputChannel.appendLine(
                `CodeTrust: Config file deleted for ${target.name} — showing recovery prompt.`,
            );
            void vscode.window
                .showWarningMessage(
                    `CodeTrust: The governance rules file for ${displayName(target)} was deleted. ` +
                    `Re-inject to restore enforcement?`,
                    ACTION_REINJECT,
                    "Dismiss",
                )
                .then((action) => {
                    if (action === ACTION_REINJECT) {
                        void injectUniversalInstructions(outputChannel);
                    }
                });
        };

        disposables.push(
            watcher,
            watcher.onDidChange(handleChange),
            watcher.onDidDelete(handleDelete),
        );
    }

    // ── Layer 2: detect newly installed IDEs on window focus ───────────────────
    const focusDisposable = vscode.window.onDidChangeWindowState((state) => {
        if (!state.focused) {
            return;
        }

        const missing = targets.filter((t) => {
            const dir = path.dirname(t.filePath);
            if (!fs.existsSync(dir)) {
                return false; // IDE not installed
            }
            if (!fs.existsSync(t.filePath)) {
                return true; // IDE installed, file missing entirely
            }
            try {
                return !alreadyInjected(fs.readFileSync(t.filePath, "utf8"));
            } catch {
                return false;
            }
        });

        if (missing.length === 0) {
            return;
        }

        const names = missing.map(displayName).join(", ");
        outputChannel.appendLine(
            `CodeTrust: Detected ${names} without governance rules — offering injection.`,
        );
        void vscode.window
            .showWarningMessage(
                `CodeTrust: ${names} detected without governance rules ` +
                `(installed after CodeTrust). Inject now to activate enforcement.`,
                "Inject Now",
                "Dismiss",
            )
            .then((action) => {
                if (action === "Inject Now") {
                    void injectUniversalInstructions(outputChannel);
                }
            });
    });

    disposables.push(focusDisposable);
    return disposables;
}
