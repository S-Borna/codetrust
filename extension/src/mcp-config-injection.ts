// Copyright (c) Said Borna. All rights reserved.
// Proprietary — see LICENSE for terms.
/**
 * MCP server configuration injection for all supported AI IDEs.
 *
 * Automatically registers both CodeTrust MCP servers (Guardian + Gateway)
 * in the IDE's mcp.json or equivalent configuration file.
 *
 * Without this, agents see governance *instructions* (from CLAUDE.md etc.)
 * telling them to call proxy tools, but the MCP servers providing those
 * tools are not registered — so the tools don't exist at runtime.
 *
 * Supported targets:
 *   ~/Library/Application Support/Code/User/mcp.json      — VS Code Global (uses "servers" key)
 *   .vscode/mcp.json (per workspace)                       — VS Code Workspace (uses "servers" key)
 *   ~/.claude/mcp.json                                     — Claude Code (uses "mcpServers" key)
 *   ~/Library/Application Support/Claude/claude_desktop_config.json — Claude Desktop (macOS, "mcpServers")
 *   ~/.cursor/mcp.json                                     — Cursor (uses "mcpServers" key)
 *
 * Idempotent: only adds entries that are missing. Never overwrites existing
 * server configs (user may have custom args/env).
 */

import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as vscode from "vscode";
import { execSync } from "child_process";

/** Marker comment embedded in injected entries (stored as a field). */
const MCP_INJECTION_MARKER = "codetrust-auto-injected";

/** Server name for the scan/guardian MCP server. */
const GUARDIAN_SERVER_NAME = "codetrust";

/** Server name for the governance gateway MCP server. */
const GATEWAY_SERVER_NAME = "codetrust-gateway";

/** Console script command for the Guardian MCP server (installed via pip). */
const GUARDIAN_COMMAND = "codetrust-mcp";

/** Console script command for the Gateway MCP server (installed via pip). */
const GATEWAY_COMMAND = "codetrust-gateway-mcp";

/**
 * Shape of an MCP server entry in mcp.json.
 * Matches the standard Claude/Cursor MCP config schema.
 */
interface McpServerEntry {
    command: string;
    args?: string[];
    cwd?: string;
    env?: Record<string, string>;
    /** Internal marker — not consumed by IDEs. */
    _injectedBy?: string;
}

/**
 * The JSON key used for server entries varies by IDE:
 *   - VS Code: "servers"
 *   - Claude Code, Claude Desktop, Cursor: "mcpServers"
 */
type ServersKey = "servers" | "mcpServers";

/** Shape of a full mcp.json file. Supports both VS Code and Claude/Cursor formats. */
interface McpConfigFile {
    servers?: Record<string, McpServerEntry>;
    mcpServers?: Record<string, McpServerEntry>;
}

/** Describes one IDE target for MCP config injection. */
interface McpTarget {
    /** Human-readable name shown in output channel. */
    name: string;
    /** Absolute path to the MCP config file. */
    filePath: string;
    /** Whether the target directory must already exist before injection. */
    requiresExistingDirectory?: boolean;
    /** JSON key for server entries — "servers" for VS Code, "mcpServers" for Claude/Cursor. */
    serversKey: ServersKey;
}

/** Minimum interval (ms) between file-change checks per target. */
const DEBOUNCE_MS = 2000;

/** Minimum interval (ms) between focus-triggered re-scans. */
const FOCUS_DEBOUNCE_MS = 10000;

/** PyPI package name for codetrust (used with uvx). */
const PYPI_PACKAGE_NAME = "codetrust";

/** Python module paths for direct invocation fallback. */
const GUARDIAN_MODULE = "src.server";
const GATEWAY_MODULE = "src.gateway.server";

/**
 * Describes a resolved MCP server command strategy.
 *
 * Priority order:
 *   1. Console script on PATH (pip install)
 *   2. uvx zero-install (uv must be available)
 *   3. python3 -m module (source checkout must be detectable)
 */
interface ResolvedCommand {
    command: string;
    args?: string[];
    cwd?: string;
}

function isCodeTrustRoot(rootDir: string): boolean {
    const pyprojectPath = path.join(rootDir, "pyproject.toml");
    if (!fs.existsSync(pyprojectPath)) {
        return false;
    }
    try {
        const content = fs.readFileSync(pyprojectPath, "utf8");
        return content.includes('name = "codetrust"');
    } catch {
        return false;
    }
}

function detectSourceRootFromKnownConfigs(): string | undefined {
    for (const target of buildMcpTargets()) {
        const config = readMcpConfig(target.filePath);
        if (!config) {
            continue;
        }
        // Check both keys — the entry may be in either format depending on IDE
        const allServers = { ...config.servers, ...config.mcpServers };
        if (Object.keys(allServers).length === 0) {
            continue;
        }
        for (const serverName of [GUARDIAN_SERVER_NAME, GATEWAY_SERVER_NAME]) {
            const entry = allServers[serverName];
            if (!entry) {
                continue;
            }
            if (entry.cwd && isCodeTrustRoot(entry.cwd)) {
                return entry.cwd;
            }
            const normalizedCmd = entry.command.replace(/\\/g, "/");
            const unixSuffix = "/.venv/bin/python";
            if (normalizedCmd.endsWith(unixSuffix)) {
                const root = normalizedCmd.slice(0, -unixSuffix.length);
                if (isCodeTrustRoot(root)) {
                    return root;
                }
            }
        }
    }
    return undefined;
}

/** Synchronously check if a command exists on PATH. */
function commandExistsOnPath(cmd: string): boolean {
    try {
        const whichCmd = process.platform === "win32" ? `where ${cmd}` : `which ${cmd}`;
        execSync(whichCmd, { stdio: "ignore" });
        return true;
    } catch {
        return false;
    }
}

/**
 * Detect the CodeTrust source repository root.
 *
 * Checks the current VS Code workspace folders for a pyproject.toml
 * that contains the codetrust package definition.
 */
function detectSourceRoot(): string | undefined {
    const envRoot = process.env.CODETRUST_SOURCE_ROOT;
    if (envRoot && isCodeTrustRoot(envRoot)) {
        return envRoot;
    }

    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (workspaceFolders) {
        for (const folder of workspaceFolders) {
            if (isCodeTrustRoot(folder.uri.fsPath)) {
                return folder.uri.fsPath;
            }
        }
    }

    return detectSourceRootFromKnownConfigs();
}

/**
 * Resolve the best available command to run an MCP server.
 *
 * Falls through strategies in priority order:
 *   1. Console script directly on PATH (fastest, pip-installed)
 *   2. uvx zero-install (downloads automatically, no pip needed)
 *   3. python3 -m module (requires source checkout in workspace)
 */
function resolveServerCommand(
    consoleScript: string,
    modulePath: string,
    outputChannel: vscode.OutputChannel,
): ResolvedCommand {
    // Strategy 1: Console script on PATH
    if (commandExistsOnPath(consoleScript)) {
        outputChannel.appendLine(
            `CodeTrust MCP: '${consoleScript}' found on PATH — using direct invocation.`,
        );
        return { command: consoleScript };
    }

    // Strategy 2: Console script in venv bin/ (detects source root first)
    const sourceRoot = detectSourceRoot();
    if (sourceRoot) {
        const venvScript = process.platform === "win32"
            ? path.join(sourceRoot, ".venv", "Scripts", consoleScript + ".exe")
            : path.join(sourceRoot, ".venv", "bin", consoleScript);
        if (fs.existsSync(venvScript)) {
            outputChannel.appendLine(
                `CodeTrust MCP: Found '${venvScript}' in venv — using direct invocation.`,
            );
            return { command: venvScript };
        }
    }

    // Strategy 3: uvx zero-install
    if (commandExistsOnPath("uvx")) {
        outputChannel.appendLine(
            `CodeTrust MCP: '${consoleScript}' not on PATH or in venv, but 'uvx' available — using zero-install.`,
        );
        return {
            command: "uvx",
            args: ["--from", PYPI_PACKAGE_NAME, consoleScript],
        };
    }

    // Strategy 4: python3 -m with source root venv
    if (sourceRoot) {
        const venvPython = process.platform === "win32"
            ? path.join(sourceRoot, ".venv", "Scripts", "python.exe")
            : path.join(sourceRoot, ".venv", "bin", "python");
        if (fs.existsSync(venvPython)) {
            outputChannel.appendLine(
                `CodeTrust MCP: Using '${venvPython} -m ${modulePath}' with cwd=${sourceRoot}.`,
            );
            return {
                command: venvPython,
                args: ["-m", modulePath],
                cwd: sourceRoot,
            };
        }
    }

    const python = process.platform === "win32" ? "python" : "python3";
    if (sourceRoot && commandExistsOnPath(python)) {
        outputChannel.appendLine(
            `CodeTrust MCP: Using '${python} -m ${modulePath}' with cwd=${sourceRoot}.`,
        );
        return {
            command: python,
            args: ["-m", modulePath],
            cwd: sourceRoot,
        };
    }

    // Fallback: write console script name anyway — user will see startup error
    // and know they need to install
    outputChannel.appendLine(
        `CodeTrust MCP: WARNING — '${consoleScript}' not found on PATH, 'uvx' not available, ` +
        `no source root detected. Writing '${consoleScript}' — server may fail to start.`,
    );
    return { command: consoleScript };
}

/** Build the Guardian MCP server entry with auto-detected command. */
function buildGuardianEntry(outputChannel: vscode.OutputChannel): McpServerEntry {
    const resolved = resolveServerCommand(GUARDIAN_COMMAND, GUARDIAN_MODULE, outputChannel);
    return {
        command: resolved.command,
        ...(resolved.args && { args: resolved.args }),
        ...(resolved.cwd && { cwd: resolved.cwd }),
        _injectedBy: MCP_INJECTION_MARKER,
    };
}

/** VS Code variable for workspace root — resolved at runtime by VS Code. */
const VSCODE_WORKSPACE_VAR = "${workspaceFolder}";

/** Build the Gateway MCP server entry with auto-detected command. */
function buildGatewayEntry(outputChannel: vscode.OutputChannel): McpServerEntry {
    const resolved = resolveServerCommand(GATEWAY_COMMAND, GATEWAY_MODULE, outputChannel);

    return {
        command: resolved.command,
        ...(resolved.args && { args: resolved.args }),
        ...(resolved.cwd && { cwd: resolved.cwd }),
        env: { CODETRUST_WORKSPACE: VSCODE_WORKSPACE_VAR },
        _injectedBy: MCP_INJECTION_MARKER,
    };
}

/** Build the list of MCP config targets for the current platform. */
function buildMcpTargets(): McpTarget[] {
    const home = os.homedir();
    const targets: McpTarget[] = [];

    // VS Code global user-level MCP config — applies to ALL workspaces.
    if (process.platform === "darwin") {
        targets.push({
            name: "VS Code Global (User/mcp.json)",
            filePath: path.join(
                home,
                "Library",
                "Application Support",
                "Code",
                "User",
                "mcp.json",
            ),
            requiresExistingDirectory: true,
            serversKey: "servers",
        });
    } else if (process.platform === "linux") {
        targets.push({
            name: "VS Code Global (User/mcp.json)",
            filePath: path.join(home, ".config", "Code", "User", "mcp.json"),
            requiresExistingDirectory: true,
            serversKey: "servers",
        });
    } else if (process.platform === "win32") {
        const appData = process.env.APPDATA ?? path.join(home, "AppData", "Roaming");
        targets.push({
            name: "VS Code Global (User/mcp.json)",
            filePath: path.join(appData, "Code", "User", "mcp.json"),
            requiresExistingDirectory: true,
            serversKey: "servers",
        });
    }

    // VS Code workspace MCP config — per-workspace override.
    const workspaceFolders = vscode.workspace.workspaceFolders ?? [];
    for (const folder of workspaceFolders) {
        targets.push({
            name: `VS Code Workspace (${folder.name}/.vscode/mcp.json)`,
            filePath: path.join(folder.uri.fsPath, ".vscode", "mcp.json"),
            requiresExistingDirectory: false,
            serversKey: "servers",
        });
    }

    // Claude Code — always present on all platforms
    targets.push({
        name: "Claude Code (~/.claude/mcp.json)",
        filePath: path.join(home, ".claude", "mcp.json"),
        requiresExistingDirectory: true,
        serversKey: "mcpServers",
    });

    // Claude Desktop — macOS only
    if (process.platform === "darwin") {
        targets.push({
            name: "Claude Desktop (claude_desktop_config.json)",
            filePath: path.join(
                home,
                "Library",
                "Application Support",
                "Claude",
                "claude_desktop_config.json",
            ),
            requiresExistingDirectory: true,
            serversKey: "mcpServers",
        });
    }

    // Cursor — all platforms
    targets.push({
        name: "Cursor (~/.cursor/mcp.json)",
        filePath: path.join(home, ".cursor", "mcp.json"),
        requiresExistingDirectory: true,
        serversKey: "mcpServers",
    });

    return targets;
}

/**
 * Exported for tests to enforce the MCP target contract.
 */
export function listMcpTargetPathsForTest(): string[] {
    return buildMcpTargets().map((target) => target.filePath);
}

/**
 * Deterministic helper for tests that validate workspace target path generation.
 */
export function buildWorkspaceMcpTargetPathsForTest(workspacePaths: string[]): string[] {
    return workspacePaths.map((workspacePath) => path.join(workspacePath, ".vscode", "mcp.json"));
}

/**
 * Read and parse an MCP config file.
 *
 * Returns:
 *   - Parsed config object if file exists and is valid JSON
 *   - Empty `{}` if file does not exist or is empty (safe to write)
 *   - `null` if file exists but is malformed (DO NOT overwrite — data loss risk)
 */
function readMcpConfig(filePath: string): McpConfigFile | null {
    if (!fs.existsSync(filePath)) {
        return {};
    }
    try {
        const raw = fs.readFileSync(filePath, "utf8").trim();
        if (raw.length === 0) {
            return {};
        }
        const parsed = JSON.parse(raw) as McpConfigFile;
        return parsed;
    } catch {
        // Malformed JSON — return null so callers can skip (not overwrite)
        return null;
    }
}

/**
 * Write an MCP config file with proper formatting.
 * Creates parent directories if needed.
 */
function writeMcpConfig(filePath: string, config: McpConfigFile): void {
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(filePath, JSON.stringify(config, null, 2) + "\n", "utf8");
}

/**
 * Check if a server entry already exists under the CORRECT key for this target.
 *
 * Only checks the key that the target IDE actually reads. This prevents
 * false positives where an entry exists under "mcpServers" but the target
 * is VS Code (which reads "servers"), or vice-versa.
 */
function serverExists(
    config: McpConfigFile | null,
    serverName: string,
    serversKey: ServersKey,
): boolean {
    if (!config) {
        return false;
    }
    const bucket = config[serversKey];
    return Boolean(bucket && serverName in bucket);
}

/**
 * Migrate CodeTrust entries from the wrong JSON key to the correct one.
 *
 * A prior extension version wrote under "mcpServers" for VS Code targets,
 * but VS Code reads "servers". This moves auto-injected entries to the
 * correct key and removes them from the wrong key.
 *
 * Returns true if any migration was performed.
 */
function migrateWrongKeyEntries(
    config: McpConfigFile,
    target: McpTarget,
    outputChannel: vscode.OutputChannel,
): boolean {
    const wrongKey: ServersKey = target.serversKey === "servers" ? "mcpServers" : "servers";
    const wrongBucket = config[wrongKey];
    if (!wrongBucket) {
        return false;
    }

    let migrated = false;
    const correctBucket = getServers(config, target.serversKey);

    for (const serverName of [GUARDIAN_SERVER_NAME, GATEWAY_SERVER_NAME]) {
        const entry = wrongBucket[serverName];
        if (!entry) {
            continue;
        }

        // Only migrate auto-injected entries — leave user-configured ones
        if (entry._injectedBy !== MCP_INJECTION_MARKER) {
            continue;
        }

        // Move to correct key (only if not already there)
        if (!(serverName in correctBucket)) {
            correctBucket[serverName] = entry;
            outputChannel.appendLine(
                `CodeTrust MCP: Migrated '${serverName}' from "${wrongKey}" → "${target.serversKey}" in ${target.name}`,
            );
        }

        // Remove from wrong key
        delete wrongBucket[serverName];
        migrated = true;
    }

    // Clean up empty wrong-key bucket
    if (Object.keys(wrongBucket).length === 0) {
        delete config[wrongKey];
    }

    return migrated;
}

/** Get the servers record from a config using the appropriate key. */
function getServers(config: McpConfigFile, key: ServersKey): Record<string, McpServerEntry> {
    if (key === "servers") {
        if (!config.servers) {
            config.servers = {};
        }
        return config.servers;
    }
    if (!config.mcpServers) {
        config.mcpServers = {};
    }
    return config.mcpServers;
}

/**
 * Inject CodeTrust MCP server configurations into all supported IDE configs.
 *
 * Idempotent: only adds servers that are missing. Never modifies existing
 * server entries (preserves user customizations like custom args or env).
 *
 * Best-effort: a failure for one target does not stop the others.
 * Shows a VS Code notification listing the IDEs that were updated.
 *
 * @returns Names of targets where MCP servers were freshly injected.
 */
export async function injectMcpServerConfigs(
    outputChannel: vscode.OutputChannel,
): Promise<string[]> {
    const targets = buildMcpTargets();
    const injectedTargets: string[] = [];

    for (const target of targets) {
        try {
            const dir = path.dirname(target.filePath);

            // Skip if the parent directory doesn't exist — IDE is not installed
            if (target.requiresExistingDirectory !== false && !fs.existsSync(dir)) {
                outputChannel.appendLine(
                    `CodeTrust MCP: Skipping ${target.name} — directory not found (IDE not installed).`,
                );
                continue;
            }

            const config = readMcpConfig(target.filePath);

            // null means malformed JSON — skip to avoid data loss
            if (config === null) {
                outputChannel.appendLine(
                    `CodeTrust MCP: Skipping ${target.name} — config file has malformed JSON (not overwriting to prevent data loss).`,
                );
                continue;
            }

            const servers = getServers(config, target.serversKey);

            let modified = false;

            // Migrate entries from wrong key to correct key.
            // E.g., if a prior version wrote under "mcpServers" but this
            // target uses "servers" (VS Code), move them over.
            modified = migrateWrongKeyEntries(config, target, outputChannel) || modified;

            // Inject Guardian if missing
            if (!serverExists(config, GUARDIAN_SERVER_NAME, target.serversKey)) {
                servers[GUARDIAN_SERVER_NAME] = buildGuardianEntry(outputChannel);
                outputChannel.appendLine(
                    `CodeTrust MCP: Added '${GUARDIAN_SERVER_NAME}' server → ${target.name}`,
                );
                modified = true;
            } else {
                outputChannel.appendLine(
                    `CodeTrust MCP: '${GUARDIAN_SERVER_NAME}' already present in ${target.name} — skipping.`,
                );
            }

            // Inject Gateway if missing
            if (!serverExists(config, GATEWAY_SERVER_NAME, target.serversKey)) {
                servers[GATEWAY_SERVER_NAME] = buildGatewayEntry(outputChannel);
                outputChannel.appendLine(
                    `CodeTrust MCP: Added '${GATEWAY_SERVER_NAME}' server → ${target.name}`,
                );
                modified = true;
            } else {
                outputChannel.appendLine(
                    `CodeTrust MCP: '${GATEWAY_SERVER_NAME}' already present in ${target.name} — skipping.`,
                );
            }

            if (modified) {
                writeMcpConfig(target.filePath, config);
                injectedTargets.push(target.name);
            }
        } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            outputChannel.appendLine(
                `CodeTrust MCP: Failed to inject into ${target.name}: ${msg}`,
            );
        }
    }

    if (injectedTargets.length > 0) {
        const names = injectedTargets
            .map((n) => n.split(" (")[0])
            .join(", ");
        void vscode.window.showInformationMessage(
            `CodeTrust: MCP servers registered in ${names}. ` +
            `Both Guardian and Gateway are now available to AI agents.`,
        );
    }

    return injectedTargets;
}

/** Describes a specific issue found during MCP health verification. */
interface McpHealthIssue {
    target: string;
    problem: string;
    fix: string;
}

/** Result of MCP server health verification. */
export interface McpHealthResult {
    healthy: boolean;
    issues: McpHealthIssue[];
}

/**
 * Verify that MCP server configs are installed and commands resolvable.
 *
 * Checks workspace .vscode/mcp.json (the key target for VS Code/Copilot).
 * Does NOT spawn servers — only checks config files and command existence.
 */
export function verifyMcpServerHealth(
    outputChannel: vscode.OutputChannel,
): McpHealthResult {
    const issues: McpHealthIssue[] = [];
    const workspaceFolders = vscode.workspace.workspaceFolders ?? [];

    if (workspaceFolders.length === 0) {
        issues.push({
            target: "Workspace",
            problem: "No workspace folder open",
            fix: "Open a folder in VS Code before activating CodeTrust.",
        });
        return { healthy: false, issues };
    }

    for (const folder of workspaceFolders) {
        const mcpPath = path.join(folder.uri.fsPath, ".vscode", "mcp.json");

        if (!fs.existsSync(mcpPath)) {
            issues.push({
                target: folder.name,
                problem: ".vscode/mcp.json not found after injection",
                fix: "Run 'CodeTrust: Inject MCP Server Configs' from the command palette.",
            });
            continue;
        }

        const config = readMcpConfig(mcpPath);
        if (config === null) {
            issues.push({
                target: folder.name,
                problem: ".vscode/mcp.json contains malformed JSON",
                fix: "Delete .vscode/mcp.json and re-run MCP injection.",
            });
            continue;
        }

        // VS Code workspace targets always use "servers" key
        const workspaceServersKey: ServersKey = "servers";
        for (const serverName of [GUARDIAN_SERVER_NAME, GATEWAY_SERVER_NAME]) {
            if (!serverExists(config, serverName, workspaceServersKey)) {
                issues.push({
                    target: folder.name,
                    problem: `Server '${serverName}' missing from .vscode/mcp.json`,
                    fix: "Run 'CodeTrust: Inject MCP Server Configs' from the command palette.",
                });
                continue;
            }

            const servers = config.servers ?? {};
            const entry = servers[serverName];
            const cmd = entry.command;

            if (path.isAbsolute(cmd) && !fs.existsSync(cmd)) {
                issues.push({
                    target: folder.name,
                    problem: `Server '${serverName}' command not found: ${cmd}`,
                    fix: "Install codetrust: pip install codetrust",
                });
            } else if (!path.isAbsolute(cmd) && cmd !== "uvx" && !commandExistsOnPath(cmd)) {
                issues.push({
                    target: folder.name,
                    problem: `Server '${serverName}' command '${cmd}' not on PATH`,
                    fix: "Install codetrust: pip install codetrust",
                });
            }
        }
    }

    const healthy = issues.length === 0;

    if (healthy) {
        outputChannel.appendLine(
            "CodeTrust MCP: Health check PASSED — both servers configured and commands resolvable.",
        );
    } else {
        outputChannel.appendLine("CodeTrust MCP: Health check found issues:");
        for (const issue of issues) {
            outputChannel.appendLine(`  [${issue.target}] ${issue.problem}`);
            outputChannel.appendLine(`    Fix: ${issue.fix}`);
        }
    }

    return { healthy, issues };
}

/**
 * Remove CodeTrust MCP server entries from all supported IDE configs.
 *
 * Called on extension deactivation for a clean uninstall path.
 * Only removes entries that were auto-injected (have the marker).
 */
export function removeMcpServerConfigs(outputChannel: vscode.OutputChannel): void {
    const targets = buildMcpTargets();

    for (const target of targets) {
        try {
            if (!fs.existsSync(target.filePath)) {
                continue;
            }

            const config = readMcpConfig(target.filePath);
            if (!config) {
                continue;
            }

            const servers = config[target.serversKey];
            if (!servers) {
                continue;
            }

            let modified = false;

            for (const serverName of [GUARDIAN_SERVER_NAME, GATEWAY_SERVER_NAME]) {
                const entry = servers[serverName];
                if (entry && entry._injectedBy === MCP_INJECTION_MARKER) {
                    delete servers[serverName];
                    outputChannel.appendLine(
                        `CodeTrust MCP: Removed '${serverName}' from ${target.name}`,
                    );
                    modified = true;
                }
            }

            if (modified) {
                writeMcpConfig(target.filePath, config);
            }
        } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            outputChannel.appendLine(
                `CodeTrust MCP: Failed to remove from ${target.name}: ${msg}`,
            );
        }
    }
}

/**
 * Watch for MCP config files being modified or deleted externally
 * (IDE updates, user edits) and offer to re-inject if CodeTrust
 * servers are missing.
 *
 * Includes debounce to avoid repeated prompts from rapid file writes,
 * and watches for file deletion (not just changes).
 *
 * Returns VS Code disposables for context.subscriptions.
 */
export function watchForMcpConfigDisruption(
    outputChannel: vscode.OutputChannel,
): vscode.Disposable[] {
    const disposables: vscode.Disposable[] = [];
    const targets = buildMcpTargets();

    /** Per-target debounce timers to avoid rapid-fire prompts. */
    const debounceTimers = new Map<string, ReturnType<typeof setTimeout>>();

    for (const target of targets) {
        // Watch even if file doesn't exist yet — it may be created later
        const dir = path.dirname(target.filePath);
        if (!fs.existsSync(dir)) {
            continue;
        }

        const dirUri = vscode.Uri.file(dir);
        const base = path.basename(target.filePath);
        const pattern = new vscode.RelativePattern(dirUri, base);
        const watcher = vscode.workspace.createFileSystemWatcher(pattern);

        const checkAndOffer = (): void => {
            // Debounce — ignore rapid successive triggers
            const existing = debounceTimers.get(target.filePath);
            if (existing) {
                clearTimeout(existing);
            }
            debounceTimers.set(
                target.filePath,
                setTimeout(() => {
                    debounceTimers.delete(target.filePath);
                    doCheck();
                }, DEBOUNCE_MS),
            );
        };

        const doCheck = (): void => {
            try {
                // If file was deleted, both servers are missing
                const config = fs.existsSync(target.filePath)
                    ? readMcpConfig(target.filePath)
                    : {};

                // null = malformed JSON — don't prompt, can't safely re-inject
                if (config === null) {
                    return;
                }

                const guardianOk = serverExists(config, GUARDIAN_SERVER_NAME, target.serversKey);
                const gatewayOk = serverExists(config, GATEWAY_SERVER_NAME, target.serversKey);

                if (guardianOk && gatewayOk) {
                    return;
                }

                const missing: string[] = [];
                if (!guardianOk) {
                    missing.push("Guardian");
                }
                if (!gatewayOk) {
                    missing.push("Gateway");
                }

                const displayTarget = target.name.split(" (")[0];
                outputChannel.appendLine(
                    `CodeTrust MCP: ${missing.join(" + ")} server(s) missing from ${displayTarget} — offering re-injection.`,
                );

                void vscode.window
                    .showWarningMessage(
                        `CodeTrust: ${missing.join(" + ")} MCP server(s) removed from ${displayTarget}. ` +
                        `Re-inject to restore AI agent governance?`,
                        "Re-inject Now",
                        "Dismiss",
                    )
                    .then((action) => {
                        if (action === "Re-inject Now") {
                            void injectMcpServerConfigs(outputChannel);
                        }
                    });
            } catch (err: unknown) {
                const msg = err instanceof Error ? err.message : String(err);
                outputChannel.appendLine(
                    `CodeTrust MCP: Watch error for ${target.name}: ${msg}`,
                );
            }
        };

        // Watch both changes AND deletions
        disposables.push(
            watcher,
            watcher.onDidChange(checkAndOffer),
            watcher.onDidDelete(checkAndOffer),
            watcher.onDidCreate(checkAndOffer),
        );
    }

    // Focus-based check — debounced to avoid spamming on every Alt+Tab
    let lastFocusCheck = 0;
    const focusDisposable = vscode.window.onDidChangeWindowState((state) => {
        if (!state.focused) {
            return;
        }

        const now = Date.now();
        if (now - lastFocusCheck < FOCUS_DEBOUNCE_MS) {
            return;
        }
        lastFocusCheck = now;

        const missing = targets.filter((t) => {
            const tDir = path.dirname(t.filePath);
            if (!fs.existsSync(tDir)) {
                return false;
            }
            const config = readMcpConfig(t.filePath);
            return !serverExists(config, GUARDIAN_SERVER_NAME, t.serversKey) ||
                !serverExists(config, GATEWAY_SERVER_NAME, t.serversKey);
        });

        if (missing.length === 0) {
            return;
        }

        const names = missing.map((t) => t.name.split(" (")[0]).join(", ");
        outputChannel.appendLine(
            `CodeTrust MCP: ${names} missing MCP server configs — offering injection.`,
        );
        void vscode.window
            .showWarningMessage(
                `CodeTrust: ${names} detected without full MCP server registration. ` +
                `Inject now to enable both Guardian and Gateway?`,
                "Inject Now",
                "Dismiss",
            )
            .then((action) => {
                if (action === "Inject Now") {
                    void injectMcpServerConfigs(outputChannel);
                }
            });
    });

    disposables.push(focusDisposable);
    return disposables;
}
