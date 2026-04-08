// Copyright (c) 2026 Said Borna. All rights reserved.
// Proprietary — see LICENSE for terms.
/**
 * CLI-delegated scanner: shells out to the installed `codetrust` binary.
 *
 * This module closes the extension's parity gap with the backend. When
 * the user has `codetrust` installed via pipx/brew/pip, we delegate
 * scanning to the CLI which runs the full 2,928 rule StaticAnalyzer
 * instead of the 120-rule embedded TypeScript fallback.
 *
 * Decision order inside the extension's scan command:
 *   1. API (cloud scan)              — full rules, shared history
 *   2. CLI subprocess (this module)  — full rules, local only
 *   3. Embedded scanner              — 120 rule offline fallback
 *
 * The CLI path takes over only when the API is unreachable AND the CLI
 * is present. If the CLI is not installed, this module's entry point
 * resolves to `null` and the caller must fall through to the embedded
 * scanner.
 *
 * The CLI availability check runs once per session and is cached — we
 * do not want to pay the `spawn` cost on every keystroke.
 */

import { spawn } from "child_process";
import { randomBytes } from "crypto";
import { mkdtemp, rm, writeFile } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";

import type { Finding, StaticScanResponse } from "./types";

/** Max seconds to wait for a CLI scan before giving up. */
const CLI_TIMEOUT_MS = 10_000;

/** Minimum acceptable CLI version — bump if we start depending on newer flags. */
const MIN_CLI_VERSION = "4.0.0";

/** Cached result of the availability check. `null` means "not yet checked". */
let cachedAvailability: { available: boolean; version: string } | null = null;

/** Shape of the raw JSON emitted by `codetrust scan --json`. */
interface CliScanJson {
    verdict: string;
    total_findings: number;
    blocks: number;
    warnings: number;
    infos: number;
    findings: Array<{
        rule_id: string;
        severity: string;
        message: string;
        file: string;
        line: number;
        suggestion?: string;
        confidence?: number;
    }>;
}

/**
 * Run a short-lived `codetrust` command and return stdout on success.
 *
 * Wraps child_process.spawn in a Promise, adds a hard timeout, and
 * swallows ENOENT (CLI not installed) as a clean `null` return.
 */
async function runCodetrust(
    args: string[],
    input?: { cwd?: string; timeoutMs?: number },
): Promise<{ stdout: string; stderr: string; exitCode: number } | null> {
    return new Promise((resolve) => {
        let finished = false;
        let stdout = "";
        let stderr = "";

        const finish = (result: typeof stdout extends string ? {
            stdout: string; stderr: string; exitCode: number;
        } | null : never): void => {
            if (finished) {
                return;
            }
            finished = true;
            resolve(result);
        };

        try {
            const child = spawn("codetrust", args, {
                cwd: input?.cwd,
                env: { ...process.env },
                stdio: ["ignore", "pipe", "pipe"],
            });

            const timer = setTimeout(() => {
                try {
                    child.kill("SIGTERM");
                } catch {
                    // Process already gone — ignore.
                }
                finish(null);
            }, input?.timeoutMs ?? CLI_TIMEOUT_MS);

            child.stdout.on("data", (chunk: Buffer) => {
                stdout += chunk.toString("utf8");
            });
            child.stderr.on("data", (chunk: Buffer) => {
                stderr += chunk.toString("utf8");
            });
            child.on("error", () => {
                clearTimeout(timer);
                finish(null);
            });
            child.on("close", (code: number | null) => {
                clearTimeout(timer);
                finish({ stdout, stderr, exitCode: code ?? -1 });
            });
        } catch {
            finish(null);
        }
    });
}

/**
 * Detect whether `codetrust` is on PATH and return its version string.
 *
 * Cached for the lifetime of the extension host process — re-checking
 * on every scan would cost ~30ms of subprocess overhead per keystroke
 * on scan-on-type workflows.
 *
 * Returns:
 *   { available: true,  version: "4.0.6" } when the CLI is usable
 *   { available: false, version: ""      } when it is not
 */
export async function detectCliAvailability(): Promise<{ available: boolean; version: string }> {
    if (cachedAvailability !== null) {
        return cachedAvailability;
    }

    const result = await runCodetrust(["--version"], { timeoutMs: 3_000 });
    if (!result || result.exitCode !== 0) {
        cachedAvailability = { available: false, version: "" };
        return cachedAvailability;
    }

    // `codetrust --version` prints a single line like "codetrust 4.0.6"
    const versionMatch = result.stdout.match(/(\d+\.\d+\.\d+)/);
    if (!versionMatch) {
        cachedAvailability = { available: false, version: "" };
        return cachedAvailability;
    }

    cachedAvailability = { available: true, version: versionMatch[1] ?? "" };
    return cachedAvailability;
}

/** Reset the cache. Tests use this; production never calls it. */
export function _resetCliAvailabilityCache(): void {
    cachedAvailability = null;
}

/** Parse the CLI's severity into our strict Finding type. */
function coerceSeverity(value: string): "BLOCK" | "WARN" | "INFO" {
    if (value === "BLOCK" || value === "WARN" || value === "INFO") {
        return value;
    }
    return "INFO";
}

/**
 * Convert the CLI's JSON response into the extension's StaticScanResponse.
 *
 * The CLI's schema is a superset of the extension's — we take only the
 * fields the extension uses and apply sane defaults for optional ones.
 */
function normalizeCliResponse(json: CliScanJson): StaticScanResponse {
    const findings: Finding[] = (json.findings ?? []).map((f) => ({
        rule_id: f.rule_id,
        severity: coerceSeverity(f.severity),
        message: f.message,
        file: f.file,
        line: f.line,
        suggestion: f.suggestion ?? "",
        confidence: typeof f.confidence === "number" ? f.confidence : 1.0,
    }));

    return {
        total_findings: json.total_findings ?? findings.length,
        blocks: json.blocks ?? findings.filter((f) => f.severity === "BLOCK").length,
        warnings: json.warnings ?? findings.filter((f) => f.severity === "WARN").length,
        infos: json.infos ?? findings.filter((f) => f.severity === "INFO").length,
        findings,
        verdict: json.verdict ?? "PASS",
    };
}

/**
 * Extract the JSON object from a CLI stdout payload.
 *
 * `codetrust scan` emits structured log lines on stdout BEFORE the JSON
 * payload. We scan for the first `{` at column 0 and parse from there
 * to the matching `}`. Returns null on any parse failure.
 */
function extractJsonPayload(stdout: string): CliScanJson | null {
    const firstBrace = stdout.indexOf("\n{");
    const start = firstBrace === -1 ? stdout.indexOf("{") : firstBrace + 1;
    if (start === -1) {
        return null;
    }

    // Scan forward to find the matching closing brace.
    let depth = 0;
    let end = -1;
    for (let i = start; i < stdout.length; i++) {
        const ch = stdout[i];
        if (ch === "{") {
            depth += 1;
        } else if (ch === "}") {
            depth -= 1;
            if (depth === 0) {
                end = i + 1;
                break;
            }
        }
    }
    if (end === -1) {
        return null;
    }

    try {
        return JSON.parse(stdout.slice(start, end)) as CliScanJson;
    } catch {
        return null;
    }
}

/**
 * Scan a file's current buffer via the installed codetrust CLI.
 *
 * Writes the in-memory buffer to a temp file so the CLI sees the
 * unsaved content, then runs `codetrust scan --json` on that path.
 * Cleans up the temp directory regardless of outcome.
 *
 * Returns null if:
 *   - the CLI is not installed
 *   - the CLI crashed or timed out
 *   - the JSON output could not be parsed
 *
 * Callers MUST treat null as "fall through to the next scanner in the
 * chain" rather than "no findings".
 */
export async function scanViaCliSubprocess(
    code: string,
    filename: string,
): Promise<StaticScanResponse | null> {
    const availability = await detectCliAvailability();
    if (!availability.available) {
        return null;
    }

    // Preserve the original file extension so the CLI's language
    // detection picks the right rules. The basename itself doesn't
    // need to match — rules key off the suffix.
    const extMatch = filename.match(/\.[A-Za-z0-9]+$/);
    const extension = extMatch ? extMatch[0] : ".txt";
    const randomSuffix = randomBytes(6).toString("hex");

    let tempDir: string | null = null;
    try {
        tempDir = await mkdtemp(join(tmpdir(), "codetrust-scan-"));
        const tempFile = join(tempDir, `buffer-${randomSuffix}${extension}`);
        await writeFile(tempFile, code, "utf8");

        const result = await runCodetrust(
            [
                "scan",
                "--json",
                "--no-verify-imports",
                "--no-verify-signatures",
                "--no-baseline",
                tempFile,
            ],
            { timeoutMs: CLI_TIMEOUT_MS },
        );
        if (!result) {
            return null;
        }

        const payload = extractJsonPayload(result.stdout);
        if (!payload) {
            return null;
        }

        const normalized = normalizeCliResponse(payload);

        // Rewrite finding paths from the temp file back to the user's
        // real filename so diagnostics attach to the correct editor.
        for (const finding of normalized.findings) {
            finding.file = filename;
        }
        return normalized;
    } catch {
        return null;
    } finally {
        if (tempDir) {
            try {
                await rm(tempDir, { recursive: true, force: true });
            } catch {
                // Best-effort cleanup — ignore.
            }
        }
    }
}

/** Exported for tests only. */
export const __test__ = {
    extractJsonPayload,
    normalizeCliResponse,
    coerceSeverity,
};
