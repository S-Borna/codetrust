/**
 * Embedded offline scanner for CodeTrust VS Code extension.
 *
 * Runs locally without any API connection, using the same regex rules
 * as the Python backend (src/rules/anti_patterns.py). This ensures
 * CodeTrust always works — even offline.
 */

import type { Finding, Severity, StaticScanResponse } from "./types";

/** Anti-pattern rule definition. */
interface Rule {
    id: string;
    pattern: RegExp;
    message: string;
    severity: Severity;
    skipComments?: boolean;
}

/**
 * BLOCK rules — must fix before proceeding.
 * Mirrors src/rules/anti_patterns.py BLOCK patterns.
 */
const BLOCK_RULES: Rule[] = [
    {
        id: "heredoc",
        pattern: /<<[-']?\w+/,
        message: "Heredoc detected. Use template files or multi-line strings.",
        severity: "BLOCK",
    },
    {
        id: "hardcoded_secret",
        pattern: /(?:api[_-]?key|secret|password|token|credentials)\s*[:=]\s*["'][^"']{8,}["']/i,
        message: "Possible hardcoded secret. Use environment variables.",
        severity: "BLOCK",
    },
    {
        id: "eval_exec",
        pattern: /\b(eval|exec)\s*\(/,
        message: "eval/exec is a security risk. Use safe alternatives.",
        severity: "BLOCK",
    },
    {
        id: "sql_injection",
        pattern: /(?:execute|executemany|cursor\.execute)\s*\(\s*(?:f["']|[^)]*\.format\s*\()/,
        message: "Possible SQL injection via string formatting. Use parameterized queries.",
        severity: "BLOCK",
    },
    {
        id: "pickle_load",
        pattern: /pickle\.loads?\s*\(/,
        message: "pickle.load is unsafe with untrusted data. Use JSON or msgpack.",
        severity: "BLOCK",
    },
];

/**
 * WARN rules — should fix, not blocking.
 * Mirrors src/rules/anti_patterns.py WARN patterns.
 */
const WARN_RULES: Rule[] = [
    {
        id: "todo_hack",
        pattern: /(?:#|\/\/)\s*(todo|hack|fixme|xxx|temp)\b/i,
        message: "Temporary marker found. Resolve before committing.",
        severity: "WARN",
    },
    {
        id: "console_log",
        pattern: /\bconsole\.(log|debug|info)\s*\(/,
        message: "Replace console logging with a structured logger.",
        severity: "WARN",
    },
    {
        id: "print_debug",
        pattern: /^\s*print\s*\(/,
        message: "Use logging module instead of print().",
        severity: "WARN",
    },
    {
        id: "any_type",
        pattern: /:\s*[Aa]ny\b/,
        message: "Avoid Any type. Use explicit types.",
        severity: "WARN",
    },
    {
        id: "wildcard_import",
        pattern: /from\s+\S+\s+import\s+\*/,
        message: "Wildcard imports reduce clarity. Import explicitly.",
        severity: "WARN",
    },
    {
        id: "nested_ternary",
        pattern: /\w\s*\?[^;]*\w\s*\?/,
        message: "Nested ternary reduces readability. Use if/else.",
        severity: "WARN",
    },
    {
        id: "bare_except",
        pattern: /except\s*:/,
        message: "Bare except catches everything including KeyboardInterrupt.",
        severity: "WARN",
    },
    {
        id: "mutable_default",
        pattern: /def\s+\w+\([^)]*(?::\s*(?:list|dict|set)\s*=\s*(?:\[\]|\{\}))/,
        message: "Mutable default argument. Use None and assign inside function.",
        severity: "WARN",
    },
];

/**
 * INFO rules — suggestions.
 * Mirrors src/rules/anti_patterns.py INFO patterns.
 */
const INFO_RULES: Rule[] = [
    {
        id: "magic_number",
        pattern: /(?<!=)\s(?<!\w)[2-9]\d{2,}\b/,
        message: "Magic number detected. Extract to a named constant.",
        severity: "INFO",
        skipComments: true,
    },
];

const ALL_RULES: Rule[] = [...BLOCK_RULES, ...WARN_RULES, ...INFO_RULES];

/**
 * Scan code locally using embedded anti-pattern rules.
 * This is a fallback when the API is unavailable.
 */
export function scanCodeOffline(code: string, filename: string): StaticScanResponse {
    const lines = code.split("\n");
    const findings: Finding[] = [];
    let inDocstring = false;

    for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
        const line = lines[lineIdx];
        const lineNum = lineIdx + 1;
        const stripped = line.trim();

        // Track docstring boundaries
        const tripleQuoteCount =
            (stripped.match(/"""/g) || []).length +
            (stripped.match(/'''/g) || []).length;
        if (tripleQuoteCount === 1) {
            inDocstring = !inDocstring;
        }

        // Skip noqa lines
        if (line.includes("noqa")) {
            continue;
        }

        for (const rule of ALL_RULES) {
            // Skip comment-sensitive rules when in comments/docstrings
            if (rule.skipComments) {
                if (
                    inDocstring ||
                    stripped.startsWith("#") ||
                    stripped.startsWith("//") ||
                    stripped.startsWith('"""') ||
                    stripped.startsWith("'''")
                ) {
                    continue;
                }
            }

            if (rule.pattern.test(line)) {
                findings.push({
                    rule_id: rule.id,
                    severity: rule.severity,
                    message: rule.message,
                    file: filename,
                    line: lineNum,
                    suggestion: "",
                    confidence: 1.0,
                });
            }
        }
    }

    const blocks = findings.filter((f) => f.severity === "BLOCK").length;
    const warnings = findings.filter((f) => f.severity === "WARN").length;
    const infos = findings.filter((f) => f.severity === "INFO").length;

    let verdict = "PASS";
    if (blocks > 0) {
        verdict = "BLOCK";
    } else if (warnings > 0) {
        verdict = "WARN";
    }

    return {
        total_findings: findings.length,
        blocks,
        warnings,
        infos,
        findings,
        verdict,
    };
}
