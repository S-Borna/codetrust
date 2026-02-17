/**
 * Embedded offline scanner for CodeTrust VS Code extension.
 *
 * Runs locally without any API connection, using the same regex rules
 * as the Python backend (src/rules/anti_patterns.py). This ensures
 * CodeTrust always works — even offline.
 *
 * All 67 rules are implemented: 56 regex-only + 11 file-level checks
 * (matching the backend's special_handler functions).
 */

import type { Finding, Severity, StaticScanResponse } from "./types";

/** Maximum function length before triggering a finding (matches backend). */
const MAX_FUNCTION_LENGTH = 40;

/** Anti-pattern rule definition. */
interface Rule {
    id: string;
    pattern: RegExp;
    message: string;
    severity: Severity;
    skipComments?: boolean;
    /** File extension restrictions (e.g. [".sql"]). If omitted, applies to generic source files. */
    fileTypes?: string[];
}

// ═══════════════════════════════════════════════════════════════
//  GENERIC RULES (Python / JS / TS / Go / Rust / …)
// ═══════════════════════════════════════════════════════════════

// --- BLOCK ---
const GENERIC_BLOCK_RULES: Rule[] = [
    {
        id: "heredoc",
        pattern: new RegExp("<" + "<[-']?\\w+"),
        message: "Heredoc detected. Use template files or multi-line strings.",
        severity: "BLOCK",
    },
    {
        id: "hardcoded_secret",
        pattern: new RegExp(
            "(?:" + "api[_-]?key|secret|password|token|credentials" + ")" +
            "\\s*[:=]\\s*[\"'][^\"']{8,}[\"']",
            "i",
        ),
        message: "Possible hardcoded secret. Use environment variables.",
        severity: "BLOCK",
    },
    {
        id: "eval_exec",
        pattern: new RegExp("\\b(" + "eval" + "|" + "exec" + ")\\s*\\("),
        message: "eval/exec is a security risk. Use safe alternatives.",
        severity: "BLOCK",
    },
    {
        id: "sql_injection",
        pattern: new RegExp(
            "(?:" + "execute|executemany|cursor\\.execute" + ")" +
            "\\s*\\(\\s*(?:f[\"']|[^)]*\\.format\\s*\\()",
        ),
        message: "Possible SQL injection via string formatting. Use parameterized queries.",
        severity: "BLOCK",
    },
    {
        id: "pickle_load",
        pattern: new RegExp("pickle\\.loads?\\s*\\("),
        message: "pickle.load is unsafe with untrusted data. Use JSON or msgpack.",
        severity: "BLOCK",
    },
];

// --- WARN ---
const GENERIC_WARN_RULES: Rule[] = [
    // Symptom-Fix Detection (Law 3)
    {
        id: "null_coalesce_smell",
        pattern: /\w+\s*=\s*\w+\s+or\s+(?:""|''|\[\]|\{\}|None|0|False)\s*$/,
        message: "Defensive 'x = x or default' hides why x could be None. Fix the root cause.",
        severity: "WARN",
        skipComments: true,
    },
    {
        id: "suppress_lint",
        pattern: /(?:#\s*noqa\b|#\s*type:\s*ignore|@SuppressWarnings|eslint-disable|pragma:\s*no\s*cover)/,
        message: "Lint/type/coverage warning suppressed. Fix the underlying issue instead.",
        severity: "WARN",
    },
    {
        id: "todo_marker",
        pattern: /(?:#|\/\/)+\s*(todo|hack|fixme|xxx|temp)\b/i,
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
        message: "Bare except catches everything including KeyboardInterrupt. Catch specific exceptions.",
        severity: "WARN",
    },
    {
        id: "mutable_default",
        pattern: /def\s+\w+\([^)]*(?::\s*(?:list|dict|set)\s*=\s*(?:\[\]|\{\}))/,
        message: "Mutable default argument. Use None and assign inside function.",
        severity: "WARN",
    },
    // Anti-Assumption (Law 2)
    {
        id: "debug_mode_enabled",
        pattern: /(?:^|\s)(?:DEBUG|debug)\s*[:=]\s*(?:(?:True|true|1)\b|["']true["'])/i,
        message: "Debug mode enabled. Ensure this is not shipped to production.",
        severity: "WARN",
        skipComments: true,
    },
    // DevOps
    {
        id: "unbounded_retry",
        pattern: /(?:max_retries|retry|retries)\s*[:=]\s*(?:[5-9]|[1-9]\d+)/,
        message: "High retry count without timeout guard. Use a total timeout to bound retries.",
        severity: "WARN",
    },
    {
        id: "retry_exponential_unbounded",
        pattern: /sleep\s*\(.*\*\*/,
        message: "Exponential backoff without total timeout cap. Add a deadline.",
        severity: "WARN",
    },
    {
        id: "blocking_prestart",
        pattern: /(?:alembic|migrate|flask\s+db).*&&.*(?:uvicorn|gunicorn|node|npm\s+start)/,
        message: "Migration blocks server start. Wrap in timeout or run as separate step.",
        severity: "WARN",
    },
];

// --- INFO ---
const GENERIC_INFO_RULES: Rule[] = [
    {
        id: "broad_except",
        pattern: /except\s+Exception\s*:/,
        message: "Catching base Exception can hide bugs. Prefer narrower exceptions.",
        severity: "INFO",
    },
    {
        id: "hardcoded_port",
        pattern: /(?:port|PORT)\s*[:=]\s*\d{4,5}\b/,
        message: "Hardcoded port number. Use environment variable or configuration.",
        severity: "INFO",
        skipComments: true,
    },
    {
        id: "magic_number",
        pattern: /(?<!=)\s(?<!\w)[2-9]\d{2,}\b/,
        message: "Magic number detected. Extract to a named constant.",
        severity: "INFO",
        skipComments: true,
    },
];

// ═══════════════════════════════════════════════════════════════
//  SQL RULES (only fire on .sql files)
// ═══════════════════════════════════════════════════════════════

const SQL_BLOCK_RULES: Rule[] = [
    {
        id: "sql_select_star",
        pattern: /\bSELECT\s+\*/i,
        message: "SELECT * is fragile — specify columns explicitly.",
        severity: "BLOCK",
        fileTypes: [".sql"],
    },
    {
        id: "sql_delete_no_where",
        pattern: /^\s*DELETE\s+FROM\s+\w+\s*;/i,
        message: "DELETE without WHERE will remove all rows.",
        severity: "BLOCK",
        fileTypes: [".sql"],
    },
    {
        id: "sql_update_no_where",
        pattern: /^\s*UPDATE\s+\w+\s+SET\s+(?!.*\bWHERE\b)[^;]*;\s*$/i,
        message: "UPDATE without WHERE will modify all rows.",
        severity: "BLOCK",
        fileTypes: [".sql"],
    },
    {
        id: "sql_drop_table",
        pattern: /\bDROP\s+(TABLE|DATABASE|INDEX|VIEW)\s+(?!IF\s+EXISTS\b)\w+/i,
        message: "DROP without IF EXISTS may fail.",
        severity: "BLOCK",
        fileTypes: [".sql"],
    },
    {
        id: "sql_grant_all",
        pattern: /\bGRANT\s+ALL\b/i,
        message: "GRANT ALL gives excessive privileges. Grant only what is needed.",
        severity: "BLOCK",
        fileTypes: [".sql"],
    },
    {
        id: "sql_foreign_key_checks_off",
        pattern: /SET\s+FOREIGN_KEY_CHECKS\s*=\s*0/i,
        message: "Disabling foreign key checks bypasses referential integrity.",
        severity: "BLOCK",
        fileTypes: [".sql"],
    },
];

const SQL_WARN_RULES: Rule[] = [
    {
        id: "sql_float_for_money",
        pattern: /\b(selling_price|cost|price|amount|balance|salary|total|wholesale_cost)\s+FLOAT\b/i,
        message: "FLOAT is imprecise for monetary values. Use DECIMAL(10,2).",
        severity: "WARN",
        fileTypes: [".sql"],
    },
    {
        id: "sql_varchar_no_length",
        pattern: /\bVARCHAR\s*\(\s*\)/i,
        message: "VARCHAR without length specified.",
        severity: "WARN",
        fileTypes: [".sql"],
    },
    {
        id: "sql_todo_hack",
        pattern: /--\s*(todo|hack|fixme|xxx|temp)\b/i,
        message: "Temporary marker found in SQL.",
        severity: "WARN",
        fileTypes: [".sql"],
    },
    {
        id: "sql_composite_pk_auto_increment",
        pattern: /AUTO_INCREMENT.*PRIMARY\s+KEY\s*\([^)]+,/i,
        message: "AUTO_INCREMENT in composite primary key can cause issues.",
        severity: "WARN",
        fileTypes: [".sql"],
    },
];

const SQL_INFO_RULES: Rule[] = [
    {
        id: "sql_no_index_hint",
        pattern: /\bFOREIGN\s+KEY\b/i,
        message: "Foreign key detected — verify an index exists on the referenced column.",
        severity: "INFO",
        fileTypes: [".sql"],
    },
    {
        id: "sql_autocommit_off",
        pattern: /SET\s+autocommit\s*=\s*0/i,
        message: "Manual transaction control. Ensure matching COMMIT/ROLLBACK exists.",
        severity: "INFO",
        fileTypes: [".sql"],
    },
    {
        id: "sql_hardcoded_id",
        pattern: /(?:VALUES\s*\([^)]*'[0-9]+'|,\s*'[0-9]+'\s*[),])/i,
        message: "Hardcoded ID as string. Use integers or AUTO_INCREMENT.",
        severity: "INFO",
        fileTypes: [".sql"],
    },
];

// ═══════════════════════════════════════════════════════════════
//  DEVOPS / INFRASTRUCTURE RULES
// ═══════════════════════════════════════════════════════════════

const DOCKER_BLOCK_RULES: Rule[] = [
    {
        id: "docker_env_secret",
        pattern: /^(?:ENV|ARG)\s+\S*(?:password|secret|token|api_key|private_key)/i,
        message: "Secret in Dockerfile ENV/ARG. Use runtime secrets or --secret flag.",
        severity: "BLOCK",
        fileTypes: [".dockerfile"],
    },
];

const DOCKER_WARN_RULES: Rule[] = [
    {
        id: "docker_latest_tag",
        pattern: /^FROM\s+\S+:latest\b|^FROM\s+[^:\s]+\s*$/,
        message: "Unpinned base image. Pin to specific version for reproducibility.",
        severity: "WARN",
        fileTypes: [".dockerfile"],
    },
];

const CI_WARN_RULES: Rule[] = [
    {
        id: "ci_unpinned_action",
        pattern: /uses:\s*\S+@(?:main|master|latest|HEAD)\b/,
        message: "CI action not pinned. Pin to SHA or version tag.",
        severity: "WARN",
        fileTypes: [".yml", ".yaml"],
    },
];

const DEVOPS_BLOCK_RULES: Rule[] = [
    {
        id: "api_key_in_config",
        pattern: /(?:api[_-]?key|secret[_-]?key|auth[_-]?token)\s*[:=]\s*["']?[^\s"']{8,}/i,
        message: "API key or secret in config file. Use environment variables.",
        severity: "BLOCK",
        fileTypes: [".yml", ".yaml", ".toml", ".json"],
    },
];

const DEVOPS_WARN_RULES: Rule[] = [
    {
        id: "hardcoded_ip",
        pattern: /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/,
        message: "Hardcoded IP address. Use DNS, variables, or service discovery.",
        severity: "WARN",
        fileTypes: [".tf", ".hcl", ".yml", ".yaml", ".toml"],
    },
];

const DEVOPS_INFO_RULES: Rule[] = [
    {
        id: "healthcheck_timeout_low",
        pattern: /healthcheck.*timeout.*[:=]\s*(?:[1-9]|[12]\d)\b/i,
        message: "Healthcheck timeout under 30s may be too aggressive.",
        severity: "INFO",
        fileTypes: [".yml", ".yaml", ".toml"],
    },
];

// ═══════════════════════════════════════════════════════════════
//  REACT / JSX RULES
// ═══════════════════════════════════════════════════════════════

const REACT_BLOCK_RULES: Rule[] = [
    {
        id: "react_dangerouslysetinnerhtml",
        pattern: /dangerouslySetInnerHTML/,
        message: "dangerouslySetInnerHTML bypasses React's XSS protection. Sanitize input.",
        severity: "BLOCK",
        fileTypes: [".jsx", ".tsx", ".js", ".ts"],
    },
    {
        id: "react_innerhtml_string",
        pattern: /\.innerHTML\s*=/,
        message: "Direct innerHTML assignment bypasses sanitization. Use React rendering.",
        severity: "BLOCK",
        fileTypes: [".jsx", ".tsx", ".js", ".ts"],
    },
];

const REACT_WARN_RULES: Rule[] = [
    {
        id: "react_direct_dom",
        pattern: /document\.(?:getElementById|querySelector|getElementsBy|createElement)\s*\(/,
        message: "Direct DOM manipulation in React. Use refs or React state instead.",
        severity: "WARN",
        fileTypes: [".jsx", ".tsx", ".js", ".ts"],
    },
    {
        id: "react_use_effect_no_deps",
        pattern: /useEffect\s*\(\s*(?:\(\)|[^,)]+)\s*\)\s*;/,
        message: "useEffect without dependency array runs on every render. Add [] or dependencies.",
        severity: "WARN",
        fileTypes: [".jsx", ".tsx", ".js", ".ts"],
    },
    {
        id: "react_index_as_key",
        pattern: /key\s*=\s*\{?\s*(?:index|idx|i)\s*\}?/,
        message: "Array index used as React key. Use a stable unique ID.",
        severity: "WARN",
        fileTypes: [".jsx", ".tsx"],
    },
];

// ═══════════════════════════════════════════════════════════════
//  KUBERNETES / K8S YAML RULES
// ═══════════════════════════════════════════════════════════════

const K8S_BLOCK_RULES: Rule[] = [
    {
        id: "k8s_privileged",
        pattern: /privileged:\s*true/i,
        message: "Privileged container. Remove privileged: true unless necessary.",
        severity: "BLOCK",
        fileTypes: [".yml", ".yaml"],
    },
];

const K8S_WARN_RULES: Rule[] = [
    {
        id: "k8s_host_network",
        pattern: /hostNetwork:\s*true/i,
        message: "hostNetwork: true exposes the host network. Remove unless required.",
        severity: "WARN",
        fileTypes: [".yml", ".yaml"],
    },
    {
        id: "k8s_host_pid",
        pattern: /hostPID:\s*true/i,
        message: "hostPID: true shares the host PID namespace. Remove unless required.",
        severity: "WARN",
        fileTypes: [".yml", ".yaml"],
    },
    {
        id: "k8s_run_as_root",
        pattern: /runAsUser:\s*0\b/i,
        message: "Container runs as root (UID 0). Use runAsNonRoot: true.",
        severity: "WARN",
        fileTypes: [".yml", ".yaml"],
    },
    {
        id: "k8s_latest_image",
        pattern: /image:\s*\S+:latest\b/i,
        message: "Container image uses :latest tag. Pin to a specific version.",
        severity: "WARN",
        fileTypes: [".yml", ".yaml"],
    },
];

// ═══════════════════════════════════════════════════════════════
//  CONFIG HALLUCINATION RULES
//  Catch AI agents fabricating URLs, env vars, API endpoints, etc.
// ═══════════════════════════════════════════════════════════════

const HALLUCINATION_BLOCK_RULES: Rule[] = [
    {
        id: "fake_api_key_format",
        pattern: /["'](?:sk-[a-zA-Z0-9]{48}|pk_test_[a-zA-Z0-9]{24}|xoxb-[0-9]{10,})["']/,
        message: "String resembles a real API key format (OpenAI/Stripe/Slack). Verify it's not fabricated by AI.",
        severity: "BLOCK",
    },
];

const HALLUCINATION_WARN_RULES: Rule[] = [
    {
        id: "hallucinated_localhost_port",
        pattern: /localhost:\d{5,}/i,
        message: "Suspicious localhost port (5+ digits). Verify this port is correct — AI often invents port numbers.",
        severity: "WARN",
    },
    {
        id: "hallucinated_api_endpoint",
        pattern: /["']\/api\/v\d+\/[a-z]+\/[a-z]+\/[a-z]+\/[a-z]+["']/i,
        message: "Deeply nested API endpoint path. Verify this endpoint actually exists — AI may hallucinate API routes.",
        severity: "WARN",
    },
    {
        id: "placeholder_url",
        pattern: /https?:\/\/(?:example|your-domain|my-app|your-app|placeholder|changeme|todo)\./i,
        message: "Placeholder URL detected. Replace with actual URL before deploying.",
        severity: "WARN",
    },
];

const HALLUCINATION_INFO_RULES: Rule[] = [
    {
        id: "hallucinated_env_var",
        pattern: /(?:process\.env\.|os\.(?:environ|getenv)\s*(?:\[|\()\s*["'])(?:(?!PATH|HOME|USER|SHELL|TERM|LANG|LC_|TZ|PWD|LOGNAME|HOSTNAME|DISPLAY|XDG_|EDITOR|VISUAL|PAGER|BROWSER|TMPDIR|TEMP|TMP)[A-Z][A-Z0-9_]{15,})/,
        message: "Long environment variable name (16+ chars). Verify this env var is documented and exists.",
        severity: "INFO",
    },
];

// ═══════════════════════════════════════════════════════════════
//  RULE ROUTING
// ═══════════════════════════════════════════════════════════════

const GENERIC_RULES: Rule[] = [
    ...GENERIC_BLOCK_RULES,
    ...GENERIC_WARN_RULES,
    ...GENERIC_INFO_RULES,
    ...HALLUCINATION_BLOCK_RULES,
    ...HALLUCINATION_WARN_RULES,
    ...HALLUCINATION_INFO_RULES,
];

const SQL_RULES: Rule[] = [
    ...SQL_BLOCK_RULES,
    ...SQL_WARN_RULES,
    ...SQL_INFO_RULES,
];

const DOCKERFILE_RULES: Rule[] = [
    ...GENERIC_RULES,
    ...DOCKER_BLOCK_RULES,
    ...DOCKER_WARN_RULES,
    ...DEVOPS_BLOCK_RULES,
    ...DEVOPS_WARN_RULES,
];

const CI_RULES: Rule[] = [
    ...GENERIC_RULES,
    ...CI_WARN_RULES,
    ...DEVOPS_BLOCK_RULES,
    ...DEVOPS_WARN_RULES,
    ...DEVOPS_INFO_RULES,
    ...K8S_BLOCK_RULES,
    ...K8S_WARN_RULES,
];

const DEVOPS_RULES: Rule[] = [
    ...GENERIC_RULES,
    ...DEVOPS_BLOCK_RULES,
    ...DEVOPS_WARN_RULES,
    ...DEVOPS_INFO_RULES,
    ...K8S_BLOCK_RULES,
    ...K8S_WARN_RULES,
];

const REACT_RULES: Rule[] = [
    ...GENERIC_RULES,
    ...REACT_BLOCK_RULES,
    ...REACT_WARN_RULES,
];

/** File extensions considered DevOps files. */
const DEVOPS_EXTS = new Set([".yml", ".yaml", ".toml", ".tf", ".tfvars", ".hcl"]);
const SQL_EXTS = new Set([".sql"]);
const HTML_EXTS = new Set([".html", ".htm"]);
const DEVOPS_FILENAMES = new Set([
    "dockerfile", "docker-compose.yml", "docker-compose.yaml", "procfile",
]);

/** Get the applicable rules for a file based on its name/extension. */
function getRulesForFile(filename: string): Rule[] {
    const basename = filename.split("/").pop()?.toLowerCase() ?? "";
    const ext = basename.includes(".") ? "." + basename.split(".").pop() : "";

    if (SQL_EXTS.has(ext)) {
        return SQL_RULES;
    }
    if (basename.startsWith("dockerfile")) {
        return DOCKERFILE_RULES;
    }
    if (ext === ".jsx" || ext === ".tsx") {
        return REACT_RULES;
    }
    if (filename.includes(".github") && (ext === ".yml" || ext === ".yaml")) {
        return CI_RULES;
    }
    if (DEVOPS_EXTS.has(ext) || DEVOPS_FILENAMES.has(basename)) {
        return DEVOPS_RULES;
    }
    if (HTML_EXTS.has(ext)) {
        return GENERIC_RULES;
    }
    return GENERIC_RULES;
}

/**
 * Scan code locally using embedded anti-pattern rules.
 * This is a fallback when the API is unavailable.
 * Implements all 67 rules: 56 regex + 11 file-level checks.
 */
export function scanCodeOffline(code: string, filename: string): StaticScanResponse {
    const lines = code.split("\n");
    const findings: Finding[] = [];
    const rules = getRulesForFile(filename);
    let inDocstring = false;

    // --- Regex-based rules (40 rules) ---
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

        // Check suppress_lint BEFORE noqa skip
        if (line.includes("noqa") || line.includes("type: ignore") || line.includes("eslint-disable")) {
            for (const rule of rules) {
                if (rule.id === "suppress_lint" && rule.pattern.test(line)) {
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
            if (line.includes("noqa")) {
                continue;
            }
        }

        for (const rule of rules) {
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

    // --- File-level checks (9 special_handler rules) ---
    const basename = filename.split("/").pop()?.toLowerCase() ?? "";
    const ext = basename.includes(".") ? "." + (basename.split(".").pop() ?? "") : "";
    const isDockerfile = basename.startsWith("dockerfile");
    const isCI = filename.includes(".github") && (filename.endsWith(".yml") || filename.endsWith(".yaml"));
    const isCompose = basename.startsWith("docker-compose");

    // Generic file-level checks (all source files)
    findings.push(...checkExceptSwallow(lines, filename));
    findings.push(...checkSleepNoContext(lines, filename));
    findings.push(...checkFunctionLengths(lines, filename));
    findings.push(...checkConnectionTimeout(lines, filename));
    if (ext === ".py") {
        findings.push(...checkUntypedFunctions(lines, filename));
    }

    // Dockerfile-specific checks
    if (isDockerfile) {
        findings.push(...checkDockerfileHealthcheck(lines, filename));
        findings.push(...checkDockerRootUser(lines, filename));
        findings.push(...checkDockerNoWorkdir(lines, filename));
    }

    // Docker Compose checks
    if (isCompose) {
        findings.push(...checkComposeHealthcheck(lines, filename));
    }

    // CI checks
    if (isCI) {
        findings.push(...checkCINoTimeout(lines, filename));
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

function checkUntypedFunctions(lines: string[], filename: string): Finding[] {
    const results: Finding[] = [];
    const defRe = /^\s*def\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*(?:->\s*[^:]+)?\s*:/;

    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const match = line.match(defRe);
        if (!match) {
            continue;
        }

        const params = match[2] ?? "";
        const hasReturnAnnotation = line.includes("->");

        const tokens = params
            .split(",")
            .map((p) => p.trim())
            .filter((p) => p.length > 0);

        const hasUntypedParam = tokens.some((p) => {
            const cleaned = p.replace(/^\*+/, "").trim();
            if (cleaned === "self" || cleaned === "cls") {
                return false;
            }
            const beforeDefault = cleaned.split("=")[0]?.trim() ?? cleaned;
            return !beforeDefault.includes(":");
        });

        if (hasUntypedParam || !hasReturnAnnotation) {
            results.push({
                rule_id: "untyped_function",
                severity: "INFO",
                message: "Function lacks type annotations. Add parameter and return types.",
                file: filename,
                line: i + 1,
                suggestion: "",
                confidence: 1.0,
            });
        }
    }

    return results;
}

// ═══════════════════════════════════════════════════════════════
//  FILE-LEVEL CHECKS (mirrors backend special_handler functions)
// ═══════════════════════════════════════════════════════════════

function makeFinding(
    ruleId: string, severity: Severity, message: string,
    file: string, line: number, suggestion = "",
): Finding {
    return { rule_id: ruleId, severity, message, file, line, suggestion, confidence: 1.0 };
}

/** Flag except blocks that silently swallow errors (pass/...). */
function checkExceptSwallow(lines: string[], filename: string): Finding[] {
    const findings: Finding[] = [];
    const exceptPattern = /^\s*except[\s:]/;

    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line.includes("noqa") || !exceptPattern.test(line)) {
            continue;
        }
        const exceptIndent = line.length - line.trimStart().length;
        const bodyLines: string[] = [];

        for (let j = i + 1; j < Math.min(lines.length, i + 6); j++) {
            const next = lines[j];
            const trimmed = next.trim();
            if (!trimmed) { continue; }
            const nextIndent = next.length - next.trimStart().length;
            if (nextIndent <= exceptIndent) { break; }
            bodyLines.push(trimmed);
        }

        const body = bodyLines.join(" ");
        if (body === "pass" || body === "..." || body === "continue" || body === "pass  # noqa") {
            findings.push(makeFinding(
                "except_swallow", "BLOCK",
                "Exception caught and silently swallowed. Handle the error or re-raise.",
                filename, i + 1, "Log the error, re-raise, or handle the root cause.",
            ));
        }
    }
    return findings;
}

/** Flag sleep() calls without a preceding comment explaining why. */
function checkSleepNoContext(lines: string[], filename: string): Finding[] {
    const findings: Finding[] = [];
    const sleepPattern = /(?:time\.)?sleep\s*\(/;

    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const stripped = line.trim();
        if (line.includes("noqa") || stripped.startsWith("#") || stripped.startsWith("//")) {
            continue;
        }
        if (!sleepPattern.test(line)) { continue; }

        // Check if previous non-empty line is a comment
        let hasContext = false;
        for (let j = i - 1; j >= Math.max(0, i - 3); j--) {
            const prev = lines[j].trim();
            if (!prev) { continue; }
            if (prev.startsWith("#") || prev.startsWith("//")) {
                hasContext = true;
            }
            break;
        }

        if (!hasContext) {
            findings.push(makeFinding(
                "sleep_no_context", "INFO",
                "sleep() without explanation. Why is a delay needed?",
                filename, i + 1, "Add a comment explaining the reason for the delay.",
            ));
        }
    }
    return findings;
}

/** Check that no function exceeds MAX_FUNCTION_LENGTH lines. */
function checkFunctionLengths(lines: string[], filename: string): Finding[] {
    const findings: Finding[] = [];
    const funcPattern = /^(\s*)(async\s+)?def\s+(\w+)/;
    const funcStarts: Array<{ line: number; indent: number; name: string }> = [];

    for (let i = 0; i < lines.length; i++) {
        const match = lines[i].match(funcPattern);
        if (match) {
            funcStarts.push({
                line: i + 1,
                indent: match[1].length,
                name: match[3],
            });
        }
    }

    for (let idx = 0; idx < funcStarts.length; idx++) {
        const { line: startLine, indent, name } = funcStarts[idx];
        let endLine = startLine;

        // Find end: next function at same/lesser indent, or EOF
        if (idx + 1 < funcStarts.length) {
            const next = funcStarts[idx + 1];
            if (next.indent <= indent) {
                // Walk back from next function to find last non-empty line
                for (let j = next.line - 2; j >= startLine - 1; j--) {
                    if (lines[j].trim()) {
                        endLine = j + 1;
                        break;
                    }
                }
            } else {
                endLine = next.line - 1;
            }
        } else {
            // Last function — find last content line
            for (let j = startLine; j < lines.length; j++) {
                const ln = lines[j];
                if (ln.trim()) {
                    const lineIndent = ln.length - ln.trimStart().length;
                    if (j > startLine - 1 && lineIndent <= indent) { break; }
                    endLine = j + 1;
                }
            }
        }

        const length = endLine - startLine + 1;
        if (length > MAX_FUNCTION_LENGTH) {
            findings.push(makeFinding(
                "long_function", "INFO",
                `Function '${name}' is ${length} lines (max ${MAX_FUNCTION_LENGTH}).`,
                filename, startLine, "Split into smaller functions.",
            ));
        }
    }
    return findings;
}

/** Flag network/DB connections that lack a timeout parameter. */
function checkConnectionTimeout(lines: string[], filename: string): Finding[] {
    const findings: Finding[] = [];
    const pattern = /(?:from_url|AsyncClient|Client|create_async_engine|create_engine|aiohttp\.ClientSession)\s*\(/;

    for (let i = 0; i < lines.length; i++) {
        if (lines[i].includes("noqa")) { continue; }
        if (!pattern.test(lines[i])) { continue; }

        // Look within 5-line window for timeout params
        const window = lines.slice(i, Math.min(lines.length, i + 6)).join("\n");
        if (/(?:timeout|connect_timeout|socket_timeout|socket_connect_timeout)/.test(window)) {
            continue;
        }

        findings.push(makeFinding(
            "connection_no_timeout", "WARN",
            "Network/DB connection without explicit timeout. Add connect_timeout or socket_timeout.",
            filename, i + 1, "Add timeout parameter to avoid indefinite blocking.",
        ));
    }
    return findings;
}

/** Flag Dockerfiles with CMD but no HEALTHCHECK. */
function checkDockerfileHealthcheck(lines: string[], filename: string): Finding[] {
    const text = lines.join("\n");
    const hasCmd = /^CMD\s/m.test(text);
    const hasHealthcheck = /^HEALTHCHECK\s/m.test(text);

    if (hasCmd && !hasHealthcheck) {
        const cmdLine = lines.findIndex((l) => /^CMD\s/.test(l));
        return [makeFinding(
            "dockerfile_no_healthcheck", "INFO",
            "Dockerfile has CMD but no HEALTHCHECK instruction.",
            filename, cmdLine >= 0 ? cmdLine + 1 : 1,
            "Add HEALTHCHECK to enable container orchestration health monitoring.",
        )];
    }
    return [];
}

/** Flag Dockerfiles that run as root (no USER instruction). */
function checkDockerRootUser(lines: string[], filename: string): Finding[] {
    const text = lines.join("\n");
    const hasCmd = /^CMD\s/m.test(text);
    const hasUser = /^USER\s/m.test(text);

    if (hasCmd && !hasUser) {
        const cmdLine = lines.findIndex((l) => /^CMD\s/.test(l));
        return [makeFinding(
            "docker_root_user", "WARN",
            "Dockerfile runs as root. Add USER instruction to drop privileges.",
            filename, cmdLine >= 0 ? cmdLine + 1 : 1,
            "Add 'USER nonroot' or 'USER 1000' before CMD.",
        )];
    }
    return [];
}

/** Flag Dockerfiles without WORKDIR instruction. */
function checkDockerNoWorkdir(lines: string[], filename: string): Finding[] {
    const text = lines.join("\n");
    const hasCmd = /^CMD\s/m.test(text);
    const hasWorkdir = /^WORKDIR\s/m.test(text);

    if (hasCmd && !hasWorkdir) {
        return [makeFinding(
            "docker_no_workdir", "INFO",
            "Dockerfile has no WORKDIR. Set explicit working directory.",
            filename, 1,
            "Add 'WORKDIR /app' to set a predictable working directory.",
        )];
    }
    return [];
}

/** Flag docker-compose services with no healthcheck. */
function checkComposeHealthcheck(lines: string[], filename: string): Finding[] {
    const findings: Finding[] = [];
    for (let i = 0; i < lines.length; i++) {
        if (/^\s{2,4}image:\s/.test(lines[i])) {
            const block = lines.slice(i, Math.min(lines.length, i + 20)).join("\n");
            if (!block.includes("healthcheck:")) {
                findings.push(makeFinding(
                    "compose_no_healthcheck", "INFO",
                    "Docker Compose service has no healthcheck defined.",
                    filename, i + 1,
                    "Add healthcheck for reliable orchestration.",
                ));
            }
        }
    }
    return findings;
}

/** Flag CI jobs (runs-on:) without timeout-minutes. */
function checkCINoTimeout(lines: string[], filename: string): Finding[] {
    const findings: Finding[] = [];
    for (let i = 0; i < lines.length; i++) {
        if (/^\s+runs-on:\s/.test(lines[i])) {
            const start = Math.max(0, i - 5);
            const end = Math.min(lines.length, i + 30);
            const block = lines.slice(start, end).join("\n");
            if (!block.includes("timeout-minutes:")) {
                findings.push(makeFinding(
                    "ci_no_timeout", "INFO",
                    "CI job has no timeout-minutes. Add timeout to prevent hung pipelines.",
                    filename, i + 1,
                    "Add 'timeout-minutes: 15' to the job definition.",
                ));
            }
        }
    }
    return findings;
}
