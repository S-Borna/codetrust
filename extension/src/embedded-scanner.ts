// Copyright (c) Said Borna. All rights reserved.
// Proprietary — see LICENSE for terms.
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
        id: "todo_hack",
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
        pattern: new RegExp("\\w\\s*\\x3F[^;]*\\w\\s*\\x3F"),
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
        id: "quality_broad_exception_type",
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
        pattern: /(^|[^=])\s[2-9]\d{2,}\b/,
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
        pattern: new RegExp(
            "(api[_-]{0,1}key|secret[_-]{0,1}key|auth[_-]{0,1}token)\\s*[:=]\\s*[\"']{0,1}[^\\s\"']{8,}",
            "i",
        ),
        message: "API key or secret in config file. Use environment variables.",
        severity: "BLOCK",
        fileTypes: [".yml", ".yaml", ".toml", ".json"],
    },
];

const DEVOPS_WARN_RULES: Rule[] = [
    {
        id: "hardcoded_ip",
        pattern: new RegExp(
            "\\b((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]{0,1}\\d)\\.){3}(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]{0,1}\\d)\\b",
        ),
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
        pattern: /key\s*=\s*(\{|)\s*(index|idx|i)\s*(\}|)/,
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
//  RUBY RULES
// ═══════════════════════════════════════════════════════════════

const RUBY_BLOCK_RULES: Rule[] = [
    {
        id: "ruby_system_exec",
        pattern: /\b(?:system|exec|`[^`]+`|%x\{)/,
        message: "Shell execution in Ruby. Use safe alternatives or sanitize input.",
        severity: "BLOCK",
        fileTypes: [".rb"],
    },
    {
        id: "ruby_eval",
        pattern: /\b(?:eval|class_eval|module_eval|instance_eval)\s*[({]/,
        message: "Dynamic code evaluation in Ruby. Avoid eval — use safe alternatives.",
        severity: "BLOCK",
        fileTypes: [".rb"],
    },
];

const RUBY_WARN_RULES: Rule[] = [
    {
        id: "ruby_global_variable",
        pattern: /\$[A-Za-z_]\w*\s*=/,
        message: "Global variable assignment. Use constants or dependency injection.",
        severity: "WARN",
        fileTypes: [".rb"],
    },
    {
        id: "ruby_rescue_all",
        pattern: /rescue\s*$/,
        message: "Bare rescue catches all exceptions. Rescue specific exception classes.",
        severity: "WARN",
        fileTypes: [".rb"],
    },
];

// ═══════════════════════════════════════════════════════════════
//  PHP RULES
// ═══════════════════════════════════════════════════════════════

const PHP_BLOCK_RULES: Rule[] = [
    {
        id: "php_eval",
        pattern: new RegExp("\\b" + "eval" + "\\s*\\("),
        message: "ev" + "al() is a critical security risk. Use safe alternatives.",
        severity: "BLOCK",
        fileTypes: [".php"],
    },
    {
        id: "php_sql_injection",
        pattern: /\$(?:_GET|_POST|_REQUEST)\s*\[.*\]\s*[^;]*(?:query|execute|prepare)/,
        message: "User input in SQL query without parameterization.",
        severity: "BLOCK",
        fileTypes: [".php"],
    },
];

const PHP_WARN_RULES: Rule[] = [
    {
        id: "php_error_suppression",
        pattern: /@\$?\w+/,
        message: "Error suppression operator (@) hides problems. Handle errors explicitly.",
        severity: "WARN",
        fileTypes: [".php"],
    },
    {
        id: "php_global_statement",
        pattern: /\bglobal\s+\$/,
        message: "global keyword creates hidden dependencies. Use dependency injection.",
        severity: "WARN",
        fileTypes: [".php"],
    },
];

// ═══════════════════════════════════════════════════════════════
//  POWERSHELL RULES
// ═══════════════════════════════════════════════════════════════

const PS_BLOCK_RULES: Rule[] = [
    {
        id: "ps_invoke_expression",
        pattern: /\bInvoke-Expression\b/i,
        message: "Invoke-Expression is a code injection risk. Use direct cmdlet calls.",
        severity: "BLOCK",
        fileTypes: [".ps1", ".psm1"],
    },
    {
        id: "ps_execution_policy_bypass",
        pattern: /Set-ExecutionPolicy\s+(?:Bypass|Unrestricted)/i,
        message: "Execution policy bypass weakens PowerShell security controls.",
        severity: "BLOCK",
        fileTypes: [".ps1", ".psm1"],
    },
    {
        id: "ps_plaintext_credential",
        pattern: /ConvertTo-SecureString\s+.*-AsPlainText/i,
        message: "Plaintext password converted to SecureString. Use credential store.",
        severity: "BLOCK",
        fileTypes: [".ps1", ".psm1"],
    },
    {
        id: "ps_hardcoded_password",
        pattern: /\$(?:password|passwd|secret|token)\s*=\s*["'][^"']+["']/i,
        message: "Hardcoded credential in script. Use SecretManagement module or env vars.",
        severity: "BLOCK",
        fileTypes: [".ps1", ".psm1"],
    },
];

const PS_WARN_RULES: Rule[] = [
    {
        id: "ps_write_host",
        pattern: /\bWrite-Host\b/i,
        message: "Write-Host bypasses pipeline. Use Write-Output or Write-Verbose.",
        severity: "WARN",
        fileTypes: [".ps1", ".psm1"],
    },
    {
        id: "ps_catch_empty",
        pattern: /catch\s*\{[\s\r\n]*\}/i,
        message: "Empty catch block swallows errors. Log or re-throw exceptions.",
        severity: "WARN",
        fileTypes: [".ps1", ".psm1"],
    },
    {
        id: "ps_no_strict_mode",
        pattern: /^(?!.*Set-StrictMode)/,
        message: "No Set-StrictMode found. Add Set-StrictMode -Version Latest for safety.",
        severity: "WARN",
        fileTypes: [".ps1", ".psm1"],
    },
    {
        id: "ps_net_webclient",
        pattern: /New-Object\s+(?:System\.Net\.)?WebClient/i,
        message: "Net.WebClient is legacy. Use Invoke-RestMethod or Invoke-WebRequest.",
        severity: "WARN",
        fileTypes: [".ps1", ".psm1"],
    },
];

const PS_INFO_RULES: Rule[] = [
    {
        id: "ps_sleep_unbounded",
        pattern: /Start-Sleep\s+-(?:Seconds|Milliseconds)\s+\d{3,}/i,
        message: "Long sleep duration. Consider event-based waiting or reduce timeout.",
        severity: "INFO",
        fileTypes: [".ps1", ".psm1"],
    },
    {
        id: "ps_rm_recurse_force",
        pattern: /Remove-Item\s+.*-Recurse\s+.*-Force/i,
        message: "Recursive forced deletion. Verify path to prevent accidental data loss.",
        severity: "INFO",
        fileTypes: [".ps1", ".psm1"],
    },
];

// ═══════════════════════════════════════════════════════════════
//  NGINX RULES
// ═══════════════════════════════════════════════════════════════

const NGINX_BLOCK_RULES: Rule[] = [
    {
        id: "nginx_server_tokens_on",
        pattern: /server_tokens\s+on/i,
        message: "server_tokens on leaks Nginx version. Set server_tokens off.",
        severity: "BLOCK",
        fileTypes: [".conf"],
    },
    {
        id: "nginx_autoindex_on",
        pattern: /autoindex\s+on/i,
        message: "autoindex on exposes directory listing. Set autoindex off.",
        severity: "BLOCK",
        fileTypes: [".conf"],
    },
    {
        id: "nginx_ssl_v3",
        pattern: /ssl_protocols\s+[^;]*SSLv3/i,
        message: "SSLv3 is insecure (POODLE). Remove SSLv3 from ssl_protocols.",
        severity: "BLOCK",
        fileTypes: [".conf"],
    },
];

const NGINX_WARN_RULES: Rule[] = [
    {
        id: "nginx_root_in_location",
        pattern: /location\s+[^{]*\{[^}]*\broot\b/,
        message: "root inside location block. Place root in server block to avoid path traversal.",
        severity: "WARN",
        fileTypes: [".conf"],
    },
    {
        id: "nginx_no_rate_limit",
        pattern: /server\s*\{(?:(?!limit_req).)*\}/s,
        message: "No rate limiting (limit_req) configured. Add rate limiting for DDoS protection.",
        severity: "WARN",
        fileTypes: [".conf"],
    },
];

const NGINX_INFO_RULES: Rule[] = [
    {
        id: "nginx_add_header_missing_always",
        pattern: /add_header\s+(?!.*\balways\b)/,
        message: "add_header without 'always' flag — header not sent on error pages.",
        severity: "INFO",
        fileTypes: [".conf"],
    },
];

// ═══════════════════════════════════════════════════════════════
//  AZURE ARM / BICEP RULES
// ═══════════════════════════════════════════════════════════════

const BICEP_BLOCK_RULES: Rule[] = [
    {
        id: "bicep_no_secure_param",
        pattern: /param\s+\w*(?:password|secret|key)\w*\s+string\b(?!.*@secure)/i,
        message: "Sensitive parameter without @secure() decorator. Add @secure().",
        severity: "BLOCK",
        fileTypes: [".bicep"],
    },
    {
        id: "bicep_http_only",
        pattern: /httpsOnly:\s*false/i,
        message: "HTTPS disabled. Set httpsOnly: true for secure transport.",
        severity: "BLOCK",
        fileTypes: [".bicep"],
    },
];

const BICEP_WARN_RULES: Rule[] = [
    {
        id: "bicep_public_network",
        pattern: /publicNetworkAccess:\s*(['"]|)Enabled(['"]|)/i,
        message: "Public network access enabled. Use private endpoints.",
        severity: "WARN",
        fileTypes: [".bicep"],
    },
];

// ═══════════════════════════════════════════════════════════════
//  REDIS CONFIGURATION RULES
// ═══════════════════════════════════════════════════════════════

const REDIS_BLOCK_RULES: Rule[] = [
    {
        id: "redis_protected_mode_off",
        pattern: /^\s*protected-mode\s+no/,
        message: "Redis protected mode disabled. Enable protected-mode to reject external connections without auth.",
        severity: "BLOCK",
        fileTypes: [".conf"],
    },
    {
        id: "redis_weak_password",
        pattern: /^\s*requirepass\s+(?:redis|password|admin|test|default|changeme|1234|pass|foobared)\s*$/i,
        message: "Weak or default Redis password. Use a strong, randomly generated password.",
        severity: "BLOCK",
        fileTypes: [".conf"],
    },
];

const REDIS_WARN_RULES: Rule[] = [
    {
        id: "redis_bind_all",
        pattern: /^\s*bind\s+(?:0\.0\.0\.0|\*)/,
        message: "Redis bound to all interfaces. Bind to 127.0.0.1 or specific IPs in production.",
        severity: "WARN",
        fileTypes: [".conf"],
    },
    {
        id: "redis_maxmemory_noeviction",
        pattern: /^\s*maxmemory-policy\s+noeviction/i,
        message: "noeviction policy causes write errors when memory is full. Use allkeys-lru or volatile-lru.",
        severity: "WARN",
        fileTypes: [".conf"],
    },
    {
        id: "redis_save_disabled",
        pattern: /^\s*save\s+""/,
        message: "RDB snapshots disabled. Ensure AOF is enabled or data loss on restart is acceptable.",
        severity: "WARN",
        fileTypes: [".conf"],
    },
    {
        id: "redis_aof_no_fsync",
        pattern: /^\s*appendfsync\s+no\b/i,
        message: "Redis AOF without fsync risks data loss on crash. Use appendfsync everysec or always.",
        severity: "WARN",
        fileTypes: [".conf"],
    },
];

// ═══════════════════════════════════════════════════════════════
//  HASHICORP VAULT RULES
// ═══════════════════════════════════════════════════════════════

const VAULT_BLOCK_RULES: Rule[] = [
    {
        id: "vault_tls_disabled",
        pattern: /tls_disable\s*=\s*(?:1|true|"true")/i,
        message: "Vault TLS disabled. Always enable TLS in production to encrypt client-server communication.",
        severity: "BLOCK",
        fileTypes: [".hcl"],
    },
];

const VAULT_WARN_RULES: Rule[] = [
    {
        id: "vault_file_storage",
        pattern: /storage\s+"file"\s*\{/i,
        message: "Vault using file storage backend. Use Consul, Raft, or cloud storage for HA in production.",
        severity: "WARN",
        fileTypes: [".hcl"],
    },
    {
        id: "vault_disable_mlock",
        pattern: /disable_mlock\s*=\s*(?:true|1|"true")/i,
        message: "Vault mlock disabled. Memory locking prevents secrets from being swapped to disk.",
        severity: "WARN",
        fileTypes: [".hcl"],
    },
    {
        id: "vault_telemetry_unauth",
        pattern: /unauthenticated_metrics_access\s*=\s*(?:true|1|"true")/i,
        message: "Vault metrics exposed without authentication. Set unauthenticated_metrics_access = false.",
        severity: "WARN",
        fileTypes: [".hcl"],
    },
];

const VAULT_INFO_RULES: Rule[] = [
    {
        id: "vault_max_lease_long",
        pattern: /max_lease_ttl\s*=\s*"\d{4,}h"/i,
        message: "Very long Vault max lease TTL (1000+ hours). Short-lived leases reduce exposure.",
        severity: "INFO",
        fileTypes: [".hcl"],
    },
];

// ═══════════════════════════════════════════════════════════════
//  PROMETHEUS / GRAFANA MONITORING RULES
// ═══════════════════════════════════════════════════════════════

const MONITORING_BLOCK_RULES: Rule[] = [
    {
        id: "grafana_anon_access",
        pattern: /GF_AUTH_ANONYMOUS_ENABLED\s*=\s*true/i,
        message: "Grafana anonymous access enabled. Require authentication for dashboard access in production.",
        severity: "BLOCK",
        fileTypes: [".yml", ".yaml"],
    },
    {
        id: "grafana_default_admin",
        pattern: /GF_SECURITY_ADMIN_PASSWORD\s*=\s*(?:admin|password|grafana|test|changeme|default)/i,
        message: "Weak or default Grafana admin password. Use a strong, unique password.",
        severity: "BLOCK",
        fileTypes: [".yml", ".yaml"],
    },
];

const MONITORING_WARN_RULES: Rule[] = [
    {
        id: "prom_scrape_too_fast",
        pattern: /scrape_interval:\s*[1-4]s\b/i,
        message: "Prometheus scrape interval under 5s may overload targets. Use 15s-60s.",
        severity: "WARN",
        fileTypes: [".yml", ".yaml"],
    },
    {
        id: "grafana_allow_embedding",
        pattern: /GF_SECURITY_ALLOW_EMBEDDING\s*=\s*true/i,
        message: "Grafana allow_embedding enables iframe embedding, creating a clickjacking risk.",
        severity: "WARN",
        fileTypes: [".yml", ".yaml"],
    },
];

const MONITORING_INFO_RULES: Rule[] = [
    {
        id: "prom_eval_too_fast",
        pattern: /evaluation_interval:\s*[1-4]s\b/i,
        message: "Prometheus evaluation interval under 5s is aggressive. Use 15s-60s.",
        severity: "INFO",
        fileTypes: [".yml", ".yaml"],
    },
];

// ═══════════════════════════════════════════════════════════════
//  SYSTEMD UNIT FILE RULES
// ═══════════════════════════════════════════════════════════════

const SYSTEMD_WARN_RULES: Rule[] = [
    {
        id: "systemd_restart_disabled",
        pattern: /^\s*Restart\s*=\s*no\s*$/i,
        message: "Systemd service will not restart on failure. Set Restart=on-failure.",
        severity: "WARN",
        fileTypes: [".service", ".timer"],
    },
    {
        id: "systemd_restart_no_delay",
        pattern: /^\s*RestartSec\s*=\s*0\s*$/i,
        message: "RestartSec=0 causes immediate restart loops. Set RestartSec=5 or higher.",
        severity: "WARN",
        fileTypes: [".service", ".timer"],
    },
    {
        id: "systemd_unlimited_resource",
        pattern: /^\s*(?:LimitNOFILE|LimitNPROC)\s*=\s*(?:infinity|unlimited)/i,
        message: "Unlimited resource limit. Set bounded limits to prevent resource exhaustion.",
        severity: "WARN",
        fileTypes: [".service", ".timer"],
    },
];

const SYSTEMD_INFO_RULES: Rule[] = [
    {
        id: "systemd_exec_shell_wrapper",
        pattern: /^\s*ExecStart\s*=\s*\/(?:bin|usr\/bin)\/(?:ba)?sh\s+-c\s+/i,
        message: "Shell wrapper in ExecStart. Use direct binary path for cleaner signal handling.",
        severity: "INFO",
        fileTypes: [".service", ".timer"],
    },
    {
        id: "systemd_no_timeout_stop",
        pattern: /^\s*TimeoutStopSec\s*=\s*(?:infinity|0)\s*$/i,
        message: "No stop timeout. Set TimeoutStopSec to prevent zombie processes.",
        severity: "INFO",
        fileTypes: [".service", ".timer"],
    },
];

// ═══════════════════════════════════════════════════════════════
//  DOCKER COMPOSE ADVANCED RULES
// ═══════════════════════════════════════════════════════════════

const COMPOSE_BLOCK_RULES: Rule[] = [
    {
        id: "compose_env_inline_secret",
        pattern: /^\s+-\s*(?:DB_PASSWORD|MYSQL_ROOT_PASSWORD|POSTGRES_PASSWORD|REDIS_PASSWORD|SECRET_KEY|API_SECRET|MONGO_INITDB_ROOT_PASSWORD)\s*=\s*\S{4,}/i,
        message: "Secret value inline in Docker Compose environment. Use env_file or Docker secrets.",
        severity: "BLOCK",
        fileTypes: [".yml", ".yaml"],
    },
];

const COMPOSE_WARN_RULES: Rule[] = [
    {
        id: "compose_ipc_host",
        pattern: /^\s+ipc:\s*["']?host/i,
        message: "Docker Compose IPC set to host, breaking container isolation.",
        severity: "WARN",
        fileTypes: [".yml", ".yaml"],
    },
    {
        id: "compose_network_host",
        pattern: /^\s+network_mode:\s*["']?host/i,
        message: "Host network mode bypasses container isolation. Use bridge networking.",
        severity: "WARN",
        fileTypes: [".yml", ".yaml"],
    },
    {
        id: "compose_pid_host",
        pattern: /^\s+pid:\s*["']?host/i,
        message: "PID mode set to host. This exposes host processes to the container.",
        severity: "WARN",
        fileTypes: [".yml", ".yaml"],
    },
];

const COMPOSE_INFO_RULES: Rule[] = [
    {
        id: "compose_restart_always",
        pattern: /^\s+restart:\s*["']?always/i,
        message: "restart: always restarts even after manual stop. Use unless-stopped.",
        severity: "INFO",
        fileTypes: [".yml", ".yaml"],
    },
];

// ═══════════════════════════════════════════════════════════════
//  GITHUB ACTIONS ADVANCED RULES
// ═══════════════════════════════════════════════════════════════

const CI_BLOCK_RULES: Rule[] = [
    {
        id: "ci_pull_request_target",
        pattern: /^\s+pull_request_target:/i,
        message: "pull_request_target runs with write permissions on fork PRs. Use pull_request + workflow_run.",
        severity: "BLOCK",
        fileTypes: [".yml", ".yaml"],
    },
    {
        id: "ci_write_all_permissions",
        pattern: /^\s+permissions:\s*write-all/i,
        message: "write-all grants excessive CI permissions. Scope to specific permissions.",
        severity: "BLOCK",
        fileTypes: [".yml", ".yaml"],
    },
    {
        id: "ci_curl_pipe_shell",
        pattern: /curl\s+.*\|\s*(?:ba)?sh/i,
        message: "Piping curl to shell in CI is unsafe. Download, verify checksum, then execute.",
        severity: "BLOCK",
        fileTypes: [".yml", ".yaml"],
    },
    {
        id: "ci_inject_untrusted_input",
        pattern: /\$\{\{\s*github\.event\.(?:issue|comment|pull_request|review|discussion)\.(?:title|body)\s*\}\}/,
        message: "Untrusted GitHub event data in expression. This enables command injection.",
        severity: "BLOCK",
        fileTypes: [".yml", ".yaml"],
    },
];

const CI_ADV_WARN_RULES: Rule[] = [
    {
        id: "ci_checkout_persist_creds",
        pattern: /persist-credentials:\s*true/i,
        message: "Persisting Git credentials in CI. Set persist-credentials: false.",
        severity: "WARN",
        fileTypes: [".yml", ".yaml"],
    },
];

// ═══════════════════════════════════════════════════════════════
//  GENERAL CONFIG HYGIENE RULES
// ═══════════════════════════════════════════════════════════════

const CONFIG_BLOCK_RULES: Rule[] = [
    {
        id: "config_ssl_verify_off",
        pattern: new RegExp(
            "(ssl[_-]{0,1}verify|verify[_-]{0,1}ssl|tls[_-]{0,1}verify)\\s*[:=]\\s*(false|0|no|off)\\b",
            "i",
        ),
        message: "SSL/TLS certificate verification disabled. This enables man-in-the-middle attacks.",
        severity: "BLOCK",
    },
    {
        id: "config_private_key_inline",
        pattern: /-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----/,
        message: "Private key embedded in config file. Store keys in secure vaults.",
        severity: "BLOCK",
    },
];

const CONFIG_WARN_RULES: Rule[] = [
    {
        id: "config_weak_tls_version",
        pattern: new RegExp(
            "(tls[_-]{0,1}(min[_-]{0,1}){0,1}version|ssl[_-]{0,1}version|min[_-]{0,1}protocol)\\s*[:=]\\s*[\"']{0,1}(1\\.[01]|TLSv1[^.2]|SSLv[23])",
            "i",
        ),
        message: "Legacy TLS/SSL version configured. Use TLS 1.2 or 1.3 only.",
        severity: "WARN",
    },
    {
        id: "config_world_writable",
        pattern: /(chmod|mode)\s*[:=]{0,1}\s*(0{0,1}777|a\+rwx)\b/i,
        message: "World-writable permission (777). Restrict file permissions to owner and group.",
        severity: "WARN",
    },
    {
        id: "config_listen_all_interfaces",
        pattern: new RegExp(
            "(listen[_-]{0,1}address|bind[_-]{0,1}address|bind[_-]{0,1}host)\\s*[:=]\\s*[\"']{0,1}0\\.0\\.0\\.0",
            "i",
        ),
        message: "Service listening on all interfaces. Bind to 127.0.0.1 or specific IPs.",
        severity: "WARN",
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
    ...CI_BLOCK_RULES,
    ...CI_WARN_RULES,
    ...CI_ADV_WARN_RULES,
    ...DEVOPS_BLOCK_RULES,
    ...DEVOPS_WARN_RULES,
    ...DEVOPS_INFO_RULES,
    ...K8S_BLOCK_RULES,
    ...K8S_WARN_RULES,
    ...CONFIG_BLOCK_RULES,
    ...CONFIG_WARN_RULES,
];

const DEVOPS_RULES: Rule[] = [
    ...GENERIC_RULES,
    ...DEVOPS_BLOCK_RULES,
    ...DEVOPS_WARN_RULES,
    ...DEVOPS_INFO_RULES,
    ...K8S_BLOCK_RULES,
    ...K8S_WARN_RULES,
    ...MONITORING_BLOCK_RULES,
    ...MONITORING_WARN_RULES,
    ...MONITORING_INFO_RULES,
    ...COMPOSE_BLOCK_RULES,
    ...COMPOSE_WARN_RULES,
    ...COMPOSE_INFO_RULES,
    ...VAULT_BLOCK_RULES,
    ...VAULT_WARN_RULES,
    ...VAULT_INFO_RULES,
    ...CONFIG_BLOCK_RULES,
    ...CONFIG_WARN_RULES,
];

const REACT_RULES: Rule[] = [
    ...GENERIC_RULES,
    ...REACT_BLOCK_RULES,
    ...REACT_WARN_RULES,
];

const RUBY_RULES: Rule[] = [
    ...GENERIC_RULES,
    ...RUBY_BLOCK_RULES,
    ...RUBY_WARN_RULES,
];

const PHP_RULES: Rule[] = [
    ...GENERIC_RULES,
    ...PHP_BLOCK_RULES,
    ...PHP_WARN_RULES,
];

const PS_RULES: Rule[] = [
    ...GENERIC_RULES,
    ...PS_BLOCK_RULES,
    ...PS_WARN_RULES,
    ...PS_INFO_RULES,
    ...DEVOPS_BLOCK_RULES,
    ...DEVOPS_WARN_RULES,
    ...DEVOPS_INFO_RULES,
];

const CONF_RULES: Rule[] = [
    ...NGINX_BLOCK_RULES,
    ...NGINX_WARN_RULES,
    ...NGINX_INFO_RULES,
    ...REDIS_BLOCK_RULES,
    ...REDIS_WARN_RULES,
    ...CONFIG_BLOCK_RULES,
    ...CONFIG_WARN_RULES,
];

const SYSTEMD_RULES: Rule[] = [
    ...SYSTEMD_WARN_RULES,
    ...SYSTEMD_INFO_RULES,
];

const BICEP_RULES: Rule[] = [
    ...GENERIC_RULES,
    ...BICEP_BLOCK_RULES,
    ...BICEP_WARN_RULES,
];

/** File extensions considered DevOps files. */
const DEVOPS_EXTS = new Set([
    ".yml", ".yaml", ".toml", ".tf", ".tfvars", ".hcl",
    ".conf", ".bicep", ".ps1", ".psm1", ".psd1",
    ".service", ".timer", ".ini", ".cfg",
]);
const SQL_EXTS = new Set([".sql"]);
const HTML_EXTS = new Set([".html", ".htm"]);
const DEVOPS_FILENAMES = new Set([
    "dockerfile", "docker-compose.yml", "docker-compose.yaml", "procfile",
]);

/** Get the applicable rules for a file based on its name/extension. */
function getRulesForFile(filename: string): Rule[] {
    const filenameParts = filename.split("/");
    const rawBasename = filenameParts.length > 0 ? filenameParts[filenameParts.length - 1] : "";
    const basename = rawBasename ? rawBasename.toLowerCase() : "";
    let ext = "";
    if (basename.includes(".")) {
        const extPart = basename.split(".").pop();
        if (extPart) {
            ext = "." + extPart;
        }
    }

    if (SQL_EXTS.has(ext)) {
        return SQL_RULES;
    }
    if (basename.startsWith("dockerfile")) {
        return DOCKERFILE_RULES;
    }
    if (ext === ".jsx" || ext === ".tsx") {
        return REACT_RULES;
    }
    if (ext === ".rb") {
        return RUBY_RULES;
    }
    if (ext === ".php") {
        return PHP_RULES;
    }
    if (ext === ".ps1" || ext === ".psm1" || ext === ".psd1") {
        return PS_RULES;
    }
    if (ext === ".conf") {
        return CONF_RULES;
    }
    if (ext === ".service" || ext === ".timer") {
        return SYSTEMD_RULES;
    }
    if (ext === ".bicep") {
        return BICEP_RULES;
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
/**
 * Rule definition files that should be skipped when they exceed
 * MIN_LINES_FOR_RULE_FILE_SKIP lines. These files contain thousands
 * of regex patterns that trigger false positives when scanned.
 */
const RULE_DEFINITION_BASENAMES = new Set([
    "anti_patterns.py",
    "enterprise.py",
    "taint_rules.py",
    "signatures.py",
]);
const MIN_LINES_FOR_RULE_FILE_SKIP = 5000;

/** Check if a file is a rule definition file that should be skipped. */
export function isRuleDefinitionFile(filename: string, lineCount: number): boolean {
    const parts = filename.split(/[/\\]/);
    const base = parts[parts.length - 1]?.toLowerCase() ?? "";
    return RULE_DEFINITION_BASENAMES.has(base) && lineCount > MIN_LINES_FOR_RULE_FILE_SKIP;
}

/**
 * Number of rules in the embedded offline scanner.
 *
 * This is a dynamic count, not a hardcoded number. It must be kept in
 * sync with the rules exported above. Exported so that UI messages
 * (output channel log lines, status bar) can never drift from reality.
 *
 * Backend (Python src/rules/anti_patterns.py) has ~2900 rules. This
 * embedded subset is the offline fallback and covers the most common
 * anti-patterns across Python, JS/TS, SQL, Docker, K8s, Ruby, PHP,
 * PowerShell, nginx, Redis, Vault, Bicep, and systemd.
 */
export const EMBEDDED_RULE_COUNT: number = (
    GENERIC_BLOCK_RULES.length +
    GENERIC_WARN_RULES.length +
    GENERIC_INFO_RULES.length +
    HALLUCINATION_BLOCK_RULES.length +
    HALLUCINATION_WARN_RULES.length +
    HALLUCINATION_INFO_RULES.length +
    SQL_BLOCK_RULES.length +
    SQL_WARN_RULES.length +
    SQL_INFO_RULES.length +
    DOCKER_BLOCK_RULES.length +
    DOCKER_WARN_RULES.length +
    CI_BLOCK_RULES.length +
    CI_WARN_RULES.length +
    CI_ADV_WARN_RULES.length +
    DEVOPS_BLOCK_RULES.length +
    DEVOPS_WARN_RULES.length +
    DEVOPS_INFO_RULES.length +
    REACT_BLOCK_RULES.length +
    REACT_WARN_RULES.length +
    K8S_BLOCK_RULES.length +
    K8S_WARN_RULES.length +
    MONITORING_BLOCK_RULES.length +
    MONITORING_WARN_RULES.length +
    MONITORING_INFO_RULES.length +
    COMPOSE_BLOCK_RULES.length +
    COMPOSE_WARN_RULES.length +
    COMPOSE_INFO_RULES.length +
    VAULT_BLOCK_RULES.length +
    VAULT_WARN_RULES.length +
    VAULT_INFO_RULES.length +
    CONFIG_BLOCK_RULES.length +
    CONFIG_WARN_RULES.length +
    RUBY_BLOCK_RULES.length +
    RUBY_WARN_RULES.length +
    PHP_BLOCK_RULES.length +
    PHP_WARN_RULES.length +
    PS_BLOCK_RULES.length +
    PS_WARN_RULES.length +
    PS_INFO_RULES.length +
    NGINX_BLOCK_RULES.length +
    NGINX_WARN_RULES.length +
    NGINX_INFO_RULES.length +
    REDIS_BLOCK_RULES.length +
    REDIS_WARN_RULES.length +
    SYSTEMD_WARN_RULES.length +
    SYSTEMD_INFO_RULES.length +
    BICEP_BLOCK_RULES.length +
    BICEP_WARN_RULES.length
);

export function scanCodeOffline(code: string, filename: string): StaticScanResponse {
    const lines = code.split("\n");

    // Skip rule definition files — scanning them produces hundreds of FP
    if (isRuleDefinitionFile(filename, lines.length)) {
        return { findings: [], total_findings: 0, blocks: 0, warnings: 0, infos: 0, verdict: "PASS" };
    }

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
    const filenameParts = filename.split("/");
    const rawBasename = filenameParts.length > 0 ? filenameParts[filenameParts.length - 1] : "";
    const basename = rawBasename ? rawBasename.toLowerCase() : "";
    let ext = "";
    if (basename.includes(".")) {
        const extPart = basename.split(".").pop();
        if (extPart) {
            ext = "." + extPart;
        }
    }
    const isDockerfile = basename.startsWith("dockerfile");
    let isCI = false;
    if (filename.includes(".github")) {
        isCI = filename.endsWith(".yml") || filename.endsWith(".yaml");
    }
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
            const split = cleaned.split("=");
            let beforeDefault = cleaned;
            if (split.length > 0 && split[0]) {
                beforeDefault = split[0].trim();
            }
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

