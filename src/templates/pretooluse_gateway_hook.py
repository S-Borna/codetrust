#!/usr/bin/env python3
"""CodeTrust Gateway Hook for Claude Code.

PreToolUse hook that validates Bash commands against Gateway rules
BEFORE execution. Runs outside the agent's control — cannot be bypassed.

Installed by: codetrust init
Location: ~/.claude/hooks/codetrust_gateway_hook.py

Exit 0 = allow, Exit 2 = block (stderr shown as error).

Standalone — no dependencies beyond Python 3.8+ stdlib.
"""

from __future__ import annotations

import json
import re
import sys

# ── Heredoc handling ───────────────────────────────────────────────────────────

_HEREDOC = "<" + "<"  # Prevent self-match when scanning this file
_HEREDOC_RE = re.compile(rf"{_HEREDOC}[-']?\s*[\w\"']+")

_HEREDOC_CONTEXTS: list = [
    (
        re.compile(r"\bgit\s+commit\b"),
        (
            "Write the message to a temp file with the Write tool, then run: "
            "git commit -F /tmp/commit_msg.txt — delete the file after."
        ),
    ),
    (
        re.compile(r"\bgit\s+tag\b"),
        (
            "Write the tag message to a temp file with the Write tool, then run: "
            "git tag -F /tmp/tag_msg.txt <tagname> — delete the file after."
        ),
    ),
    (
        re.compile(r"\b(?:cat|tee)\s+.*>\s*\S+"),
        "Use the Write tool to create the file directly.",
    ),
    (
        re.compile(r"\becho\s+.*>\s*\S+"),
        "Use the Write tool to create the file directly.",
    ),
    (
        re.compile(r"\b(?:ssh|mysql|psql|sqlite3)\b"),
        (
            "Write the commands/query to a temp file with the Write tool, "
            "then pass it via -f or stdin redirect from the file."
        ),
    ),
]


def _heredoc_suggestion(command: str) -> str:
    """Return a context-specific remediation for heredoc usage."""
    for ctx_pattern, suggestion in _HEREDOC_CONTEXTS:
        if ctx_pattern.search(command):
            return suggestion
    return "Use the Write/Edit tool to create or modify files. Never use heredoc."


# ── Interpreter -c/-e inner-string validation ──────────────────────────────────

_INTERPRETER_FLAG_RE = re.compile(
    r"""(?:python(?:\d+(?:\.\d+)*)?|node|ruby|perl)\s+-[ce]\s+(.+)""",
    re.DOTALL,
)

_DANGEROUS_INNER_PATTERNS: list = [
    (re.compile(r"\brm\s+-"), "rm command"),
    (re.compile(r"\brm\b.*-r"), "recursive delete"),
    (re.compile(r"os\.system\s*\("), "os.system() call"),
    (re.compile(r"subprocess\.\w+\s*\("), "subprocess call"),
    (re.compile(r"child_process"), "child_process module"),
    (re.compile(r"execSync\s*\("), "execSync() call"),
    (re.compile(r"\.exec\s*\("), "exec() call"),  # noqa: codetrust — pattern to BLOCK, not usage
    (re.compile(r"\bsystem\s*\("), "system() call"),
    (re.compile(r"\beval\s*\("), "eval() call"),  # noqa: codetrust — pattern to BLOCK, not usage
    (re.compile(r"\bexec\s*\("), "exec() call"),  # noqa: codetrust — pattern to BLOCK, not usage
    (re.compile(r"__import__\s*\("), "__import__() call"),
    (re.compile(r"\bchr\s*\(\s*\d"), "chr() obfuscation"),
    (re.compile(r"\.claude/hooks/"), ".claude/hooks/ path manipulation"),
    (re.compile(r"codetrust_gateway_hook"), "gateway hook file manipulation"),
    (re.compile(r"codetrust_file_write_hook"), "file write hook manipulation"),
    (re.compile(r"\bchmod\s+777"), "chmod 777"),
    (re.compile(r"curl.*\|\s*(?:ba)?sh"), "curl pipe to shell"),
    (re.compile(r"git\s+push"), "git push"),
    (re.compile(r"dd\s+.*of="), "dd write"),
]


def _check_interpreter_inner_string(
    command: str,
) -> tuple | None:
    """Detect dangerous commands embedded inside python3 -c, node -e, etc."""
    match = _INTERPRETER_FLAG_RE.search(command)
    if not match:
        return None
    inner = match.group(1)
    for pattern, description in _DANGEROUS_INNER_PATTERNS:
        if pattern.search(inner):
            return (
                "gateway_interpreter_inner_dangerous",
                f"Dangerous {description} embedded in interpreter -c/-e argument.",
                "Write the code to a file with the Write tool, then run: "
                "python3 /tmp/script.py. Dangerous commands inside -c/-e "
                "bypass outer validation.",
            )
    return None


# ── Blocked patterns ───────────────────────────────────────────────────────────

BLOCKED_PATTERNS: list = [
    # Category 1: File system destruction
    (
        "gateway_rm_rf_root",
        re.compile(r"rm\s+-[rR]f?\s+/(\s|$)"),
        "Recursive delete of root filesystem blocked.",
        "Specify the exact path: rm -rf /path/to/specific/directory.",
    ),
    (
        "gateway_rm_rf_home",
        re.compile(r"rm\s+-[rR]f?\s+~/"),
        "Recursive delete of home directory blocked.",
        "Specify the exact subdirectory: rm -rf ~/project/build/.",
    ),
    (
        "gateway_dd_of_dev",
        re.compile(r"\bdd\s+.*of=/dev/"),
        "Writing to block device blocked.",
        "Write to a regular file path instead.",
    ),
    (
        "gateway_mkfs",
        re.compile(r"\bmkfs\b"),
        "Filesystem format blocked — irreversible data destruction.",
        "Ask the user to run this manually.",
    ),
    (
        "gateway_truncate_system",
        re.compile(r"\btruncate\s+.*(/etc/|/var/|/usr/)"),
        "Truncating system files blocked.",
        "Do not modify system files.",
    ),

    # Category 2: Arbitrary code execution
    (
        "gateway_eval",
        re.compile(r"\beval\s+"),
        "Shell eval blocked — arbitrary code execution risk.",
        "Run the command directly instead of wrapping in eval.",
    ),
    (
        "gateway_curl_pipe_sh",
        re.compile(r"curl\s+.*\|\s*(ba)?sh"),
        "curl piped to shell blocked — remote code execution risk.",
        "Download first: curl -o /tmp/script.sh <URL>. Review, then execute.",
    ),
    (
        "gateway_wget_pipe_sh",
        re.compile(r"wget\s+.*\|\s*(ba)?sh"),
        "wget piped to shell blocked — remote code execution risk.",
        "Download first: wget -O /tmp/script.sh <URL>. Review, then execute.",
    ),
    (
        "gateway_curl_pipe_python",
        re.compile(r"curl\s+.*\|\s*python"),
        "curl piped to python blocked — remote code execution risk.",
        "Download first: curl -o /tmp/script.py <URL>. Review, then execute.",
    ),
    (
        "gateway_base64_decode_exec",
        re.compile(r"base64\s+(-d|--decode)\s*.*\|\s*(ba)?sh"),
        "Base64 decode piped to shell blocked — obfuscated execution.",
        "Decode to file first, review, then execute if safe.",
    ),

    # Category 3: Encoding bypass detection
    (
        "gateway_xxd_pipe_exec",
        re.compile(r"xxd\s+(-r|-revert)\s*.*\|\s*(ba)?sh"),
        "Hex decode piped to shell blocked.",
        "Decode to file first, review, then execute if safe.",
    ),
    (
        "gateway_gzip_pipe_exec",
        re.compile(r"(?:gunzip|zcat|gzip\s+-d)\s*.*\|\s*(ba)?sh"),
        "Compressed data piped to shell blocked.",
        "Decompress to file first, review, then execute if safe.",
    ),
    (
        "gateway_printf_decode_exec",
        re.compile(r"printf\s+.*\\x[0-9a-fA-F].*\|\s*(ba)?sh"),
        "Printf hex escape piped to shell blocked.",
        "Write the command as plain text using the Write tool.",
    ),

    # Category 4: Privilege escalation
    (
        "gateway_chmod_777",
        re.compile(r"chmod\s+777\b"),
        "chmod 777 blocked — world-writable files are a security risk.",
        "Use chmod 755 for dirs or chmod 644 for files.",
    ),
    (
        "gateway_chmod_suid",
        re.compile(r"chmod\s+[u+]*s\b|chmod\s+[24]7\d\d\b"),
        "SUID/SGID bit modification blocked.",
        "Use sudo with specific commands instead of SUID.",
    ),
    (
        "gateway_sudoers_edit",
        re.compile(r"(?:visudo|/etc/sudoers)"),
        "Sudoers file modification blocked.",
        "Ask the user to configure sudo rules manually.",
    ),
    (
        "gateway_sudo_su",
        re.compile(r"\bsudo\s+su\b"),
        "sudo su blocked — full root escalation prohibited.",
        "Use sudo with the specific command: sudo <command>.",
    ),

    # Category 5: Git operations
    (
        "gateway_git_push",
        re.compile(r"\bgit\s+push\b"),
        "git push blocked — user pushes manually.",
        "Commit your changes. Tell the user: 'Ready to push. Run: git push origin <branch>'.",
    ),
    (
        "gateway_git_reset_hard",
        re.compile(r"\bgit\s+reset\s+--hard\b"),
        "git reset --hard blocked — destroys uncommitted work.",
        "Use git stash, or restore specific files: git checkout -- <file>.",
    ),
    (
        "gateway_git_clean_fd",
        re.compile(r"\bgit\s+clean\s+-fd\b"),
        "git clean -fd blocked — permanently removes untracked files.",
        "Remove specific files by name, or use git stash --include-untracked.",
    ),
    (
        "gateway_git_force_push",
        re.compile(r"\bgit\s+push\s+.*--force\b"),
        "git force push blocked — rewrites shared remote history.",
        "Ask the user before force pushing.",
    ),
    (
        "gateway_git_rm_governance",
        re.compile(r"\bgit\s+rm\s+.*(?:CLAUDE\.md|\.codetrust\.toml|pre-commit|codetrust_pre_commit)"),
        "Removing governance files from git is blocked.",
        "Governance files must remain in the repository.",
    ),

    # Category 6: Container escape
    (
        "gateway_docker_privileged",
        re.compile(r"docker\s+run\s+.*--privileged"),
        "Privileged container blocked — full host access.",
        "Add only needed capabilities: --cap-add=NET_ADMIN.",
    ),
    (
        "gateway_docker_socket_mount",
        re.compile(r"-v\s+/var/run/docker\.sock"),
        "Docker socket mount blocked.",
        "Use Docker-in-Docker (dind) image instead.",
    ),
    (
        "gateway_docker_pid_host",
        re.compile(r"docker\s+run\s+.*--pid\s*=?\s*host"),
        "Docker PID namespace sharing blocked.",
        "Remove --pid=host. Use docker exec for container interaction.",
    ),
    (
        "gateway_nsenter",
        re.compile(r"\bnsenter\b"),
        "nsenter blocked — enters another process's namespaces.",
        "Use docker exec -it <container> /bin/sh instead.",
    ),

    # Category 7: Network exfiltration & reverse shells
    (
        "gateway_reverse_shell",
        re.compile(
            r"(?:bash\s+-i\s+>&|/dev/tcp/|nc\s+-e|ncat\s+-e|"
            r"python[23]?\s+-c\s+.*socket.*connect|"
            r"perl\s+-e\s+.*socket.*connect)"
        ),
        "Reverse shell pattern blocked.",
        "Use SSH for remote access. Never open outbound shell connections.",
    ),
    (
        "gateway_ssrf_metadata",
        re.compile(r"(?:curl|wget|http)\s+.*169\.254\.169\.254"),
        "Cloud metadata endpoint access blocked — SSRF risk.",
        "Use the cloud SDK for credentials.",
    ),
    (
        "gateway_nc_listen",
        re.compile(r"\bnc\s+.*-l\s*-?p?\s*\d+"),
        "Netcat listen blocked — potential backdoor.",
        "Use proper server tools instead.",
    ),

    # Category 8: Credential file access
    (
        "gateway_cat_ssh_key",
        re.compile(r"(?:cat|head|tail|less|more|cp|scp|rsync)\s+.*(?:~|\$HOME)/\.ssh/"),
        "Reading/copying SSH keys blocked.",
        "Use ssh-add to manage keys.",
    ),
    (
        "gateway_cat_aws_creds",
        re.compile(r"(?:cat|head|tail|less|more|cp)\s+.*(?:~|\$HOME)/\.aws/"),
        "Reading AWS credentials blocked.",
        "Use aws sts get-caller-identity to verify auth.",
    ),
    (
        "gateway_cat_env_file",
        re.compile(r"(?:cat|head|tail|less|more)\s+.*\.env(?:\.\w+)?$"),
        "Reading .env file via Bash blocked.",
        "Use the Read tool instead, or check specific vars: echo $VAR_NAME.",
    ),

    # Category 9: File-write bypass
    (
        "gateway_tee_write",
        re.compile(
            r"\btee\s+(-a\s+)?\S+\."
            r"(py|js|ts|sh|yaml|yml|toml|json|md|sql|go|rs|rb|java|c|cpp|h)"
        ),
        "tee to code file blocked.",
        "Use the Write tool to create files.",
    ),
    (
        "gateway_sed_inline",
        re.compile(r"\bsed\s+-i"),
        "sed -i blocked — untracked in-place file modification.",
        "Use the Edit tool with old_string/new_string.",
    ),
    (
        "gateway_python_write_file",
        re.compile(r"python[23]?\s+-c\s+.*(?:open|write)\s*\("),
        "Python -c file write blocked.",
        "Use the Write tool to create files.",
    ),

    # Category 10: Resource abuse
    (
        "gateway_fork_bomb",
        re.compile(r":\(\)\s*\{\s*:\|\s*:\s*&\s*\}\s*;?\s*:"),
        "Fork bomb blocked.",
        "Describe what you are trying to accomplish.",
    ),
    (
        "gateway_kill_pid1",
        re.compile(r"\bkill\s+-9\s+(?:1|init|systemd)\b"),
        "Kill PID 1 blocked.",
        "Kill specific processes by name: pkill <name>.",
    ),

    # Category 11: Secrets & environment
    (
        "gateway_env_secret_export",
        re.compile(
            r"export\s+(?:AWS_SECRET|DATABASE_URL|API_KEY|"
            r"PRIVATE_KEY|PASSWORD|TOKEN|SECRET)\s*="
        ),
        "Exporting secrets in shell blocked.",
        "Add the variable to .env file using the Write/Edit tool.",
    ),
    (
        "gateway_env_dump",
        re.compile(r"\benv\b\s*$|\bprintenv\b"),
        "Dumping all environment variables blocked — may expose secrets.",
        "Access specific variables: echo $SPECIFIC_VAR.",
    ),

    # Category 12: Supply chain
    (
        "gateway_pip_no_verify",
        re.compile(r"pip\s+install\s+.*--no-verify"),
        "pip install without verification blocked.",
        "Remove the --no-verify flag.",
    ),
    (
        "gateway_pip_trusted_host",
        re.compile(r"pip\s+install\s+.*--trusted-host"),
        "pip install with --trusted-host blocked — bypasses TLS.",
        "Use the official PyPI registry.",
    ),
    (
        "gateway_npm_from_url",
        re.compile(r"npm\s+install\s+https?://"),
        "npm install from URL blocked — unverified source.",
        "Install from the npm registry: npm install <package-name>.",
    ),

    # Category 13: Destructive database operations
    (
        "gateway_prisma_db_push_data_loss",
        re.compile(r"prisma\s+(?:db\s+push|migrate\s+reset).*--accept-data-loss"),
        "prisma db push with --accept-data-loss blocked — drops production tables.",
        "Run prisma db push WITHOUT --accept-data-loss. Review the migration plan first.",
    ),
    (
        "gateway_prisma_force_reset",
        re.compile(r"prisma\s+(?:db\s+push\s+--force-reset|migrate\s+reset)"),
        "prisma destructive reset blocked — drops all tables and recreates.",
        "Use prisma migrate deploy for production databases.",
    ),
    (
        "gateway_drop_database",
        re.compile(r"\b(?:dropdb|DROP\s+DATABASE)\b", re.IGNORECASE),
        "DROP DATABASE blocked — irreversible data destruction.",
        "Ask the user to perform destructive database operations manually.",
    ),
    (
        "gateway_drop_table",
        re.compile(r"\bDROP\s+TABLE\b", re.IGNORECASE),
        "DROP TABLE blocked — irreversible data loss.",
        "Ask the user to review and run this manually.",
    ),
    (
        "gateway_truncate_table",
        re.compile(r"\bTRUNCATE\b", re.IGNORECASE),
        "TRUNCATE blocked — deletes all rows without logging.",
        "Use DELETE with a WHERE clause, or ask the user to run this manually.",
    ),
    (
        "gateway_delete_no_where",
        re.compile(r"\bDELETE\s+FROM\s+\w+\s*;", re.IGNORECASE),
        "DELETE FROM without WHERE blocked — deletes all rows.",
        "Add a WHERE clause to limit deletion scope.",
    ),
]


def validate_command(command: str) -> tuple | None:
    """Check command against blocked patterns.

    Returns (rule_id, message, suggestion) if blocked, None if allowed.
    """
    # Heredoc check with context-aware suggestion
    if _HEREDOC_RE.search(command):
        suggestion = _heredoc_suggestion(command)
        return (
            "gateway_heredoc",
            "Heredoc (<<) is permanently prohibited. Zero exceptions.",
            suggestion,
        )

    # Interpreter -c/-e inner string validation
    inner_result = _check_interpreter_inner_string(command)
    if inner_result is not None:
        return inner_result

    for rule_id, pattern, message, suggestion in BLOCKED_PATTERNS:
        if pattern.search(command):
            return (rule_id, message, suggestion)
    return None


def main() -> int:
    """Read tool input from stdin, validate, exit 0 or 2."""
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            return 0

        data = json.loads(raw)
        tool_input = data.get("tool_input", {})
        command = tool_input.get("command", "") if isinstance(tool_input, dict) else ""
        if not command:
            command = data.get("command", "")
        if not command:
            return 0

        result = validate_command(command)
        if result is not None:
            rule_id, message, suggestion = result
            sys.stderr.write(
                f"\n\u2554\u2550\u2550 CodeTrust Gateway BLOCK \u2550\u2550\u2557\n"
                f"\u2551 Rule: {rule_id}\n"
                f"\u2551 {message}\n"
                f"\u2551 Suggestion: {suggestion}\n"
                f"\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d\n"
            )
            return 2

    except json.JSONDecodeError:
        return 0
    except Exception:
        # Hook must not crash — fail open
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
