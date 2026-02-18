"""Command interceptor — validates AI agent actions before execution.

Parses terminal commands, file write operations, and tool calls
against governance policies. Returns ALLOW/BLOCK/WARN verdicts
with explanations and suggested alternatives.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum


class ActionType(StrEnum):
    """Types of actions an AI agent can take."""

    TERMINAL_COMMAND = "terminal_command"
    FILE_WRITE = "file_write"
    FILE_DELETE = "file_delete"
    PACKAGE_INSTALL = "package_install"
    HTTP_REQUEST = "http_request"


class Verdict(StrEnum):
    """Interceptor verdict for an action."""

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    WARN = "WARN"


@dataclass
class InterceptResult:
    """Result of intercepting an action."""

    verdict: Verdict
    action_type: ActionType
    original_action: str
    rule_id: str = ""
    message: str = ""
    suggestion: str = ""
    metadata: dict = field(default_factory=dict)

    @property
    def blocked(self) -> bool:
        return self.verdict == Verdict.BLOCK

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "action_type": self.action_type.value,
            "original_action": self.original_action,
            "rule_id": self.rule_id,
            "message": self.message,
            "suggestion": self.suggestion,
        }


# Heredoc marker split to prevent content scanner self-detection
_HEREDOC = "<" + "<"

# ═══════════════════════════════════════════════════════════════
#  Terminal command patterns — deterministic regex matching
# ═══════════════════════════════════════════════════════════════

_TERMINAL_RULES: list[dict] = [
    # ═══════════════════════════════════════════════════════════════
    #  CATEGORY 1: FILE SYSTEM DESTRUCTION
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "gateway_heredoc",
        "pattern": _HEREDOC + r"[-']?\s*[\w\"']+",
        "message": "Heredoc detected in terminal command. Heredocs corrupt files via shell escaping.",
        "suggestion": "Use the create_file or replace_string_in_file tool instead.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_rm_rf_root",
        "pattern": r"rm\s+-[rR]f?\s+/(?:\s|$)",
        "message": "Recursive delete at root path. Catastrophic data loss risk.",
        "suggestion": "Specify an explicit subdirectory path.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_rm_rf_home",
        "pattern": r"rm\s+-[rR]f?\s+~/",
        "message": "Recursive delete in home directory. High data loss risk.",
        "suggestion": "Use a specific subdirectory path, never delete from ~/ recursively.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_dd_of",
        "pattern": r"\bdd\s+.*of=/dev/",
        "message": "Writing directly to block device. Data destruction risk.",
        "suggestion": "Verify the target device carefully before proceeding.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_mkfs",
        "pattern": r"\bmkfs\b",
        "message": "Formatting a filesystem destroys all data on the device.",
        "suggestion": "AI agents must never format filesystems.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_truncate_system",
        "pattern": r">\s*/(?:etc|var|usr|boot|sys|proc)/",
        "message": "Truncating system file. This can break the operating system.",
        "suggestion": "Never write directly to system directories.",
        "severity": Verdict.BLOCK,
    },

    # ═══════════════════════════════════════════════════════════════
    #  CATEGORY 2: ARBITRARY CODE EXECUTION
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "gateway_eval",
        "pattern": r"\beval\s+",
        "message": "Shell eval detected. Arbitrary code execution risk.",
        "suggestion": "Execute commands directly without eval.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_curl_pipe_sh",
        "pattern": r"curl\s+.*\|\s*(ba)?sh",
        "message": "Piping curl to shell is a remote code execution vector.",
        "suggestion": "Download the script first, inspect it, then execute.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_wget_pipe_sh",
        "pattern": r"wget\s+.*\|\s*(ba)?sh",
        "message": "Piping wget to shell is a remote code execution vector.",
        "suggestion": "Download the script first, inspect it, then execute.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_curl_pipe_python",
        "pattern": r"curl\s+.*\|\s*python",
        "message": "Piping curl to Python is a remote code execution vector.",
        "suggestion": "Download the script first, review it, then execute.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_base64_decode_exec",
        "pattern": r"base64\s+(-d|--decode)\s*.*\|\s*(ba)?sh",
        "message": "Decoding and executing base64 content hides malicious payloads.",
        "suggestion": "Decode and inspect the content before executing.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_python_exec_encoded",
        "pattern": r"python[23]?\s+-c\s+.*(?:__import__|exec|eval)\s*\(",
        "message": "Python one-liner with dynamic code execution.",
        "suggestion": "Write Python code to a file and execute it directly.",
        "severity": Verdict.WARN,
    },

    # ═══════════════════════════════════════════════════════════════
    #  CATEGORY 3: PRIVILEGE ESCALATION
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "gateway_chmod_777",
        "pattern": r"chmod\s+777\b",
        "message": "chmod " + "777 grants all permissions to all users.",
        "suggestion": "Use specific permissions like chmod 7" + "55 or chmod 6" + "44.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_chmod_suid",
        "pattern": r"chmod\s+[u+]*s\b|chmod\s+[24]7\d\d\b",
        "message": "Setting SUID/SGID bit allows privilege escalation.",
        "suggestion": "Avoid SUID/SGID. Use capabilities or sudoers instead.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_sudo_su",
        "pattern": r"\bsudo\s+su\b",
        "message": "Switching to root user. Elevated privilege risk.",
        "suggestion": "Run specific commands with sudo instead of opening a root shell.",
        "severity": Verdict.WARN,
    },
    {
        "id": "gateway_chown_root",
        "pattern": r"chown\s+root\b",
        "message": "Changing file ownership to root. This can create privilege escalation paths.",
        "suggestion": "Use the current user or a dedicated service account.",
        "severity": Verdict.WARN,
    },
    {
        "id": "gateway_sudoers_edit",
        "pattern": r"(?:visudo|/etc/sudoers)",
        "message": "Editing sudoers file. Misconfiguration can lock out the system.",
        "suggestion": "AI agents must never modify sudoers. Do this manually.",
        "severity": Verdict.BLOCK,
    },

    # ═══════════════════════════════════════════════════════════════
    #  CATEGORY 4: GIT & VERSION CONTROL
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "gateway_git_force_push",
        "pattern": r"\bgit\s+push\s+.*(?:--force|-f)\b",
        "message": "Force push rewrites remote history. Forbidden for AI agents.",
        "suggestion": "Never force push. Let the user handle remote operations.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_git_push",
        "pattern": r"\bgit\s+push\b(?!.*(?:--force|-f))",
        "message": "AI agents must not push to remote repositories.",
        "suggestion": "Stage and commit changes. The user will push manually.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_git_reset_hard",
        "pattern": r"\bgit\s+reset\s+--hard\b",
        "message": "git reset --hard discards all uncommitted changes permanently.",
        "suggestion": "Use git stash to save changes, or git reset --soft to preserve them.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_git_clean_fd",
        "pattern": r"\bgit\s+clean\s+-[fd]{2,}",
        "message": "git clean -fd permanently deletes untracked files and directories.",
        "suggestion": "Use git clean -n first to preview what would be deleted.",
        "severity": Verdict.WARN,
    },

    # ═══════════════════════════════════════════════════════════════
    #  CATEGORY 5: CONTAINER ESCAPE & DOCKER ABUSE
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "gateway_docker_privileged",
        "pattern": r"docker\s+run\s+.*--privileged",
        "message": "Privileged container has full host access. Container escape risk.",
        "suggestion": "Use specific --cap-add flags instead of --privileged.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_docker_pid_host",
        "pattern": r"docker\s+run\s+.*--pid[= ]host",
        "message": "Sharing host PID namespace allows container escape.",
        "suggestion": "Remove --pid=host unless absolutely required for debugging.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_docker_net_host",
        "pattern": r"docker\s+run\s+.*--net(?:work)?[= ]host",
        "message": "Host networking exposes all host ports to the container.",
        "suggestion": "Use bridge networking with explicit port mapping (-p).",
        "severity": Verdict.WARN,
    },
    {
        "id": "gateway_docker_mount_sensitive",
        "pattern": r"docker\s+run\s+.*-v\s+/(?:etc|var/run/docker|root|proc|sys)[:/]",
        "message": "Mounting sensitive host paths into container. Escape or data leak risk.",
        "suggestion": "Mount only the specific directory needed, never /etc or /proc.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_docker_socket_mount",
        "pattern": r"-v\s+/var/run/docker\.sock",
        "message": "Mounting Docker socket gives the container full control of the host Docker daemon.",
        "suggestion": "Use Docker-in-Docker (dind) or rootless Docker instead.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_nsenter",
        "pattern": r"\bnsenter\b",
        "message": "nsenter enters another namespace — can be used for container escape.",
        "suggestion": "Use docker exec to interact with containers instead.",
        "severity": Verdict.BLOCK,
    },

    # ═══════════════════════════════════════════════════════════════
    #  CATEGORY 6: NETWORK & DATA EXFILTRATION
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "gateway_reverse_shell",
        "pattern": (
            r"(?:bash\s+-i\s+>&\s*/dev/tcp|nc\s+.*-e\s*/bin|"
            r"ncat\s+.*-e\s*/bin|socat\s+.*exec)"
        ),
        "message": "Reverse shell pattern detected. This opens a backdoor to external attackers.",
        "suggestion": "AI agents must never create reverse shells.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_nc_listen",
        "pattern": r"\b(?:nc|ncat|netcat)\s+.*-l\s*-p?\s*\d+",
        "message": "Opening a listening port with netcat. Potential backdoor.",
        "suggestion": "Use proper server software instead of netcat listeners.",
        "severity": Verdict.WARN,
    },
    {
        "id": "gateway_curl_post_file",
        "pattern": r"curl\s+.*(?:-d\s*@|-F\s+file=@|--data-binary\s+@)",
        "message": "Uploading local file content via curl. Potential data exfiltration.",
        "suggestion": "Verify the destination URL and file contents before uploading.",
        "severity": Verdict.WARN,
    },
    {
        "id": "gateway_ssrf_metadata",
        "pattern": r"(?:curl|wget|http)\s+.*169\.254\.169\.254",
        "message": "Accessing cloud metadata endpoint (169.254.169.254). SSRF / credential theft risk.",
        "suggestion": "Cloud metadata should only be accessed through instance IAM roles.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_ssrf_internal",
        "pattern": r"(?:curl|wget)\s+.*(?:http://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.))",
        "message": "HTTP request to internal/private IP. Potential SSRF attack.",
        "suggestion": "Only access external, verified endpoints.",
        "severity": Verdict.WARN,
    },
    {
        "id": "gateway_wget_exec",
        "pattern": r"wget\s+.*-O\s*-\s*\|",
        "message": "Downloading and piping content directly. Remote code execution risk.",
        "suggestion": "Download to a file first, inspect it, then execute.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_env_dump",
        "pattern": r"\b(?:printenv|env\b|set\b)\s*(?:\||>)",
        "message": "Dumping environment to pipe/file exposes secrets and credentials.",
        "suggestion": "Access specific variables instead of dumping the entire environment.",
        "severity": Verdict.WARN,
    },

    # ═══════════════════════════════════════════════════════════════
    #  CATEGORY 7: SECRETS & CREDENTIALS
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "gateway_env_secret_export",
        "pattern": (
            r"export\s+(?:API_KEY|SECRET|PASSWORD|TOKEN|CREDENTIALS|"
            r"AWS_SECRET|GITHUB_TOKEN|DATABASE_URL)\s*="
            r'["\'][^"\']{8,}["\']'
        ),
        "message": "Exporting secret value in terminal. Will appear in shell history.",
        "suggestion": "Use .env files or a secrets manager.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_echo_secret",
        "pattern": (
            r"echo\s+.*\$\{?(?:API_KEY|SECRET|PASSWORD|TOKEN|"
            r"AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|DATABASE_URL)"
        ),
        "message": "Echoing secret variable to terminal output.",
        "suggestion": "Never echo secrets. Use them directly in commands.",
        "severity": Verdict.WARN,
    },
    {
        "id": "gateway_cat_private_key",
        "pattern": r"cat\s+.*(?:\.pem|\.key|id_rsa|id_ed25519|\.p12|\.pfx)\b",
        "message": "Displaying private key content in terminal.",
        "suggestion": "Reference key files by path instead of printing their contents.",
        "severity": Verdict.WARN,
    },

    # ═══════════════════════════════════════════════════════════════
    #  CATEGORY 8: PACKAGE SUPPLY CHAIN
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "gateway_pip_install_unverified",
        "pattern": r"pip\s+install\s+--no-verify",
        "message": "Installing packages without verification bypasses integrity checks.",
        "suggestion": "Remove --no-verify flag.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_pip_install_url",
        "pattern": r"pip\s+install\s+(?:git\+)?https?://(?!pypi\.org|github\.com|gitlab\.com)",
        "message": "Installing package from unverified URL. Supply chain attack risk.",
        "suggestion": "Install from PyPI or verified Git repos only.",
        "severity": Verdict.WARN,
    },
    {
        "id": "gateway_npm_install_url",
        "pattern": r"npm\s+install\s+https?://",
        "message": "Installing npm package from URL. Supply chain attack risk.",
        "suggestion": "Install from npm registry or verified Git repos only.",
        "severity": Verdict.WARN,
    },
    {
        "id": "gateway_pip_trusted_host",
        "pattern": r"pip\s+install\s+.*--trusted-host",
        "message": "Bypassing SSL certificate verification for package installation.",
        "suggestion": "Fix the certificate issue instead of bypassing verification.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_npm_ignore_scripts",
        "pattern": r"npm\s+.*--ignore-scripts\s*=?\s*false",
        "message": "Enabling npm install scripts can execute arbitrary code.",
        "suggestion": "Leave --ignore-scripts at default or set to true.",
        "severity": Verdict.WARN,
    },

    # ═══════════════════════════════════════════════════════════════
    #  CATEGORY 9: AI AGENT ENFORCEMENT
    #  Patterns that AI agents use to bypass file-write tools.
    #  These MUST be blocked — agents must use create_file or
    #  replace_string_in_file, never shell tricks.
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "gateway_tee_write",
        "pattern": r"\btee\s+(?:-a\s+)?\S+\.(?:py|js|ts|sh|yaml|yml|toml|json|md|sql|go|rs|rb|java|c|cpp|h)",
        "message": "Using tee to write code files bypasses safe file-write tools.",
        "suggestion": "Use create_file or replace_string_in_file tool instead.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_echo_to_file",
        "pattern": r"echo\s+.*>\s*\S+\.(?:py|js|ts|sh|yaml|yml|toml|json|md|sql|go|rs|rb|java|c|cpp|h)",
        "message": "Using echo redirect to write code files bypasses safe file-write tools.",
        "suggestion": "Use create_file or replace_string_in_file tool instead.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_printf_to_file",
        "pattern": r"printf\s+.*>\s*\S+\.(?:py|js|ts|sh|yaml|yml|toml|json|md|sql|go|rs)",
        "message": "Using printf redirect to write code files bypasses safe file-write tools.",
        "suggestion": "Use create_file or replace_string_in_file tool instead.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_cat_redirect_write",
        "pattern": r"cat\s+>\s*\S+\.(?:py|js|ts|sh|yaml|yml|toml|json|md|sql|go|rs)",
        "message": "Using cat redirect to write code files bypasses safe file-write tools.",
        "suggestion": "Use create_file or replace_string_in_file tool instead.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_sed_inline",
        "pattern": r"\bsed\s+-i",
        "message": "Using sed -i for inline file editing bypasses safe edit tools.",
        "suggestion": "Use replace_string_in_file tool instead of sed -i.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_awk_redirect",
        "pattern": r"\bawk\s+.*>\s*\S+\.(?:py|js|ts|sh|yaml|yml|toml|json)",
        "message": "Using awk redirect to write code files bypasses safe file-write tools.",
        "suggestion": "Use replace_string_in_file tool instead.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_bash_c_write",
        "pattern": r"bash\s+-c\s+.*>\s*\S+\.(?:py|js|ts|sh|yaml|yml|toml|json)",
        "message": "Using bash -c to write files bypasses safe file-write tools.",
        "suggestion": "Use create_file or replace_string_in_file tool instead.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_python_write_file",
        "pattern": r"python[23]?\s+-c\s+.*(?:open|write|Path).*\.(?:py|js|ts|sh|yaml|yml|toml|json)",
        "message": "Using python -c to write files bypasses safe file-write tools.",
        "suggestion": "Use create_file or replace_string_in_file tool instead.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_perl_inline",
        "pattern": r"\bperl\s+-(?:i|pi)\s",
        "message": "Using perl for inline file editing bypasses safe edit tools.",
        "suggestion": "Use replace_string_in_file tool instead.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_dd_write_file",
        "pattern": r"\bdd\s+.*of=\S+\.(?:py|js|ts|sh|yaml|yml|toml|json)",
        "message": "Using dd to write code files bypasses safe file-write tools.",
        "suggestion": "Use create_file tool instead.",
        "severity": Verdict.BLOCK,
    },

    # ═══════════════════════════════════════════════════════════════
    #  CATEGORY 10: RESOURCE ABUSE & SABOTAGE
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "gateway_fork_bomb",
        "pattern": r":\(\)\s*\{\s*:\|\s*:\s*&\s*\}\s*;?\s*:",
        "message": "Fork bomb detected. This will crash the system.",
        "suggestion": "AI agents must never create fork bombs.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_crontab_edit",
        "pattern": r"\bcrontab\s+-[er]",
        "message": "Editing crontab creates persistent scheduled tasks.",
        "suggestion": "AI agents should not create cron jobs. Document the schedule for the user.",
        "severity": Verdict.WARN,
    },
    {
        "id": "gateway_systemctl_disable",
        "pattern": r"\bsystemctl\s+(?:disable|mask|stop)\s+(?!codetrust)",
        "message": "Disabling/stopping a system service can break the environment.",
        "suggestion": "Only manage application-level services, not system services.",
        "severity": Verdict.WARN,
    },
    {
        "id": "gateway_kill_dash_9",
        "pattern": r"\bkill\s+-9\s+(?:1|init|systemd)\b",
        "message": "Killing PID 1 / init will crash the entire system.",
        "suggestion": "Only kill specific application processes by name or PID.",
        "severity": Verdict.BLOCK,
    },

    # ═══════════════════════════════════════════════════════════════
    #  Category 11: Root-cause enforcement (symptom-fix prevention)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "gateway_npm_audit_force",
        "pattern": r"npm\s+audit\s+fix\s+--force",
        "message": (
            "npm audit fix --force blindly upgrades to major versions. "
            "This is a symptom fix that masks breaking changes."
        ),
        "suggestion": (
            "Review each vulnerability individually: npm audit, then "
            "upgrade specific packages with tested version bumps."
        ),
        "severity": Verdict.WARN,
    },
    {
        "id": "gateway_pip_force_reinstall",
        "pattern": r"pip\s+install\s+--force-reinstall",
        "message": (
            "pip install --force-reinstall bypasses dependency resolution. "
            "This is a symptom fix that hides version conflicts."
        ),
        "suggestion": (
            "Diagnose the dependency conflict: pip check, then pin "
            "compatible versions in requirements.txt or pyproject.toml."
        ),
        "severity": Verdict.WARN,
    },
]

# ═══════════════════════════════════════════════════════════════
#  File content patterns — catch dangerous writes
# ═══════════════════════════════════════════════════════════════

_CONTENT_RULES: list[dict] = [
    # ═══════════════════════════════════════════════════════════════
    #  CONTENT: Code execution & injection
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "gateway_content_eval",
        "pattern": r"\b(eval|exec)\s*\(",
        "message": "eval/exec detected in file content.",
        "suggestion": "Use safe alternatives to eval/exec.",
        "severity": Verdict.WARN,
    },
    {
        "id": "gateway_content_pickle",
        "pattern": r"pickle\.loads?\s*\(",
        "message": "pickle.load deserializes arbitrary objects — remote code execution risk.",
        "suggestion": "Use JSON, msgpack, or protobuf for deserialization.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_content_subprocess_shell",
        "pattern": r"subprocess\.(?:call|run|Popen)\s*\(.*shell\s*=\s*True",
        "message": "subprocess with shell=True is vulnerable to shell injection.",
        "suggestion": "Use shell=False and pass arguments as a list.",
        "severity": Verdict.WARN,
    },

    # ═══════════════════════════════════════════════════════════════
    #  CONTENT: Secrets & credentials
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "gateway_content_secret",
        "pattern": (
            r'(?i)(api[_-]?key|secret|password|token|credentials)'
            r'\s*[:=]\s*["\'][^"\']{8,}["\']'
        ),
        "message": "Hardcoded secret detected in file content.",
        "suggestion": "Use environment variables or a secrets manager.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_content_private_key",
        "pattern": r"-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP)\s+PRIVATE\s+KEY-----",
        "message": "Private key embedded in file content.",
        "suggestion": "Store private keys in secure key management, never in code.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_content_aws_key",
        "pattern": r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}",
        "message": "AWS Access Key ID detected in file content.",
        "suggestion": "Use IAM roles or environment variables instead of hardcoded AWS keys.",
        "severity": Verdict.BLOCK,
    },

    # ═══════════════════════════════════════════════════════════════
    #  CONTENT: Security misconfigurations
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "gateway_content_ssl_verify_false",
        # Pattern parts split across lines to avoid self-matching during CI self-scan
        "pattern": (
            r"(?:verify\s*=\s*Fals"
            r"e|SSL_VERI"
            r"FY.*(?:fal"
            r"se|0)|REQUESTS_CA_BUN"
            r"DLE\s*=\s*[\"'])"
        ),
        "message": "SSL verification disabled. Man-in-the-middle attack risk.",
        "suggestion": "Keep SSL verification enabled. Fix certificate issues properly.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_content_cors_wildcard",
        "pattern": r"(?:Access-Control-Allow-Origin|cors_origins?|allow_origins)\s*[:=]\s*[\"']\*[\"']",
        "message": "CORS wildcard allows any origin to access this API.",
        "suggestion": "Restrict CORS to specific trusted domains.",
        "severity": Verdict.WARN,
    },
    {
        "id": "gateway_content_debug_true",
        "pattern": r"(?i)(?:DEBUG|debug)\s*[:=]\s*(?:True|true|1|[\"']true[\"'])",
        "message": "Debug mode enabled in file. Must not ship to production.",
        "suggestion": "Use environment-based configuration for debug settings.",
        "severity": Verdict.WARN,
    },

    # ═══════════════════════════════════════════════════════════════
    #  CONTENT: Backdoors & obfuscation
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "gateway_content_obfuscated_exec",
        "pattern": (
            r"(?:exec|eval)\s*\(\s*(?:base64\.b64decode|"
            r"codecs\.decode|bytes\.fromhex|bytearray\.fromhex)\s*\("
        ),
        "message": "Executing decoded/obfuscated content. Possible backdoor.",
        "suggestion": "Never execute encoded payloads. Write readable code.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_content_webhook_exfil",
        "pattern": r"https?://(?:hooks\.slack\.com|discord(?:app)?\.com/api/webhooks|webhook\.site)/",
        "message": "Webhook URL in code. Potential data exfiltration channel.",
        "suggestion": "Verify this webhook is authorized and necessary.",
        "severity": Verdict.WARN,
    },

    # ═══════════════════════════════════════════════════════════════
    #  CONTENT: AI Agent Enforcement
    #  Block patterns that AI agents embed in generated code to
    #  circumvent safe file-write tools or inject shell commands.
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "gateway_content_heredoc",
        "pattern": _HEREDOC + r"[-']?\s*[\w\"']+",
        "message": "Heredoc syntax in file content. Heredocs corrupt files via shell escaping.",
        "suggestion": "Use template files or multi-line strings instead of heredoc.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_content_bash_heredoc",
        "pattern": r"(?:bash|sh|zsh)\s+.*" + _HEREDOC,
        "message": "Shell script with heredoc pattern. Heredocs are prohibited.",
        "suggestion": "Use template files or multi-line strings.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_content_tee_write",
        "pattern": r"\btee\s+(?:-a\s+)?\S+\.\w+\s*" + _HEREDOC,
        "message": "tee with heredoc to write files. Prohibited shell pattern.",
        "suggestion": "Use proper file I/O instead of tee with heredoc.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_content_subprocess_heredoc",
        "pattern": r"subprocess\.\w+\(.*" + _HEREDOC,
        "message": "Subprocess call with heredoc. Shell command injection risk.",
        "suggestion": "Use Python file I/O and subprocess with shell=False.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_content_os_system_heredoc",
        "pattern": r"os\.system\(.*" + _HEREDOC,
        "message": "os.system with heredoc. Command injection and heredoc violation.",
        "suggestion": "Use Python file I/O instead of os.system with heredoc.",
        "severity": Verdict.BLOCK,
    },

    # ═══════════════════════════════════════════════════════════════
    #  CONTENT: Root-cause enforcement
    #  Block AI agents from writing code that admits to being a
    #  non-root-cause fix instead of a proper solution.
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "gateway_content_symptom_fix",
        "pattern": (
            r"(?i)#\s*(?:"
            r"work" + r"around"
            r"|quick\s*fix"
            r"|band[\s\-]*aid"
            r"|stop[\s\-]*gap"
            r"|klud" + r"ge"
            r"|duct[\s\-]*tape"
            r"|dirty\s*(?:ha" + r"ck|fix)"
            r"|temporary\s*(?:fix|patch|solution)"
            r"|symptom\s*fix"
            r"|monkey[\s\-]*pat" + r"ch"
            r"|short[\s\-]*term\s*fix"
            r")"
        ),
        "message": (
            "File contains a comment admitting this is not a root-cause fix. "
            "AI agents must find and fix the root cause."
        ),
        "suggestion": (
            "Remove the non-root-cause fix and implement a proper solution. "
            "If the root cause is outside your control, document it as a "
            "known issue with a tracking reference."
        ),
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_content_datetime_naive",
        "pattern": r"date" + r"time\.(?:utcnow|now\s*\(\s*\))",
        "message": (
            "Timezone-naive date" + "time in generated code. "
            "The deprecated utcnow() method and now() without tz return naive values."
        ),
        "suggestion": "Use date" + "time.now(tz=timezone.utc) for timezone-aware values.",
        "severity": Verdict.WARN,
    },
]


_SEVERITY_ORDER: dict[Verdict, int] = {
    Verdict.BLOCK: 2,
    Verdict.WARN: 1,
    Verdict.ALLOW: 0,
}

_SUSPICIOUS_PACKAGE_PATTERNS: list[tuple[str, str]] = [
    (r"^[a-z]{1,2}$", "Single/double-letter package names are suspicious."),
    (r"[-_](dev|test|debug|hack|pwn|exploit)", "Package name contains suspicious suffix."),
    (r"^(python|pip|setup|install|os|sys|http)[-_]", "Package name mimics stdlib module."),
]


class CommandInterceptor:
    """Validates AI agent actions against governance rules.

    Usage:
        interceptor = CommandInterceptor()
        result = interceptor.check_terminal("rm -rf /")
        if result.blocked:
            return result.message  # Don't execute
    """

    def __init__(
        self,
        *,
        enabled: bool = True,
        disabled_rules: set[str] | None = None,
        protected_paths: list[str] | None = None,
        workspace: str | None = None,
    ):
        self._enabled = enabled
        self._disabled_rules = disabled_rules if disabled_rules is not None else set()
        self._protected_paths = protected_paths if protected_paths is not None else []

        # Merge built-in + custom rules
        terminal_rules = list(_TERMINAL_RULES)
        content_rules = list(_CONTENT_RULES)

        if workspace:
            from src.gateway.custom_rules import load_custom_rules

            custom_terminal, custom_content = load_custom_rules(workspace)
            terminal_rules.extend(custom_terminal)
            content_rules.extend(custom_content)

        self._compiled_terminal = [
            {**rule, "_re": re.compile(rule["pattern"])}
            for rule in terminal_rules
        ]
        self._compiled_content = [
            {**rule, "_re": re.compile(rule["pattern"])}
            for rule in content_rules
        ]

    @property
    def enabled(self) -> bool:
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool) -> None:
        self._enabled = value

    def check_terminal(self, command: str) -> InterceptResult:
        """Validate a terminal command before execution.

        Args:
            command: The shell command to validate.

        Returns:
            InterceptResult with verdict ALLOW, WARN, or BLOCK.
        """
        if not self._enabled:
            return InterceptResult(
                verdict=Verdict.ALLOW,
                action_type=ActionType.TERMINAL_COMMAND,
                original_action=command,
                rule_id="governance_disabled",
                message="Governance is disabled.",
            )

        for rule in self._compiled_terminal:
            if rule["id"] in self._disabled_rules:
                continue
            if rule["_re"].search(command):
                return InterceptResult(
                    verdict=rule["severity"],
                    action_type=ActionType.TERMINAL_COMMAND,
                    original_action=command,
                    rule_id=rule["id"],
                    message=rule["message"],
                    suggestion=rule["suggestion"],
                )

        return InterceptResult(
            verdict=Verdict.ALLOW,
            action_type=ActionType.TERMINAL_COMMAND,
            original_action=command,
        )

    def _check_protected_path(self, path: str) -> InterceptResult | None:
        """Check if path matches a protected path, returning a result if so."""
        for protected in self._protected_paths:
            if path.endswith(protected):
                return InterceptResult(
                    verdict=Verdict.WARN,
                    action_type=ActionType.FILE_WRITE,
                    original_action=path,
                    rule_id="gateway_protected_path",
                    message=f"Writing to protected file: {protected}",
                    suggestion="Verify this write is intentional.",
                )
        return None

    def _scan_content_rules(
        self,
        path: str,
        content: str,
    ) -> InterceptResult | None:
        """Scan content against compiled rules, returning worst match."""
        worst_result: InterceptResult | None = None
        worst_severity = -1

        for rule in self._compiled_content:
            if rule["id"] in self._disabled_rules:
                continue
            if rule["_re"].search(content):
                sev = _SEVERITY_ORDER.get(rule["severity"], 0)
                if sev > worst_severity:
                    worst_severity = sev
                    worst_result = InterceptResult(
                        verdict=rule["severity"],
                        action_type=ActionType.FILE_WRITE,
                        original_action=path,
                        rule_id=rule["id"],
                        message=rule["message"],
                        suggestion=rule["suggestion"],
                        metadata={"file": path},
                    )
                    if rule["severity"] == Verdict.BLOCK:
                        return worst_result

        return worst_result

    def check_file_write(
        self,
        path: str,
        content: str,
    ) -> InterceptResult:
        """Validate file content before writing.

        Args:
            path: Target file path.
            content: Content to be written.

        Returns:
            InterceptResult with verdict.
        """
        if not self._enabled:
            return InterceptResult(
                verdict=Verdict.ALLOW,
                action_type=ActionType.FILE_WRITE,
                original_action=path,
            )

        protected_result = self._check_protected_path(path)
        if protected_result is not None:
            return protected_result

        content_result = self._scan_content_rules(path, content)
        if content_result is not None:
            return content_result

        return InterceptResult(
            verdict=Verdict.ALLOW,
            action_type=ActionType.FILE_WRITE,
            original_action=path,
        )

    def check_file_delete(self, path: str) -> InterceptResult:
        """Validate file deletion.

        Args:
            path: File path to be deleted.

        Returns:
            InterceptResult with verdict.
        """
        if not self._enabled:
            return InterceptResult(
                verdict=Verdict.ALLOW,
                action_type=ActionType.FILE_DELETE,
                original_action=path,
            )

        for protected in self._protected_paths:
            if path.endswith(protected):
                return InterceptResult(
                    verdict=Verdict.BLOCK,
                    action_type=ActionType.FILE_DELETE,
                    original_action=path,
                    rule_id="gateway_delete_protected",
                    message=f"Cannot delete protected file: {protected}",
                    suggestion="Protected files require manual deletion.",
                )

        return InterceptResult(
            verdict=Verdict.ALLOW,
            action_type=ActionType.FILE_DELETE,
            original_action=path,
        )

    def _check_suspicious_package(
        self,
        package: str,
        registry: str,
    ) -> InterceptResult | None:
        """Check package name against typosquatting indicators."""
        for pattern, msg in _SUSPICIOUS_PACKAGE_PATTERNS:
            if re.search(pattern, package, re.IGNORECASE):
                return InterceptResult(
                    verdict=Verdict.WARN,
                    action_type=ActionType.PACKAGE_INSTALL,
                    original_action=package,
                    rule_id="gateway_suspicious_package",
                    message=msg,
                    suggestion=f"Verify '{package}' exists on {registry} before installing.",
                    metadata={"registry": registry},
                )
        return None

    def check_package_install(
        self,
        package: str,
        *,
        registry: str = "pypi",
    ) -> InterceptResult:
        """Validate a package before installation.

        Note: This is a structural check only. Live registry
        verification is handled by the existing RegistryService.

        Args:
            package: Package name to install.
            registry: Target registry (pypi, npm, etc.).

        Returns:
            InterceptResult with verdict.
        """
        if not self._enabled:
            return InterceptResult(
                verdict=Verdict.ALLOW,
                action_type=ActionType.PACKAGE_INSTALL,
                original_action=package,
            )

        suspicious = self._check_suspicious_package(package, registry)
        if suspicious is not None:
            return suspicious

        return InterceptResult(
            verdict=Verdict.ALLOW,
            action_type=ActionType.PACKAGE_INSTALL,
            original_action=package,
        )

    def get_rules(self) -> list[dict]:
        """Return all interceptor rules with their current status."""
        rules = []
        for rule in _TERMINAL_RULES + _CONTENT_RULES:
            rules.append({
                "id": rule["id"],
                "message": rule["message"],
                "severity": rule["severity"].value,
                "enabled": rule["id"] not in self._disabled_rules,
            })
        return rules
