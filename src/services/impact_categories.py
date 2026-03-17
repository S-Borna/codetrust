# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Rule-to-category mapping for impact telemetry."""

from __future__ import annotations

IMPACT_CATEGORY_OTHER: str = "other"

RULE_TO_CATEGORY: dict[str, str] = {
    # Category 1: Destructive Commands Blocked
    "agent_os_system": "destructive_commands",
    "agent_os_popen": "destructive_commands",
    "agent_subprocess_shell": "destructive_commands",
    "agent_subprocess_shell_true": "destructive_commands",
    "agent_rm_rf": "destructive_commands",
    "sql_drop_table": "destructive_commands",
    "sql_drop_no_if_exists": "destructive_commands",
    "sql_truncate": "destructive_commands",
    "sql_delete_no_where": "destructive_commands",
    "git_force_push": "destructive_commands",
    "docker_run_privileged": "destructive_commands",
    "k8s_privileged_pod": "destructive_commands",
    "k8s_privileged": "destructive_commands",

    # Category 2: AI Hallucinations Caught
    "import_not_found": "hallucinations",
    "sig_unknown_function": "hallucinations",
    "sig_too_few_args": "hallucinations",
    "sig_too_many_args": "hallucinations",
    "hallucinated_import_nonexistent": "hallucinations",
    "hallucinated_import_misspelled": "hallucinations",
    "hallucinated_method_chain": "hallucinations",
    "hallucinated_config_option": "hallucinations",
    "hallucinated_cli_flag": "hallucinations",
    "hallucinated_version": "hallucinations",

    # Category 3: Secrets Exposure Prevented
    "hardcoded_secret": "secrets_exposure",
    "api_key_in_config": "secrets_exposure",
    "database_url_credentials": "secrets_exposure",
    "ansible_plaintext_password": "secrets_exposure",
    "private_key_in_code": "secrets_exposure",
    "config_private_key_inline": "secrets_exposure",
    "docker_env_secret": "secrets_exposure",
    "cfn_hardcoded_credentials": "secrets_exposure",
    "ps_hardcoded_password": "secrets_exposure",
    "redis_weak_password": "secrets_exposure",

    # Category 4: Injection Attacks Stopped
    "eval_exec": "injection_attacks",
    "string_concat_sql": "injection_attacks",
    "heredoc": "injection_attacks",
    "agent_code_injection": "injection_attacks",
    "sql_injection": "injection_attacks",
    "ruby_eval": "injection_attacks",
    "php_eval": "injection_attacks",

    # Category 5: Unsafe Configurations Detected
    "config_world_writable": "unsafe_config",
    "debug_mode_enabled": "unsafe_config",
    "any_type": "unsafe_config",
    "datetime_utcnow": "unsafe_config",
    "bare_except": "unsafe_config",
    "mutable_default": "unsafe_config",
    "docker_latest_tag": "unsafe_config",
    "config_ssl_verify_off": "unsafe_config",

    # Category 6: Supply Chain Risks Identified
    "cve_detected": "supply_chain",
    "license_violation": "supply_chain",
    "docker_image_unverified": "supply_chain",
    "ci_unpinned_action": "supply_chain",
    "tf_no_versioned_module": "supply_chain",
}

CATEGORY_DISPLAY: dict[str, dict[str, str]] = {
    "destructive_commands": {
        "label": "Destructive Commands Blocked",
        "description": "rm -rf, DROP TABLE, force push, privileged containers",
        "icon": "🛡️",
    },
    "hallucinations": {
        "label": "AI Hallucinations Caught",
        "description": "Non-existent packages, unknown functions, wrong signatures",
        "icon": "🧠",
    },
    "secrets_exposure": {
        "label": "Secrets Exposure Prevented",
        "description": "Hardcoded API keys, passwords, tokens, credentials",
        "icon": "🔑",
    },
    "injection_attacks": {
        "label": "Injection Attacks Stopped",
        "description": "eval/exec, SQL injection, heredoc injection",
        "icon": "🐛",
    },
    "unsafe_config": {
        "label": "Unsafe Configurations Detected",
        "description": "World-writable permissions, debug mode, deprecated APIs",
        "icon": "⚙️",
    },
    "supply_chain": {
        "label": "Supply Chain Risks Identified",
        "description": "CVE-affected packages, license violations, unverified images",
        "icon": "📦",
    },
}

IMPACT_CATEGORIES: tuple[str, ...] = (
    "destructive_commands",
    "hallucinations",
    "secrets_exposure",
    "injection_attacks",
    "unsafe_config",
    "supply_chain",
    IMPACT_CATEGORY_OTHER,
)


def get_rule_category(rule_id: str) -> str:
    """Return the impact category for a rule id.

    Args:
        rule_id: CodeTrust rule id.

    Returns:
        Category key used for impact telemetry counters.
    """
    return RULE_TO_CATEGORY.get(rule_id, IMPACT_CATEGORY_OTHER)
