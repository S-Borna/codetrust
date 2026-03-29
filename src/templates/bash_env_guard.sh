#!/bin/bash
# CodeTrust BASH_ENV Guard — real-time command validation
# Copyright (c) 2026 Said Borna. All rights reserved.
#
# This file is sourced by bash BEFORE every non-interactive -c command
# when BASH_ENV points to it. It validates $BASH_EXECUTION_STRING against
# governance rules and exits with code 2 if a violation is found.
#
# Installed by: codetrust init
# Uninstalled by: codetrust shield uninstall
#
# Design constraints:
#   - Must be pure bash (no Python, no external tools except grep)
#   - Must be fast (<5ms overhead per command)
#   - Must fail-open on any error (never break the user's shell)
#   - Must write to audit log for observability

# --- Configuration ---
_CT_AUDIT_DIR="$HOME/.codetrust/shield"
_CT_AUDIT_FILE="$_CT_AUDIT_DIR/audit.jsonl"
_CT_GUARD_VERSION="1.0.0"

# --- Early exit for empty commands ---
if [ -z "$BASH_EXECUTION_STRING" ]; then
    return 0 2>/dev/null || true
fi

# --- Trivial command skip (performance) ---
case "$BASH_EXECUTION_STRING" in
    cd\ *|echo\ *|true|false|exit*|pwd|whoami|date|which\ *|type\ *|alias\ *|ls\ *|ls|cat\ *)
        return 0 2>/dev/null || true
        ;;
esac

# --- Rule checks ---
_ct_blocked=""
_ct_rule_id=""
_ct_message=""
_ct_suggestion=""

# Rule 1: Heredoc (<<) — zero tolerance
# Quote-aware: strip single-quoted and simple double-quoted strings first,
# then check for << in unquoted code. Preserves $() subshells.
_ct_stripped=$(echo "$BASH_EXECUTION_STRING" | sed "s/'[^']*'/'_Q_'/g" | sed 's/"[^"$]*"/"_Q_"/g')
if echo "$_ct_stripped" | grep -qE '<<[-'"'"']?\s*[A-Za-z_]'; then
    _ct_blocked=1
    _ct_rule_id="guard_heredoc"
    _ct_message="Heredoc (<<) is permanently prohibited. Zero exceptions."
    # Context-aware suggestion
    if echo "$BASH_EXECUTION_STRING" | grep -qE '\bgit\s+commit\b'; then
        _ct_suggestion="Write message to temp file with Write tool, then: git commit -F /tmp/commit_msg.txt"
    elif echo "$BASH_EXECUTION_STRING" | grep -qE '\bgit\s+tag\b'; then
        _ct_suggestion="Write tag message to temp file, then: git tag -F /tmp/tag_msg.txt <tagname>"
    elif echo "$BASH_EXECUTION_STRING" | grep -qE '\b(cat|tee)\s+.*>\s*\S+'; then
        _ct_suggestion="Use the Write/Edit tool to create or modify files directly."
    elif echo "$BASH_EXECUTION_STRING" | grep -qE '\b(ssh|mysql|psql|sqlite3)\b'; then
        _ct_suggestion="Write commands to a temp file, then pass via -f or stdin redirect."
    else
        _ct_suggestion="Use the Write/Edit tool to create files. Never use heredoc."
    fi
fi

# Rule 2: git push — user pushes manually
if [ -z "$_ct_blocked" ] && echo "$BASH_EXECUTION_STRING" | grep -qE '\bgit\s+push\b'; then
    _ct_blocked=1
    _ct_rule_id="guard_git_push"
    _ct_message="git push blocked — user pushes manually."
    _ct_suggestion="Ask the user to push when ready."
fi

# Rule 3: rm -rf / or rm -rf ~
if [ -z "$_ct_blocked" ] && echo "$BASH_EXECUTION_STRING" | grep -qE '\brm\s+(-[a-zA-Z]*)?r[a-zA-Z]*f[a-zA-Z]*\s+(/|~|\$HOME)\b'; then
    _ct_blocked=1
    _ct_rule_id="guard_rm_rf_root"
    _ct_message="Recursive delete at root/home path. Catastrophic data loss risk."
    _ct_suggestion="Specify the exact directory to remove."
fi

# Rule 4: Force push
if [ -z "$_ct_blocked" ] && echo "$BASH_EXECUTION_STRING" | grep -qE '\bgit\s+push\s+.*--force\b|\bgit\s+push\s+-f\b'; then
    _ct_blocked=1
    _ct_rule_id="guard_force_push"
    _ct_message="Force push blocked — rewrites shared remote history."
    _ct_suggestion="Use --force-with-lease if you must force push."
fi

# Rule 5: curl | sh (pipe to shell)
if [ -z "$_ct_blocked" ] && echo "$BASH_EXECUTION_STRING" | grep -qE '\bcurl\b.*\|\s*(ba)?sh\b|\bwget\b.*\|\s*(ba)?sh\b'; then
    _ct_blocked=1
    _ct_rule_id="guard_pipe_to_shell"
    _ct_message="Piping remote content to shell. Supply chain risk."
    _ct_suggestion="Download first, inspect, then execute."
fi

# --- Audit logging (non-blocking) ---
if [ -n "$_ct_blocked" ]; then
    mkdir -p "$_CT_AUDIT_DIR" 2>/dev/null
    _ct_ts=$(date -u +"%Y-%m-%dT%H:%M:%S+00:00" 2>/dev/null || echo "unknown")
    _ct_cmd_safe=$(echo "$BASH_EXECUTION_STRING" | head -c 500 | tr '"' "'")
    printf '{"timestamp":"%s","source":"bash_env_guard","command":"%s","verdict":"BLOCK","rule_id":"%s","message":"%s"}\n' \
        "$_ct_ts" "$_ct_cmd_safe" "$_ct_rule_id" "$_ct_message" >> "$_CT_AUDIT_FILE" 2>/dev/null

    # Print block message to stderr
    echo "" >&2
    echo "╔══ CodeTrust BLOCK ══╗" >&2
    echo "║ Rule: $_ct_rule_id" >&2
    echo "║ $_ct_message" >&2
    if [ -n "$_ct_suggestion" ]; then
        echo "║ Suggestion: $_ct_suggestion" >&2
    fi
    echo "╚═════════════════════╝" >&2
    exit 2
fi

# --- Clean up variables (don't pollute command namespace) ---
unset _ct_blocked _ct_rule_id _ct_message _ct_suggestion _CT_AUDIT_DIR _CT_AUDIT_FILE _CT_GUARD_VERSION _ct_ts _ct_cmd_safe
