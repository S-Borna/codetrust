# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""CodeTrust Gateway — AI action governance layer.

Intercepts, validates, and audits AI agent actions before execution.
Prevents hallucinations, heredoc corruption, and policy violations
at the command level — not just post-hoc file scanning.

Architecture:
    AI Model → Gateway (intercept) → Validate → Allow/Block → Execute
"""

from src.gateway.audit import AuditEntry, AuditLogger
from src.gateway.interceptor import CommandInterceptor
from src.gateway.policies import GovernancePolicy, PolicyEngine, PolicyVerdict
from src.gateway.siem import SiemFormat, export_entries, export_entry, export_to_file
from src.gateway.webhooks import WebhookConfig, WebhookNotifier, WebhookProvider

__all__ = [
    "AuditEntry",
    "AuditLogger",
    "CommandInterceptor",
    "GovernancePolicy",
    "PolicyEngine",
    "PolicyVerdict",
    "SiemFormat",
    "WebhookConfig",
    "WebhookNotifier",
    "WebhookProvider",
    "export_entries",
    "export_entry",
    "export_to_file",
]
