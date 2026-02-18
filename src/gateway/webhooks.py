"""Gateway webhook notifications — alert external systems on governance events.

Sends real-time alerts to Slack, Microsoft Teams, PagerDuty, or generic
webhook endpoints when BLOCK or WARN verdicts are issued.

Usage:
    from src.gateway.webhooks import WebhookNotifier, WebhookConfig

    config = WebhookConfig(
        url="<your-webhook-url>",
        provider="slack",
        on_block=True,
        on_warn=True,
    )
    notifier = WebhookNotifier(config)
    await notifier.send(audit_entry)
"""

from __future__ import annotations

import json
import logging
import urllib.request
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.gateway.audit import AuditEntry

logger = logging.getLogger("codetrust.webhooks")


class WebhookProvider(StrEnum):
    """Supported webhook providers."""

    SLACK = "slack"
    TEAMS = "teams"
    PAGERDUTY = "pagerduty"
    GENERIC = "generic"


@dataclass
class WebhookConfig:
    """Webhook notification configuration."""

    url: str = ""
    provider: WebhookProvider = WebhookProvider.GENERIC
    on_block: bool = True
    on_warn: bool = False
    on_allow: bool = False
    timeout: int = 5
    enabled: bool = True
    custom_headers: dict[str, str] = field(default_factory=dict)


def _verdict_emoji(verdict: str) -> str:
    """Return emoji for verdict."""
    return {"BLOCK": "\U0001f6d1", "WARN": "\u26a0\ufe0f", "ALLOW": "\u2705"}.get(
        verdict, "\u2753"
    )


def _verdict_color(verdict: str) -> str:
    """Return hex color for verdict (Slack/Teams)."""
    return {"BLOCK": "#dc3545", "WARN": "#ffc107", "ALLOW": "#28a745"}.get(
        verdict, "#6c757d"
    )


MAX_ACTION_DISPLAY_LEN: int = 200
MAX_ORIGINAL_ACTION_LEN: int = 500
_HTTP_REDIRECT_START: int = 300


def _build_slack_blocks(entry: AuditEntry, action: str) -> list[dict]:
    """Build Slack Block Kit blocks for a governance event."""
    emoji = _verdict_emoji(entry.verdict)
    rule = entry.rule_id or "none"
    agent = entry.agent_id or "unknown"
    workspace = entry.workspace or "unknown"
    return [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{emoji} CodeTrust {entry.verdict}",
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Rule:*\n`{rule}`"},
                {"type": "mrkdwn", "text": f"*Agent:*\n{agent}"},
                {"type": "mrkdwn", "text": f"*Action:*\n{entry.action_type}"},
                {"type": "mrkdwn", "text": f"*Workspace:*\n{workspace}"},
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"```{action}```",
            },
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"_{entry.message}_",
                }
            ],
        },
    ]


def _build_slack_payload(entry: AuditEntry) -> dict:
    """Build Slack Block Kit message."""
    color = _verdict_color(entry.verdict)
    action = entry.original_action
    if len(action) > MAX_ACTION_DISPLAY_LEN:
        action = action[:MAX_ACTION_DISPLAY_LEN] + "..."

    return {
        "attachments": [
            {
                "color": color,
                "blocks": _build_slack_blocks(entry, action),
            }
        ]
    }


def _build_teams_payload(entry: AuditEntry) -> dict:
    """Build Microsoft Teams Adaptive Card payload."""
    emoji = _verdict_emoji(entry.verdict)
    color = _verdict_color(entry.verdict)
    rule = entry.rule_id or "none"
    agent = entry.agent_id or "unknown"
    action = entry.original_action
    if len(action) > MAX_ACTION_DISPLAY_LEN:
        action = action[:MAX_ACTION_DISPLAY_LEN] + "..."

    return {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": color.lstrip("#"),
        "summary": f"CodeTrust {entry.verdict}: {rule}",
        "sections": [
            {
                "activityTitle": f"{emoji} CodeTrust {entry.verdict}",
                "facts": [
                    {"name": "Rule", "value": rule},
                    {"name": "Agent", "value": agent},
                    {"name": "Action Type", "value": entry.action_type},
                    {"name": "Workspace", "value": entry.workspace or "unknown"},
                ],
                "text": f"**Command:** `{action}`\n\n_{entry.message}_",
            }
        ],
    }


def _build_pagerduty_payload(entry: AuditEntry) -> dict:
    """Build PagerDuty Events API v2 payload."""
    severity_map = {
        "BLOCK": "critical",
        "WARN": "warning",
        "ALLOW": "info",
    }
    return {
        "routing_key": "",  # filled from URL
        "event_action": "trigger",
        "payload": {
            "summary": f"CodeTrust {entry.verdict}: {entry.rule_id or 'unknown'} — {entry.message}",
            "source": entry.workspace or "codetrust",
            "severity": severity_map.get(entry.verdict, "info"),
            "component": "codetrust-gateway",
            "group": entry.action_type,
            "class": entry.verdict,
            "custom_details": {
                "rule_id": entry.rule_id,
                "agent": entry.agent_id or "unknown",
                "original_action": entry.original_action[:MAX_ORIGINAL_ACTION_LEN],
                "suggestion": entry.suggestion,
                "session_id": entry.session_id or "unknown",
            },
        },
    }


def _build_generic_payload(entry: AuditEntry) -> dict:
    """Build a simple JSON payload for generic webhooks."""
    return {
        "event": "codetrust.governance",
        "verdict": entry.verdict,
        "rule_id": entry.rule_id,
        "action_type": entry.action_type,
        "message": entry.message,
        "original_action": entry.original_action[:MAX_ORIGINAL_ACTION_LEN],
        "suggestion": entry.suggestion,
        "agent_id": entry.agent_id or "unknown",
        "session_id": entry.session_id or "unknown",
        "workspace": entry.workspace or "unknown",
        "timestamp": entry.timestamp,
    }


def build_payload(entry: AuditEntry, provider: WebhookProvider) -> dict:
    """Build provider-specific webhook payload."""
    builders = {
        WebhookProvider.SLACK: _build_slack_payload,
        WebhookProvider.TEAMS: _build_teams_payload,
        WebhookProvider.PAGERDUTY: _build_pagerduty_payload,
        WebhookProvider.GENERIC: _build_generic_payload,
    }
    builder = builders.get(provider, _build_generic_payload)
    return builder(entry)


def should_notify(entry: AuditEntry, config: WebhookConfig) -> bool:
    """Determine if an entry should trigger a webhook notification."""
    if not config.enabled or not config.url:
        return False
    if entry.verdict == "BLOCK" and config.on_block:
        return True
    if entry.verdict == "WARN" and config.on_warn:
        return True
    return bool(entry.verdict == "ALLOW" and config.on_allow)


class WebhookNotifier:
    """Sends webhook notifications for governance events.

    Thread-safe, fire-and-forget. Failures are logged but never
    raise exceptions to avoid disrupting the governance pipeline.
    """

    def __init__(self, config: WebhookConfig):
        self._config = config

    @property
    def config(self) -> WebhookConfig:
        return self._config

    def send(self, entry: AuditEntry) -> bool:
        """Send a webhook notification if the entry matches filters.

        Returns True if notification was sent successfully, False otherwise.
        """
        if not should_notify(entry, self._config):
            return False

        payload = build_payload(entry, self._config.provider)

        # PagerDuty: inject routing key from URL
        if self._config.provider == WebhookProvider.PAGERDUTY:
            payload["routing_key"] = self._config.url

        try:
            return self._post(payload)
        except Exception:
            logger.exception("Webhook delivery failed")
            return False

    def _post(self, payload: dict) -> bool:
        """HTTP POST the JSON payload to the webhook URL."""
        url = self._config.url
        if self._config.provider == WebhookProvider.PAGERDUTY:
            url = "https://events.pagerduty.com/v2/enqueue"

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "CodeTrust-Gateway/2.0",
        }
        headers.update(self._config.custom_headers)

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=self._config.timeout) as resp:
                status = resp.status
                if status < _HTTP_REDIRECT_START:
                    logger.info("Webhook sent: %s → %d", url[:60], status)
                    return True
                logger.warning("Webhook non-2xx: %s → %d", url[:60], status)
                return False
        except urllib.error.URLError as exc:
            logger.warning("Webhook failed: %s → %s", url[:60], exc.reason)
            return False
