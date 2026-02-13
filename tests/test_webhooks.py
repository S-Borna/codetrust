"""Tests for gateway webhook notifications."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from src.gateway.audit import AuditEntry
from src.gateway.webhooks import (
    WebhookConfig,
    WebhookNotifier,
    WebhookProvider,
    build_payload,
    should_notify,
)


@pytest.fixture
def block_entry() -> AuditEntry:
    return AuditEntry(
        timestamp=1700000000.0,
        action_type="terminal_command",
        verdict="BLOCK",
        rule_id="gateway_rm_rf",
        original_action="rm -rf /",
        message="Blocked dangerous command",
        suggestion="Use targeted rm",
        session_id="sess-1",
        agent_id="copilot",
        workspace="/home/user/project",
    )


@pytest.fixture
def warn_entry() -> AuditEntry:
    return AuditEntry(
        timestamp=1700000100.0,
        action_type="package_install",
        verdict="WARN",
        rule_id="unverified_pkg",
        original_action="pip install foo",
        message="Unverified package",
        suggestion="Check PyPI first",
        session_id="sess-2",
        agent_id="claude",
        workspace="/home/user/project",
    )


@pytest.fixture
def allow_entry() -> AuditEntry:
    return AuditEntry(
        timestamp=1700000200.0,
        action_type="file_write",
        verdict="ALLOW",
        rule_id="",
        original_action="write main.py",
        message="Allowed",
        suggestion="",
    )


@pytest.fixture
def slack_config() -> WebhookConfig:
    return WebhookConfig(
        url="https://hooks.slack.com/services/T123/B456/xxx",
        provider=WebhookProvider.SLACK,
        on_block=True,
        on_warn=True,
    )


@pytest.fixture
def teams_config() -> WebhookConfig:
    return WebhookConfig(
        url="https://outlook.office.com/webhook/xxx",
        provider=WebhookProvider.TEAMS,
        on_block=True,
        on_warn=False,
    )


@pytest.fixture
def pagerduty_config() -> WebhookConfig:
    return WebhookConfig(
        url="routing-key-xxx",
        provider=WebhookProvider.PAGERDUTY,
        on_block=True,
        on_warn=True,
    )


@pytest.fixture
def generic_config() -> WebhookConfig:
    return WebhookConfig(
        url="https://example.com/webhook",
        provider=WebhookProvider.GENERIC,
        on_block=True,
        on_warn=False,
    )


# --- should_notify ---


class TestShouldNotify:
    def test_block_notifies(self, block_entry, slack_config):
        assert should_notify(block_entry, slack_config) is True

    def test_warn_notifies_when_enabled(self, warn_entry, slack_config):
        assert should_notify(warn_entry, slack_config) is True

    def test_warn_skips_when_disabled(self, warn_entry, teams_config):
        assert should_notify(warn_entry, teams_config) is False

    def test_allow_skips_by_default(self, allow_entry, slack_config):
        assert should_notify(allow_entry, slack_config) is False

    def test_allow_notifies_when_enabled(self, allow_entry):
        cfg = WebhookConfig(url="https://x.com/w", on_allow=True)
        assert should_notify(allow_entry, cfg) is True

    def test_disabled_config(self, block_entry):
        cfg = WebhookConfig(url="https://x.com/w", enabled=False)
        assert should_notify(block_entry, cfg) is False

    def test_no_url(self, block_entry):
        cfg = WebhookConfig(url="")
        assert should_notify(block_entry, cfg) is False


# --- Payload builders ---


class TestSlackPayload:
    def test_has_attachments(self, block_entry):
        payload = build_payload(block_entry, WebhookProvider.SLACK)
        assert "attachments" in payload

    def test_attachment_color_block(self, block_entry):
        payload = build_payload(block_entry, WebhookProvider.SLACK)
        assert payload["attachments"][0]["color"] == "#dc3545"

    def test_contains_rule_id(self, block_entry):
        payload = build_payload(block_entry, WebhookProvider.SLACK)
        raw = json.dumps(payload)
        assert "gateway_rm_rf" in raw

    def test_contains_agent(self, block_entry):
        payload = build_payload(block_entry, WebhookProvider.SLACK)
        raw = json.dumps(payload)
        assert "copilot" in raw


class TestTeamsPayload:
    def test_message_card_type(self, block_entry):
        payload = build_payload(block_entry, WebhookProvider.TEAMS)
        assert payload["@type"] == "MessageCard"

    def test_theme_color(self, block_entry):
        payload = build_payload(block_entry, WebhookProvider.TEAMS)
        assert payload["themeColor"] == "dc3545"

    def test_sections_present(self, block_entry):
        payload = build_payload(block_entry, WebhookProvider.TEAMS)
        assert len(payload["sections"]) == 1

    def test_facts_contain_rule(self, block_entry):
        payload = build_payload(block_entry, WebhookProvider.TEAMS)
        facts = payload["sections"][0]["facts"]
        rule_fact = next(f for f in facts if f["name"] == "Rule")
        assert rule_fact["value"] == "gateway_rm_rf"


class TestPagerDutyPayload:
    def test_event_action(self, block_entry):
        payload = build_payload(block_entry, WebhookProvider.PAGERDUTY)
        assert payload["event_action"] == "trigger"

    def test_severity_critical(self, block_entry):
        payload = build_payload(block_entry, WebhookProvider.PAGERDUTY)
        assert payload["payload"]["severity"] == "critical"

    def test_severity_warning(self, warn_entry):
        payload = build_payload(warn_entry, WebhookProvider.PAGERDUTY)
        assert payload["payload"]["severity"] == "warning"

    def test_custom_details(self, block_entry):
        payload = build_payload(block_entry, WebhookProvider.PAGERDUTY)
        details = payload["payload"]["custom_details"]
        assert details["rule_id"] == "gateway_rm_rf"
        assert details["agent"] == "copilot"


class TestGenericPayload:
    def test_event_field(self, block_entry):
        payload = build_payload(block_entry, WebhookProvider.GENERIC)
        assert payload["event"] == "codetrust.governance"

    def test_verdict_field(self, block_entry):
        payload = build_payload(block_entry, WebhookProvider.GENERIC)
        assert payload["verdict"] == "BLOCK"

    def test_timestamp_field(self, block_entry):
        payload = build_payload(block_entry, WebhookProvider.GENERIC)
        assert payload["timestamp"] == 1700000000.0


# --- WebhookNotifier ---


class TestWebhookNotifier:
    def test_skips_when_not_matching(self, allow_entry, slack_config):
        notifier = WebhookNotifier(slack_config)
        result = notifier.send(allow_entry)
        assert result is False

    @patch("src.gateway.webhooks.urllib.request.urlopen")
    def test_sends_on_block(self, mock_urlopen, block_entry, slack_config):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        notifier = WebhookNotifier(slack_config)
        result = notifier.send(block_entry)
        assert result is True
        mock_urlopen.assert_called_once()

    @patch("src.gateway.webhooks.urllib.request.urlopen")
    def test_pagerduty_uses_events_api(self, mock_urlopen, block_entry, pagerduty_config):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        notifier = WebhookNotifier(pagerduty_config)
        notifier.send(block_entry)
        # Verify the request URL is the PagerDuty events API
        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        assert req.full_url == "https://events.pagerduty.com/v2/enqueue"

    @patch("src.gateway.webhooks.urllib.request.urlopen")
    def test_handles_failure_gracefully(self, mock_urlopen, block_entry, slack_config):
        import urllib.error
        mock_urlopen.side_effect = urllib.error.URLError("connection refused")

        notifier = WebhookNotifier(slack_config)
        result = notifier.send(block_entry)
        assert result is False  # no exception raised

    def test_config_property(self, slack_config):
        notifier = WebhookNotifier(slack_config)
        assert notifier.config is slack_config


# --- Provider enum ---


class TestWebhookProvider:
    def test_values(self):
        assert WebhookProvider.SLACK == "slack"
        assert WebhookProvider.TEAMS == "teams"
        assert WebhookProvider.PAGERDUTY == "pagerduty"
        assert WebhookProvider.GENERIC == "generic"

    def test_from_string(self):
        assert WebhookProvider("slack") == WebhookProvider.SLACK
