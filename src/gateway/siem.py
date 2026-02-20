# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""SIEM export formatters — convert audit entries to enterprise log formats.

Supports:
  - CEF (Common Event Format) — ArcSight, Splunk, QRadar
  - LEEF (Log Event Extended Format) — IBM QRadar
  - Syslog (RFC 5424) — any syslog collector
  - JSON (structured) — Elastic, Datadog, Loki

Usage:
    from src.gateway.siem import export_entries, SiemFormat

    entries = audit_logger.get_entries(since=...)
    cef_lines = export_entries(entries, SiemFormat.CEF)
    syslog_lines = export_entries(entries, SiemFormat.SYSLOG)
"""

from __future__ import annotations

import datetime
import json
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.gateway.audit import AuditEntry


class SiemFormat(StrEnum):
    """Supported SIEM export formats."""

    CEF = "cef"
    LEEF = "leef"
    SYSLOG = "syslog"
    JSON = "json"


_SEVERITY_MAP = {
    "ALLOW": 0,
    "WARN": 5,
    "BLOCK": 9,
}


def _ts_iso(ts: float) -> str:
    """Convert Unix timestamp to ISO 8601."""
    return datetime.datetime.fromtimestamp(ts, tz=datetime.UTC).isoformat()


def _ts_syslog(ts: float) -> str:
    """Convert Unix timestamp to syslog RFC 5424 format."""
    return datetime.datetime.fromtimestamp(ts, tz=datetime.UTC).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )


def _escape_cef(value: str) -> str:
    """Escape special characters for CEF values."""
    return value.replace("\\", "\\\\").replace("=", "\\=").replace("|", "\\|")


def to_cef(entry: AuditEntry) -> str:
    """Convert an audit entry to CEF (Common Event Format).

    Format: CEF:0|Vendor|Product|Version|EventID|Name|Severity|Extensions

    CEF is the standard format for ArcSight, Splunk Enterprise Security,
    and IBM QRadar.
    """
    severity = _SEVERITY_MAP.get(entry.verdict, 3)
    extensions = (
        f"act={_escape_cef(entry.action_type)} "
        f"msg={_escape_cef(entry.message)} "
        f"cs1={_escape_cef(entry.rule_id)} cs1Label=RuleID "
        f"cs2={_escape_cef(entry.agent_id or 'unknown')} cs2Label=AgentID "
        f"cs3={_escape_cef(entry.session_id or 'unknown')} cs3Label=SessionID "
        f"dvchost={_escape_cef(entry.workspace or 'unknown')} "
        f"rt={int(entry.timestamp * 1000)}"
    )
    name = f"CodeTrust {entry.verdict}: {entry.rule_id or 'none'}"
    return (
        f"CEF:0|CodeTrust|Gateway|2.0.0|{entry.action_type}|"
        f"{_escape_cef(name)}|{severity}|{extensions}"
    )


def to_leef(entry: AuditEntry) -> str:
    """Convert an audit entry to LEEF (IBM QRadar native format).

    Format: LEEF:2.0|Vendor|Product|Version|EventID|key=value\tkey=value
    """
    parts = [
        f"LEEF:2.0|CodeTrust|Gateway|2.0.0|{entry.action_type}",
    ]
    attrs = (
        f"devTime={_ts_iso(entry.timestamp)}\t"
        f"sev={_SEVERITY_MAP.get(entry.verdict, 3)}\t"
        f"cat={entry.verdict}\t"
        f"action={entry.action_type}\t"
        f"msg={entry.message}\t"
        f"policy={entry.rule_id}\t"
        f"identSrc={entry.agent_id or 'unknown'}\t"
        f"identHostName={entry.workspace or 'unknown'}"
    )
    return "|".join(parts) + "|" + attrs


def to_syslog(entry: AuditEntry) -> str:
    """Convert an audit entry to RFC 5424 syslog format.

    Compatible with rsyslog, syslog-ng, Fluentd, and Logstash.
    """
    # Map verdict to syslog severity (RFC 5424)
    syslog_severity = {
        "ALLOW": 6,   # informational
        "WARN": 4,    # warning
        "BLOCK": 2,   # critical
    }
    severity = syslog_severity.get(entry.verdict, 5)
    # Facility 16 (local0) combined with severity
    priority = 16 * 8 + severity
    timestamp = _ts_syslog(entry.timestamp)
    hostname = (entry.workspace or "codetrust").split("/")[-1]

    structured_data = (
        f'[codetrust@49152 verdict="{entry.verdict}" '
        f'rule="{entry.rule_id}" '
        f'action="{entry.action_type}" '
        f'agent="{entry.agent_id or "unknown"}" '
        f'session="{entry.session_id or "unknown"}"]'
    )

    return (
        f"<{priority}>1 {timestamp} {hostname} codetrust-gateway - - "
        f"{structured_data} {entry.message}"
    )


def to_json_structured(entry: AuditEntry) -> str:
    """Convert an audit entry to structured JSON for Elastic/Datadog/Loki.

    Uses ECS (Elastic Common Schema) compatible field names.
    """
    doc = {
        "@timestamp": _ts_iso(entry.timestamp),
        "event.kind": "alert" if entry.verdict == "BLOCK" else "event",
        "event.category": "intrusion_detection",
        "event.action": entry.action_type,
        "event.outcome": "failure" if entry.verdict == "BLOCK" else "success",
        "event.severity": _SEVERITY_MAP.get(entry.verdict, 3),
        "rule.id": entry.rule_id,
        "rule.name": entry.rule_id,
        "message": entry.message,
        "codetrust.verdict": entry.verdict,
        "codetrust.suggestion": entry.suggestion,
        "codetrust.original_action": entry.original_action,
        "agent.name": entry.agent_id or "unknown",
        "host.name": entry.workspace or "unknown",
        "labels.session_id": entry.session_id or "unknown",
    }
    return json.dumps(doc, ensure_ascii=False)


def export_entry(entry: AuditEntry, fmt: SiemFormat) -> str:
    """Export a single audit entry in the given format."""
    formatters = {
        SiemFormat.CEF: to_cef,
        SiemFormat.LEEF: to_leef,
        SiemFormat.SYSLOG: to_syslog,
        SiemFormat.JSON: to_json_structured,
    }
    formatter = formatters.get(fmt)
    if formatter is None:
        msg = f"Unknown SIEM format: {fmt}"
        raise ValueError(msg)
    return formatter(entry)


def export_entries(entries: list[AuditEntry], fmt: SiemFormat) -> list[str]:
    """Export multiple audit entries in the given format.

    Args:
        entries: List of AuditEntry objects to export.
        fmt: Target SIEM format.

    Returns:
        List of formatted strings, one per entry.
    """
    return [export_entry(e, fmt) for e in entries]


def export_to_file(
    entries: list[AuditEntry],
    fmt: SiemFormat,
    path: str,
) -> int:
    """Export entries to a file.

    Args:
        entries: Audit entries to export.
        fmt: Target format.
        path: Output file path.

    Returns:
        Number of entries written.
    """
    lines = export_entries(entries, fmt)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return len(lines)
