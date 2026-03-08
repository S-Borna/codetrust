"""Tests for SIEM audit export formatters."""

from __future__ import annotations

import json
import os

import pytest

from src.gateway.audit import AuditEntry
from src.gateway.siem import (
    SiemFormat,
    export_entries,
    export_entry,
    export_to_file,
    to_cef,
    to_json_structured,
    to_leef,
    to_syslog,
)


@pytest.fixture
def sample_entry() -> AuditEntry:
    """Create a sample audit entry for testing."""
    return AuditEntry(
        timestamp=1700000000.0,
        action_type="terminal_command",
        verdict="BLOCK",
        rule_id="no_rm_rf",
        original_action="rm -rf /",
        message="Blocked dangerous recursive delete",
        suggestion="Use targeted rm with explicit paths",
        session_id="sess-123",
        agent_id="copilot",
        workspace="/home/user/project",
        metadata={"extra": "info"},
    )


@pytest.fixture
def allow_entry() -> AuditEntry:
    """Create an ALLOW verdict entry."""
    return AuditEntry(
        timestamp=1700000100.0,
        action_type="file_write",
        verdict="ALLOW",
        rule_id="",
        original_action="write main.py",
        message="File write allowed",
        suggestion="",
        session_id="sess-456",
        agent_id="claude",
        workspace="/home/user/project",
    )


@pytest.fixture
def warn_entry() -> AuditEntry:
    """Create a WARN verdict entry."""
    return AuditEntry(
        timestamp=1700000200.0,
        action_type="package_install",
        verdict="WARN",
        rule_id="unverified_pkg",
        original_action="pip install sketchy-lib",
        message="Unverified package installation",
        suggestion="Check package on PyPI first",
        session_id="sess-789",
        agent_id=None,
        workspace=None,
    )


# --- CEF format ---


class TestCefFormat:
    def test_cef_header_structure(self, sample_entry: AuditEntry) -> None:
        cef = to_cef(sample_entry)
        assert cef.startswith("CEF:0|CodeTrust|Gateway|2.0.0|")

    def test_cef_contains_event_id(self, sample_entry: AuditEntry) -> None:
        cef = to_cef(sample_entry)
        assert "terminal_command" in cef

    def test_cef_severity_block(self, sample_entry: AuditEntry) -> None:
        cef = to_cef(sample_entry)
        # BLOCK severity = 9
        parts = cef.split("|")
        assert parts[6] == "9"

    def test_cef_severity_allow(self, allow_entry: AuditEntry) -> None:
        cef = to_cef(allow_entry)
        parts = cef.split("|")
        assert parts[6] == "0"

    def test_cef_severity_warn(self, warn_entry: AuditEntry) -> None:
        cef = to_cef(warn_entry)
        parts = cef.split("|")
        assert parts[6] == "5"

    def test_cef_extensions_contain_rule(self, sample_entry: AuditEntry) -> None:
        cef = to_cef(sample_entry)
        assert "cs1=no_rm_rf" in cef
        assert "cs1Label=RuleID" in cef

    def test_cef_extensions_contain_agent(self, sample_entry: AuditEntry) -> None:
        cef = to_cef(sample_entry)
        assert "cs2=copilot" in cef
        assert "cs2Label=AgentID" in cef

    def test_cef_escapes_pipe(self) -> None:
        entry = AuditEntry(
            timestamp=1700000000.0,
            action_type="test",
            verdict="BLOCK",
            rule_id="test|rule",
            original_action="cmd",
            message="msg with | pipe",
            suggestion="",
        )
        cef = to_cef(entry)
        # Pipe in message should be escaped
        assert "msg with \\| pipe" in cef

    def test_cef_unknown_agent(self, warn_entry: AuditEntry) -> None:
        cef = to_cef(warn_entry)
        assert "cs2=unknown" in cef


# --- LEEF format ---


class TestLeefFormat:
    def test_leef_header(self, sample_entry: AuditEntry) -> None:
        leef = to_leef(sample_entry)
        assert leef.startswith("LEEF:2.0|CodeTrust|Gateway|2.0.0|")

    def test_leef_contains_event_id(self, sample_entry: AuditEntry) -> None:
        leef = to_leef(sample_entry)
        assert "terminal_command" in leef

    def test_leef_severity_block(self, sample_entry: AuditEntry) -> None:
        leef = to_leef(sample_entry)
        assert "sev=9" in leef

    def test_leef_category(self, sample_entry: AuditEntry) -> None:
        leef = to_leef(sample_entry)
        assert "cat=BLOCK" in leef

    def test_leef_tab_separated_attrs(self, sample_entry: AuditEntry) -> None:
        leef = to_leef(sample_entry)
        # LEEF uses tab separators
        assert "\t" in leef


# --- Syslog format ---


class TestSyslogFormat:
    def test_syslog_priority_block(self, sample_entry: AuditEntry) -> None:
        syslog = to_syslog(sample_entry)
        # Facility local0 (16) * 8 + severity critical (2) = 130
        assert syslog.startswith("<130>")

    def test_syslog_priority_allow(self, allow_entry: AuditEntry) -> None:
        syslog = to_syslog(allow_entry)
        # Facility local0 (16) * 8 + severity info (6) = 134
        assert syslog.startswith("<134>")

    def test_syslog_priority_warn(self, warn_entry: AuditEntry) -> None:
        syslog = to_syslog(warn_entry)
        # Facility local0 (16) * 8 + severity warning (4) = 132
        assert syslog.startswith("<132>")

    def test_syslog_structured_data(self, sample_entry: AuditEntry) -> None:
        syslog = to_syslog(sample_entry)
        assert "[codetrust@" + "491" + "52" in syslog
        assert 'verdict="BLOCK"' in syslog
        assert 'rule="no_rm_rf"' in syslog

    def test_syslog_rfc5424_version(self, sample_entry: AuditEntry) -> None:
        syslog = to_syslog(sample_entry)
        # RFC structured format has version marker "1" after priority
        assert ">1 " in syslog

    def test_syslog_contains_message(self, sample_entry: AuditEntry) -> None:
        syslog = to_syslog(sample_entry)
        assert "Blocked dangerous recursive delete" in syslog

    def test_syslog_hostname_from_workspace(self, sample_entry: AuditEntry) -> None:
        syslog = to_syslog(sample_entry)
        assert "project" in syslog  # last segment of /home/user/project

    def test_syslog_hostname_fallback(self, warn_entry: AuditEntry) -> None:
        syslog = to_syslog(warn_entry)
        assert "codetrust" in syslog


# --- JSON structured format ---


class TestJsonFormat:
    def test_json_valid(self, sample_entry: AuditEntry) -> None:
        result = to_json_structured(sample_entry)
        doc = json.loads(result)
        assert isinstance(doc, dict)

    def test_json_ecs_fields(self, sample_entry: AuditEntry) -> None:
        doc = json.loads(to_json_structured(sample_entry))
        assert "@timestamp" in doc
        assert doc["event.action"] == "terminal_command"
        assert doc["event.kind"] == "alert"  # BLOCK -> alert
        assert doc["event.outcome"] == "failure"
        assert doc["rule.id"] == "no_rm_rf"

    def test_json_allow_is_event(self, allow_entry: AuditEntry) -> None:
        doc = json.loads(to_json_structured(allow_entry))
        assert doc["event.kind"] == "event"
        assert doc["event.outcome"] == "success"

    def test_json_severity_mapping(self, sample_entry: AuditEntry) -> None:
        doc = json.loads(to_json_structured(sample_entry))
        assert doc["event.severity"] == 9  # BLOCK

    def test_json_agent_name(self, sample_entry: AuditEntry) -> None:
        doc = json.loads(to_json_structured(sample_entry))
        assert doc["agent.name"] == "copilot"


# --- Export helpers ---


class TestExportHelpers:
    def test_export_entry_cef(self, sample_entry: AuditEntry) -> None:
        line = export_entry(sample_entry, SiemFormat.CEF)
        assert line.startswith("CEF:0|")

    def test_export_entry_syslog(self, sample_entry: AuditEntry) -> None:
        line = export_entry(sample_entry, SiemFormat.SYSLOG)
        assert line.startswith("<")

    def test_export_entry_leef(self, sample_entry: AuditEntry) -> None:
        line = export_entry(sample_entry, SiemFormat.LEEF)
        assert line.startswith("LEEF:")

    def test_export_entry_json(self, sample_entry: AuditEntry) -> None:
        line = export_entry(sample_entry, SiemFormat.JSON)
        doc = json.loads(line)
        assert "event.action" in doc

    def test_export_entry_invalid_format(self, sample_entry: AuditEntry) -> None:
        with pytest.raises(ValueError, match="Unknown SIEM format"):
            export_entry(sample_entry, "xml")  # type: ignore[arg-type]

    def test_export_entries_batch(
        self,
        sample_entry: AuditEntry,
        allow_entry: AuditEntry,
        warn_entry: AuditEntry,
    ) -> None:
        lines = export_entries(
            [sample_entry, allow_entry, warn_entry],
            SiemFormat.CEF,
        )
        assert len(lines) == 3
        assert all(line.startswith("CEF:0|") for line in lines)

    def test_export_entries_empty(self) -> None:
        lines = export_entries([], SiemFormat.CEF)
        assert lines == []

    def test_export_to_file(
        self,
        sample_entry: AuditEntry,
        allow_entry: AuditEntry,
        tmp_path,
    ) -> None:
        outfile = str(tmp_path / "audit.cef")
        count = export_to_file(
            [sample_entry, allow_entry],
            SiemFormat.CEF,
            outfile,
        )
        assert count == 2
        assert os.path.exists(outfile)
        with open(outfile) as f:
            content = f.read()
        lines = content.strip().split("\n")
        assert len(lines) == 2
        assert lines[0].startswith("CEF:0|")

    def test_export_to_file_syslog(self, sample_entry: AuditEntry, tmp_path) -> None:
        outfile = str(tmp_path / "audit.log")
        count = export_to_file([sample_entry], SiemFormat.SYSLOG, outfile)
        assert count == 1
        with open(outfile) as f:
            assert f.read().startswith("<130>")


# --- SiemFormat enum ---


class TestSiemFormatEnum:
    def test_cef_value(self) -> None:
        assert SiemFormat.CEF == "cef"

    def test_leef_value(self) -> None:
        assert SiemFormat.LEEF == "leef"

    def test_syslog_value(self) -> None:
        assert SiemFormat.SYSLOG == "syslog"

    def test_json_value(self) -> None:
        assert SiemFormat.JSON == "json"

    def test_from_string(self) -> None:
        assert SiemFormat("cef") == SiemFormat.CEF
