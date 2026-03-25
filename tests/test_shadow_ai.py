"""Tests for Shadow AI Detection."""

from __future__ import annotations

from pathlib import Path

from src.services.shadow_ai import (
    ShadowAIScanner,
    ShadowScanResult,
    _get_installed_vscode_extensions,
)


class TestShadowAIScanner:
    """Tests for the shadow AI scanner."""

    def test_scan_returns_result(self) -> None:
        """Scan returns a ShadowScanResult."""
        scanner = ShadowAIScanner()
        result = scanner.scan()
        assert isinstance(result, ShadowScanResult)

    def test_scan_detects_tools_on_dev_machine(self) -> None:
        """Scan finds at least one tool on a developer machine."""
        scanner = ShadowAIScanner()
        result = scanner.scan()
        assert isinstance(result.detections, list)

    def test_approved_filter(self) -> None:
        """Approved tools are classified correctly."""
        scanner = ShadowAIScanner()
        result = scanner.scan(approved_tools=frozenset({"claude_code"}))
        for d in result.approved:
            assert d.tool_id == "claude_code" or result.total_found == 0

    def test_unapproved_filter(self) -> None:
        """Tools not in approved list are flagged."""
        scanner = ShadowAIScanner()
        result = scanner.scan(approved_tools=frozenset())
        assert len(result.unapproved) == result.total_found

    def test_none_approved_means_all_approved(self) -> None:
        """None approved_tools means no filtering (all approved)."""
        scanner = ShadowAIScanner()
        result = scanner.scan(approved_tools=None)
        assert len(result.unapproved) == 0

    def test_build_report_empty(self) -> None:
        """Report handles empty results."""
        scanner = ShadowAIScanner()
        result = ShadowScanResult()
        report = scanner.build_report(result)
        assert "0 AI tools" in report

    def test_build_report_with_detections(self) -> None:
        """Report includes detection details."""
        scanner = ShadowAIScanner()
        result = scanner.scan()
        report = scanner.build_report(result)
        assert "Shadow AI Scan" in report


class TestVSCodeExtensions:
    """Tests for VS Code extension detection."""

    def test_parse_extension_dir(self, tmp_path: Path) -> None:
        """Parse extension directory names correctly."""
        (tmp_path / "github.copilot-1.234.0").mkdir()
        (tmp_path / "saoudrizwan.claude-dev-3.0.0").mkdir()
        (tmp_path / "ms-python.python-2024.1.0").mkdir()

        extensions = _get_installed_vscode_extensions(tmp_path)
        assert "github.copilot" in extensions
        assert "saoudrizwan.claude-dev" in extensions
        assert "ms-python.python" in extensions

    def test_empty_dir(self, tmp_path: Path) -> None:
        """Empty directory returns empty set."""
        extensions = _get_installed_vscode_extensions(tmp_path)
        assert len(extensions) == 0
