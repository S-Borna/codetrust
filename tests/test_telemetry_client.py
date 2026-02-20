# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Tests for the anonymous telemetry emitter (src/telemetry_client.py)."""

from __future__ import annotations

import threading
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.telemetry_client import (
    _installation_id,
    _read_text,
    _telemetry_suppressed,
    _write_text,
    send_telemetry,
)

# ------------------------------------------------------------------
# _read_text / _write_text helpers
# ------------------------------------------------------------------


class TestReadText:
    """Tests for the _read_text helper."""

    def test_reads_existing_file(self, tmp_path: Path) -> None:
        f = tmp_path / "data.txt"
        f.write_text("  hello  ", encoding="utf-8")
        assert _read_text(f) == "hello"

    def test_returns_empty_on_missing_file(self, tmp_path: Path) -> None:
        assert _read_text(tmp_path / "missing.txt") == ""

    def test_returns_empty_on_permission_error(self, tmp_path: Path) -> None:
        f = tmp_path / "noperm.txt"
        f.write_text("x", encoding="utf-8")
        f.chmod(0o000)
        result = _read_text(f)
        f.chmod(0o644)  # restore for cleanup
        assert result == ""


class TestWriteText:
    """Tests for the _write_text helper."""

    def test_writes_to_new_file(self, tmp_path: Path) -> None:
        f = tmp_path / "sub" / "out.txt"
        _write_text(f, "data123")
        assert f.read_text(encoding="utf-8") == "data123"

    def test_creates_parent_directories(self, tmp_path: Path) -> None:
        f = tmp_path / "a" / "b" / "c" / "file.txt"
        _write_text(f, "deep")
        assert f.exists()

    def test_silently_handles_write_error(self) -> None:
        """Attempting to write to /dev/null/x should not raise."""
        _write_text(Path("/dev/null/impossible/file.txt"), "data")


# ------------------------------------------------------------------
# _installation_id
# ------------------------------------------------------------------


class TestInstallationId:
    """Tests for the _installation_id function."""

    def test_creates_new_id(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("src.telemetry_client.INSTALL_ID_REL", Path("test_install_id"))
        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
        uid = _installation_id()
        assert len(uid) == 36  # UUID format
        assert "-" in uid

    def test_returns_existing_id(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("src.telemetry_client.INSTALL_ID_REL", Path("test_install_id"))
        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
        id_path = tmp_path / "test_install_id"
        id_path.parent.mkdir(parents=True, exist_ok=True)
        id_path.write_text("fixed-uuid-1234", encoding="utf-8")
        assert _installation_id() == "fixed-uuid-1234"


# ------------------------------------------------------------------
# _telemetry_suppressed
# ------------------------------------------------------------------


class TestTelemetrySuppressed:
    """Tests for the _telemetry_suppressed guard."""

    def test_suppressed_when_env_zero(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CODETRUST_TELEMETRY", "0")
        assert _telemetry_suppressed() is True

    def test_not_suppressed_when_env_one(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CODETRUST_TELEMETRY", "1")
        assert _telemetry_suppressed() is False

    def test_not_suppressed_when_env_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("CODETRUST_TELEMETRY", raising=False)
        assert _telemetry_suppressed() is False


# ------------------------------------------------------------------
# send_telemetry
# ------------------------------------------------------------------


class TestSendTelemetry:
    """Tests for the send_telemetry function."""

    def test_suppressed_does_not_send(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CODETRUST_TELEMETRY", "0")
        mock_post = MagicMock()
        monkeypatch.setattr("src.telemetry_client.httpx.post", mock_post)
        send_telemetry(
            event_type="test",
            source="unit_test",
            payload={"k": "v"},
            version="1.0.0",
        )
        mock_post.assert_not_called()

    def test_sends_when_not_suppressed(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("CODETRUST_TELEMETRY", "1")
        monkeypatch.setattr("src.telemetry_client.INSTALL_ID_REL", Path("test_id"))
        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)

        mock_post = MagicMock()
        monkeypatch.setattr("src.telemetry_client.httpx.post", mock_post)

        send_telemetry(
            event_type="scan",
            source="cli",
            payload={"files": 1},
            version="2.6.0",
        )

        # Wait for background thread to complete
        for t in threading.enumerate():
            if t.daemon and t.name != "MainThread":
                t.join(timeout=2)

        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        body = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert body["event_type"] == "scan"
        assert body["source"] == "cli"
        assert body["version"] == "2.6.0"

    def test_send_failure_is_silent(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("CODETRUST_TELEMETRY", "1")
        monkeypatch.setattr("src.telemetry_client.INSTALL_ID_REL", Path("test_id"))
        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)

        def _raise(*a: object, **kw: object) -> None:
            msg = "connection refused"
            raise ConnectionError(msg)

        monkeypatch.setattr("src.telemetry_client.httpx.post", _raise)

        # Should not raise
        send_telemetry(
            event_type="err",
            source="test",
            payload={},
            version="0.0.0",
        )

        for t in threading.enumerate():
            if t.daemon and t.name != "MainThread":
                t.join(timeout=2)
