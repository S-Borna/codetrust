# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Anonymous telemetry emitter for CodeTrust CLI/MCP/Action.

Design goals:
- Fire-and-forget: never blocks user workflows.
- Best-effort: never raises to caller.
- Privacy-preserving: never sends code, filenames, paths, repo URLs, IPs, or API keys.
"""

from __future__ import annotations

import os
import threading
import uuid
from pathlib import Path

import httpx
import structlog

logger = structlog.get_logger()

TELEMETRY_URL: str = "https://api.codetrust.ai/v1/telemetry"
TELEMETRY_TIMEOUT_SECONDS: float = 3.0
INSTALL_ID_REL: Path = Path(".codetrust") / "install_id"


def _read_text(path: Path) -> str:
    try:
        # Explicit mode-bit guard keeps behavior deterministic across platforms.
        mode = path.stat().st_mode
        if (mode & 0o444) == 0:
            return ""
        return path.read_text(encoding="utf-8").strip()
    except Exception:
        return ""


def _write_text(path: Path, value: str) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="utf-8")
    except Exception:
        return


def _installation_id() -> str:
    """Get or create anonymous installation ID stored under ~/.codetrust/install_id."""

    home = Path.home()
    id_path = home / INSTALL_ID_REL
    existing = _read_text(id_path)
    if existing:
        return existing
    new_id = str(uuid.uuid4())
    _write_text(id_path, new_id)
    return new_id


def _telemetry_suppressed() -> bool:
    """Internal guard: suppress telemetry during test runs.

    Telemetry is always active in production.  This exists solely so
    that ``conftest.py`` can set ``CODETRUST_TELEMETRY=0`` to prevent
    outbound HTTP during ``pytest``.
    """

    return os.environ.get("CODETRUST_TELEMETRY", "1").strip() == "0"


def send_telemetry(
    *,
    event_type: str,
    source: str,
    payload: dict[str, object],
    version: str,
) -> None:
    """Send telemetry asynchronously (best-effort)."""

    if _telemetry_suppressed():
        return

    def _send() -> None:
        try:
            httpx.post(
                TELEMETRY_URL,
                json={
                    "event_type": event_type,
                    "source": source,
                    "installation_id": _installation_id(),
                    "version": version,
                    "payload": payload,
                },
                headers={"X-Client-Version": version},
                timeout=TELEMETRY_TIMEOUT_SECONDS,
            )
        except Exception as exc:
            logger.debug("telemetry_send_failed", error=str(exc), event_type=event_type)

    threading.Thread(target=_send, daemon=True).start()
