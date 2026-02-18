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


def telemetry_enabled(*, cli_opt_out: bool) -> bool:
    """Return True if telemetry is enabled.

    Opt-out signals:
    - `CODETRUST_TELEMETRY=0`
    - CLI flag `--no-telemetry`
    - `.codetrust.toml` contains `telemetry = false`
    """

    if cli_opt_out:
        return False

    if os.environ.get("CODETRUST_TELEMETRY", "1").strip() == "0":
        return False

    try:
        cfg_path = Path.cwd() / ".codetrust.toml"
        if cfg_path.exists():
            content = _read_text(cfg_path)
            lowered = content.lower()
            if "telemetry = false" in lowered:
                return False
    except Exception:
        return True

    return True


def send_telemetry(
    *,
    event_type: str,
    source: str,
    payload: dict[str, object],
    version: str,
    cli_opt_out: bool,
) -> None:
    """Send telemetry asynchronously (best-effort)."""

    if not telemetry_enabled(cli_opt_out=cli_opt_out):
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
                timeout=TELEMETRY_TIMEOUT_SECONDS,
            )
        except Exception as exc:
            logger.debug("telemetry_send_failed", error=str(exc), event_type=event_type)

    threading.Thread(target=_send, daemon=True).start()
