# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""GDPR data export and deletion service.

Implements the following GDPR rights:
  - Right of Access (Art. 15): Export all personal data
  - Right to Erasure (Art. 17): Delete all personal data
  - Right to Data Portability (Art. 20): Machine-readable export (JSON)

Usage:
    gdpr = GDPRService(database_service)
    data = await gdpr.export_user_data(user_id)
    await gdpr.delete_user_data(user_id)
"""

from __future__ import annotations

import datetime

import structlog
from sqlalchemy import delete, select

from src.models.database import ApiKeyRecord, ScanLog, UsageDay, User

logger = structlog.get_logger()

_DATA_CATEGORIES: dict[str, str] = {
    "profile_data": "GitHub ID, email, name, avatar URL",
    "authentication_data": "API key metadata (names, prefixes, timestamps)",
    "usage_data": "Scan history, daily aggregates, latency metrics",
    "content_data": "None — scanned code is NOT stored after processing",
}


class GDPRService:
    """GDPR compliance service for user data operations."""

    def __init__(self, db_service: object) -> None:
        """Initialize with a DatabaseService instance.

        Args:
            db_service: DatabaseService instance with _session_factory.
        """
        self._db = db_service

    @staticmethod
    def _export_metadata(user_id: str) -> dict[str, object]:
        """Build GDPR export metadata header."""
        return {
            "exported_at": datetime.datetime.now(datetime.UTC).isoformat(),
            "user_id": user_id,
            "format_version": "1.0",
            "gdpr_articles": ["Art. 15 — Right of Access", "Art. 20 — Data Portability"],
        }

    @staticmethod
    def _serialize_profile(user: User) -> dict[str, object]:
        """Serialize user profile for GDPR export."""
        return {
            "id": user.id,
            "github_id": user.github_id,
            "email": user.email,
            "name": user.name,
            "avatar_url": user.avatar_url,
            "plan": user.plan,
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "updated_at": user.updated_at.isoformat() if user.updated_at else None,
        }

    @staticmethod
    def _serialize_api_keys(api_keys: list[ApiKeyRecord]) -> list[dict[str, object]]:
        """Serialize API key records for GDPR export."""
        return [
            {
                "id": k.id,
                "name": k.name,
                "prefix": k.prefix,
                "is_revoked": k.is_revoked,
                "created_at": k.created_at.isoformat() if k.created_at else None,
                "revoked_at": k.revoked_at.isoformat() if k.revoked_at else None,
                "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
            }
            for k in api_keys
        ]

    @staticmethod
    def _serialize_scan_history(scan_logs: list[ScanLog]) -> list[dict[str, object]]:
        """Serialize scan log records for GDPR export."""
        return [
            {
                "id": s.id,
                "scan_type": s.scan_type,
                "verdict": s.verdict,
                "findings_count": s.findings_count,
                "language": s.language,
                "filename": s.filename,
                "latency_ms": s.latency_ms,
                "input_size": s.input_size,
                "created_at": s.created_at.isoformat() if s.created_at else None,
            }
            for s in scan_logs
        ]

    @staticmethod
    def _serialize_usage_days(usage_days: list[UsageDay]) -> list[dict[str, object]]:
        """Serialize usage day records for GDPR export."""
        return [
            {
                "date": d.date.isoformat(),
                "scan_count": d.scan_count,
                "findings_total": d.findings_total,
                "avg_latency_ms": d.avg_latency_ms,
            }
            for d in usage_days
        ]

    async def export_user_data(self, user_id: str) -> dict[str, object]:
        """Export all personal data for a user (GDPR Art. 15 + Art. 20)."""
        async with self._db._session_factory() as session:
            user = await session.get(User, user_id)
            if user is None:
                logger.warning("gdpr_export_user_not_found", user_id=user_id)
                return {}

            keys_result = await session.execute(
                select(ApiKeyRecord).where(ApiKeyRecord.user_id == user_id).order_by(ApiKeyRecord.created_at.desc())
            )
            api_keys = list(keys_result.scalars().all())
            scans_result = await session.execute(
                select(ScanLog).where(ScanLog.user_id == user_id).order_by(ScanLog.created_at.desc())
            )
            scan_logs = list(scans_result.scalars().all())
            usage_result = await session.execute(
                select(UsageDay).where(UsageDay.user_id == user_id).order_by(UsageDay.date.desc())
            )
            usage_days = list(usage_result.scalars().all())

        export: dict[str, object] = {
            "export_metadata": self._export_metadata(user_id),
            "profile": self._serialize_profile(user),
            "api_keys": self._serialize_api_keys(api_keys),
            "scan_history": self._serialize_scan_history(scan_logs),
            "usage_statistics": self._serialize_usage_days(usage_days),
            "data_categories": _DATA_CATEGORIES,
        }

        logger.info(
            "gdpr_data_exported", user_id=user_id,
            keys=len(api_keys), scans=len(scan_logs), usage_days=len(usage_days),
        )
        return export

    @staticmethod
    async def _count_user_records(
        session: object,
        user_id: str,
    ) -> dict[str, int]:
        """Count all user records by type."""
        usage_count = len(
            (await session.execute(
                select(UsageDay).where(UsageDay.user_id == user_id)
            )).scalars().all()
        )
        scan_count = len(
            (await session.execute(
                select(ScanLog).where(ScanLog.user_id == user_id)
            )).scalars().all()
        )
        key_count = len(
            (await session.execute(
                select(ApiKeyRecord).where(ApiKeyRecord.user_id == user_id)
            )).scalars().all()
        )
        return {"usage_days": usage_count, "scan_logs": scan_count, "api_keys": key_count}

    async def _count_and_delete_records(
        self, user_id: str,
    ) -> dict[str, int]:
        """Count records then delete all user data within a session."""
        async with self._db._session_factory() as session:
            user = await session.get(User, user_id)
            if user is None:
                return {}

            counts = await self._count_user_records(session, user_id)

            await session.execute(delete(UsageDay).where(UsageDay.user_id == user_id))
            await session.execute(delete(ScanLog).where(ScanLog.user_id == user_id))
            await session.execute(delete(ApiKeyRecord).where(ApiKeyRecord.user_id == user_id))
            await session.execute(delete(User).where(User.id == user_id))
            await session.commit()

        return counts

    async def delete_user_data(self, user_id: str) -> dict[str, object]:
        """Delete all personal data for a user (GDPR Art. 17 — Right to Erasure).

        Cascades deletion through:
        1. Usage statistics
        2. Scan logs
        3. API keys
        4. User profile

        Args:
            user_id: The user's database ID.

        Returns:
            Dict with deletion summary (counts of deleted records).
        """
        counts = await self._count_and_delete_records(user_id)
        if not counts:
            logger.warning("gdpr_delete_user_not_found", user_id=user_id)
            return {"deleted": False, "reason": "user_not_found"}

        logger.info("gdpr_data_deleted", user_id=user_id, **counts)

        return {
            "deleted": True,
            "user_id": user_id,
            "deleted_at": datetime.datetime.now(datetime.UTC).isoformat(),
            "records_deleted": counts,
            "gdpr_article": "Art. 17 — Right to Erasure",
        }

    @staticmethod
    def _anonymize_entry(
        line: str, user_id: str,
    ) -> tuple[str, bool]:
        """Anonymize a single audit log entry if it matches the user."""
        import json
        if not line.strip():
            return line, False
        try:
            entry = json.loads(line)
            if entry.get("agent_id") == user_id or entry.get("user_id") == user_id:
                entry["agent_id"] = "REDACTED"
                if "user_id" in entry:
                    entry["user_id"] = "REDACTED"
                return json.dumps(entry), True
            return json.dumps(entry), False
        except json.JSONDecodeError:
            return line, False

    async def anonymize_audit_entries(
        self, user_id: str, audit_path: str = "",
    ) -> int:
        """Anonymize audit log entries for a deleted user.

        Replaces user identifiers with 'REDACTED' in the audit log.
        This preserves the audit trail for compliance while removing PII.

        Args:
            user_id: The user ID to anonymize.
            audit_path: Path to audit.jsonl file.

        Returns:
            Number of entries anonymized.
        """
        from pathlib import Path

        if not audit_path:
            audit_path = str(Path.cwd() / ".codetrust" / "audit.jsonl")

        path = Path(audit_path)
        if not path.exists():
            return 0

        lines = path.read_text().strip().split("\n")
        count = 0
        new_lines: list[str] = []

        for line in lines:
            replaced, matched = self._anonymize_entry(line, user_id)
            new_lines.append(replaced)
            if matched:
                count += 1

        path.write_text("\n".join(new_lines) + "\n")
        logger.info("gdpr_audit_anonymized", user_id=user_id, entries=count)
        return count
