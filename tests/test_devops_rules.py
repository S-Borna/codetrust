"""Tests for DevOps / infrastructure anti-pattern rules."""

import pytest

from src.models.enums import Severity
from src.services.static_analyzer import StaticAnalyzer


@pytest.fixture()
def analyzer() -> StaticAnalyzer:
    """Create a StaticAnalyzer instance."""
    return StaticAnalyzer()


# ---------------------------------------------------------------------------
# connection_no_timeout
# ---------------------------------------------------------------------------


class TestConnectionNoTimeout:
    """Detect network/DB connections without explicit timeout."""

    def test_redis_from_url_no_timeout(self, analyzer: StaticAnalyzer) -> None:
        code = (
            "client = redis.from_url(\n"
            '    "redis://localhost:6379",\n'
            "    decode_responses=True,\n"
            ")"
        )
        findings = [f for f in analyzer.scan_code(code, "cache.py") if f.rule_id == "connection_no_timeout"]
        assert len(findings) >= 1
        assert findings[0].severity == Severity.WARN

    def test_redis_from_url_with_timeout_ok(self, analyzer: StaticAnalyzer) -> None:
        code = (
            "client = redis.from_url(\n"
            '    "redis://localhost:6379",\n'
            "    decode_responses=True,\n"
            "    socket_timeout=5,\n"
            ")"
        )
        findings = [f for f in analyzer.scan_code(code, "cache.py") if f.rule_id == "connection_no_timeout"]
        assert len(findings) == 0

    def test_httpx_client_no_timeout(self, analyzer: StaticAnalyzer) -> None:
        code = "http = httpx.AsyncClient()"
        findings = [f for f in analyzer.scan_code(code, "client.py") if f.rule_id == "connection_no_timeout"]
        assert len(findings) >= 1

    def test_httpx_client_with_timeout_ok(self, analyzer: StaticAnalyzer) -> None:
        code = "http = httpx.AsyncClient(\n    timeout=10.0,\n)"
        findings = [f for f in analyzer.scan_code(code, "client.py") if f.rule_id == "connection_no_timeout"]
        assert len(findings) == 0

    def test_sqlalchemy_engine_no_timeout(self, analyzer: StaticAnalyzer) -> None:
        code = (
            "engine = create_async_engine(\n"
            '    "postgresql+asyncpg://localhost/db",\n'
            "    pool_pre_ping=True,\n"
            ")"
        )
        findings = [f for f in analyzer.scan_code(code, "db.py") if f.rule_id == "connection_no_timeout"]
        assert len(findings) >= 1

    def test_sqlalchemy_engine_with_timeout_ok(self, analyzer: StaticAnalyzer) -> None:
        code = (
            "engine = create_async_engine(\n"
            '    "postgresql+asyncpg://localhost/db",\n'
            "    connect_timeout=5,\n"
            ")"
        )
        findings = [f for f in analyzer.scan_code(code, "db.py") if f.rule_id == "connection_no_timeout"]
        assert len(findings) == 0

    def test_noqa_suppresses(self, analyzer: StaticAnalyzer) -> None:
        code = "client = redis.from_url(url)  # noqa"
        findings = [f for f in analyzer.scan_code(code, "cache.py") if f.rule_id == "connection_no_timeout"]
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# unbounded_retry
# ---------------------------------------------------------------------------


class TestUnboundedRetry:
    """Detect high retry counts without timeout guards."""

    def test_high_retries(self, analyzer: StaticAnalyzer) -> None:
        code = "max_retries = 5"
        findings = [f for f in analyzer.scan_code(code, "env.py") if f.rule_id == "unbounded_retry"]
        assert len(findings) >= 1
        assert findings[0].severity == Severity.WARN

    def test_very_high_retries(self, analyzer: StaticAnalyzer) -> None:
        code = "max_retries = 10"
        findings = [f for f in analyzer.scan_code(code, "env.py") if f.rule_id == "unbounded_retry"]
        assert len(findings) >= 1

    def test_low_retries_ok(self, analyzer: StaticAnalyzer) -> None:
        code = "max_retries = 3"
        findings = [f for f in analyzer.scan_code(code, "env.py") if f.rule_id == "unbounded_retry"]
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# retry_exponential_unbounded
# ---------------------------------------------------------------------------


class TestExponentialBackoff:
    """Detect exponential backoff without total timeout cap."""

    def test_exponential_sleep(self, analyzer: StaticAnalyzer) -> None:
        code = "time.sleep(delay * (2 ** attempt))"
        findings = [f for f in analyzer.scan_code(code, "env.py") if f.rule_id == "retry_exponential_unbounded"]
        assert len(findings) >= 1
        assert findings[0].severity == Severity.WARN

    def test_linear_sleep_ok(self, analyzer: StaticAnalyzer) -> None:
        code = "time.sleep(5)"
        findings = [f for f in analyzer.scan_code(code, "env.py") if f.rule_id == "retry_exponential_unbounded"]
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# blocking_prestart
# ---------------------------------------------------------------------------


class TestBlockingPrestart:
    """Detect migration commands that block server startup."""

    def test_alembic_blocks_uvicorn(self, analyzer: StaticAnalyzer) -> None:
        code = "web: alembic upgrade head && uvicorn src.api:app --host 0.0.0.0"
        findings = [f for f in analyzer.scan_code(code, "Procfile") if f.rule_id == "blocking_prestart"]
        assert len(findings) >= 1
        assert findings[0].severity == Severity.WARN

    def test_alembic_with_timeout_ok(self, analyzer: StaticAnalyzer) -> None:
        code = "web: timeout 30 alembic upgrade head || true; exec uvicorn src.api:app"
        findings = [f for f in analyzer.scan_code(code, "Procfile") if f.rule_id == "blocking_prestart"]
        assert len(findings) == 0

    def test_flask_db_blocks_gunicorn(self, analyzer: StaticAnalyzer) -> None:
        code = "flask db upgrade && gunicorn app:app"
        findings = [f for f in analyzer.scan_code(code, "start.sh") if f.rule_id == "blocking_prestart"]
        assert len(findings) >= 1


# ---------------------------------------------------------------------------
# dockerfile_no_healthcheck
# ---------------------------------------------------------------------------


class TestDockerfileHealthcheck:
    """Detect Dockerfiles without HEALTHCHECK."""

    def test_cmd_without_healthcheck(self, analyzer: StaticAnalyzer) -> None:
        code = "FROM python:3.12\nWORKDIR /app\nCMD [\"uvicorn\", \"app:app\"]"
        findings = [f for f in analyzer.scan_code(code, "Dockerfile") if f.rule_id == "dockerfile_no_healthcheck"]
        assert len(findings) >= 1
        assert findings[0].severity == Severity.INFO

    def test_cmd_with_healthcheck_ok(self, analyzer: StaticAnalyzer) -> None:
        code = (
            "FROM python:3.12\n"
            "HEALTHCHECK CMD curl -f http://localhost/health\n"
            'CMD ["uvicorn", "app:app"]'
        )
        findings = [f for f in analyzer.scan_code(code, "Dockerfile") if f.rule_id == "dockerfile_no_healthcheck"]
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Rule counts sanity check
# ---------------------------------------------------------------------------


class TestDevOpsRulesCoverage:
    """Verify DevOps rules are registered and running."""

    def test_devops_rules_exist(self) -> None:
        from src.rules.anti_patterns import ANTI_PATTERNS
        devops_ids = {
            "connection_no_timeout",
            "unbounded_retry",
            "retry_exponential_unbounded",
            "blocking_prestart",
            "dockerfile_no_healthcheck",
            "compose_no_healthcheck",
            "healthcheck_timeout_low",
        }
        found_ids = {r["id"] for r in ANTI_PATTERNS}
        assert devops_ids.issubset(found_ids), f"Missing: {devops_ids - found_ids}"
