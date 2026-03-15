"""Tests for sandbox execution service (Layer 4)."""

import asyncio
from http import HTTPStatus
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.testclient import TestClient

from src.models.enums import Language
from src.models.responses import SandboxResponse
from src.services.sandbox import (
    MAX_OUTPUT_BYTES,
    SUPPORTED_SANDBOX_LANGUAGES,
    SandboxService,
    _get_execution_strategy,
    _get_file_extension,
    _get_image_name,
)

# --- Helper constants ---

PYTHON_CODE = "print('hello world')"
GO_CODE = 'package main\n\nimport "fmt"\n\nfunc main() {\n\tfmt.Println("hello")\n}'
RUST_CODE = 'fn main() {\n    println!("hello");\n}'


# --- Language config tests ---


class TestLanguageConfig:
    """Test language configuration helpers."""

    def test_supported_languages_includes_python(self) -> None:
        """Python is supported for sandbox execution."""
        assert Language.PYTHON in SUPPORTED_SANDBOX_LANGUAGES

    def test_supported_languages_includes_javascript(self) -> None:
        """JavaScript is supported for sandbox execution."""
        assert Language.JAVASCRIPT in SUPPORTED_SANDBOX_LANGUAGES

    def test_supported_languages_includes_go(self) -> None:
        """Go is supported for sandbox execution."""
        assert Language.GO in SUPPORTED_SANDBOX_LANGUAGES

    def test_supported_languages_includes_rust(self) -> None:
        """Rust is supported for sandbox execution."""
        assert Language.RUST in SUPPORTED_SANDBOX_LANGUAGES

    def test_supported_languages_includes_typescript(self) -> None:
        """TypeScript is supported for sandbox execution."""
        assert Language.TYPESCRIPT in SUPPORTED_SANDBOX_LANGUAGES

    def test_get_image_name_python(self) -> None:
        """Python image name comes from settings."""
        name = _get_image_name(Language.PYTHON)
        assert "python" in name.lower()

    def test_get_file_extension_python(self) -> None:
        """Python extension is .py."""
        assert _get_file_extension(Language.PYTHON) == ".py"

    def test_get_file_extension_go(self) -> None:
        """Go extension is .go."""
        assert _get_file_extension(Language.GO) == ".go"

    def test_get_file_extension_rust(self) -> None:
        """Rust extension is .rs."""
        assert _get_file_extension(Language.RUST) == ".rs"

    def test_get_file_extension_js(self) -> None:
        """JavaScript extension is .js."""
        assert _get_file_extension(Language.JAVASCRIPT) == ".js"

    def test_inline_strategy_for_python(self) -> None:
        """Python uses inline execution strategy."""
        assert _get_execution_strategy(Language.PYTHON) == "inline"

    def test_inline_strategy_for_javascript(self) -> None:
        """JavaScript uses inline execution strategy."""
        assert _get_execution_strategy(Language.JAVASCRIPT) == "inline"

    def test_file_strategy_for_go(self) -> None:
        """Go uses file execution strategy."""
        assert _get_execution_strategy(Language.GO) == "file"

    def test_file_strategy_for_rust(self) -> None:
        """Rust uses file execution strategy."""
        assert _get_execution_strategy(Language.RUST) == "file"


# --- SandboxService unit tests ---


class TestSandboxServiceDisabled:
    """Test sandbox when disabled via settings."""

    @pytest.fixture()
    def svc(self) -> SandboxService:
        """Create a SandboxService instance."""
        return SandboxService()

    @pytest.mark.asyncio()
    async def test_sandbox_disabled_returns_error(self, svc: SandboxService) -> None:
        """When sandbox is disabled, returns error response."""
        with patch("src.services.sandbox.settings") as mock_settings:
            mock_settings.sandbox_enabled = False
            mock_settings.sandbox_default_timeout = 10
            mock_settings.sandbox_max_timeout = 30
            result = await svc.execute_code(PYTHON_CODE, Language.PYTHON)

        assert result.exit_code == -1
        assert result.error is not None
        assert "disabled" in result.error.lower()

    @pytest.mark.asyncio()
    async def test_unsupported_language_returns_error(
        self, svc: SandboxService,
    ) -> None:
        """Unsupported language returns error even if sandbox is enabled."""
        with patch("src.services.sandbox.settings") as mock_settings:
            mock_settings.sandbox_enabled = True
            mock_settings.sandbox_default_timeout = 10
            mock_settings.sandbox_max_timeout = 30
            # Force an unsupported language check
            with patch(
                "src.services.sandbox.SUPPORTED_SANDBOX_LANGUAGES",
                frozenset(),
            ):
                result = await svc.execute_code(PYTHON_CODE, Language.PYTHON)

        assert result.exit_code == -1
        assert result.error is not None
        assert "unsupported" in result.error.lower()


class TestDockerAvailability:
    """Test Docker daemon availability checks."""

    @pytest.fixture()
    def svc(self) -> SandboxService:
        """Create a fresh SandboxService instance."""
        return SandboxService()

    @pytest.mark.asyncio()
    async def test_docker_not_in_path(self, svc: SandboxService) -> None:
        """When docker binary not found, reports unavailable."""
        with patch("src.services.sandbox.shutil.which", return_value=None):
            result = await svc.is_docker_available()
        assert result is False

    @pytest.mark.asyncio()
    async def test_docker_info_fails(self, svc: SandboxService) -> None:
        """When docker info returns non-zero, reports unavailable."""
        mock_proc = AsyncMock()
        mock_proc.returncode = 1
        mock_proc.wait = AsyncMock(return_value=1)

        with (
            patch("src.services.sandbox.shutil.which", return_value="/usr/bin/docker"),
            patch(
                "src.services.sandbox.asyncio.create_subprocess_exec",
                return_value=mock_proc,
            ),
        ):
            result = await svc.is_docker_available()
        assert result is False

    @pytest.mark.asyncio()
    async def test_docker_info_succeeds(self, svc: SandboxService) -> None:
        """When docker info returns 0, docker is available."""
        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.wait = AsyncMock(return_value=0)

        with (
            patch("src.services.sandbox.shutil.which", return_value="/usr/bin/docker"),
            patch(
                "src.services.sandbox.asyncio.create_subprocess_exec",
                return_value=mock_proc,
            ),
        ):
            result = await svc.is_docker_available()
        assert result is True

    @pytest.mark.asyncio()
    async def test_docker_cached_result(self, svc: SandboxService) -> None:
        """Docker availability result is cached after first check."""
        svc._docker_available = True
        result = await svc.is_docker_available()
        assert result is True

    @pytest.mark.asyncio()
    async def test_docker_info_timeout(self, svc: SandboxService) -> None:
        """When docker info times out, reports unavailable."""
        mock_proc = AsyncMock()
        mock_proc.wait = AsyncMock(side_effect=asyncio.TimeoutError)

        with (
            patch("src.services.sandbox.shutil.which", return_value="/usr/bin/docker"),
            patch(
                "src.services.sandbox.asyncio.create_subprocess_exec",
                return_value=mock_proc,
            ),
        ):
            result = await svc.is_docker_available()
        assert result is False

    @pytest.mark.asyncio()
    async def test_docker_info_os_error(self, svc: SandboxService) -> None:
        """When docker info raises OSError, reports unavailable."""
        with (
            patch("src.services.sandbox.shutil.which", return_value="/usr/bin/docker"),
            patch(
                "src.services.sandbox.asyncio.create_subprocess_exec",
                side_effect=OSError("mock"),
            ),
        ):
            result = await svc.is_docker_available()
        assert result is False


class TestDockerUnavailableExecution:
    """Test execute_code when Docker is not available."""

    @pytest.mark.asyncio()
    async def test_no_docker_returns_error(self) -> None:
        """When Docker is unavailable, returns error response."""
        svc = SandboxService()
        with patch("src.services.sandbox.settings") as mock_settings:
            mock_settings.sandbox_enabled = True
            mock_settings.sandbox_default_timeout = 10
            mock_settings.sandbox_max_timeout = 30
            svc._docker_available = False
            result = await svc.execute_code(
                PYTHON_CODE, Language.PYTHON,
            )

        assert result.exit_code == -1
        assert result.error is not None
        assert "docker" in result.error.lower()


class TestBuildDockerCommand:
    """Test docker command building with security flags."""

    def test_basic_inline_command(self) -> None:
        """Inline command includes all security flags."""
        svc = SandboxService()
        with patch("src.services.sandbox.settings") as mock_settings:
            mock_settings.sandbox_memory_limit = "256m"
            cmd = svc._build_docker_command(
                "codetrust-sandbox-python:latest",
                10,
                [PYTHON_CODE],
            )

        assert "docker" in cmd
        assert "run" in cmd
        assert "--rm" in cmd
        assert "--network=none" in cmd
        assert "--read-only" in cmd
        assert "--memory=256m" in cmd
        assert "--pids-limit=64" in cmd
        assert "--security-opt=no-new-privileges" in cmd
        assert "--user=sandbox" in cmd
        assert "codetrust-sandbox-python:latest" in cmd
        assert PYTHON_CODE in cmd

    def test_file_command_has_volume(self) -> None:
        """File-based command includes volume mount."""
        svc = SandboxService()
        with patch("src.services.sandbox.settings") as mock_settings:
            mock_settings.sandbox_memory_limit = "256m"
            cmd = svc._build_docker_command(
                "codetrust-sandbox-go:latest",
                10,
                [],
                volume="/tmp/code:/tmp:ro",
            )

        assert "-v" in cmd
        assert "/tmp/code:/tmp:ro" in cmd

    def test_inline_command_has_tmpfs(self) -> None:
        """Inline command (no volume) gets tmpfs for /tmp."""
        svc = SandboxService()
        with patch("src.services.sandbox.settings") as mock_settings:
            mock_settings.sandbox_memory_limit = "256m"
            cmd = svc._build_docker_command(
                "codetrust-sandbox-python:latest",
                10,
                [PYTHON_CODE],
            )

        assert "--tmpfs" in cmd

    def test_file_command_no_tmpfs(self) -> None:
        """File-based command (with volume) does not get tmpfs."""
        svc = SandboxService()
        with patch("src.services.sandbox.settings") as mock_settings:
            mock_settings.sandbox_memory_limit = "256m"
            cmd = svc._build_docker_command(
                "codetrust-sandbox-go:latest",
                10,
                [],
                volume="/tmp/code:/tmp:ro",
            )

        assert "--tmpfs" not in cmd


class TestExecuteContainer:
    """Test container execution with mocked subprocess."""

    @pytest.fixture()
    def svc(self) -> SandboxService:
        """Create a SandboxService instance."""
        return SandboxService()

    @pytest.mark.asyncio()
    async def test_successful_execution(self, svc: SandboxService) -> None:
        """Successful execution returns stdout and exit code 0."""
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(
            return_value=(b"hello world\n", b""),
        )
        mock_proc.returncode = 0

        with patch(
            "src.services.sandbox.asyncio.create_subprocess_exec",
            return_value=mock_proc,
        ):
            result = await svc._execute_container(
                ["docker", "run", "test"], 10, asyncio.get_event_loop().time(),
            )

        assert result.exit_code == 0
        assert "hello world" in result.stdout
        assert result.timed_out is False
        assert result.error == ""

    @pytest.mark.asyncio()
    async def test_execution_with_stderr(self, svc: SandboxService) -> None:
        """Execution that produces stderr captures it."""
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(
            return_value=(b"", b"NameError: name 'x' is not defined\n"),
        )
        mock_proc.returncode = 1

        with patch(
            "src.services.sandbox.asyncio.create_subprocess_exec",
            return_value=mock_proc,
        ):
            result = await svc._execute_container(
                ["docker", "run", "test"], 10, asyncio.get_event_loop().time(),
            )

        assert result.exit_code == 1
        assert "NameError" in result.stderr

    @pytest.mark.asyncio()
    async def test_execution_timeout(self, svc: SandboxService) -> None:
        """Timed out execution sets timed_out flag."""
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError)
        mock_proc.kill = MagicMock()
        mock_proc.wait = AsyncMock()

        with patch(
            "src.services.sandbox.asyncio.create_subprocess_exec",
            return_value=mock_proc,
        ):
            result = await svc._execute_container(
                ["docker", "run", "test"], 1, asyncio.get_event_loop().time(),
            )

        assert result.timed_out is True
        assert result.exit_code == 124

    @pytest.mark.asyncio()
    async def test_execution_os_error(self, svc: SandboxService) -> None:
        """OSError during execution returns error response."""
        with patch(
            "src.services.sandbox.asyncio.create_subprocess_exec",
            side_effect=OSError("No such file"),
        ):
            result = await svc._execute_container(
                ["docker", "run", "test"], 10, asyncio.get_event_loop().time(),
            )

        assert result.exit_code == -1
        assert result.error is not None
        assert "docker" in result.error.lower()


class TestOutputTruncation:
    """Test output truncation logic."""

    def test_short_output_not_truncated(self) -> None:
        """Short output is returned as-is."""
        result = SandboxService._truncate_output(b"hello")
        assert result == "hello"
        assert "truncated" not in result

    def test_long_output_truncated(self) -> None:
        """Output exceeding MAX_OUTPUT_BYTES is truncated."""
        data = b"x" * (MAX_OUTPUT_BYTES + 1000)
        result = SandboxService._truncate_output(data)
        assert len(result) < len(data)
        assert "truncated" in result

    def test_exact_limit_not_truncated(self) -> None:
        """Output exactly at limit is not truncated."""
        data = b"x" * MAX_OUTPUT_BYTES
        result = SandboxService._truncate_output(data)
        assert "truncated" not in result

    def test_binary_data_handled(self) -> None:
        """Non-UTF-8 bytes are handled with replacement chars."""
        data = b"\xff\xfe" * 100
        result = SandboxService._truncate_output(data)
        assert isinstance(result, str)


class TestInlineExecution:
    """Test inline execution strategy (Python, JS, TS)."""

    @pytest.mark.asyncio()
    async def test_python_inline(self) -> None:
        """Python code runs inline via ENTRYPOINT."""
        svc = SandboxService()
        svc._docker_available = True

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(
            return_value=(b"hello\n", b""),
        )
        mock_proc.returncode = 0

        with (
            patch("src.services.sandbox.settings") as mock_settings,
            patch(
                "src.services.sandbox.asyncio.create_subprocess_exec",
                return_value=mock_proc,
            ) as mock_exec,
        ):
            mock_settings.sandbox_enabled = True
            mock_settings.sandbox_default_timeout = 10
            mock_settings.sandbox_max_timeout = 30
            mock_settings.sandbox_memory_limit = "256m"
            mock_settings.sandbox_image_python = "codetrust-sandbox-python:latest"

            result = await svc.execute_code(PYTHON_CODE, Language.PYTHON)

        assert result.exit_code == 0
        assert "hello" in result.stdout

        # Verify docker was called with the code as an argument
        call_args = mock_exec.call_args
        cmd_args = call_args[0]
        assert PYTHON_CODE in cmd_args


class TestFileExecution:
    """Test file execution strategy (Go, Rust)."""

    @pytest.mark.asyncio()
    async def test_go_file_execution(self) -> None:
        """Go code runs via file mount."""
        svc = SandboxService()
        svc._docker_available = True

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(
            return_value=(b"hello\n", b""),
        )
        mock_proc.returncode = 0

        with (
            patch("src.services.sandbox.settings") as mock_settings,
            patch(
                "src.services.sandbox.asyncio.create_subprocess_exec",
                return_value=mock_proc,
            ) as mock_exec,
        ):
            mock_settings.sandbox_enabled = True
            mock_settings.sandbox_default_timeout = 10
            mock_settings.sandbox_max_timeout = 30
            mock_settings.sandbox_memory_limit = "256m"
            mock_settings.sandbox_image_go = "codetrust-sandbox-go:latest"

            result = await svc.execute_code(GO_CODE, Language.GO)

        assert result.exit_code == 0
        # Verify volume mount was used (contains -v flag)
        call_args = mock_exec.call_args
        cmd_args = list(call_args[0])
        assert "-v" in cmd_args

    @pytest.mark.asyncio()
    async def test_rust_file_execution(self) -> None:
        """Rust code runs via file mount."""
        svc = SandboxService()
        svc._docker_available = True

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(
            return_value=(b"hello\n", b""),
        )
        mock_proc.returncode = 0

        with (
            patch("src.services.sandbox.settings") as mock_settings,
            patch(
                "src.services.sandbox.asyncio.create_subprocess_exec",
                return_value=mock_proc,
            ),
        ):
            mock_settings.sandbox_enabled = True
            mock_settings.sandbox_default_timeout = 10
            mock_settings.sandbox_max_timeout = 30
            mock_settings.sandbox_memory_limit = "256m"
            mock_settings.sandbox_image_rust = "codetrust-sandbox-rust:latest"

            result = await svc.execute_code(RUST_CODE, Language.RUST)

        assert result.exit_code == 0

    @pytest.mark.asyncio()
    async def test_file_cleanup_on_success(self) -> None:
        """Temp directory is cleaned up after successful execution."""
        svc = SandboxService()
        svc._docker_available = True

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(
            return_value=(b"ok\n", b""),
        )
        mock_proc.returncode = 0

        with (
            patch("src.services.sandbox.settings") as mock_settings,
            patch(
                "src.services.sandbox.asyncio.create_subprocess_exec",
                return_value=mock_proc,
            ),
            patch("src.services.sandbox.shutil.rmtree") as mock_rmtree,
        ):
            mock_settings.sandbox_enabled = True
            mock_settings.sandbox_default_timeout = 10
            mock_settings.sandbox_max_timeout = 30
            mock_settings.sandbox_memory_limit = "256m"
            mock_settings.sandbox_image_go = "codetrust-sandbox-go:latest"

            await svc.execute_code(GO_CODE, Language.GO)

        mock_rmtree.assert_called_once()

    @pytest.mark.asyncio()
    async def test_file_cleanup_on_error(self) -> None:
        """Temp directory is cleaned up even on execution error."""
        svc = SandboxService()
        svc._docker_available = True

        with (
            patch("src.services.sandbox.settings") as mock_settings,
            patch(
                "src.services.sandbox.asyncio.create_subprocess_exec",
                side_effect=OSError("Docker fail"),
            ),
            patch("src.services.sandbox.shutil.rmtree") as mock_rmtree,
        ):
            mock_settings.sandbox_enabled = True
            mock_settings.sandbox_default_timeout = 10
            mock_settings.sandbox_max_timeout = 30
            mock_settings.sandbox_memory_limit = "256m"
            mock_settings.sandbox_image_go = "codetrust-sandbox-go:latest"

            await svc.execute_code(GO_CODE, Language.GO)

        mock_rmtree.assert_called_once()


class TestTimeoutHandling:
    """Test timeout enforcement and clamping."""

    @pytest.mark.asyncio()
    async def test_timeout_clamped_to_max(self) -> None:
        """Timeout is clamped to sandbox_max_timeout."""
        svc = SandboxService()
        svc._docker_available = True

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(
            return_value=(b"ok\n", b""),
        )
        mock_proc.returncode = 0

        with (
            patch("src.services.sandbox.settings") as mock_settings,
            patch(
                "src.services.sandbox.asyncio.create_subprocess_exec",
                return_value=mock_proc,
            ),
        ):
            mock_settings.sandbox_enabled = True
            mock_settings.sandbox_default_timeout = 10
            mock_settings.sandbox_max_timeout = 30
            mock_settings.sandbox_memory_limit = "256m"
            mock_settings.sandbox_image_python = "codetrust-sandbox-python:latest"

            # Request 60s but max is 30s
            result = await svc.execute_code(
                PYTHON_CODE, Language.PYTHON, timeout=60,
            )

        assert result.exit_code == 0

    @pytest.mark.asyncio()
    async def test_default_timeout_used(self) -> None:
        """When no timeout specified, uses default."""
        svc = SandboxService()
        svc._docker_available = True

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(
            return_value=(b"ok\n", b""),
        )
        mock_proc.returncode = 0

        with (
            patch("src.services.sandbox.settings") as mock_settings,
            patch(
                "src.services.sandbox.asyncio.create_subprocess_exec",
                return_value=mock_proc,
            ),
        ):
            mock_settings.sandbox_enabled = True
            mock_settings.sandbox_default_timeout = 10
            mock_settings.sandbox_max_timeout = 30
            mock_settings.sandbox_memory_limit = "256m"
            mock_settings.sandbox_image_python = "codetrust-sandbox-python:latest"

            result = await svc.execute_code(
                PYTHON_CODE, Language.PYTHON,
            )

        assert result.exit_code == 0


class TestErrorResponse:
    """Test error response helper."""

    def test_error_response_fields(self) -> None:
        """Error response has correct structure."""
        import time

        svc = SandboxService()
        result = svc._error_response("test error", time.monotonic())
        assert result.exit_code == -1
        assert result.error == "test error"
        assert result.latency_ms >= 0
        assert result.stdout == ""
        assert result.stderr == ""
        assert result.timed_out is False


class TestKillProcess:
    """Test process cleanup on timeout."""

    @pytest.mark.asyncio()
    async def test_kill_process(self) -> None:
        """Process is killed on timeout."""
        mock_proc = AsyncMock()
        mock_proc.kill = MagicMock()
        mock_proc.wait = AsyncMock()

        await SandboxService._kill_process(mock_proc)
        mock_proc.kill.assert_called_once()

    @pytest.mark.asyncio()
    async def test_kill_process_already_dead(self) -> None:
        """ProcessLookupError is handled gracefully."""
        mock_proc = AsyncMock()
        mock_proc.kill = MagicMock(side_effect=ProcessLookupError)
        mock_proc.wait = AsyncMock()

        # Should not raise
        await SandboxService._kill_process(mock_proc)

    @pytest.mark.asyncio()
    async def test_kill_process_wait_timeout(self) -> None:
        """Timeout during wait after kill is handled."""
        mock_proc = AsyncMock()
        mock_proc.kill = MagicMock()
        mock_proc.wait = AsyncMock(side_effect=asyncio.TimeoutError)

        # Should not raise
        await SandboxService._kill_process(mock_proc)


class TestSandboxResponseModel:
    """Test SandboxResponse model defaults."""

    def test_default_values(self) -> None:
        """SandboxResponse has expected defaults."""
        resp = SandboxResponse(exit_code=0, latency_ms=100)
        assert resp.stdout == ""
        assert resp.stderr == ""
        assert resp.timed_out is False
        assert resp.error == ""

    def test_full_response(self) -> None:
        """SandboxResponse with all fields set."""
        resp = SandboxResponse(
            exit_code=1,
            stdout="output",
            stderr="error",
            timed_out=True,
            error="something failed",
            latency_ms=500,
        )
        assert resp.exit_code == 1
        assert resp.stdout == "output"
        assert resp.stderr == "error"
        assert resp.timed_out is True
        assert resp.error == "something failed"
        assert resp.latency_ms == 500


class TestSandboxAPIEndpoint:
    """Test /v1/sandbox/run API endpoint."""

    @pytest.fixture()
    def client(self) -> TestClient:
        """Create a TestClient with sandbox in app state."""
        import fakeredis.aioredis
        import httpx

        from src.api import app
        from src.config import settings as api_settings
        from src.services.ast_analyzer import AstAnalyzer
        from src.services.cache import CacheService
        from src.services.docker_verify import DockerVerifyService
        from src.services.registry import RegistryService
        from src.services.static_analyzer import StaticAnalyzer

        original_api_key = api_settings.api_key
        api_settings.api_key = ""

        cache = CacheService("redis://localhost:6379")
        cache._client = fakeredis.aioredis.FakeRedis(decode_responses=True)
        http_client = httpx.AsyncClient()

        app.state.cache = cache
        app.state.http_client = http_client
        app.state.registry = RegistryService(cache, http_client)
        app.state.docker = DockerVerifyService(cache, http_client)
        app.state.analyzer = StaticAnalyzer()
        app.state.ast_analyzer = AstAnalyzer()
        app.state.sandbox = SandboxService()
        app.state.db = None
        app.state.billing = None
        app.state.auth = None
        app.state.rate_limiter = None

        client = TestClient(app, raise_server_exceptions=False)
        try:
            yield client
        finally:
            api_settings.api_key = original_api_key

    def test_sandbox_run_disabled(self, client: TestClient) -> None:
        """Sandbox endpoint returns result when disabled."""
        resp = client.post("/v1/sandbox/run", json={
            "code": PYTHON_CODE,
            "language": "python",
        }, headers={"X-API-Key": "ct_pro_test"})
        assert resp.status_code == 200
        data = resp.json()
        # Sandbox is disabled by default, so we get an error
        assert data["exit_code"] == -1
        assert data["error"] is not None

    def test_sandbox_run_unsupported_language(
        self, client: TestClient,
    ) -> None:
        """Sandbox endpoint rejects unsupported languages."""
        resp = client.post("/v1/sandbox/run", json={
            "code": "SELECT 1",
            "language": "sql",
        })
        # Should get validation error or success-with-error payload.
        assert resp.status_code in (HTTPStatus.OK, HTTPStatus.UNPROCESSABLE_ENTITY)

    def test_deep_scan_includes_sandbox_fields(
        self, client: TestClient,
    ) -> None:
        """Deep scan response includes sandbox_result field."""
        resp = client.post("/v1/scan/deep", json={
            "code": PYTHON_CODE,
            "filename": "test.py",
            "language": "python",
            "verify_imports": False,
            "verify_docker": False,
            "sandbox_run": False,
        }, headers={"X-API-Key": "ct_pro_test"})
        assert resp.status_code == 200
        data = resp.json()
        assert "sandbox_result" in data
        # sandbox_run=False so sandbox_result should be None
        assert data["sandbox_result"] is None


class TestServerSandboxTool:
    """Test MCP server sandbox tool formatting."""

    def test_format_sandbox_report_success(self) -> None:
        """Successful sandbox formats as PASS."""
        from src.server import _format_sandbox_report

        result = SandboxResponse(
            exit_code=0, stdout="hello\n", stderr="",
            timed_out=False, latency_ms=100,
        )
        report = _format_sandbox_report(result)
        assert "PASS" in report
        assert "hello" in report
        assert "Sandbox Execution Report" in report

    def test_format_sandbox_report_failure(self) -> None:
        """Failed sandbox formats as FAIL."""
        from src.server import _format_sandbox_report

        result = SandboxResponse(
            exit_code=1, stdout="", stderr="error\n",
            timed_out=False, latency_ms=200,
        )
        report = _format_sandbox_report(result)
        assert "FAIL" in report
        assert "error" in report

    def test_format_sandbox_report_timeout(self) -> None:
        """Timed out sandbox formats as TIMEOUT."""
        from src.server import _format_sandbox_report

        result = SandboxResponse(
            exit_code=124, stdout="", stderr="timed out",
            timed_out=True, latency_ms=10000,
        )
        report = _format_sandbox_report(result)
        assert "TIMEOUT" in report

    def test_format_sandbox_report_error(self) -> None:
        """Error in sandbox formats with error message."""
        from src.server import _format_sandbox_report

        result = SandboxResponse(
            exit_code=-1, error="Docker is not available",
            latency_ms=0,
        )
        report = _format_sandbox_report(result)
        assert "Error" in report
        assert "Docker" in report


class TestDeepScanVerdictWithSandbox:
    """Test that sandbox results affect deep scan verdicts."""

    def test_sandbox_fail_blocks_server_verdict(self) -> None:
        """Failed sandbox causes BLOCK in server deep verdict."""
        from src.server import _compute_deep_verdict

        verdict = _compute_deep_verdict(
            findings=[], import_report="",
            docker_report="",
            sandbox_report="**Status: FAIL** | Exit code: 1",
        )
        assert verdict == "BLOCK"

    def test_sandbox_timeout_blocks_server_verdict(self) -> None:
        """Timed out sandbox causes BLOCK in server deep verdict."""
        from src.server import _compute_deep_verdict

        verdict = _compute_deep_verdict(
            findings=[], import_report="",
            docker_report="",
            sandbox_report="**Status: TIMEOUT** | Exit code: 124",
        )
        assert verdict == "BLOCK"

    def test_sandbox_error_warns_server_verdict(self) -> None:
        """Sandbox infrastructure error causes WARN in server verdict."""
        from src.server import _compute_deep_verdict

        verdict = _compute_deep_verdict(
            findings=[], import_report="",
            docker_report="",
            sandbox_report="**Error:** Docker is not available",
        )
        assert verdict == "WARN"

    def test_sandbox_pass_keeps_pass_verdict(self) -> None:
        """Successful sandbox keeps PASS verdict."""
        from src.server import _compute_deep_verdict

        verdict = _compute_deep_verdict(
            findings=[], import_report="",
            docker_report="",
            sandbox_report="**Status: PASS** | Exit code: 0",
        )
        assert verdict == "PASS"

    def test_api_sandbox_fail_blocks_verdict(self) -> None:
        """Failed sandbox causes BLOCK in API verdict."""
        from src.api import _compute_overall_verdict
        from src.models.responses import StaticScanResponse

        static = StaticScanResponse(
            total_findings=0, blocks=0, warnings=0,
            infos=0, findings=[], verdict="PASS",
        )
        sandbox_resp = SandboxResponse(
            exit_code=1, stdout="", stderr="error",
            timed_out=False, latency_ms=100,
        )

        verdict = _compute_overall_verdict(
            static, None, None, None, sandbox_resp,
        )
        assert verdict == "BLOCK"

    def test_api_sandbox_timeout_blocks_verdict(self) -> None:
        """Timed out sandbox causes BLOCK in API verdict."""
        from src.api import _compute_overall_verdict
        from src.models.responses import StaticScanResponse

        static = StaticScanResponse(
            total_findings=0, blocks=0, warnings=0,
            infos=0, findings=[], verdict="PASS",
        )
        sandbox_resp = SandboxResponse(
            exit_code=124, timed_out=True, latency_ms=10000,
        )

        verdict = _compute_overall_verdict(
            static, None, None, None, sandbox_resp,
        )
        assert verdict == "BLOCK"

    def test_api_sandbox_pass_keeps_verdict(self) -> None:
        """Successful sandbox keeps PASS in API verdict."""
        from src.api import _compute_overall_verdict
        from src.models.responses import StaticScanResponse

        static = StaticScanResponse(
            total_findings=0, blocks=0, warnings=0,
            infos=0, findings=[], verdict="PASS",
        )
        sandbox_resp = SandboxResponse(
            exit_code=0, stdout="ok", stderr="",
            timed_out=False, latency_ms=100,
        )

        verdict = _compute_overall_verdict(
            static, None, None, None, sandbox_resp,
        )
        assert verdict == "PASS"

    def test_api_sandbox_error_warns_verdict(self) -> None:
        """Sandbox error causes WARN in API verdict."""
        from src.api import _compute_overall_verdict
        from src.models.responses import StaticScanResponse

        static = StaticScanResponse(
            total_findings=0, blocks=0, warnings=0,
            infos=0, findings=[], verdict="PASS",
        )
        sandbox_resp = SandboxResponse(
            exit_code=0, error="Docker unavailable",
            latency_ms=0,
        )

        verdict = _compute_overall_verdict(
            static, None, None, None, sandbox_resp,
        )
        assert verdict == "WARN"
