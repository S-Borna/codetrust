"""Layer 4: Sandbox code execution in isolated Docker containers.

Runs untrusted code in short-lived Docker containers with strict resource
limits: no network, read-only filesystem, limited memory and CPU time.
Catches import errors, syntax errors, and runtime crashes that static
analysis cannot detect.
"""

import asyncio
import shutil
import tempfile
import time
from pathlib import Path

import structlog

from src.config import settings
from src.models.enums import Language
from src.models.responses import SandboxResponse

logger = structlog.get_logger()

# Maximum output capture to prevent memory exhaustion
MAX_OUTPUT_BYTES: int = 50_000

# Language → (sandbox image, file extension, entrypoint strategy)
_LANGUAGE_CONFIG: dict[Language, tuple[str, str, str]] = {
    Language.PYTHON: ("sandbox_image_python", ".py", "inline"),
    Language.JAVASCRIPT: ("sandbox_image_node", ".js", "inline"),
    Language.TYPESCRIPT: ("sandbox_image_node", ".ts", "inline"),
    Language.GO: ("sandbox_image_go", ".go", "file"),
    Language.RUST: ("sandbox_image_rust", ".rs", "file"),
}

SUPPORTED_SANDBOX_LANGUAGES: frozenset[Language] = frozenset(
    _LANGUAGE_CONFIG.keys()
)


def _get_image_name(language: Language) -> str:
    """Get the Docker image name for a language from settings."""
    config_attr = _LANGUAGE_CONFIG[language][0]
    return str(getattr(settings, config_attr))


def _get_file_extension(language: Language) -> str:
    """Get the file extension for a language."""
    return _LANGUAGE_CONFIG[language][1]


def _get_execution_strategy(language: Language) -> str:
    """Get the execution strategy: 'inline' or 'file'."""
    return _LANGUAGE_CONFIG[language][2]


class SandboxService:
    """Execute code in isolated Docker containers."""

    def __init__(self) -> None:
        """Initialize sandbox service."""
        self._docker_available: bool | None = None

    async def is_docker_available(self) -> bool:
        """Check if Docker daemon is running and accessible."""
        if self._docker_available is not None:
            return self._docker_available

        docker_path = shutil.which("docker")
        if docker_path is None:
            self._docker_available = False
            return False

        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "info",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.wait(), timeout=5.0)
            self._docker_available = proc.returncode == 0
        except (TimeoutError, OSError):
            self._docker_available = False

        return self._docker_available

    async def execute_code(
        self,
        code: str,
        language: Language,
        timeout: int | None = None,
    ) -> SandboxResponse:
        """Execute code in an isolated Docker container.

        Args:
            code: Source code to execute.
            language: Programming language.
            timeout: Max execution time in seconds.

        Returns:
            SandboxResponse with exit code, stdout, stderr, timing.
        """
        start = time.monotonic()
        effective_timeout = min(
            timeout or settings.sandbox_default_timeout,
            settings.sandbox_max_timeout,
        )

        if not settings.sandbox_enabled:
            return self._error_response(
                "Sandbox is disabled (set CODETRUST_SANDBOX_ENABLED=true)",
                start,
            )

        if language not in SUPPORTED_SANDBOX_LANGUAGES:
            return self._error_response(
                f"Unsupported language for sandbox: {language}",
                start,
            )

        if not await self.is_docker_available():
            return self._error_response(
                "Docker is not available", start,
            )

        strategy = _get_execution_strategy(language)
        if strategy == "inline":
            return await self._run_inline(
                code, language, effective_timeout, start,
            )
        return await self._run_with_file(
            code, language, effective_timeout, start,
        )

    async def _run_inline(
        self,
        code: str,
        language: Language,
        timeout: int,
        start: float,
    ) -> SandboxResponse:
        """Run code via docker run with inline code argument."""
        image = _get_image_name(language)
        cmd = self._build_docker_command(image, timeout, [code])

        return await self._execute_container(cmd, timeout, start)

    async def _run_with_file(
        self,
        code: str,
        language: Language,
        timeout: int,
        start: float,
    ) -> SandboxResponse:
        """Run code by mounting a temp file into the container."""
        image = _get_image_name(language)
        ext = _get_file_extension(language)
        filename = f"main{ext}"

        tmp_dir = Path(tempfile.mkdtemp(prefix="codetrust-sandbox-"))
        try:
            code_file = tmp_dir / filename
            code_file.write_text(code, encoding="utf-8")

            volume_mount = f"{tmp_dir}:/tmp:ro"
            cmd = self._build_docker_command(
                image, timeout, [], volume=volume_mount,
            )
            return await self._execute_container(cmd, timeout, start)
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def _build_docker_command(
        self,
        image: str,
        timeout: int,
        extra_args: list[str],
        volume: str = "",
    ) -> list[str]:
        """Build the docker run command with security constraints."""
        cmd = [
            "docker", "run",
            "--rm",
            "--network=none",
            "--read-only",
            f"--memory={settings.sandbox_memory_limit}",
            "--memory-swap=-1",
            "--cpus=1",
            "--pids-limit=64",
            "--security-opt=no-new-privileges",
            "--user=sandbox",
        ]

        if volume:
            cmd.extend(["-v", volume])

        # tmpfs for writable /tmp (Go/Rust compilers need it)
        if not volume:
            cmd.extend(["--tmpfs", "/tmp:rw,noexec,nosuid,size=64m"])

        cmd.append(image)
        cmd.extend(extra_args)
        return cmd

    async def _execute_container(
        self,
        cmd: list[str],
        timeout: int,
        start: float,
    ) -> SandboxResponse:
        """Execute the docker run command and capture output."""
        timed_out = False
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=float(timeout + 2),
            )
            exit_code = proc.returncode or 0
        except TimeoutError:
            timed_out = True
            exit_code = 124
            stdout_bytes = b""
            stderr_bytes = b"Execution timed out"
            await self._kill_process(proc)
        except OSError as exc:
            return self._error_response(
                f"Failed to start Docker: {exc}", start,
            )

        return SandboxResponse(
            exit_code=exit_code,
            stdout=self._truncate_output(stdout_bytes),
            stderr=self._truncate_output(stderr_bytes),
            timed_out=timed_out,
            latency_ms=int((time.monotonic() - start) * 1000),
        )

    @staticmethod
    async def _kill_process(
        proc: asyncio.subprocess.Process,
    ) -> None:
        """Kill a timed-out process gracefully."""
        try:
            proc.kill()
            await asyncio.wait_for(proc.wait(), timeout=5.0)
        except (ProcessLookupError, TimeoutError):
            pass

    @staticmethod
    def _truncate_output(data: bytes) -> str:
        """Decode and truncate output to MAX_OUTPUT_BYTES."""
        text = data[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
        if len(data) > MAX_OUTPUT_BYTES:
            text += "\n... (output truncated)"
        return text

    @staticmethod
    def _error_response(message: str, start: float) -> SandboxResponse:
        """Build an error SandboxResponse."""
        logger.warning("sandbox_error", error=message)
        return SandboxResponse(
            exit_code=-1,
            error=message,
            latency_ms=int((time.monotonic() - start) * 1000),
        )
