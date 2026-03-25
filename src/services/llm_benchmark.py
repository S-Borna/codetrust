# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""LLM Security Benchmarking — per-model code quality statistics.

Correlates AI model attribution with scan findings to build
per-model quality metrics over time.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path  # noqa: TC003 — used at runtime

import structlog

logger = structlog.get_logger()

# ─────────────────────────────────────────────────────────────────
#  Types
# ─────────────────────────────────────────────────────────────────

BENCHMARK_FILENAME = "benchmark.jsonl"
CODETRUST_DIR = ".codetrust"


@dataclass(frozen=True)
class BenchmarkEntry:
    """Single benchmark data point: one scan of one file."""

    model: str
    provider: str
    language: str
    lines: int
    block_count: int
    warn_count: int
    info_count: int
    timestamp: str


@dataclass
class ModelStats:
    """Aggregated statistics for a single model."""

    model: str
    files_scanned: int = 0
    total_lines: int = 0
    total_blocks: int = 0
    total_warns: int = 0
    total_infos: int = 0
    block_rate_per_100: float = 0.0  # blocks per 100 lines
    warn_rate_per_100: float = 0.0


@dataclass
class BenchmarkResult:
    """Aggregated benchmark result across all models."""

    models: list[ModelStats] = field(default_factory=list)
    total_entries: int = 0
    total_files: int = 0


# ─────────────────────────────────────────────────────────────────
#  LLMBenchmarkService
# ─────────────────────────────────────────────────────────────────


class LLMBenchmarkService:
    """Record and aggregate LLM code quality benchmarks."""

    def record(
        self,
        workspace: Path,
        entry: BenchmarkEntry,
    ) -> None:
        """Append a benchmark entry to the JSONL file."""
        benchmark_dir = workspace / CODETRUST_DIR
        benchmark_dir.mkdir(parents=True, exist_ok=True)
        filepath = benchmark_dir / BENCHMARK_FILENAME

        data = {
            "model": entry.model,
            "provider": entry.provider,
            "language": entry.language,
            "lines": entry.lines,
            "block_count": entry.block_count,
            "warn_count": entry.warn_count,
            "info_count": entry.info_count,
            "timestamp": entry.timestamp,
        }

        try:
            with open(filepath, "a", encoding="utf-8") as f:
                f.write(json.dumps(data) + "\n")
        except OSError as exc:
            logger.warning("benchmark_write_error", error=str(exc))

    def aggregate(self, workspace: Path) -> BenchmarkResult:
        """Read all benchmark entries and compute per-model statistics."""
        filepath = workspace / CODETRUST_DIR / BENCHMARK_FILENAME
        result = BenchmarkResult()

        if not filepath.exists():
            return result

        # Collect entries grouped by model
        model_entries: dict[str, list[BenchmarkEntry]] = defaultdict(list)

        try:
            for line in filepath.read_text(encoding="utf-8").strip().split("\n"):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    entry = BenchmarkEntry(
                        model=data.get("model", "unknown"),
                        provider=data.get("provider", "unknown"),
                        language=data.get("language", "unknown"),
                        lines=int(data.get("lines", 0)),
                        block_count=int(data.get("block_count", 0)),
                        warn_count=int(data.get("warn_count", 0)),
                        info_count=int(data.get("info_count", 0)),
                        timestamp=data.get("timestamp", ""),
                    )
                    model_entries[entry.model].append(entry)
                    result.total_entries += 1
                except (json.JSONDecodeError, ValueError, TypeError):
                    continue
        except OSError:
            return result

        # Aggregate per model
        for model, entries in sorted(model_entries.items()):
            stats = ModelStats(model=model)
            stats.files_scanned = len(entries)
            stats.total_lines = sum(e.lines for e in entries)
            stats.total_blocks = sum(e.block_count for e in entries)
            stats.total_warns = sum(e.warn_count for e in entries)
            stats.total_infos = sum(e.info_count for e in entries)

            if stats.total_lines > 0:
                stats.block_rate_per_100 = (stats.total_blocks / stats.total_lines) * 100
                stats.warn_rate_per_100 = (stats.total_warns / stats.total_lines) * 100

            result.models.append(stats)

        result.total_files = sum(s.files_scanned for s in result.models)
        return result

    def build_report(self, result: BenchmarkResult) -> str:
        """Build markdown table report from benchmark data."""
        lines: list[str] = [
            "## LLM Security Benchmark",
            "",
            f"**{result.total_entries} scans recorded** across "
            f"{result.total_files} files",
            "",
        ]

        if not result.models:
            lines.append("No benchmark data available yet.")
            lines.append("Run scans with attribution to collect data.")
            return "\n".join(lines)

        lines.append(
            "| Model | Files | Lines | BLOCKs | WARNs | BLOCK/100 |"
        )
        lines.append(
            "|-------|-------|-------|--------|-------|-----------|"
        )

        for s in sorted(result.models, key=lambda x: x.block_rate_per_100):
            lines.append(
                f"| {s.model} | {s.files_scanned} | "
                f"{s.total_lines:,} | {s.total_blocks} | "
                f"{s.total_warns} | {s.block_rate_per_100:.2f} |"
            )

        return "\n".join(lines)
