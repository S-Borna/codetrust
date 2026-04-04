# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""LLM Cost Tracking Engine — per-developer, per-team cost analysis.

Tracks token usage across models/providers, calculates costs from a
maintained pricing table, detects anomalies (3x 7-day average, 50%+
of team spend), and enforces budgets with warn/alert/block thresholds.

Pricing updated 2026-04 from official provider pricing pages.
"""

from __future__ import annotations

import fnmatch
import logging
import subprocess
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from src.services.cost_storage import LLMUsageEvent, append_event, read_events

logger = logging.getLogger("codetrust.cost_tracker")

# ───────────────────────────────────────────────────────────────
#  Model pricing table — (input_per_1M_tokens, output_per_1M_tokens) in USD
#  Updated: 2026-04. Sources: anthropic.com, openai.com, cloud.google.com
# ───────────────────────────────────────────────────────────────

MODEL_PRICING: dict[str, tuple[float, float]] = {
    # Anthropic — Claude 4.x family
    "claude-opus-4-20250514": (15.0, 75.0),
    "claude-opus-4.6": (15.0, 75.0),
    "claude-sonnet-4-20250514": (3.0, 15.0),
    "claude-sonnet-4.6": (3.0, 15.0),
    "claude-haiku-4-20250414": (0.80, 4.0),
    "claude-haiku-4.5": (0.80, 4.0),
    # OpenAI — GPT/o-series (as of 2026-04)
    "gpt-4.1": (2.0, 8.0),
    "gpt-4.1-mini": (0.40, 1.60),
    "gpt-4.1-nano": (0.10, 0.40),
    "gpt-4o": (2.50, 10.0),
    "gpt-4o-mini": (0.15, 0.60),
    "o3": (10.0, 40.0),
    "o3-mini": (1.10, 4.40),
    "o4-mini": (1.10, 4.40),
    "codex-mini": (1.50, 6.0),
    # Google — Gemini 2.x family
    "gemini-2.5-pro": (1.25, 10.0),
    "gemini-2.5-flash": (0.15, 0.60),
    "gemini-2.0-flash": (0.10, 0.40),
    # Meta — Llama (self-hosted, estimate based on compute)
    "llama-4-maverick": (0.20, 0.80),
    "llama-4-scout": (0.05, 0.20),
}

# Prefix-based fallback for version-suffixed models
_PRICING_PREFIXES: list[tuple[str, tuple[float, float]]] = [
    ("claude-opus", (15.0, 75.0)),
    ("claude-sonnet", (3.0, 15.0)),
    ("claude-haiku", (0.80, 4.0)),
    ("gpt-4.1-mini", (0.40, 1.60)),
    ("gpt-4.1-nano", (0.10, 0.40)),
    ("gpt-4.1", (2.0, 8.0)),
    ("gpt-4o-mini", (0.15, 0.60)),
    ("gpt-4o", (2.50, 10.0)),
    ("o3-mini", (1.10, 4.40)),
    ("o4-mini", (1.10, 4.40)),
    ("gemini-2.5-pro", (1.25, 10.0)),
    ("gemini-2.5-flash", (0.15, 0.60)),
]

# Default fallback for completely unknown models
_UNKNOWN_MODEL_PRICING: tuple[float, float] = (2.0, 8.0)


def get_model_pricing(model: str) -> tuple[tuple[float, float], bool]:
    """Look up pricing for a model.

    Args:
        model: Model identifier.

    Returns:
        Tuple of ((input_per_1M, output_per_1M), is_estimated).
    """
    model_lower = model.lower()
    if model_lower in MODEL_PRICING:
        return MODEL_PRICING[model_lower], False

    for prefix, pricing in _PRICING_PREFIXES:
        if model_lower.startswith(prefix):
            return pricing, False

    return _UNKNOWN_MODEL_PRICING, True


def calculate_cost(
    model: str,
    input_tokens: int,
    output_tokens: int,
) -> tuple[float, bool]:
    """Calculate estimated cost for a model invocation.

    Args:
        model: Model identifier.
        input_tokens: Number of input tokens.
        output_tokens: Number of output tokens.

    Returns:
        Tuple of (cost_usd, is_estimated).
    """
    pricing, estimated = get_model_pricing(model)
    input_cost = (input_tokens / 1_000_000) * pricing[0]
    output_cost = (output_tokens / 1_000_000) * pricing[1]
    return round(input_cost + output_cost, 6), estimated


# ───────────────────────────────────────────────────────────────
#  Event creation helpers
# ───────────────────────────────────────────────────────────────


def _get_developer() -> str:
    """Get current developer identity from git config."""
    try:
        result = subprocess.run(
            ["git", "config", "user.name"],
            capture_output=True, text=True, timeout=5,
        )
        name = result.stdout.strip()
        return name if name else "unknown"
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"


def _get_project() -> str:
    """Get current project name from git remote or directory."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=5,
        )
        top = result.stdout.strip()
        return Path(top).name if top else Path.cwd().name
    except (OSError, subprocess.TimeoutExpired):
        return Path.cwd().name


def log_usage(
    model: str,
    provider: str,
    input_tokens: int,
    output_tokens: int,
    action: str = "code_generation",
    developer: str = "",
    team: str = "",
    project: str = "",
    session_id: str = "",
    project_dir: Path | None = None,
) -> LLMUsageEvent:
    """Log an LLM usage event with cost calculation.

    Args:
        model: Model identifier.
        provider: Provider name.
        input_tokens: Input token count.
        output_tokens: Output token count.
        action: Action type (code_generation, scan, review, etc.).
        developer: Developer name (auto-detected from git if empty).
        team: Team name (from policy if empty).
        project: Project name (auto-detected if empty).
        session_id: Session identifier.
        project_dir: Project root for storage.

    Returns:
        The created LLMUsageEvent.
    """
    cost, estimated = calculate_cost(model, input_tokens, output_tokens)

    if not developer:
        developer = _get_developer()
    if not team:
        team = _resolve_team(developer, project_dir)
    if not project:
        project = _get_project()

    event = LLMUsageEvent(
        timestamp=datetime.now(UTC).isoformat(),
        model=model,
        provider=provider,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        total_tokens=input_tokens + output_tokens,
        estimated_cost_usd=cost,
        developer=developer,
        team=team,
        project=project,
        session_id=session_id,
        action=action,
        cost_estimated=estimated,
    )

    append_event(event, project_dir)
    return event


# ───────────────────────────────────────────────────────────────
#  Team resolution from .codetrust.toml
# ───────────────────────────────────────────────────────────────


def _resolve_team(developer: str, project_dir: Path | None = None) -> str:
    """Resolve a developer's team from .codetrust.toml [cost.team] config."""
    root = project_dir or Path.cwd()
    config_path = root / ".codetrust.toml"
    if not config_path.is_file():
        return ""

    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError:
            return ""

    try:
        raw = tomllib.loads(config_path.read_text(encoding="utf-8"))
        teams = raw.get("cost", {}).get("team", {})
        for team_name, members in teams.items():
            if isinstance(members, list) and developer in members:
                return team_name
    except (OSError, ValueError, KeyError):
        pass
    return ""


# ───────────────────────────────────────────────────────────────
#  Cost report generation
# ───────────────────────────────────────────────────────────────


@dataclass
class CostReport:
    """Aggregated cost report for a period."""

    period: str
    start_date: str
    end_date: str
    total_cost_usd: float
    total_tokens: int
    event_count: int
    by_developer: dict[str, float]
    by_team: dict[str, float]
    by_model: dict[str, float]
    by_project: dict[str, float]
    by_provider: dict[str, float]
    daily_trend: list[dict[str, Any]]
    anomalies: list[dict[str, Any]]
    budget_status: dict[str, Any] | None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-safe dictionary."""
        return {
            "period": self.period,
            "start_date": self.start_date,
            "end_date": self.end_date,
            "total_cost_usd": round(self.total_cost_usd, 2),
            "total_tokens": self.total_tokens,
            "event_count": self.event_count,
            "by_developer": {k: round(v, 2) for k, v in self.by_developer.items()},
            "by_team": {k: round(v, 2) for k, v in self.by_team.items()},
            "by_model": {k: round(v, 2) for k, v in self.by_model.items()},
            "by_project": {k: round(v, 2) for k, v in self.by_project.items()},
            "by_provider": {k: round(v, 2) for k, v in self.by_provider.items()},
            "daily_trend": self.daily_trend,
            "anomalies": self.anomalies,
            "budget_status": self.budget_status,
        }


def _compute_date_range(period: str) -> tuple[str, str]:
    """Compute start/end ISO dates for a period.

    Args:
        period: "daily", "weekly", "monthly".

    Returns:
        Tuple of (start_date, end_date) as ISO strings.
    """
    now = datetime.now(UTC)
    end = now.isoformat()

    if period == "daily":
        start = now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    elif period == "weekly":
        start_dt = now - timedelta(days=now.weekday())
        start = start_dt.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    else:  # monthly
        start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()

    return start, end


def generate_report(
    period: str = "monthly",
    developer: str = "",
    team: str = "",
    model_filter: str = "",
    project_filter: str = "",
    project_dir: Path | None = None,
) -> CostReport:
    """Generate an aggregated cost report.

    Args:
        period: "daily", "weekly", "monthly".
        developer: Filter by developer name.
        team: Filter by team name.
        model_filter: Filter by model pattern (supports wildcards).
        project_filter: Filter by project name.
        project_dir: Project root for storage.

    Returns:
        CostReport with aggregated data.
    """
    start_date, end_date = _compute_date_range(period)
    events = read_events(project_dir, start_date=start_date, end_date=end_date)

    # Apply filters
    if developer:
        events = [e for e in events if e.developer == developer]
    if team:
        events = [e for e in events if e.team == team]
    if model_filter:
        events = [e for e in events if fnmatch.fnmatch(e.model.lower(), model_filter.lower())]
    if project_filter:
        events = [e for e in events if e.project == project_filter]

    # Aggregate
    by_developer: dict[str, float] = defaultdict(float)
    by_team: dict[str, float] = defaultdict(float)
    by_model: dict[str, float] = defaultdict(float)
    by_project: dict[str, float] = defaultdict(float)
    by_provider: dict[str, float] = defaultdict(float)
    daily_buckets: dict[str, float] = defaultdict(float)
    total_cost = 0.0
    total_tokens = 0

    for event in events:
        cost = event.estimated_cost_usd
        total_cost += cost
        total_tokens += event.total_tokens
        by_developer[event.developer] += cost
        if event.team:
            by_team[event.team] += cost
        by_model[event.model] += cost
        by_project[event.project] += cost
        by_provider[event.provider] += cost
        day = event.timestamp[:10]
        daily_buckets[day] += cost

    daily_trend = [
        {"date": d, "cost_usd": round(c, 2)}
        for d, c in sorted(daily_buckets.items())
    ]

    anomalies = detect_anomalies(events, project_dir)
    budget_status = check_budget(total_cost, by_developer, project_dir)

    return CostReport(
        period=period,
        start_date=start_date,
        end_date=end_date,
        total_cost_usd=total_cost,
        total_tokens=total_tokens,
        event_count=len(events),
        by_developer=dict(by_developer),
        by_team=dict(by_team),
        by_model=dict(by_model),
        by_project=dict(by_project),
        by_provider=dict(by_provider),
        daily_trend=daily_trend,
        anomalies=anomalies,
        budget_status=budget_status,
    )


# ───────────────────────────────────────────────────────────────
#  Anomaly detection
# ───────────────────────────────────────────────────────────────

_ANOMALY_MULTIPLIER = 3.0
_ANOMALY_TEAM_THRESHOLD = 0.50
_ANOMALY_LOOKBACK_DAYS = 7


def detect_anomalies(
    current_events: list[LLMUsageEvent],
    project_dir: Path | None = None,
) -> list[dict[str, Any]]:
    """Detect cost anomalies in usage data.

    Flags:
    - Developer daily cost > 3x their 7-day average
    - Developer > 50% of team total cost

    Args:
        current_events: Events in the current reporting period.
        project_dir: Project root for historical data.

    Returns:
        List of anomaly dicts with type, developer, detail.
    """
    anomalies: list[dict[str, Any]] = []

    if not current_events:
        return anomalies

    # Get 7-day historical data for baseline
    now = datetime.now(UTC)
    lookback_start = (now - timedelta(days=_ANOMALY_LOOKBACK_DAYS)).isoformat()
    historical = read_events(project_dir, start_date=lookback_start)

    # Compute 7-day daily average per developer
    dev_daily: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    for event in historical:
        day = event.timestamp[:10]
        dev_daily[event.developer][day] += event.estimated_cost_usd

    dev_avg: dict[str, float] = {}
    for dev, days in dev_daily.items():
        if days:
            dev_avg[dev] = sum(days.values()) / max(len(days), 1)

    # Check current period per developer
    today = now.strftime("%Y-%m-%d")
    today_cost: dict[str, float] = defaultdict(float)
    for event in current_events:
        if event.timestamp[:10] == today:
            today_cost[event.developer] += event.estimated_cost_usd

    for dev, cost in today_cost.items():
        avg = dev_avg.get(dev, 0)
        if avg > 0 and cost > avg * _ANOMALY_MULTIPLIER:
            anomalies.append({
                "type": "high_daily_spend",
                "developer": dev,
                "today_cost": round(cost, 2),
                "average_cost": round(avg, 2),
                "multiplier": round(cost / avg, 1),
                "detail": f"{dev}: ${cost:.2f} today vs ${avg:.2f} 7-day avg ({cost / avg:.1f}x)",
            })

    # Check team concentration
    team_totals: dict[str, float] = defaultdict(float)
    team_dev_cost: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    for event in current_events:
        if event.team:
            team_totals[event.team] += event.estimated_cost_usd
            team_dev_cost[event.team][event.developer] += event.estimated_cost_usd

    for team_name, total in team_totals.items():
        if total <= 0:
            continue
        for dev, cost in team_dev_cost[team_name].items():
            ratio = cost / total
            if ratio > _ANOMALY_TEAM_THRESHOLD:
                anomalies.append({
                    "type": "team_concentration",
                    "developer": dev,
                    "team": team_name,
                    "cost": round(cost, 2),
                    "team_total": round(total, 2),
                    "ratio": round(ratio, 2),
                    "detail": f"{dev}: ${cost:.2f} = {ratio:.0%} of team '{team_name}' (${total:.2f})",
                })

    return anomalies


# ───────────────────────────────────────────────────────────────
#  Budget checking
# ───────────────────────────────────────────────────────────────

_DEFAULT_BUDGET: dict[str, Any] = {
    "monthly_limit": 0,
    "warn_threshold": 0.80,
    "alert_threshold": 0.95,
    "block_on_exceed": False,
    "per_developer": {"monthly_limit": 0},
}


def load_cost_config(project_dir: Path | None = None) -> dict[str, Any]:
    """Load cost configuration from .codetrust.toml [cost] section.

    Args:
        project_dir: Project root.

    Returns:
        Cost config dict with budget, team, enabled flags.
    """
    root = project_dir or Path.cwd()
    config_path = root / ".codetrust.toml"
    if not config_path.is_file():
        return {"enabled": True, "budget": dict(_DEFAULT_BUDGET), "team": {}}

    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError:
            return {"enabled": True, "budget": dict(_DEFAULT_BUDGET), "team": {}}

    try:
        raw = tomllib.loads(config_path.read_text(encoding="utf-8"))
        cost_section = raw.get("cost", {})
        budget = {**_DEFAULT_BUDGET, **cost_section.get("budget", {})}
        per_dev = cost_section.get("budget", {}).get("per_developer", {})
        budget["per_developer"] = {**_DEFAULT_BUDGET["per_developer"], **per_dev}
        return {
            "enabled": cost_section.get("enabled", True),
            "budget": budget,
            "team": cost_section.get("team", {}),
        }
    except (OSError, ValueError, KeyError):
        return {"enabled": True, "budget": dict(_DEFAULT_BUDGET), "team": {}}


def check_budget(
    total_cost: float,
    by_developer: dict[str, float],
    project_dir: Path | None = None,
) -> dict[str, Any]:
    """Check budget thresholds and return status.

    Args:
        total_cost: Total cost in current period.
        by_developer: Cost per developer.
        project_dir: Project root for config.

    Returns:
        Budget status dict with level (ok/warn/alert/exceeded), usage percentage.
    """
    config = load_cost_config(project_dir)
    budget = config.get("budget", _DEFAULT_BUDGET)
    monthly_limit = budget.get("monthly_limit", 0)

    if not monthly_limit or monthly_limit <= 0:
        return {
            "configured": False,
            "level": "ok",
            "message": "No budget configured",
        }

    usage_pct = total_cost / monthly_limit
    warn_threshold = budget.get("warn_threshold", 0.80)
    alert_threshold = budget.get("alert_threshold", 0.95)
    block = budget.get("block_on_exceed", False)

    if usage_pct >= 1.0:
        level = "exceeded"
        message = f"Budget exceeded: ${total_cost:.2f} / ${monthly_limit:.2f} ({usage_pct:.0%})"
    elif usage_pct >= alert_threshold:
        level = "alert"
        message = f"Budget alert: ${total_cost:.2f} / ${monthly_limit:.2f} ({usage_pct:.0%})"
    elif usage_pct >= warn_threshold:
        level = "warn"
        message = f"Budget warning: ${total_cost:.2f} / ${monthly_limit:.2f} ({usage_pct:.0%})"
    else:
        level = "ok"
        message = f"Budget on track: ${total_cost:.2f} / ${monthly_limit:.2f} ({usage_pct:.0%})"

    # Per-developer limits
    dev_limit = budget.get("per_developer", {}).get("monthly_limit", 0)
    dev_alerts: list[dict[str, Any]] = []
    if dev_limit and dev_limit > 0:
        for dev, cost in by_developer.items():
            dev_pct = cost / dev_limit
            if dev_pct >= 1.0:
                dev_alerts.append({"developer": dev, "cost": round(cost, 2), "limit": dev_limit, "level": "exceeded"})
            elif dev_pct >= alert_threshold:
                dev_alerts.append({"developer": dev, "cost": round(cost, 2), "limit": dev_limit, "level": "alert"})
            elif dev_pct >= warn_threshold:
                dev_alerts.append({"developer": dev, "cost": round(cost, 2), "limit": dev_limit, "level": "warn"})

    return {
        "configured": True,
        "level": level,
        "monthly_limit": monthly_limit,
        "total_cost": round(total_cost, 2),
        "usage_percent": round(usage_pct * 100, 1),
        "block_on_exceed": block,
        "message": message,
        "developer_alerts": dev_alerts,
    }
