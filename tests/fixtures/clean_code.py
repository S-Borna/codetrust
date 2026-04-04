"""A clean Python file with no PII — used for PII false-positive testing."""

from dataclasses import dataclass


@dataclass
class UserConfig:
    """Application configuration."""

    max_retries: int = 3
    timeout_seconds: float = 30.0
    log_level: str = "INFO"
    version: str = "1.2.3"


def calculate_risk_score(likelihood: int, impact: int) -> float:
    """Calculate risk score from likelihood and impact.

    Args:
        likelihood: Likelihood rating (1-5).
        impact: Impact rating (1-5).

    Returns:
        Normalized risk score between 0.0 and 1.0.
    """
    return (likelihood * impact) / 25.0


def format_report(items: list[str], title: str = "Report") -> str:
    """Format items as a simple text report.

    Args:
        items: List of items to include.
        title: Report title.

    Returns:
        Formatted report string.
    """
    lines = [title, "=" * len(title)]
    for i, item in enumerate(items, 1):
        lines.append(f"{i}. {item}")
    return "\n".join(lines)
