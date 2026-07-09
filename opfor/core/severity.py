"""Severity labels, one ordered vocabulary shared by every scenario.

Kept in one place so a scenario's triage, a report, and a gate all grade against
the same words. The order is least to most severe, so a caller can threshold with a
comparison on the index.
"""

from __future__ import annotations

# Least to most severe. INFO records a fact worth noting that is not itself a risk.
SEVERITIES: tuple[str, ...] = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def rank(severity: str) -> int:
    """Rank a severity, fail loud on an unknown label so a typo cannot slip a gate."""
    try:
        return SEVERITIES.index(severity)
    except ValueError:
        raise ValueError(f"unknown severity {severity!r}, known: {', '.join(SEVERITIES)}") from None
