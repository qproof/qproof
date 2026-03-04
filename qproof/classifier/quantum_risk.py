"""Quantum risk classifier — enriches findings with risk levels."""

from pathlib import Path

from qproof.models import ClassifiedFinding, Finding


def classify(
    findings: list[Finding], algo_db_path: Path | None = None
) -> list[ClassifiedFinding]:
    """Classify findings by quantum computing risk level.

    Args:
        findings: Raw findings to classify.
        algo_db_path: Path to the algorithm database YAML file.

    Returns:
        List of classified findings with quantum risk levels.
    """
    return []
