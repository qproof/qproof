"""Dependency scanner — detects cryptographic libraries in project dependencies."""

from pathlib import Path

from qproof.models import Finding


def scan_dependencies(root: Path) -> list[Finding]:
    """Scan dependency files for cryptographic library usage.

    Args:
        root: Root directory to scan.

    Returns:
        List of findings from dependency analysis.
    """
    return []
