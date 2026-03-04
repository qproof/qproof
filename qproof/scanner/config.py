"""Configuration scanner — detects cryptographic settings in config files."""

from pathlib import Path

from qproof.models import Finding


def scan_configs(root: Path) -> list[Finding]:
    """Scan configuration files for cryptographic settings.

    Args:
        root: Root directory to scan.

    Returns:
        List of findings from configuration analysis.
    """
    return []
