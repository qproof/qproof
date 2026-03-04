"""Source code scanner — detects cryptographic patterns in source files."""

from pathlib import Path

from qproof.models import Finding


def scan_source_files(root: Path) -> list[Finding]:
    """Scan source code files for cryptographic algorithm usage.

    Args:
        root: Root directory to scan.

    Returns:
        List of findings from source code analysis.
    """
    return []
