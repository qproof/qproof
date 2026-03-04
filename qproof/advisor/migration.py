"""Migration advisor — recommends post-quantum alternatives."""

from qproof.models import ClassifiedFinding


def advise(findings: list[ClassifiedFinding]) -> list[str]:
    """Generate migration advice for classified findings.

    Args:
        findings: Classified findings to generate advice for.

    Returns:
        List of advisory messages.
    """
    return []
