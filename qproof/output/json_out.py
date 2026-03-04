"""JSON output renderer for scan results."""

from qproof.models import ScanResult


def render_json(result: ScanResult) -> str:
    """Render scan results as JSON.

    Args:
        result: The scan result to render.

    Returns:
        JSON string output.
    """
    return "{}"
