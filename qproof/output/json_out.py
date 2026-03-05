"""JSON output renderer for scan results."""

from __future__ import annotations

import json
from typing import Any

from qproof import __version__
from qproof.models import ClassifiedFinding, ScanResult


def _finding_to_dict(cf: ClassifiedFinding, scan_path: str) -> dict[str, Any]:
    """Convert a ClassifiedFinding to a JSON-serialisable dict.

    File paths are made relative to *scan_path* when possible.

    Args:
        cf: The classified finding to convert.
        scan_path: The root path of the scan, used for relative paths.

    Returns:
        Dictionary representation of the finding.
    """
    file_str = str(cf.finding.file_path)
    try:
        file_str = str(cf.finding.file_path.relative_to(scan_path))
    except ValueError:
        pass

    return {
        "file_path": file_str,
        "line_number": cf.finding.line_number,
        "matched_text": cf.finding.matched_text,
        "algorithm_id": cf.algorithm.id,
        "algorithm_name": cf.algorithm.name,
        "algorithm_type": cf.algorithm.type,
        "source": cf.finding.source,
        "quantum_risk": cf.quantum_risk.value,
        "reason": cf.reason,
        "replacement": cf.replacement,
        "confidence": cf.confidence,
        "context": cf.context,
        "severity": cf.severity,
        "category": cf.category,
        "remediation": cf.remediation,
    }


def render_json(result: ScanResult) -> str:
    """Render scan results as a JSON string for CI/CD integration.

    Produces a structured JSON document with version info, summary
    statistics, and detailed findings.

    Args:
        result: The scan result to render.

    Returns:
        Pretty-printed JSON string (indent=2).
    """
    scan_path = str(result.path)

    output: dict[str, Any] = {
        "version": __version__,
        "scan_path": scan_path,
        "total_files_scanned": result.total_files_scanned,
        "scan_duration_seconds": result.scan_duration_seconds,
        "summary": {
            "total_findings": len(result.findings),
            "vulnerable": result.vulnerable_count,
            "partial": result.partial_count,
            "safe": result.safe_count,
            "quantum_ready_score": result.quantum_ready_score,
        },
        "findings": [
            _finding_to_dict(cf, scan_path) for cf in result.findings
        ],
    }

    return json.dumps(output, indent=2)
