"""SARIF v2.1.0 output for GitHub Security integration."""

from __future__ import annotations

import json
from typing import Any

from qproof import __version__
from qproof.models import ClassifiedFinding, QuantumRisk

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
    "sarif-2.1/schema/sarif-schema-2.1.0.json"
)

_RISK_TO_LEVEL: dict[QuantumRisk, str] = {
    QuantumRisk.VULNERABLE: "error",
    QuantumRisk.PARTIAL: "warning",
    QuantumRisk.SAFE: "note",
    QuantumRisk.UNKNOWN: "warning",
}


def _build_rule(cf: ClassifiedFinding) -> dict[str, Any]:
    """Build a SARIF rule entry from a classified finding."""
    return {
        "id": f"qproof/{cf.algorithm.id}",
        "name": "QuantumVulnerableCrypto",
        "shortDescription": {"text": f"{cf.algorithm.name} — {cf.reason}"},
        "fullDescription": {
            "text": (
                f"{cf.algorithm.name} ({cf.algorithm.type}) is classified as "
                f"{cf.quantum_risk.value}. Recommended replacement: {cf.replacement}"
            ),
        },
        "helpUri": "https://github.com/qproof/qproof#standards-referenced",
        "defaultConfiguration": {"level": _RISK_TO_LEVEL[cf.quantum_risk]},
        "properties": {
            "tags": ["security", "cryptography", "quantum", "pqc"],
            "precision": "medium",
        },
    }


def _build_result(
    cf: ClassifiedFinding, scan_path: str,
) -> dict[str, Any]:
    """Build a SARIF result entry from a classified finding."""
    file_str = str(cf.finding.file_path)
    try:
        file_str = str(cf.finding.file_path.relative_to(scan_path))
    except ValueError:
        pass

    result: dict[str, Any] = {
        "ruleId": f"qproof/{cf.algorithm.id}",
        "level": _RISK_TO_LEVEL[cf.quantum_risk],
        "message": {
            "text": (
                f"{cf.algorithm.name} detected — {cf.reason}. "
                f"Replace with {cf.replacement}"
            ),
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": file_str,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {
                        "startLine": cf.finding.line_number or 1,
                        "startColumn": 1,
                    },
                },
            },
        ],
        "properties": {
            "quantum_risk": cf.quantum_risk.value,
            "algorithm_type": cf.algorithm.type,
            "replacement": cf.replacement,
            "confidence": cf.confidence,
            "context": cf.context,
        },
    }
    return result


def findings_to_sarif(
    classified: list[ClassifiedFinding],
    scanned_path: str,
    scan_duration: float,
) -> str:
    """Generate SARIF v2.1.0 JSON string from classified findings.

    Returns valid SARIF JSON that can be uploaded to GitHub via
    github/codeql-action/upload-sarif.

    Args:
        classified: List of classified findings from the scan.
        scanned_path: Root path that was scanned.
        scan_duration: Scan duration in seconds.

    Returns:
        Pretty-printed SARIF JSON string (indent=2).
    """
    # Build rules — one per unique algorithm_id
    seen_ids: dict[str, dict[str, Any]] = {}
    for cf in classified:
        if cf.algorithm.id not in seen_ids:
            seen_ids[cf.algorithm.id] = _build_rule(cf)

    sarif: dict[str, Any] = {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "qproof",
                        "version": __version__,
                        "informationUri": "https://github.com/qproof/qproof",
                        "rules": list(seen_ids.values()),
                    },
                },
                "results": [
                    _build_result(cf, scanned_path) for cf in classified
                ],
            },
        ],
    }

    return json.dumps(sarif, indent=2)
