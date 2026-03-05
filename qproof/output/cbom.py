"""CycloneDX v1.6 CBOM (Cryptography Bill of Materials) output."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from qproof import __version__
from qproof.models import ClassifiedFinding

# Mapping of algorithm IDs to OID values (ITU-T X.660 / ISO/IEC 9834-1).
_KNOWN_OIDS: dict[str, str] = {
    "RSA": "1.2.840.113549.1.1.1",
    "DSA": "1.2.840.10040.4.1",
    "ECDSA": "1.2.840.10045.2.1",
    "AES-256": "2.16.840.1.101.3.4.1.41",
    "AES-128": "2.16.840.1.101.3.4.1.1",
    "SHA-256": "2.16.840.1.101.3.4.2.1",
    "SHA-384": "2.16.840.1.101.3.4.2.2",
    "SHA-512": "2.16.840.1.101.3.4.2.3",
    "SHA-1": "1.3.14.3.2.26",
    "MD5": "1.2.840.113549.2.5",
    "Ed25519": "1.3.101.112",
    "X25519": "1.3.101.110",
}

# Asymmetric algorithms primarily used for key exchange / encapsulation.
_KEX_ALGORITHMS: set[str] = {"RSA", "ECDH", "DH", "X25519", "X448", "ElGamal"}

# Mapping from algorithm type to CycloneDX cryptoProperties primitive.
_TYPE_TO_PRIMITIVE: dict[str, str] = {
    "symmetric": "blockcipher",
    "hash": "hash",
    "kdf": "kdf",
    "mac": "mac",
}


def _resolve_primitive(algo_type: str, algo_id: str) -> str | None:
    """Resolve the CycloneDX algorithmProperties primitive for an algorithm.

    Returns None for protocol-type algorithms (no algorithmProperties needed).

    Args:
        algo_type: The algorithm type (asymmetric, symmetric, hash, etc.).
        algo_id: The algorithm identifier for disambiguation.

    Returns:
        The CycloneDX primitive string, or None if not applicable.
    """
    if algo_type == "protocol":
        return None
    if algo_type == "asymmetric":
        return "pke" if algo_id in _KEX_ALGORITHMS else "signature"
    return _TYPE_TO_PRIMITIVE.get(algo_type)


def _make_relative(file_path: str, scan_path: str) -> str:
    """Attempt to make a file path relative to the scan root.

    Args:
        file_path: Absolute or relative file path.
        scan_path: The root scan directory.

    Returns:
        Relative path string, or the original path if relativisation fails.
    """
    from pathlib import Path

    try:
        return str(Path(file_path).relative_to(scan_path))
    except ValueError:
        return file_path


def _build_component(
    algo_id: str,
    findings: list[ClassifiedFinding],
    index: int,
    scan_path: str,
) -> dict[str, Any]:
    """Build a single CycloneDX component from grouped findings.

    All findings in the list share the same algorithm_id. The first finding
    is used for algorithm metadata; all findings contribute occurrences.

    Args:
        algo_id: Algorithm identifier.
        findings: Classified findings for this algorithm.
        index: Unique index for bom-ref generation.
        scan_path: Root scan path for relative file paths.

    Returns:
        CycloneDX component dictionary.
    """
    representative = findings[0]
    algo = representative.algorithm

    # Determine asset type
    asset_type = "protocol" if algo.type == "protocol" else "algorithm"

    # Build cryptoProperties
    crypto_props: dict[str, Any] = {"assetType": asset_type}

    # Add OID if known
    oid = _KNOWN_OIDS.get(algo_id)
    if oid is not None:
        crypto_props["oid"] = oid

    # Add algorithmProperties for non-protocol types
    primitive = _resolve_primitive(algo.type, algo_id)
    if primitive is not None:
        crypto_props["algorithmProperties"] = {"primitive": primitive}

    # Build occurrences from all findings
    occurrences: list[dict[str, Any]] = []
    for cf in findings:
        occurrence: dict[str, Any] = {
            "location": _make_relative(str(cf.finding.file_path), scan_path),
            "line": cf.finding.line_number or 1,
        }
        if cf.finding.matched_text:
            occurrence["additionalContext"] = cf.finding.matched_text
        occurrences.append(occurrence)

    # Build properties
    properties: list[dict[str, str]] = [
        {"name": "qproof:quantum_risk", "value": representative.quantum_risk.value},
        {"name": "qproof:replacement", "value": representative.replacement},
        {"name": "qproof:source", "value": representative.finding.source},
        {"name": "qproof:confidence", "value": representative.confidence},
        {"name": "qproof:context", "value": representative.context},
    ]

    component: dict[str, Any] = {
        "type": "cryptographic-asset",
        "name": algo.name,
        "bom-ref": f"crypto-{algo_id}-{index}",
        "cryptoProperties": crypto_props,
        "evidence": {"occurrences": occurrences},
        "properties": properties,
    }

    return component


def findings_to_cbom(
    classified: list[ClassifiedFinding],
    scanned_path: str,
    scan_duration: float,
) -> str:
    """Generate CycloneDX v1.6 CBOM JSON string from classified findings.

    Produces a valid CycloneDX BOM with cryptographic asset components.
    Findings sharing the same algorithm_id are deduplicated into a single
    component with multiple occurrences.

    Args:
        classified: List of classified findings from the scan.
        scanned_path: Root path that was scanned.
        scan_duration: Scan duration in seconds.

    Returns:
        Pretty-printed CycloneDX JSON string (indent=2).
    """
    from pathlib import Path

    # Group findings by algorithm_id for deduplication
    grouped: dict[str, list[ClassifiedFinding]] = {}
    for cf in classified:
        grouped.setdefault(cf.algorithm.id, []).append(cf)

    # Build components — one per unique algorithm
    components: list[dict[str, Any]] = []
    for idx, (algo_id, findings) in enumerate(grouped.items()):
        components.append(_build_component(algo_id, findings, idx, scanned_path))

    # Resolve project name from scan path
    project_name = Path(scanned_path).name or "project"

    cbom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "qproof",
                        "version": __version__,
                    },
                ],
            },
            "component": {
                "type": "application",
                "name": project_name,
                "bom-ref": "scanned-project",
            },
        },
        "components": components,
    }

    return json.dumps(cbom, indent=2)
