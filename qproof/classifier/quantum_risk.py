"""Quantum risk classifier — enriches findings with risk levels."""

from __future__ import annotations

from pathlib import Path

from qproof.data.loader import load_algorithms
from qproof.models import AlgorithmInfo, ClassifiedFinding, Finding, QuantumRisk


def classify(
    findings: list[Finding], algo_db_path: Path | None = None
) -> list[ClassifiedFinding]:
    """Classify findings by quantum computing risk level.

    Looks up each finding's algorithm_id in the algorithm database and
    creates a ClassifiedFinding with the corresponding risk, replacement,
    and reason. Unknown algorithms get UNKNOWN risk.

    Args:
        findings: Raw findings to classify.
        algo_db_path: Path to the algorithm database YAML file.
                      Defaults to the bundled database.

    Returns:
        List of classified findings with quantum risk levels.
        Returns empty list on bad input or database load failure.
    """
    if not findings:
        return []

    try:
        algo_db = load_algorithms(path=algo_db_path)
    except (FileNotFoundError, ValueError):
        return []

    classified: list[ClassifiedFinding] = []

    for finding in findings:
        algo_info = algo_db.get(finding.algorithm_id)

        if algo_info is not None:
            classified.append(
                ClassifiedFinding(
                    finding=finding,
                    algorithm=algo_info,
                    quantum_risk=algo_info.quantum_risk,
                    replacement=algo_info.replacement,
                    reason=algo_info.reason,
                )
            )
        else:
            unknown_algo = AlgorithmInfo(
                id=finding.algorithm_id,
                name=finding.algorithm_id,
                type="unknown",
                quantum_risk=QuantumRisk.UNKNOWN,
                reason="Algorithm not in database",
                replacement="",
            )
            classified.append(
                ClassifiedFinding(
                    finding=finding,
                    algorithm=unknown_algo,
                    quantum_risk=QuantumRisk.UNKNOWN,
                    replacement="",
                    reason="Algorithm not in database",
                )
            )

    return classified
