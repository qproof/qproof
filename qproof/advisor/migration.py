"""Migration advisor — recommends post-quantum alternatives."""

from __future__ import annotations

from qproof.models import ClassifiedFinding, QuantumRisk

# Sort order: VULNERABLE first, then PARTIAL, then UNKNOWN.
_RISK_SORT_ORDER: dict[QuantumRisk, int] = {
    QuantumRisk.VULNERABLE: 0,
    QuantumRisk.PARTIAL: 1,
    QuantumRisk.UNKNOWN: 2,
    QuantumRisk.SAFE: 3,
}


def _format_location(finding: ClassifiedFinding) -> str:
    """Format file path and line number for display."""
    line = finding.finding.line_number
    if line is not None:
        return f"{finding.finding.file_path}:{line}"
    return str(finding.finding.file_path)


def advise(findings: list[ClassifiedFinding]) -> list[str]:
    """Generate migration advice for classified findings.

    Groups findings by quantum risk level and produces actionable
    advisory messages. SAFE findings are skipped (no action needed).

    Messages are sorted: VULNERABLE first, then PARTIAL, then UNKNOWN.

    Args:
        findings: Classified findings to generate advice for.

    Returns:
        List of advisory message strings, ordered by severity.
    """
    if not findings:
        return []

    # Filter out SAFE and sort by risk severity.
    actionable = [
        f for f in findings if f.quantum_risk != QuantumRisk.SAFE
    ]
    actionable.sort(key=lambda f: _RISK_SORT_ORDER.get(f.quantum_risk, 99))

    messages: list[str] = []

    for cf in actionable:
        location = _format_location(cf)

        if cf.quantum_risk == QuantumRisk.VULNERABLE:
            messages.append(
                f"CRITICAL: {cf.algorithm.name} in {location} "
                f"— {cf.reason}. Replace with: {cf.replacement}"
            )
        elif cf.quantum_risk == QuantumRisk.PARTIAL:
            messages.append(
                f"WARNING: {cf.algorithm.name} in {location} "
                f"— {cf.reason}. Consider: {cf.replacement}"
            )
        elif cf.quantum_risk == QuantumRisk.UNKNOWN:
            messages.append(
                f"INFO: Unknown algorithm '{cf.finding.algorithm_id}' "
                f"in {location}"
            )

    return messages
