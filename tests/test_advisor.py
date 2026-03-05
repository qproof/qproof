"""Tests for the migration advisor."""

from pathlib import Path

from qproof.advisor.migration import advise
from qproof.models import AlgorithmInfo, ClassifiedFinding, Finding, QuantumRisk


def _make_classified(
    quantum_risk: QuantumRisk,
    algorithm_id: str = "rsa-2048",
    algo_name: str = "RSA-2048",
    replacement: str = "ML-KEM-768",
    reason: str = "Broken by Shor's algorithm",
    file_path: str = "app.py",
    line_number: int | None = 10,
) -> ClassifiedFinding:
    """Create a ClassifiedFinding for test purposes."""
    finding = Finding(
        file_path=Path(file_path),
        line_number=line_number,
        matched_text=algo_name,
        algorithm_id=algorithm_id,
        source="source_code",
    )
    algo = AlgorithmInfo(
        id=algorithm_id,
        name=algo_name,
        type="asymmetric",
        quantum_risk=quantum_risk,
        reason=reason,
        replacement=replacement,
    )
    return ClassifiedFinding(
        finding=finding,
        algorithm=algo,
        quantum_risk=quantum_risk,
        replacement=replacement,
        reason=reason,
    )


def test_advise_empty_input() -> None:
    """advise returns empty list for empty input."""
    assert advise([]) == []


def test_advise_vulnerable() -> None:
    """advise generates CRITICAL message for VULNERABLE findings."""
    cf = _make_classified(QuantumRisk.VULNERABLE)
    result = advise([cf])

    assert len(result) == 1
    assert result[0].startswith("CRITICAL:")
    assert "RSA-2048" in result[0]
    assert "app.py:10" in result[0]
    assert "ML-KEM-768" in result[0]


def test_advise_partial() -> None:
    """advise generates WARNING message for PARTIAL findings."""
    cf = _make_classified(
        QuantumRisk.PARTIAL,
        algorithm_id="aes-128",
        algo_name="AES-128",
        replacement="AES-256",
        reason="Grover's algorithm halves effective key strength",
    )
    result = advise([cf])

    assert len(result) == 1
    assert result[0].startswith("WARNING:")
    assert "AES-128" in result[0]
    assert "Consider: AES-256" in result[0]


def test_advise_unknown() -> None:
    """advise generates INFO message for UNKNOWN findings."""
    cf = _make_classified(
        QuantumRisk.UNKNOWN,
        algorithm_id="mystery-cipher",
        algo_name="mystery-cipher",
        replacement="",
        reason="Algorithm not in database",
    )
    result = advise([cf])

    assert len(result) == 1
    assert result[0].startswith("INFO:")
    assert "mystery-cipher" in result[0]


def test_advise_skips_safe() -> None:
    """advise skips SAFE findings — no action needed."""
    cf = _make_classified(
        QuantumRisk.SAFE,
        algorithm_id="aes-256",
        algo_name="AES-256",
        replacement="AES-256",
        reason="Quantum-safe at 256-bit key size",
    )
    result = advise([cf])
    assert result == []


def test_advise_sort_order() -> None:
    """advise sorts VULNERABLE first, then PARTIAL, then UNKNOWN."""
    unknown = _make_classified(QuantumRisk.UNKNOWN, algorithm_id="x")
    partial = _make_classified(QuantumRisk.PARTIAL, algorithm_id="y")
    vulnerable = _make_classified(QuantumRisk.VULNERABLE, algorithm_id="z")
    safe = _make_classified(QuantumRisk.SAFE, algorithm_id="w")

    # Pass in reverse order to ensure sorting works.
    result = advise([safe, unknown, partial, vulnerable])

    assert len(result) == 3  # SAFE skipped
    assert result[0].startswith("CRITICAL:")
    assert result[1].startswith("WARNING:")
    assert result[2].startswith("INFO:")


def test_advise_no_line_number() -> None:
    """advise handles findings without a line number."""
    cf = _make_classified(
        QuantumRisk.VULNERABLE,
        line_number=None,
    )
    result = advise([cf])

    assert len(result) == 1
    assert "app.py" in result[0]
    # Should NOT have ":None"
    assert ":None" not in result[0]
