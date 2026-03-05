"""Tests for the quantum risk classifier."""

from pathlib import Path

from qproof.classifier.quantum_risk import classify
from qproof.models import Finding, QuantumRisk


def _make_finding(
    algorithm_id: str = "RSA",
    file_path: str = "app.py",
    line_number: int = 10,
    matched_text: str = "RSA",
) -> Finding:
    """Create a Finding for test purposes."""
    return Finding(
        file_path=Path(file_path),
        line_number=line_number,
        matched_text=matched_text,
        algorithm_id=algorithm_id,
        source="source_code",
    )


def test_classify_empty_input() -> None:
    """classify returns empty list for empty input."""
    assert classify([]) == []


def test_classify_known_algorithm() -> None:
    """classify enriches a finding with data from the algorithm database."""
    finding = _make_finding(algorithm_id="RSA")
    result = classify([finding])

    assert len(result) == 1
    cf = result[0]
    assert cf.finding is finding
    assert cf.quantum_risk == QuantumRisk.VULNERABLE
    assert cf.algorithm.id == "RSA"
    assert cf.replacement != ""
    assert cf.reason != ""


def test_classify_unknown_algorithm() -> None:
    """classify returns UNKNOWN for algorithms not in the database."""
    finding = _make_finding(algorithm_id="nonexistent-algo-xyz")
    result = classify([finding])

    assert len(result) == 1
    cf = result[0]
    assert cf.quantum_risk == QuantumRisk.UNKNOWN
    assert cf.replacement == ""
    assert cf.reason == "Algorithm not in database"
    assert cf.algorithm.type == "unknown"


def test_classify_multiple_findings() -> None:
    """classify handles multiple findings including known and unknown."""
    findings = [
        _make_finding(algorithm_id="RSA"),
        _make_finding(algorithm_id="AES-256"),
        _make_finding(algorithm_id="fake-algo"),
    ]
    result = classify(findings)

    assert len(result) == 3
    risks = [cf.quantum_risk for cf in result]
    assert QuantumRisk.VULNERABLE in risks
    assert QuantumRisk.UNKNOWN in risks


def test_classify_safe_algorithm() -> None:
    """classify correctly identifies SAFE algorithms."""
    finding = _make_finding(algorithm_id="AES-256")
    result = classify([finding])

    assert len(result) == 1
    assert result[0].quantum_risk == QuantumRisk.SAFE


def test_classify_bad_db_path_returns_empty() -> None:
    """classify returns empty list when the database path is invalid."""
    finding = _make_finding()
    result = classify([finding], algo_db_path=Path("/nonexistent/path.yaml"))
    assert result == []


def test_classify_preserves_finding_data() -> None:
    """classify preserves all original finding fields."""
    finding = _make_finding(
        algorithm_id="RSA",
        file_path="src/crypto.py",
        line_number=42,
        matched_text="RSA-2048",
    )
    result = classify([finding])

    assert len(result) == 1
    cf = result[0]
    assert cf.finding.file_path == Path("src/crypto.py")
    assert cf.finding.line_number == 42
    assert cf.finding.matched_text == "RSA-2048"
