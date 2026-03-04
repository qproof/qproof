"""Tests for qproof data models."""

from pathlib import Path

import pytest

from qproof.models import (
    AlgorithmInfo,
    ClassifiedFinding,
    Finding,
    QuantumRisk,
    ScanResult,
)


def test_quantum_risk_enum() -> None:
    """QuantumRisk enum has all four expected values."""
    assert QuantumRisk.VULNERABLE.value == "VULNERABLE"
    assert QuantumRisk.PARTIAL.value == "PARTIAL"
    assert QuantumRisk.SAFE.value == "SAFE"
    assert QuantumRisk.UNKNOWN.value == "UNKNOWN"
    assert len(QuantumRisk) == 4


def test_scan_result_score_empty() -> None:
    """An empty ScanResult has a perfect quantum-ready score."""
    result = ScanResult(path=Path("."))
    assert result.quantum_ready_score == 100.0
    assert result.vulnerable_count == 0
    assert result.partial_count == 0
    assert result.safe_count == 0


def test_scan_result_counts() -> None:
    """ScanResult correctly counts findings by risk level."""
    finding = Finding(
        file_path=Path("test.py"),
        line_number=1,
        matched_text="RSA",
        algorithm_id="rsa-2048",
        source="source_code",
    )
    algo_vuln = AlgorithmInfo(
        id="rsa-2048",
        name="RSA-2048",
        type="asymmetric",
        quantum_risk=QuantumRisk.VULNERABLE,
        reason="Shor's algorithm",
        replacement="ML-KEM",
    )
    algo_safe = AlgorithmInfo(
        id="aes-256",
        name="AES-256",
        type="symmetric",
        quantum_risk=QuantumRisk.SAFE,
        reason="Grover halves key strength",
        replacement="AES-256",
    )
    classified_vuln = ClassifiedFinding(
        finding=finding,
        algorithm=algo_vuln,
        quantum_risk=QuantumRisk.VULNERABLE,
        replacement="ML-KEM",
        reason="Shor's algorithm",
    )
    classified_safe = ClassifiedFinding(
        finding=finding,
        algorithm=algo_safe,
        quantum_risk=QuantumRisk.SAFE,
        replacement="AES-256",
        reason="Grover halves key strength",
    )
    result = ScanResult(
        path=Path("."),
        findings=[classified_vuln, classified_vuln, classified_safe],
    )
    assert result.vulnerable_count == 2
    assert result.safe_count == 1
    assert result.partial_count == 0
    assert result.quantum_ready_score == pytest.approx(33.33, abs=0.01)
