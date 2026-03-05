"""Tests for Rich text output renderer."""

from pathlib import Path

from qproof.models import (
    AlgorithmInfo,
    ClassifiedFinding,
    Finding,
    QuantumRisk,
    ScanResult,
)
from qproof.output.text import render_text


def _make_classified(
    algorithm_id: str,
    name: str,
    risk: QuantumRisk,
    replacement: str,
    file_path: str = "src/crypto.py",
    line_number: int = 10,
    source: str = "source_code",
) -> ClassifiedFinding:
    """Helper to build a ClassifiedFinding for tests."""
    finding = Finding(
        file_path=Path(file_path),
        line_number=line_number,
        matched_text=name,
        algorithm_id=algorithm_id,
        source=source,
    )
    algo = AlgorithmInfo(
        id=algorithm_id,
        name=name,
        type="asymmetric",
        quantum_risk=risk,
        reason=f"{name} is {risk.value}",
        replacement=replacement,
    )
    return ClassifiedFinding(
        finding=finding,
        algorithm=algo,
        quantum_risk=risk,
        replacement=replacement,
        reason=f"{name} is {risk.value}",
    )


def test_render_text_no_findings() -> None:
    """When there are zero findings, show success message."""
    result = ScanResult(
        path=Path("/tmp/project"),
        findings=[],
        total_files_scanned=42,
        scan_duration_seconds=1.5,
    )
    output = render_text(result)
    assert "No quantum-vulnerable cryptography found!" in output
    assert "42" in output


def test_render_text_with_findings() -> None:
    """Findings table should include algorithm name, risk, and replacement."""
    findings = [
        _make_classified("RSA", "RSA", QuantumRisk.VULNERABLE, "ML-KEM"),
        _make_classified("AES-256", "AES-256", QuantumRisk.SAFE, "AES-256"),
        _make_classified("SHA-1", "SHA-1", QuantumRisk.PARTIAL, "SHA-3"),
    ]
    result = ScanResult(
        path=Path("/tmp/project"),
        findings=findings,
        total_files_scanned=10,
        scan_duration_seconds=0.5,
    )
    output = render_text(result)
    assert "RSA" in output
    assert "AES-256" in output
    assert "SHA-1" in output
    assert "ML-KEM" in output
    assert "VULNERABLE" in output
    assert "SAFE" in output
    assert "PARTIAL" in output
    assert "Quantum Risk Report" in output


def test_render_text_ordering() -> None:
    """VULNERABLE findings should appear before SAFE ones."""
    findings = [
        _make_classified("AES-256", "AES-256", QuantumRisk.SAFE, "AES-256"),
        _make_classified("RSA", "RSA", QuantumRisk.VULNERABLE, "ML-KEM"),
    ]
    result = ScanResult(
        path=Path("/tmp/project"),
        findings=findings,
        total_files_scanned=5,
        scan_duration_seconds=0.1,
    )
    output = render_text(result)
    vuln_pos = output.index("VULNERABLE")
    safe_pos = output.index("SAFE")
    assert vuln_pos < safe_pos


def test_render_text_returns_string() -> None:
    """render_text must return a str, never None."""
    result = ScanResult(path=Path("/tmp"), findings=[], total_files_scanned=0)
    output = render_text(result)
    assert isinstance(output, str)
    assert len(output) > 0


def test_render_text_quantum_ready_score() -> None:
    """The quantum-ready score should appear in the output."""
    result = ScanResult(
        path=Path("/tmp/project"),
        findings=[],
        total_files_scanned=5,
        scan_duration_seconds=0.1,
    )
    output = render_text(result)
    assert "100.0%" in output
