"""Tests for JSON output renderer."""

import json
from pathlib import Path

from qproof.models import (
    AlgorithmInfo,
    ClassifiedFinding,
    Finding,
    QuantumRisk,
    ScanResult,
)
from qproof.output.json_out import render_json


def _make_classified(
    algorithm_id: str,
    name: str,
    risk: QuantumRisk,
    replacement: str,
    file_path: str = "/tmp/project/src/crypto.py",
    line_number: int = 10,
    source: str = "source_code",
    algo_type: str = "asymmetric",
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
        type=algo_type,
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


def test_render_json_valid() -> None:
    """Output must be valid JSON."""
    result = ScanResult(
        path=Path("/tmp/project"),
        findings=[],
        total_files_scanned=0,
        scan_duration_seconds=0.0,
    )
    output = render_json(result)
    parsed = json.loads(output)
    assert isinstance(parsed, dict)


def test_render_json_empty_findings() -> None:
    """Empty scan should have zero findings and 100% score."""
    result = ScanResult(
        path=Path("/tmp/project"),
        findings=[],
        total_files_scanned=42,
        scan_duration_seconds=1.5,
    )
    parsed = json.loads(render_json(result))
    assert parsed["total_files_scanned"] == 42
    assert parsed["scan_duration_seconds"] == 1.5
    assert parsed["summary"]["total_findings"] == 0
    assert parsed["summary"]["quantum_ready_score"] == 100.0
    assert parsed["findings"] == []


def test_render_json_with_findings() -> None:
    """Findings should be serialised with all expected fields."""
    findings = [
        _make_classified("RSA", "RSA", QuantumRisk.VULNERABLE, "ML-KEM"),
        _make_classified(
            "AES-256", "AES-256", QuantumRisk.SAFE, "AES-256",
            algo_type="symmetric",
        ),
    ]
    result = ScanResult(
        path=Path("/tmp/project"),
        findings=findings,
        total_files_scanned=10,
        scan_duration_seconds=0.5,
    )
    parsed = json.loads(render_json(result))
    assert parsed["summary"]["total_findings"] == 2
    assert parsed["summary"]["vulnerable"] == 1
    assert parsed["summary"]["safe"] == 1

    rsa_finding = parsed["findings"][0]
    assert rsa_finding["algorithm_id"] == "RSA"
    assert rsa_finding["algorithm_name"] == "RSA"
    assert rsa_finding["algorithm_type"] == "asymmetric"
    assert rsa_finding["quantum_risk"] == "VULNERABLE"
    assert rsa_finding["replacement"] == "ML-KEM"
    assert rsa_finding["line_number"] == 10
    assert rsa_finding["source"] == "source_code"


def test_render_json_relative_paths() -> None:
    """File paths should be relative to the scan root."""
    cf = _make_classified(
        "RSA", "RSA", QuantumRisk.VULNERABLE, "ML-KEM",
        file_path="/tmp/project/src/crypto.py",
    )
    result = ScanResult(
        path=Path("/tmp/project"),
        findings=[cf],
        total_files_scanned=1,
        scan_duration_seconds=0.1,
    )
    parsed = json.loads(render_json(result))
    assert parsed["findings"][0]["file_path"] == "src/crypto.py"


def test_render_json_version() -> None:
    """Output must include the qproof version."""
    from qproof import __version__

    result = ScanResult(path=Path("/tmp"), findings=[], total_files_scanned=0)
    parsed = json.loads(render_json(result))
    assert parsed["version"] == __version__


def test_render_json_score_calculation() -> None:
    """Quantum-ready score reflects the ratio of SAFE findings."""
    findings = [
        _make_classified("RSA", "RSA", QuantumRisk.VULNERABLE, "ML-KEM"),
        _make_classified("AES-256", "AES-256", QuantumRisk.SAFE, "AES-256"),
        _make_classified("AES-128", "AES-128", QuantumRisk.SAFE, "AES-256"),
    ]
    result = ScanResult(
        path=Path("/tmp/project"),
        findings=findings,
        total_files_scanned=5,
        scan_duration_seconds=0.2,
    )
    parsed = json.loads(render_json(result))
    # 2 SAFE out of 3 = 66.67%
    score = parsed["summary"]["quantum_ready_score"]
    assert abs(score - 66.67) < 0.1
