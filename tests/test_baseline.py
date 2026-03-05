"""Tests for baseline snapshot generation and loading (QP-013)."""

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from qproof.baseline import (
    finding_hash,
    generate_baseline,
    git_commit_or_null,
    load_baseline,
)
from qproof.models import (
    AlgorithmInfo,
    ClassifiedFinding,
    Finding,
    QuantumRisk,
)


def _make_classified(
    file_path: str = "src/auth.py",
    line_number: int = 10,
    algorithm_id: str = "RSA",
    source: str = "source_code",
    quantum_risk: QuantumRisk = QuantumRisk.VULNERABLE,
    severity: str = "critical",
) -> ClassifiedFinding:
    """Create a ClassifiedFinding for testing."""
    finding = Finding(
        file_path=Path(file_path),
        line_number=line_number,
        matched_text=algorithm_id,
        algorithm_id=algorithm_id,
        source=source,
    )
    algo = AlgorithmInfo(
        id=algorithm_id,
        name=algorithm_id,
        type="asymmetric",
        quantum_risk=quantum_risk,
        reason="test reason",
        replacement="ML-KEM",
    )
    return ClassifiedFinding(
        finding=finding,
        algorithm=algo,
        quantum_risk=quantum_risk,
        replacement="ML-KEM",
        reason="test reason",
        severity=severity,
    )


# ---------- finding_hash ----------


def test_baseline_hash_determinism() -> None:
    """Same finding produces the same hash every time."""
    cf = _make_classified()
    assert finding_hash(cf) == finding_hash(cf)


def test_baseline_hash_uniqueness() -> None:
    """Different findings produce different hashes."""
    cf1 = _make_classified(file_path="a.py", algorithm_id="RSA")
    cf2 = _make_classified(file_path="b.py", algorithm_id="AES-256")
    assert finding_hash(cf1) != finding_hash(cf2)


def test_baseline_hash_length() -> None:
    """Hash is 16 hex characters."""
    cf = _make_classified()
    h = finding_hash(cf)
    assert len(h) == 16
    assert all(c in "0123456789abcdef" for c in h)


def test_baseline_hash_different_lines() -> None:
    """Same file, different lines produce different hashes."""
    cf1 = _make_classified(line_number=10)
    cf2 = _make_classified(line_number=20)
    assert finding_hash(cf1) != finding_hash(cf2)


def test_baseline_hash_different_sources() -> None:
    """Same algo, different sources produce different hashes."""
    cf1 = _make_classified(source="source_code")
    cf2 = _make_classified(source="dependency")
    assert finding_hash(cf1) != finding_hash(cf2)


# ---------- generate_baseline ----------


def test_baseline_generation() -> None:
    """generate_baseline produces a valid baseline dict."""
    findings = [_make_classified(), _make_classified(file_path="b.py")]
    baseline = generate_baseline(findings, "0.3.0")

    assert baseline["baseline_version"] == "1.0"
    assert baseline["qproof_version"] == "0.3.0"
    assert baseline["findings_count"] == 2
    assert len(baseline["findings"]) == 2
    assert "generated_at" in baseline


def test_baseline_determinism() -> None:
    """Same findings produce identical baseline (except timestamp)."""
    findings = [
        _make_classified(file_path="a.py"),
        _make_classified(file_path="b.py"),
    ]
    bl1 = generate_baseline(findings, "0.3.0")
    bl2 = generate_baseline(findings, "0.3.0")

    # Findings and hashes must be identical
    assert bl1["findings"] == bl2["findings"]
    assert bl1["findings_count"] == bl2["findings_count"]


def test_baseline_sorted() -> None:
    """Findings in different input order produce the same sorted output."""
    cf_a = _make_classified(file_path="a.py", algorithm_id="RSA")
    cf_b = _make_classified(file_path="b.py", algorithm_id="AES-256")

    bl_ab = generate_baseline([cf_a, cf_b], "0.3.0")
    bl_ba = generate_baseline([cf_b, cf_a], "0.3.0")

    assert bl_ab["findings"] == bl_ba["findings"]


def test_baseline_empty() -> None:
    """Empty findings produce a valid baseline with count 0."""
    baseline = generate_baseline([], "0.3.0")

    assert baseline["findings_count"] == 0
    assert baseline["findings"] == []
    assert baseline["baseline_version"] == "1.0"


def test_baseline_includes_metadata() -> None:
    """Baseline contains all required metadata fields."""
    baseline = generate_baseline([_make_classified()], "0.3.0")

    assert "baseline_version" in baseline
    assert "qproof_version" in baseline
    assert "generated_at" in baseline
    assert "commit" in baseline
    assert "findings_count" in baseline
    assert "findings" in baseline


def test_baseline_finding_fields() -> None:
    """Each finding entry has all expected fields."""
    cf = _make_classified(
        file_path="src/auth.py",
        line_number=42,
        algorithm_id="RSA",
        source="source_code",
        severity="critical",
    )
    baseline = generate_baseline([cf], "0.3.0")
    entry = baseline["findings"][0]

    assert "hash" in entry
    assert entry["file"] == "src/auth.py"
    assert entry["line"] == 42
    assert entry["algorithm"] == "RSA"
    assert entry["risk"] == "VULNERABLE"
    assert entry["severity"] == "critical"
    assert entry["source"] == "source_code"


def test_baseline_includes_all_scanner_types() -> None:
    """Baseline includes findings from source, dependency, and config scanners."""
    findings = [
        _make_classified(source="source_code"),
        _make_classified(source="dependency", file_path="req.txt"),
        _make_classified(source="config", file_path="nginx.conf"),
    ]
    baseline = generate_baseline(findings, "0.3.0")
    sources = {f["source"] for f in baseline["findings"]}
    assert sources == {"source_code", "dependency", "config"}


# ---------- git_commit_or_null ----------


def test_baseline_git_commit() -> None:
    """When git succeeds, commit hash is returned."""
    fake_result = subprocess.CompletedProcess(
        args=[], returncode=0, stdout="abc123def456\n",
    )
    with patch("qproof.baseline.subprocess.run", return_value=fake_result):
        assert git_commit_or_null() == "abc123def456"


def test_baseline_no_git() -> None:
    """When git fails, None is returned."""
    fake_result = subprocess.CompletedProcess(
        args=[], returncode=128, stdout="", stderr="not a git repo",
    )
    with patch("qproof.baseline.subprocess.run", return_value=fake_result):
        assert git_commit_or_null() is None


def test_baseline_git_not_installed() -> None:
    """When git binary is not found, None is returned."""
    with patch(
        "qproof.baseline.subprocess.run",
        side_effect=FileNotFoundError("git not found"),
    ):
        assert git_commit_or_null() is None


# ---------- load_baseline ----------


def test_baseline_load_valid(tmp_path: Path) -> None:
    """Loading a valid baseline file returns the parsed dict."""
    findings = [_make_classified()]
    baseline = generate_baseline(findings, "0.3.0")
    bl_path = tmp_path / "baseline.json"
    bl_path.write_text(json.dumps(baseline, indent=2), encoding="utf-8")

    loaded = load_baseline(bl_path)
    assert loaded["findings_count"] == 1
    assert loaded["baseline_version"] == "1.0"
    assert len(loaded["findings"]) == 1


def test_baseline_load_missing() -> None:
    """Loading a non-existent file raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError, match="not found"):
        load_baseline("/nonexistent/baseline.json")


def test_baseline_load_invalid_json(tmp_path: Path) -> None:
    """Loading invalid JSON raises ValueError."""
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("not { valid json", encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid JSON"):
        load_baseline(bad_file)


def test_baseline_load_missing_keys(tmp_path: Path) -> None:
    """Loading JSON missing required keys raises ValueError."""
    incomplete = tmp_path / "incomplete.json"
    incomplete.write_text(json.dumps({"version": "1.0"}), encoding="utf-8")

    with pytest.raises(ValueError, match="missing required keys"):
        load_baseline(incomplete)


# ---------- CLI integration ----------


def test_baseline_file_write(tmp_path: Path) -> None:
    """CLI --baseline writes a valid JSON file."""
    bl_path = tmp_path / "baseline.json"
    result = subprocess.run(
        [
            sys.executable, "-m", "qproof", "scan",
            "tests/fixtures/sample_project",
            "--baseline", str(bl_path),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0
    assert bl_path.exists()

    data = json.loads(bl_path.read_text())
    assert data["baseline_version"] == "1.0"
    assert data["findings_count"] > 0
    assert len(data["findings"]) == data["findings_count"]


def test_baseline_cli_no_normal_output(tmp_path: Path) -> None:
    """--baseline suppresses normal output to stdout."""
    bl_path = tmp_path / "baseline.json"
    result = subprocess.run(
        [
            sys.executable, "-m", "qproof", "scan",
            "tests/fixtures/sample_project",
            "--baseline", str(bl_path),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    # stdout should be empty (summary goes to stderr)
    assert result.stdout == ""
    assert "Baseline generated" in result.stderr


def test_baseline_cli_summary_on_stderr(tmp_path: Path) -> None:
    """--baseline prints summary to stderr."""
    bl_path = tmp_path / "baseline.json"
    result = subprocess.run(
        [
            sys.executable, "-m", "qproof", "scan",
            "tests/fixtures/sample_project",
            "--baseline", str(bl_path),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert "Baseline generated" in result.stderr
    assert "findings" in result.stderr
