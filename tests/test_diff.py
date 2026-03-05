"""Tests for diff mode (QP-014)."""

import json
import subprocess
import sys
from pathlib import Path

from qproof.baseline import (
    diff_findings,
    generate_baseline,
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


# ---------- diff_findings ----------


def test_diff_new_finding() -> None:
    """A finding not in the baseline is marked as new."""
    baseline = generate_baseline([], "0.3.0")
    current = [_make_classified()]
    result = diff_findings(current, baseline)

    assert len(result.new) == 1
    assert result.new[0].diff_status == "new"
    assert len(result.worsened) == 0
    assert len(result.resolved) == 0
    assert len(result.unchanged) == 0


def test_diff_unchanged_finding() -> None:
    """A finding matching the baseline (same hash + severity) is unchanged."""
    cf = _make_classified()
    baseline = generate_baseline([cf], "0.3.0")
    current = [_make_classified()]
    result = diff_findings(current, baseline)

    assert len(result.unchanged) == 1
    assert result.unchanged[0].diff_status is None
    assert len(result.new) == 0
    assert len(result.worsened) == 0


def test_diff_resolved_finding() -> None:
    """A baseline finding absent from current scan is resolved."""
    cf = _make_classified()
    baseline = generate_baseline([cf], "0.3.0")
    result = diff_findings([], baseline)

    assert len(result.resolved) == 1
    assert result.resolved[0]["algorithm"] == "RSA"
    assert len(result.new) == 0


def test_diff_worsened_finding() -> None:
    """A finding with higher severity than baseline is marked as worsened."""
    cf_baseline = _make_classified(severity="medium")
    baseline = generate_baseline([cf_baseline], "0.3.0")

    cf_current = _make_classified(severity="critical")
    result = diff_findings([cf_current], baseline)

    assert len(result.worsened) == 1
    assert result.worsened[0].diff_status == "worsened"
    assert len(result.new) == 0
    assert len(result.unchanged) == 0


def test_diff_improved_not_worsened() -> None:
    """A finding with lower severity than baseline is unchanged, not worsened."""
    cf_baseline = _make_classified(severity="critical")
    baseline = generate_baseline([cf_baseline], "0.3.0")

    cf_current = _make_classified(severity="low")
    result = diff_findings([cf_current], baseline)

    assert len(result.unchanged) == 1
    assert len(result.worsened) == 0


def test_diff_mixed_scenario() -> None:
    """Mixed scenario: new + unchanged + resolved findings."""
    cf_old = _make_classified(file_path="old.py", algorithm_id="DSA")
    cf_same = _make_classified(file_path="same.py", algorithm_id="RSA")
    baseline = generate_baseline([cf_old, cf_same], "0.3.0")

    cf_same_current = _make_classified(file_path="same.py", algorithm_id="RSA")
    cf_new = _make_classified(file_path="new.py", algorithm_id="ECDSA")
    result = diff_findings([cf_same_current, cf_new], baseline)

    assert len(result.new) == 1
    assert len(result.unchanged) == 1
    assert len(result.resolved) == 1
    assert result.new[0].finding.file_path == Path("new.py")


# ---------- DiffResult.has_new_debt ----------


def test_diff_has_new_debt_with_new() -> None:
    """has_new_debt is True when there are new findings."""
    cf = _make_classified()
    baseline = generate_baseline([], "0.3.0")
    result = diff_findings([cf], baseline)
    assert result.has_new_debt is True


def test_diff_has_new_debt_with_worsened() -> None:
    """has_new_debt is True when there are worsened findings."""
    cf_baseline = _make_classified(severity="low")
    baseline = generate_baseline([cf_baseline], "0.3.0")
    cf_current = _make_classified(severity="critical")
    result = diff_findings([cf_current], baseline)
    assert result.has_new_debt is True


def test_diff_no_new_debt() -> None:
    """has_new_debt is False when only unchanged/resolved findings exist."""
    cf = _make_classified()
    baseline = generate_baseline([cf], "0.3.0")
    result = diff_findings([_make_classified()], baseline)
    assert result.has_new_debt is False


def test_diff_empty_both() -> None:
    """Empty current + empty baseline yields no diff."""
    baseline = generate_baseline([], "0.3.0")
    result = diff_findings([], baseline)
    assert result.has_new_debt is False
    assert len(result.new) == 0
    assert len(result.resolved) == 0


# ---------- diff_status on ClassifiedFinding ----------


def test_diff_status_set_on_findings() -> None:
    """diff_findings sets diff_status on each ClassifiedFinding."""
    cf_baseline = _make_classified(file_path="a.py", severity="medium")
    baseline = generate_baseline([cf_baseline], "0.3.0")

    cf_same = _make_classified(file_path="a.py", severity="medium")
    cf_new = _make_classified(file_path="b.py")

    diff_findings([cf_same, cf_new], baseline)

    assert cf_same.diff_status is None  # unchanged
    assert cf_new.diff_status == "new"


def test_diff_status_default_none() -> None:
    """ClassifiedFinding has diff_status=None by default."""
    cf = _make_classified()
    assert cf.diff_status is None


# ---------- CLI integration ----------


def test_diff_cli_exit_code_1(tmp_path: Path) -> None:
    """--diff exits with 1 when new findings exist vs empty baseline."""
    # Generate empty baseline
    bl_path = tmp_path / "baseline.json"
    bl_path.write_text(
        json.dumps(generate_baseline([], "0.3.0"), indent=2),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable, "-m", "qproof", "scan",
            "tests/fixtures/sample_project",
            "--diff", str(bl_path),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 1
    assert "new" in result.stderr.lower()


def test_diff_cli_exit_code_0(tmp_path: Path) -> None:
    """--diff exits with 0 when baseline matches current scan."""
    bl_path = tmp_path / "baseline.json"

    # Generate baseline from actual scan
    subprocess.run(
        [
            sys.executable, "-m", "qproof", "scan",
            "tests/fixtures/sample_project",
            "--baseline", str(bl_path),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert bl_path.exists()

    # Diff against itself
    result = subprocess.run(
        [
            sys.executable, "-m", "qproof", "scan",
            "tests/fixtures/sample_project",
            "--diff", str(bl_path),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0


def test_diff_cli_mutual_exclusion(tmp_path: Path) -> None:
    """--baseline and --diff together exits with code 2."""
    bl_path = tmp_path / "baseline.json"
    bl_path.write_text(
        json.dumps(generate_baseline([], "0.3.0"), indent=2),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable, "-m", "qproof", "scan",
            "tests/fixtures/sample_project",
            "--baseline", str(tmp_path / "out.json"),
            "--diff", str(bl_path),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 2
    assert "mutually exclusive" in result.stderr.lower()


def test_diff_cli_json_format(tmp_path: Path) -> None:
    """--diff with --format json includes diff_summary."""
    bl_path = tmp_path / "baseline.json"
    bl_path.write_text(
        json.dumps(generate_baseline([], "0.3.0"), indent=2),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable, "-m", "qproof", "scan",
            "tests/fixtures/sample_project",
            "--diff", str(bl_path),
            "--format", "json",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    data = json.loads(result.stdout)
    assert "diff_summary" in data
    assert data["diff_summary"]["new"] > 0


def test_diff_cli_stderr_summary(tmp_path: Path) -> None:
    """--diff prints diff summary to stderr."""
    bl_path = tmp_path / "baseline.json"
    bl_path.write_text(
        json.dumps(generate_baseline([], "0.3.0"), indent=2),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable, "-m", "qproof", "scan",
            "tests/fixtures/sample_project",
            "--diff", str(bl_path),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert "Diff:" in result.stderr
    assert "new" in result.stderr
    assert "worsened" in result.stderr
    assert "resolved" in result.stderr
