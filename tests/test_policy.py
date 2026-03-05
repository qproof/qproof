"""Tests for policy-as-code engine (QP-015)."""

from __future__ import annotations

import subprocess
import sys
from datetime import date, timedelta
from pathlib import Path

import pytest

from qproof.models import (
    AlgorithmInfo,
    ClassifiedFinding,
    Finding,
    QuantumRisk,
)
from qproof.policy import (
    AllowRule,
    FailConfig,
    IgnoreConfig,
    PolicyConfig,
    PolicyValidationError,
    SeverityOverride,
    apply_severity_overrides,
    check_fail_conditions,
    load_policy,
    load_policy_from_file,
    should_ignore_finding,
    should_ignore_path,
)


def _make_classified(
    file_path: str = "src/auth.py",
    line_number: int = 10,
    algorithm_id: str = "RSA",
    source: str = "source_code",
    quantum_risk: QuantumRisk = QuantumRisk.VULNERABLE,
    severity: str = "critical",
    diff_status: str | None = None,
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
    cf = ClassifiedFinding(
        finding=finding,
        algorithm=algo,
        quantum_risk=quantum_risk,
        replacement="ML-KEM",
        reason="test reason",
        severity=severity,
    )
    cf.diff_status = diff_status
    return cf


def _empty_policy(**overrides: object) -> PolicyConfig:
    """Create a minimal PolicyConfig with optional overrides."""
    defaults: dict[str, object] = {
        "version": "1",
        "ignore": IgnoreConfig(),
        "allow": [],
        "fail": FailConfig(),
        "severity_overrides": [],
    }
    defaults.update(overrides)
    return PolicyConfig(**defaults)  # type: ignore[arg-type]


# ---------- load_policy ----------


def test_policy_load_valid(tmp_path: Path) -> None:
    """Valid qproof.yml produces a PolicyConfig with correct values."""
    yml = tmp_path / "qproof.yml"
    yml.write_text(
        'version: "1"\n'
        "ignore:\n"
        "  paths:\n"
        '    - "vendor/**"\n'
        "  algorithms:\n"
        "    - MD5\n"
        "allow:\n"
        '  - algorithm: RSA\n'
        '    paths: ["legacy/**"]\n'
        '    reason: "planned"\n'
        '    expires: "2030-01-01"\n'
        "fail:\n"
        "  on_severity: medium\n"
        "  max_new_findings: 5\n"
        "severity_overrides:\n"
        '  - algorithm: SHA-1\n'
        '    severity: critical\n'
        '    reason: "no SHA-1"\n',
        encoding="utf-8",
    )
    policy = load_policy(tmp_path)
    assert policy is not None
    assert policy.version == "1"
    assert policy.ignore.paths == ["vendor/**"]
    assert policy.ignore.algorithms == ["MD5"]
    assert len(policy.allow) == 1
    assert policy.allow[0].algorithm == "RSA"
    assert policy.allow[0].expires == date(2030, 1, 1)
    assert policy.fail.on_severity == "medium"
    assert policy.fail.max_new_findings == 5
    assert len(policy.severity_overrides) == 1
    assert policy.severity_overrides[0].severity == "critical"


def test_policy_load_missing(tmp_path: Path) -> None:
    """No qproof.yml returns None."""
    assert load_policy(tmp_path) is None


def test_policy_load_invalid_yaml(tmp_path: Path) -> None:
    """Broken YAML syntax raises PolicyValidationError."""
    yml = tmp_path / "qproof.yml"
    yml.write_text("version: [invalid yaml\n  broken:", encoding="utf-8")
    with pytest.raises(PolicyValidationError, match="Invalid YAML"):
        load_policy(tmp_path)


def test_policy_load_invalid_schema(tmp_path: Path) -> None:
    """Wrong field types raise PolicyValidationError with detail."""
    yml = tmp_path / "qproof.yml"
    yml.write_text(
        'version: "1"\n'
        "ignore:\n"
        '  paths: "not-a-list"\n',
        encoding="utf-8",
    )
    with pytest.raises(PolicyValidationError, match="ignore.paths"):
        load_policy(tmp_path)


def test_policy_load_unknown_field(tmp_path: Path) -> None:
    """Unknown top-level key raises PolicyValidationError."""
    yml = tmp_path / "qproof.yml"
    yml.write_text(
        'version: "1"\n'
        "typo_field: true\n",
        encoding="utf-8",
    )
    with pytest.raises(PolicyValidationError, match="unknown keys"):
        load_policy(tmp_path)


def test_policy_load_missing_version(tmp_path: Path) -> None:
    """Missing version key raises PolicyValidationError."""
    yml = tmp_path / "qproof.yml"
    yml.write_text("ignore:\n  paths: []\n", encoding="utf-8")
    with pytest.raises(PolicyValidationError, match="version"):
        load_policy(tmp_path)


def test_policy_load_invalid_severity_in_fail(tmp_path: Path) -> None:
    """Invalid on_severity value raises PolicyValidationError."""
    yml = tmp_path / "qproof.yml"
    yml.write_text(
        'version: "1"\n'
        "fail:\n"
        "  on_severity: ultra\n",
        encoding="utf-8",
    )
    with pytest.raises(PolicyValidationError, match="on_severity"):
        load_policy(tmp_path)


def test_policy_load_defaults(tmp_path: Path) -> None:
    """Minimal qproof.yml uses defaults for missing sections."""
    yml = tmp_path / "qproof.yml"
    yml.write_text('version: "1"\n', encoding="utf-8")
    policy = load_policy(tmp_path)
    assert policy is not None
    assert policy.ignore.paths == []
    assert policy.ignore.algorithms == []
    assert policy.allow == []
    assert policy.fail.on_severity == "high"
    assert policy.fail.max_new_findings == 0
    assert policy.severity_overrides == []


# ---------- should_ignore_path ----------


def test_policy_ignore_paths() -> None:
    """Vendor file matches ignore pattern."""
    policy = _empty_policy(ignore=IgnoreConfig(paths=["vendor/**"]))
    assert should_ignore_path("vendor/lib/crypto.py", policy) is True


def test_policy_ignore_paths_no_match() -> None:
    """Non-matching path is not ignored."""
    policy = _empty_policy(ignore=IgnoreConfig(paths=["vendor/**"]))
    assert should_ignore_path("src/auth.py", policy) is False


def test_policy_ignore_paths_glob_test_prefix() -> None:
    """test_* glob pattern matches test files."""
    policy = _empty_policy(ignore=IgnoreConfig(paths=["**/test_*"]))
    assert should_ignore_path("tests/test_crypto.py", policy) is True


# ---------- should_ignore_finding (algorithms) ----------


def test_policy_ignore_algorithms() -> None:
    """MD5 in ignore.algorithms suppresses MD5 findings."""
    policy = _empty_policy(ignore=IgnoreConfig(algorithms=["MD5"]))
    cf = _make_classified(algorithm_id="MD5")
    assert should_ignore_finding(cf, policy) is True


def test_policy_ignore_algorithms_case() -> None:
    """Algorithm match is case-insensitive."""
    policy = _empty_policy(ignore=IgnoreConfig(algorithms=["md5"]))
    cf = _make_classified(algorithm_id="MD5")
    assert should_ignore_finding(cf, policy) is True


def test_policy_ignore_algorithms_no_match() -> None:
    """Non-ignored algorithm is not suppressed."""
    policy = _empty_policy(ignore=IgnoreConfig(algorithms=["MD5"]))
    cf = _make_classified(algorithm_id="RSA")
    assert should_ignore_finding(cf, policy) is False


# ---------- should_ignore_finding (allow rules) ----------


def test_policy_allow_matching() -> None:
    """RSA in legacy/auth/ with active allow rule is ignored."""
    policy = _empty_policy(allow=[
        AllowRule(
            algorithm="RSA",
            paths=["legacy/auth/**"],
            reason="planned migration",
        ),
    ])
    cf = _make_classified(file_path="legacy/auth/login.py", algorithm_id="RSA")
    assert should_ignore_finding(cf, policy) is True


def test_policy_allow_wrong_path() -> None:
    """RSA in non-matching path is NOT ignored."""
    policy = _empty_policy(allow=[
        AllowRule(
            algorithm="RSA",
            paths=["legacy/auth/**"],
            reason="planned migration",
        ),
    ])
    cf = _make_classified(file_path="src/new/crypto.py", algorithm_id="RSA")
    assert should_ignore_finding(cf, policy) is False


def test_policy_allow_expired() -> None:
    """Expired allow rule does NOT suppress the finding."""
    policy = _empty_policy(allow=[
        AllowRule(
            algorithm="RSA",
            paths=["legacy/**"],
            reason="was planned",
            expires=date(2020, 1, 1),
        ),
    ])
    cf = _make_classified(file_path="legacy/auth.py", algorithm_id="RSA")
    assert should_ignore_finding(cf, policy) is False


def test_policy_allow_not_expired() -> None:
    """Non-expired allow rule suppresses the finding."""
    future = date.today() + timedelta(days=365)
    policy = _empty_policy(allow=[
        AllowRule(
            algorithm="RSA",
            paths=["legacy/**"],
            reason="migration pending",
            expires=future,
        ),
    ])
    cf = _make_classified(file_path="legacy/auth.py", algorithm_id="RSA")
    assert should_ignore_finding(cf, policy) is True


def test_policy_allow_no_expires() -> None:
    """Allow rule without expires is always active."""
    policy = _empty_policy(allow=[
        AllowRule(
            algorithm="RSA",
            paths=["legacy/**"],
            reason="permanent exception",
        ),
    ])
    cf = _make_classified(file_path="legacy/old.py", algorithm_id="RSA")
    assert should_ignore_finding(cf, policy) is True


# ---------- apply_severity_overrides ----------


def test_policy_severity_override() -> None:
    """Override changes SHA-1 severity to critical."""
    policy = _empty_policy(severity_overrides=[
        SeverityOverride(algorithm="SHA-1", severity="critical", reason="policy"),
    ])
    cf = _make_classified(algorithm_id="SHA-1", severity="medium")
    apply_severity_overrides([cf], policy)
    assert cf.severity == "critical"


def test_policy_severity_override_only_target() -> None:
    """Override for SHA-1 does not affect RSA."""
    policy = _empty_policy(severity_overrides=[
        SeverityOverride(algorithm="SHA-1", severity="critical", reason="policy"),
    ])
    cf_rsa = _make_classified(algorithm_id="RSA", severity="high")
    cf_sha = _make_classified(algorithm_id="SHA-1", severity="medium")
    apply_severity_overrides([cf_rsa, cf_sha], policy)
    assert cf_rsa.severity == "high"
    assert cf_sha.severity == "critical"


# ---------- check_fail_conditions ----------


def test_policy_fail_on_severity_high() -> None:
    """Critical finding with on_severity=high causes failure."""
    policy = _empty_policy(fail=FailConfig(on_severity="high"))
    cf = _make_classified(severity="critical")
    assert check_fail_conditions([cf], policy) is True


def test_policy_fail_on_severity_high_medium_ok() -> None:
    """Medium finding with on_severity=high does NOT cause failure."""
    policy = _empty_policy(fail=FailConfig(on_severity="high"))
    cf = _make_classified(severity="medium")
    assert check_fail_conditions([cf], policy) is False


def test_policy_fail_on_severity_exact_match() -> None:
    """Finding at exact threshold severity causes failure."""
    policy = _empty_policy(fail=FailConfig(on_severity="medium"))
    cf = _make_classified(severity="medium")
    assert check_fail_conditions([cf], policy) is True


def test_policy_fail_max_new_findings() -> None:
    """3 new findings with max=2 causes failure in diff mode."""
    policy = _empty_policy(fail=FailConfig(on_severity="info", max_new_findings=2))
    findings = [
        _make_classified(severity="info", diff_status="new", file_path=f"f{i}.py")
        for i in range(3)
    ]
    assert check_fail_conditions(findings, policy, is_diff_mode=True) is True


def test_policy_fail_max_not_diff() -> None:
    """max_new_findings is ignored outside diff mode."""
    policy_high = _empty_policy(
        fail=FailConfig(on_severity="critical", max_new_findings=0),
    )
    cf = _make_classified(severity="medium", diff_status="new")
    # In non-diff mode, max_new_findings is not checked
    assert check_fail_conditions([cf], policy_high, is_diff_mode=False) is False


def test_policy_fail_empty_findings() -> None:
    """No findings means no failure."""
    policy = _empty_policy(fail=FailConfig(on_severity="info"))
    assert check_fail_conditions([], policy) is False


# ---------- CLI: policy validate ----------


def test_policy_validate_command_valid() -> None:
    """qproof policy validate with valid file exits 0."""
    fixture = str(Path("tests/fixtures/qproof_valid.yml"))
    result = subprocess.run(
        [sys.executable, "-m", "qproof", "policy", "validate", "--file", fixture],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0
    assert "valid" in result.stdout.lower() or "Valid" in result.stdout


def test_policy_validate_command_invalid() -> None:
    """qproof policy validate with invalid file exits 2."""
    fixture = str(Path("tests/fixtures/qproof_invalid.yml"))
    result = subprocess.run(
        [sys.executable, "-m", "qproof", "policy", "validate", "--file", fixture],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 2


def test_policy_validate_command_missing() -> None:
    """qproof policy validate with missing file exits 2."""
    result = subprocess.run(
        [
            sys.executable, "-m", "qproof", "policy", "validate",
            "--file", "/nonexistent/qproof.yml",
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 2


# ---------- backward compatibility ----------


def test_policy_backward_compat() -> None:
    """Scan without qproof.yml works identically to before."""
    result = subprocess.run(
        [
            sys.executable, "-m", "qproof", "scan",
            "tests/fixtures/sample_project",
            "--format", "json",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0
    import json

    data = json.loads(result.stdout)
    assert data["summary"]["total_findings"] > 0


# ---------- load_policy_from_file ----------


def test_policy_from_file_valid() -> None:
    """load_policy_from_file works with explicit path."""
    fixture = Path("tests/fixtures/qproof_valid.yml")
    policy = load_policy_from_file(fixture)
    assert policy.version == "1"
    assert len(policy.ignore.paths) == 4


def test_policy_from_file_missing() -> None:
    """load_policy_from_file raises FileNotFoundError for missing file."""
    with pytest.raises(FileNotFoundError):
        load_policy_from_file("/nonexistent/qproof.yml")
