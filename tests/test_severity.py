"""Tests for severity model and finding enrichment (QP-017)."""

from pathlib import Path

import yaml

from qproof.classifier.severity import (
    calculate_severity,
    enrich_severity,
    severity_to_sarif_level,
)
from qproof.models import (
    AlgorithmInfo,
    ClassifiedFinding,
    Finding,
    QuantumRisk,
)


def _make_classified(
    quantum_risk: QuantumRisk = QuantumRisk.VULNERABLE,
    confidence: str = "high",
    context: str = "runtime",
    algorithm_id: str = "RSA",
) -> ClassifiedFinding:
    """Create a ClassifiedFinding for testing."""
    finding = Finding(
        file_path=Path("src/auth.py"),
        line_number=10,
        matched_text="RSA",
        algorithm_id=algorithm_id,
        source="source_code",
        context="key = RSA.generate(2048)",
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
        confidence=confidence,
        context=context,
    )


# ---------- calculate_severity ----------


def test_severity_critical() -> None:
    """VULNERABLE + high + runtime → critical."""
    assert calculate_severity("VULNERABLE", "high", "runtime") == "critical"


def test_severity_downgrade_test() -> None:
    """VULNERABLE + high + test → low."""
    assert calculate_severity("VULNERABLE", "high", "test") == "low"


def test_severity_downgrade_docs() -> None:
    """VULNERABLE + high + docs → low."""
    assert calculate_severity("VULNERABLE", "high", "docs") == "low"


def test_severity_downgrade_comment() -> None:
    """VULNERABLE + high + comment → low."""
    assert calculate_severity("VULNERABLE", "high", "comment") == "low"


def test_severity_medium_conf_runtime() -> None:
    """VULNERABLE + medium + runtime → high."""
    assert calculate_severity("VULNERABLE", "medium", "runtime") == "high"


def test_severity_medium_conf_test() -> None:
    """VULNERABLE + medium + test → medium."""
    assert calculate_severity("VULNERABLE", "medium", "test") == "medium"


def test_severity_low_confidence() -> None:
    """VULNERABLE + low → medium."""
    assert calculate_severity("VULNERABLE", "low", "runtime") == "medium"


def test_severity_partial_runtime() -> None:
    """PARTIAL + high + runtime → high."""
    assert calculate_severity("PARTIAL", "high", "runtime") == "high"


def test_severity_partial_test() -> None:
    """PARTIAL + high + test → info."""
    assert calculate_severity("PARTIAL", "high", "test") == "info"


def test_severity_partial_medium_runtime() -> None:
    """PARTIAL + medium + runtime → medium."""
    assert calculate_severity("PARTIAL", "medium", "runtime") == "medium"


def test_severity_partial_low() -> None:
    """PARTIAL + low → low."""
    assert calculate_severity("PARTIAL", "low", "runtime") == "low"


def test_severity_safe_always_info() -> None:
    """SAFE + any combination → info."""
    for conf in ("low", "medium", "high"):
        for ctx in ("runtime", "test", "docs", "comment", "build"):
            assert calculate_severity("SAFE", conf, ctx) == "info"


# ---------- SARIF level mapping ----------


def test_sarif_level_critical() -> None:
    """critical → error."""
    assert severity_to_sarif_level("critical") == "error"


def test_sarif_level_high() -> None:
    """high → error."""
    assert severity_to_sarif_level("high") == "error"


def test_sarif_level_medium() -> None:
    """medium → warning."""
    assert severity_to_sarif_level("medium") == "warning"


def test_sarif_level_low() -> None:
    """low → note."""
    assert severity_to_sarif_level("low") == "note"


def test_sarif_level_info() -> None:
    """info → note."""
    assert severity_to_sarif_level("info") == "note"


# ---------- enrich_severity ----------


def test_enrich_severity_sets_fields() -> None:
    """enrich_severity sets severity, category, remediation."""
    cf = _make_classified(
        quantum_risk=QuantumRisk.VULNERABLE,
        confidence="high",
        context="runtime",
        algorithm_id="RSA",
    )
    enrich_severity([cf])
    assert cf.severity == "critical"
    assert cf.category == "pki"
    assert cf.remediation is not None
    assert "ML-KEM" in cf.remediation


def test_enrich_severity_safe_algo() -> None:
    """SAFE algorithm gets info severity and 'No action required' remediation."""
    cf = _make_classified(
        quantum_risk=QuantumRisk.SAFE,
        confidence="high",
        context="runtime",
        algorithm_id="AES-256",
    )
    enrich_severity([cf])
    assert cf.severity == "info"
    assert cf.category == "at-rest"
    assert cf.remediation is not None
    assert "No action required" in cf.remediation


# ---------- algorithms.yaml coverage ----------


def test_all_algos_have_category() -> None:
    """Every algorithm in algorithms.yaml has a category field."""
    yaml_path = Path(__file__).parent.parent / "qproof" / "data" / "algorithms.yaml"
    with open(yaml_path) as f:
        raw = yaml.safe_load(f)

    for algo_id, data in raw["algorithms"].items():
        assert "category" in data, f"{algo_id} missing category"
        assert isinstance(data["category"], str), f"{algo_id} category not a string"
        assert len(data["category"]) > 0, f"{algo_id} has empty category"


def test_all_algos_have_remediation() -> None:
    """Every algorithm in algorithms.yaml has a remediation field."""
    yaml_path = Path(__file__).parent.parent / "qproof" / "data" / "algorithms.yaml"
    with open(yaml_path) as f:
        raw = yaml.safe_load(f)

    for algo_id, data in raw["algorithms"].items():
        assert "remediation" in data, f"{algo_id} missing remediation"
        assert isinstance(data["remediation"], str), f"{algo_id} remediation not a string"
        assert len(data["remediation"]) > 0, f"{algo_id} has empty remediation"


def test_category_values() -> None:
    """Category values from YAML are from the expected set."""
    valid = {"pki", "at-rest", "hash", "kdf", "mac", "tls", "protocol", "jwt"}
    yaml_path = Path(__file__).parent.parent / "qproof" / "data" / "algorithms.yaml"
    with open(yaml_path) as f:
        raw = yaml.safe_load(f)

    for algo_id, data in raw["algorithms"].items():
        assert data["category"] in valid, (
            f"{algo_id} has invalid category: {data['category']}"
        )


def test_category_from_yaml_rsa() -> None:
    """RSA → pki."""
    cf = _make_classified(algorithm_id="RSA")
    enrich_severity([cf])
    assert cf.category == "pki"


def test_category_from_yaml_aes256() -> None:
    """AES-256 → at-rest."""
    cf = _make_classified(
        quantum_risk=QuantumRisk.SAFE, algorithm_id="AES-256",
    )
    enrich_severity([cf])
    assert cf.category == "at-rest"


def test_category_from_yaml_sha1() -> None:
    """SHA-1 → hash."""
    cf = _make_classified(algorithm_id="SHA-1")
    enrich_severity([cf])
    assert cf.category == "hash"


def test_category_from_yaml_bcrypt() -> None:
    """bcrypt → kdf."""
    cf = _make_classified(
        quantum_risk=QuantumRisk.PARTIAL, algorithm_id="bcrypt",
    )
    enrich_severity([cf])
    assert cf.category == "kdf"


def test_remediation_from_yaml_rsa() -> None:
    """RSA remediation mentions ML-KEM."""
    cf = _make_classified(algorithm_id="RSA")
    enrich_severity([cf])
    assert "ML-KEM" in cf.remediation


def test_remediation_from_yaml_sha1() -> None:
    """SHA-1 remediation mentions SHA-256."""
    cf = _make_classified(algorithm_id="SHA-1")
    enrich_severity([cf])
    assert "SHA-256" in cf.remediation
