"""Tests for SARIF v2.1.0 output."""

import json
import subprocess
import sys
from pathlib import Path

from qproof.models import (
    AlgorithmInfo,
    ClassifiedFinding,
    Finding,
    QuantumRisk,
)
from qproof.output.sarif import findings_to_sarif


def _make_classified(
    algorithm_id: str,
    name: str,
    risk: QuantumRisk,
    replacement: str,
    file_path: str = "/tmp/project/src/crypto.py",
    line_number: int = 10,
    algo_type: str = "asymmetric",
) -> ClassifiedFinding:
    """Helper to build a ClassifiedFinding for tests."""
    finding = Finding(
        file_path=Path(file_path),
        line_number=line_number,
        matched_text=name,
        algorithm_id=algorithm_id,
        source="source_code",
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


class TestSarifOutput:
    """Tests for SARIF output generation."""

    def test_empty_findings_produces_valid_sarif(self) -> None:
        sarif = findings_to_sarif([], ".", 0.1)
        data = json.loads(sarif)
        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1
        assert len(data["runs"][0]["results"]) == 0

    def test_sarif_has_tool_info(self) -> None:
        sarif = findings_to_sarif([], ".", 0.1)
        data = json.loads(sarif)
        driver = data["runs"][0]["tool"]["driver"]
        assert driver["name"] == "qproof"
        assert "version" in driver
        assert driver["informationUri"] == "https://github.com/qproof/qproof"

    def test_sarif_schema_field_present(self) -> None:
        sarif = findings_to_sarif([], ".", 0.1)
        data = json.loads(sarif)
        assert "$schema" in data
        assert "sarif-schema-2.1.0" in data["$schema"]

    def test_vulnerable_finding_maps_to_error(self) -> None:
        cf = _make_classified("RSA", "RSA", QuantumRisk.VULNERABLE, "ML-KEM")
        sarif = findings_to_sarif([cf], "/tmp/project", 0.1)
        data = json.loads(sarif)
        assert data["runs"][0]["results"][0]["level"] == "error"

    def test_partial_finding_maps_to_warning(self) -> None:
        cf = _make_classified(
            "AES-128", "AES-128", QuantumRisk.PARTIAL, "AES-256",
            algo_type="symmetric",
        )
        sarif = findings_to_sarif([cf], "/tmp/project", 0.1)
        data = json.loads(sarif)
        assert data["runs"][0]["results"][0]["level"] == "warning"

    def test_safe_finding_maps_to_note(self) -> None:
        cf = _make_classified(
            "AES-256", "AES-256", QuantumRisk.SAFE, "AES-256",
            algo_type="symmetric",
        )
        sarif = findings_to_sarif([cf], "/tmp/project", 0.1)
        data = json.loads(sarif)
        assert data["runs"][0]["results"][0]["level"] == "note"

    def test_results_have_location(self) -> None:
        cf = _make_classified(
            "RSA", "RSA", QuantumRisk.VULNERABLE, "ML-KEM",
            file_path="/tmp/project/app.py", line_number=5,
        )
        sarif = findings_to_sarif([cf], "/tmp/project", 0.1)
        data = json.loads(sarif)
        result = data["runs"][0]["results"][0]
        loc = result["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "app.py"
        assert loc["artifactLocation"]["uriBaseId"] == "%SRCROOT%"
        assert loc["region"]["startLine"] == 5
        assert loc["region"]["startColumn"] == 1

    def test_rules_generated_from_findings(self) -> None:
        cf_rsa = _make_classified("RSA", "RSA", QuantumRisk.VULNERABLE, "ML-KEM")
        cf_sha1 = _make_classified(
            "SHA-1", "SHA-1", QuantumRisk.VULNERABLE, "SHA-256",
            algo_type="hash",
        )
        sarif = findings_to_sarif([cf_rsa, cf_sha1], "/tmp/project", 0.1)
        data = json.loads(sarif)
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = {r["id"] for r in rules}
        assert "qproof/RSA" in rule_ids
        assert "qproof/SHA-1" in rule_ids
        assert len(rules) == 2

    def test_duplicate_algorithm_produces_single_rule(self) -> None:
        cf1 = _make_classified(
            "RSA", "RSA", QuantumRisk.VULNERABLE, "ML-KEM",
            file_path="/tmp/project/a.py", line_number=1,
        )
        cf2 = _make_classified(
            "RSA", "RSA", QuantumRisk.VULNERABLE, "ML-KEM",
            file_path="/tmp/project/b.py", line_number=5,
        )
        sarif = findings_to_sarif([cf1, cf2], "/tmp/project", 0.1)
        data = json.loads(sarif)
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        assert rules[0]["id"] == "qproof/RSA"
        assert len(data["runs"][0]["results"]) == 2

    def test_result_message_contains_replacement(self) -> None:
        cf = _make_classified("RSA", "RSA", QuantumRisk.VULNERABLE, "ML-KEM")
        sarif = findings_to_sarif([cf], "/tmp/project", 0.1)
        data = json.loads(sarif)
        msg = data["runs"][0]["results"][0]["message"]["text"]
        assert "ML-KEM" in msg
        assert "RSA" in msg

    def test_result_properties_include_metadata(self) -> None:
        cf = _make_classified("RSA", "RSA", QuantumRisk.VULNERABLE, "ML-KEM")
        sarif = findings_to_sarif([cf], "/tmp/project", 0.1)
        data = json.loads(sarif)
        props = data["runs"][0]["results"][0]["properties"]
        assert props["quantum_risk"] == "VULNERABLE"
        assert props["algorithm_type"] == "asymmetric"
        assert props["replacement"] == "ML-KEM"

    def test_rule_has_tags(self) -> None:
        cf = _make_classified("RSA", "RSA", QuantumRisk.VULNERABLE, "ML-KEM")
        sarif = findings_to_sarif([cf], "/tmp/project", 0.1)
        data = json.loads(sarif)
        rule = data["runs"][0]["tool"]["driver"]["rules"][0]
        assert "security" in rule["properties"]["tags"]
        assert "cryptography" in rule["properties"]["tags"]
        assert "quantum" in rule["properties"]["tags"]

    def test_rule_default_level_matches_risk(self) -> None:
        cf = _make_classified(
            "AES-128", "AES-128", QuantumRisk.PARTIAL, "AES-256",
            algo_type="symmetric",
        )
        sarif = findings_to_sarif([cf], "/tmp/project", 0.1)
        data = json.loads(sarif)
        rule = data["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["defaultConfiguration"]["level"] == "warning"


class TestSarifCli:
    """CLI integration tests for --format sarif."""

    def test_format_sarif_via_cli(self) -> None:
        result = subprocess.run(
            [
                sys.executable, "-m", "qproof", "scan",
                "tests/fixtures/sample_project", "--format", "sarif",
            ],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["version"] == "2.1.0"
        assert len(data["runs"][0]["results"]) > 0

    def test_format_sarif_to_file(self, tmp_path: Path) -> None:
        out_file = tmp_path / "report.sarif"
        result = subprocess.run(
            [
                sys.executable, "-m", "qproof", "scan",
                "tests/fixtures/sample_project",
                "--format", "sarif", "-o", str(out_file),
            ],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0
        data = json.loads(out_file.read_text())
        assert data["version"] == "2.1.0"
        assert len(data["runs"][0]["results"]) > 0
