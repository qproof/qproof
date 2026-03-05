"""Tests for CycloneDX v1.6 CBOM output."""

import json
from pathlib import Path

from qproof.models import (
    AlgorithmInfo,
    ClassifiedFinding,
    Finding,
    QuantumRisk,
)
from qproof.output.cbom import findings_to_cbom


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


class TestCbomOutput:
    """Tests for CycloneDX v1.6 CBOM output generation."""

    def test_empty_findings_produces_valid_cbom(self) -> None:
        cbom = findings_to_cbom([], ".", 0.1)
        data = json.loads(cbom)
        assert data["bomFormat"] == "CycloneDX"
        assert data["specVersion"] == "1.6"
        assert "serialNumber" in data
        assert data["version"] == 1
        assert data["components"] == []

    def test_cbom_has_metadata_tool(self) -> None:
        cbom = findings_to_cbom([], ".", 0.1)
        data = json.loads(cbom)
        tools = data["metadata"]["tools"]["components"]
        assert len(tools) == 1
        assert tools[0]["name"] == "qproof"
        assert tools[0]["type"] == "application"
        assert "version" in tools[0]

    def test_cbom_has_timestamp(self) -> None:
        cbom = findings_to_cbom([], ".", 0.1)
        data = json.loads(cbom)
        assert "timestamp" in data["metadata"]
        # ISO 8601 timestamps contain 'T' separator
        assert "T" in data["metadata"]["timestamp"]

    def test_findings_become_crypto_components(self) -> None:
        cf_rsa = _make_classified("RSA", "RSA", QuantumRisk.VULNERABLE, "ML-KEM")
        cf_sha1 = _make_classified(
            "SHA-1", "SHA-1", QuantumRisk.VULNERABLE, "SHA-256",
            algo_type="hash",
        )
        cbom = findings_to_cbom([cf_rsa, cf_sha1], "/tmp/project", 0.1)
        data = json.loads(cbom)
        assert len(data["components"]) == 2
        names = {c["name"] for c in data["components"]}
        assert "RSA" in names
        assert "SHA-1" in names

    def test_components_have_crypto_properties(self) -> None:
        cf = _make_classified("RSA", "RSA", QuantumRisk.VULNERABLE, "ML-KEM")
        cbom = findings_to_cbom([cf], "/tmp/project", 0.1)
        data = json.loads(cbom)
        component = data["components"][0]
        assert "cryptoProperties" in component
        assert component["cryptoProperties"]["assetType"] == "algorithm"

    def test_multiple_findings_same_algo_dedup(self) -> None:
        cf1 = _make_classified(
            "RSA", "RSA", QuantumRisk.VULNERABLE, "ML-KEM",
            file_path="/tmp/project/a.py", line_number=1,
        )
        cf2 = _make_classified(
            "RSA", "RSA", QuantumRisk.VULNERABLE, "ML-KEM",
            file_path="/tmp/project/b.py", line_number=5,
        )
        cf3 = _make_classified(
            "RSA", "RSA", QuantumRisk.VULNERABLE, "ML-KEM",
            file_path="/tmp/project/c.py", line_number=20,
        )
        cbom = findings_to_cbom([cf1, cf2, cf3], "/tmp/project", 0.1)
        data = json.loads(cbom)
        # Deduplicated: 3 RSA findings -> 1 component
        assert len(data["components"]) == 1
        # All 3 occurrences present
        occurrences = data["components"][0]["evidence"]["occurrences"]
        assert len(occurrences) == 3

    def test_quantum_risk_in_properties(self) -> None:
        cf = _make_classified("RSA", "RSA", QuantumRisk.VULNERABLE, "ML-KEM")
        cbom = findings_to_cbom([cf], "/tmp/project", 0.1)
        data = json.loads(cbom)
        props = data["components"][0]["properties"]
        risk_props = [p for p in props if p["name"] == "qproof:quantum_risk"]
        assert len(risk_props) == 1
        assert risk_props[0]["value"] == "VULNERABLE"

    def test_replacement_in_properties(self) -> None:
        cf = _make_classified("RSA", "RSA", QuantumRisk.VULNERABLE, "ML-KEM")
        cbom = findings_to_cbom([cf], "/tmp/project", 0.1)
        data = json.loads(cbom)
        props = data["components"][0]["properties"]
        repl_props = [p for p in props if p["name"] == "qproof:replacement"]
        assert len(repl_props) == 1
        assert repl_props[0]["value"] == "ML-KEM"

    def test_component_type_is_cryptographic_asset(self) -> None:
        cf = _make_classified(
            "AES-256", "AES-256", QuantumRisk.SAFE, "AES-256",
            algo_type="symmetric",
        )
        cbom = findings_to_cbom([cf], "/tmp/project", 0.1)
        data = json.loads(cbom)
        assert data["components"][0]["type"] == "cryptographic-asset"

    def test_occurrences_have_location(self) -> None:
        cf = _make_classified(
            "RSA", "RSA", QuantumRisk.VULNERABLE, "ML-KEM",
            file_path="/tmp/project/app.py", line_number=42,
        )
        cbom = findings_to_cbom([cf], "/tmp/project", 0.1)
        data = json.loads(cbom)
        occ = data["components"][0]["evidence"]["occurrences"][0]
        assert occ["location"] == "app.py"
        assert occ["line"] == 42

    def test_serialnumber_is_urn_uuid(self) -> None:
        cbom = findings_to_cbom([], ".", 0.1)
        data = json.loads(cbom)
        assert data["serialNumber"].startswith("urn:uuid:")
        # UUID is 36 chars (8-4-4-4-12)
        uuid_part = data["serialNumber"][len("urn:uuid:"):]
        assert len(uuid_part) == 36

    def test_known_oid_included(self) -> None:
        cf = _make_classified("RSA", "RSA", QuantumRisk.VULNERABLE, "ML-KEM")
        cbom = findings_to_cbom([cf], "/tmp/project", 0.1)
        data = json.loads(cbom)
        crypto_props = data["components"][0]["cryptoProperties"]
        assert crypto_props["oid"] == "1.2.840.113549.1.1.1"

    def test_unknown_oid_omitted(self) -> None:
        cf = _make_classified(
            "bcrypt", "bcrypt", QuantumRisk.PARTIAL, "Argon2id",
            algo_type="kdf",
        )
        cbom = findings_to_cbom([cf], "/tmp/project", 0.1)
        data = json.loads(cbom)
        crypto_props = data["components"][0]["cryptoProperties"]
        assert "oid" not in crypto_props

    def test_protocol_asset_type(self) -> None:
        cf = _make_classified(
            "TLS-1.0", "TLS 1.0", QuantumRisk.VULNERABLE,
            "TLS 1.3 with post-quantum key exchange",
            algo_type="protocol",
        )
        cbom = findings_to_cbom([cf], "/tmp/project", 0.1)
        data = json.loads(cbom)
        crypto_props = data["components"][0]["cryptoProperties"]
        assert crypto_props["assetType"] == "protocol"
        # Protocols should NOT have algorithmProperties
        assert "algorithmProperties" not in crypto_props

    def test_asymmetric_kex_has_pke_primitive(self) -> None:
        cf = _make_classified("ECDH", "ECDH", QuantumRisk.VULNERABLE, "ML-KEM")
        cbom = findings_to_cbom([cf], "/tmp/project", 0.1)
        data = json.loads(cbom)
        algo_props = data["components"][0]["cryptoProperties"]["algorithmProperties"]
        assert algo_props["primitive"] == "pke"

    def test_asymmetric_sig_has_signature_primitive(self) -> None:
        cf = _make_classified("ECDSA", "ECDSA", QuantumRisk.VULNERABLE, "ML-DSA")
        cbom = findings_to_cbom([cf], "/tmp/project", 0.1)
        data = json.loads(cbom)
        algo_props = data["components"][0]["cryptoProperties"]["algorithmProperties"]
        assert algo_props["primitive"] == "signature"

    def test_symmetric_has_blockcipher_primitive(self) -> None:
        cf = _make_classified(
            "AES-256", "AES-256", QuantumRisk.SAFE, "AES-256",
            algo_type="symmetric",
        )
        cbom = findings_to_cbom([cf], "/tmp/project", 0.1)
        data = json.loads(cbom)
        algo_props = data["components"][0]["cryptoProperties"]["algorithmProperties"]
        assert algo_props["primitive"] == "blockcipher"

    def test_hash_has_hash_primitive(self) -> None:
        cf = _make_classified(
            "SHA-256", "SHA-256", QuantumRisk.SAFE, "SHA-256",
            algo_type="hash",
        )
        cbom = findings_to_cbom([cf], "/tmp/project", 0.1)
        data = json.loads(cbom)
        algo_props = data["components"][0]["cryptoProperties"]["algorithmProperties"]
        assert algo_props["primitive"] == "hash"

    def test_metadata_component_has_project_name(self) -> None:
        cbom = findings_to_cbom([], "/home/user/my-project", 0.1)
        data = json.loads(cbom)
        meta_comp = data["metadata"]["component"]
        assert meta_comp["type"] == "application"
        assert meta_comp["name"] == "my-project"
        assert meta_comp["bom-ref"] == "scanned-project"

    def test_source_in_properties(self) -> None:
        cf = _make_classified("RSA", "RSA", QuantumRisk.VULNERABLE, "ML-KEM")
        cbom = findings_to_cbom([cf], "/tmp/project", 0.1)
        data = json.loads(cbom)
        props = data["components"][0]["properties"]
        src_props = [p for p in props if p["name"] == "qproof:source"]
        assert len(src_props) == 1
        assert src_props[0]["value"] == "source_code"
