"""Tests for the algorithm and library databases."""

from pathlib import Path

import pytest
import yaml

from qproof.data.loader import (
    get_all_patterns,
    get_patterns_for_algorithm,
    load_algorithms,
    load_libraries,
)
from qproof.models import QuantumRisk

DATA_DIR = Path(__file__).parent.parent / "qproof" / "data"


class TestAlgorithmsYaml:
    """Tests for algorithms.yaml integrity."""

    def test_loads_without_error(self) -> None:
        """Algorithm database loads successfully."""
        db = load_algorithms()
        assert isinstance(db, dict)

    def test_minimum_35_algorithms(self) -> None:
        """Database has at least 35 algorithms."""
        db = load_algorithms()
        assert len(db) >= 35, f"Expected >= 35 algorithms, got {len(db)}"

    def test_all_have_required_fields(self) -> None:
        """Every algorithm has the required fields populated."""
        db = load_algorithms()
        for algo_id, info in db.items():
            assert info.name, f"{algo_id} missing name"
            assert info.type, f"{algo_id} missing type"
            assert info.quantum_risk is not None, f"{algo_id} missing quantum_risk"
            assert info.reason, f"{algo_id} missing reason"
            assert info.replacement, f"{algo_id} missing replacement"
            assert len(info.patterns) >= 1, f"{algo_id} must have at least 1 pattern"

    def test_valid_types(self) -> None:
        """All algorithms have a valid type."""
        valid_types = {"asymmetric", "symmetric", "hash", "kdf", "mac", "protocol"}
        db = load_algorithms()
        for algo_id, info in db.items():
            assert info.type in valid_types, f"{algo_id} has invalid type: {info.type}"

    def test_valid_quantum_risk_values(self) -> None:
        """All algorithms have a valid QuantumRisk enum value."""
        db = load_algorithms()
        for algo_id, info in db.items():
            assert isinstance(info.quantum_risk, QuantumRisk), (
                f"{algo_id} has invalid quantum_risk"
            )

    def test_known_vulnerables(self) -> None:
        """Known VULNERABLE algorithms must be classified correctly."""
        db = load_algorithms()
        must_be_vulnerable = [
            "RSA", "DSA", "ECDSA", "ECDH", "Ed25519", "X25519",
            "DH", "DES", "3DES", "RC4", "MD5", "SHA-1",
        ]
        for algo_id in must_be_vulnerable:
            assert algo_id in db, f"Missing algorithm: {algo_id}"
            assert db[algo_id].quantum_risk == QuantumRisk.VULNERABLE, (
                f"{algo_id} should be VULNERABLE"
            )

    def test_known_safes(self) -> None:
        """Known SAFE algorithms must be classified correctly."""
        db = load_algorithms()
        must_be_safe = [
            "AES-256", "SHA-256", "SHA-384", "SHA-512",
            "SHA-3", "ChaCha20-Poly1305", "Argon2", "scrypt",
        ]
        for algo_id in must_be_safe:
            assert algo_id in db, f"Missing algorithm: {algo_id}"
            assert db[algo_id].quantum_risk == QuantumRisk.SAFE, (
                f"{algo_id} should be SAFE"
            )

    def test_aes128_is_partial(self) -> None:
        """AES-128 should be PARTIAL (Grover reduces to 64-bit)."""
        db = load_algorithms()
        assert "AES-128" in db
        assert db["AES-128"].quantum_risk == QuantumRisk.PARTIAL

    def test_no_duplicate_patterns_within_algorithm(self) -> None:
        """No algorithm should have duplicate patterns."""
        db = load_algorithms()
        for algo_id, info in db.items():
            assert len(info.patterns) == len(set(info.patterns)), (
                f"{algo_id} has duplicate patterns"
            )

    def test_vulnerable_algorithms_have_meaningful_replacement(self) -> None:
        """VULNERABLE algorithms should have non-trivial replacement text."""
        db = load_algorithms()
        for algo_id, info in db.items():
            if info.quantum_risk == QuantumRisk.VULNERABLE:
                assert len(info.replacement) > 10, (
                    f"{algo_id} replacement too short: '{info.replacement}'"
                )

    def test_patterns_are_nonempty_strings(self) -> None:
        """All patterns must be non-empty strings."""
        db = load_algorithms()
        for algo_id, info in db.items():
            for p in info.patterns:
                assert isinstance(p, str) and len(p.strip()) > 0, (
                    f"{algo_id} has empty pattern"
                )

    def test_get_all_patterns_returns_valid_dict(self) -> None:
        """get_all_patterns returns dict with algo IDs as keys."""
        patterns = get_all_patterns()
        assert isinstance(patterns, dict)
        assert len(patterns) >= 35

    def test_get_patterns_for_known_algorithm(self) -> None:
        """Known algorithm returns its patterns."""
        patterns = get_patterns_for_algorithm("RSA")
        assert len(patterns) >= 3
        assert "RSA" in patterns

    def test_get_patterns_for_unknown_algorithm(self) -> None:
        """Unknown algorithm returns empty list."""
        patterns = get_patterns_for_algorithm("NONEXISTENT_ALGO")
        assert patterns == []


class TestAlgorithmsYamlReferences:
    """Tests for formal reference integrity in algorithms.yaml."""

    @pytest.fixture(autouse=True)
    def _load_raw_yaml(self) -> None:
        yaml_path = DATA_DIR / "algorithms.yaml"
        with open(yaml_path) as f:
            self.raw = yaml.safe_load(f)

    def test_yaml_has_references_field(self) -> None:
        """All algorithms should have a references field."""
        for algo_id, data in self.raw["algorithms"].items():
            assert "references" in data, f"{algo_id} missing 'references' field"

    def test_references_have_nist_or_ietf(self) -> None:
        """All algorithms should reference at least one standard body."""
        for algo_id, data in self.raw["algorithms"].items():
            refs = data.get("references", {})
            has_standard = "nist" in refs or "ietf" in refs or "cnsa" in refs
            assert has_standard, (
                f"{algo_id} must reference at least one standard body (nist/ietf/cnsa)"
            )

    def test_vulnerable_asymmetric_have_cnsa_reference(self) -> None:
        """VULNERABLE asymmetric algorithms must reference CNSA 2.0."""
        for algo_id, data in self.raw["algorithms"].items():
            if data.get("type") == "asymmetric" and data.get("quantum_risk") == "VULNERABLE":
                refs = data.get("references", {})
                assert "cnsa" in refs, (
                    f"{algo_id} (VULNERABLE asymmetric) must have CNSA 2.0 reference"
                )

    def test_vulnerable_asymmetric_have_eu_deadlines(self) -> None:
        """VULNERABLE asymmetric algorithms must have EU transition deadlines."""
        for algo_id, data in self.raw["algorithms"].items():
            if data.get("type") == "asymmetric" and data.get("quantum_risk") == "VULNERABLE":
                assert "deadlines" in data, f"{algo_id} missing 'deadlines' field"
                deadlines = data["deadlines"]
                assert "eu_high_risk" in deadlines, (
                    f"{algo_id} missing eu_high_risk deadline"
                )
                assert "eu_full_transition" in deadlines, (
                    f"{algo_id} missing eu_full_transition deadline"
                )

    def test_has_ccn_references(self) -> None:
        """Key algorithms should have CCN-STIC references for ENS compliance."""
        must_have_ccn = ["RSA", "ECDSA", "AES-256", "SHA-256"]
        for algo_id in must_have_ccn:
            refs = self.raw["algorithms"][algo_id].get("references", {})
            assert "ccn" in refs, (
                f"{algo_id} should have CCN-STIC reference for ENS compliance"
            )


class TestLibrariesYaml:
    """Tests for libraries.yaml integrity."""

    def test_loads_without_error(self) -> None:
        """Library database loads successfully."""
        libs = load_libraries()
        assert isinstance(libs, dict)

    def test_minimum_12_libraries(self) -> None:
        """Database has at least 12 libraries."""
        libs = load_libraries()
        assert len(libs) >= 12, f"Expected >= 12 libraries, got {len(libs)}"

    def test_all_have_required_fields(self) -> None:
        """Every library has required fields."""
        libs = load_libraries()
        for lib_id, data in libs.items():
            assert "ecosystem" in data, f"{lib_id} missing ecosystem"
            assert "package_name" in data, f"{lib_id} missing package_name"
            assert "description" in data, f"{lib_id} missing description"
            assert "exposes" in data, f"{lib_id} missing exposes"
            assert "default_risk" in data, f"{lib_id} missing default_risk"

    def test_valid_ecosystems(self) -> None:
        """All libraries have a valid ecosystem."""
        valid = {"python", "npm", "go", "java", "rust"}
        libs = load_libraries()
        for lib_id, data in libs.items():
            assert data["ecosystem"] in valid, (
                f"{lib_id} has invalid ecosystem: {data['ecosystem']}"
            )

    def test_python_cryptography_present(self) -> None:
        """The 'cryptography' Python package must be in the database."""
        libs = load_libraries()
        assert "cryptography" in libs

    def test_npm_jsonwebtoken_present(self) -> None:
        """The 'jsonwebtoken' npm package must be in the database."""
        libs = load_libraries()
        assert "jsonwebtoken" in libs

    def test_libraries_reference_valid_algorithms(self) -> None:
        """All algorithms referenced in libraries must exist in algorithms.yaml."""
        algos = load_algorithms()
        libs = load_libraries()
        for lib_id, data in libs.items():
            for algo_ref in data["exposes"]:
                assert algo_ref in algos, (
                    f"Library '{lib_id}' references algorithm '{algo_ref}' "
                    f"which doesn't exist in algorithms.yaml"
                )

    def test_valid_default_risk(self) -> None:
        """All libraries have a valid default_risk value."""
        valid_risks = {"VULNERABLE", "PARTIAL", "SAFE"}
        libs = load_libraries()
        for lib_id, data in libs.items():
            assert data["default_risk"] in valid_risks, (
                f"{lib_id} has invalid default_risk"
            )


class TestLoaderEdgeCases:
    """Tests for loader error handling."""

    def test_missing_algorithms_file_raises(self) -> None:
        """Loading a nonexistent algorithms file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            load_algorithms(Path("/nonexistent/algorithms.yaml"))

    def test_missing_libraries_file_raises(self) -> None:
        """Loading a nonexistent libraries file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            load_libraries(Path("/nonexistent/libraries.yaml"))

    def test_invalid_yaml_structure_raises(self, tmp_path: Path) -> None:
        """Loading invalid YAML structure raises ValueError."""
        bad_yaml = tmp_path / "bad.yaml"
        bad_yaml.write_text("just_a_string: true\n")
        with pytest.raises(ValueError):
            load_algorithms(bad_yaml)

    def test_invalid_library_yaml_structure_raises(self, tmp_path: Path) -> None:
        """Loading invalid library YAML structure raises ValueError."""
        bad_yaml = tmp_path / "bad.yaml"
        bad_yaml.write_text("just_a_string: true\n")
        with pytest.raises(ValueError):
            load_libraries(bad_yaml)
