"""End-to-end integration tests for qproof."""

import json
import subprocess
import sys
from pathlib import Path

from qproof.classifier.quantum_risk import classify
from qproof.data.loader import load_algorithms
from qproof.models import QuantumRisk, ScanResult
from qproof.output.json_out import render_json
from qproof.output.text import render_text
from qproof.scanner.deps import scan_dependencies
from qproof.scanner.source import compile_patterns, scan_source_files

FIXTURES = Path(__file__).parent / "fixtures" / "sample_project"


class TestFullPipeline:
    """Test the complete scan -> classify -> render pipeline."""

    def test_pipeline_produces_findings(self) -> None:
        """Scan fixtures should produce results."""
        source_findings = scan_source_files(FIXTURES)
        deps_findings = scan_dependencies(FIXTURES)
        all_findings = source_findings + deps_findings
        assert len(all_findings) > 0

    def test_pipeline_classifies_all_findings(self) -> None:
        """All findings should be classified."""
        source_findings = scan_source_files(FIXTURES)
        deps_findings = scan_dependencies(FIXTURES)
        all_findings = source_findings + deps_findings
        classified = classify(all_findings)
        assert len(classified) == len(all_findings)

    def test_pipeline_finds_vulnerable(self) -> None:
        """Should find VULNERABLE crypto in fixtures."""
        source_findings = scan_source_files(FIXTURES)
        deps_findings = scan_dependencies(FIXTURES)
        classified = classify(source_findings + deps_findings)
        vulnerable = [c for c in classified if c.quantum_risk == QuantumRisk.VULNERABLE]
        assert len(vulnerable) > 0

    def test_pipeline_finds_safe(self) -> None:
        """Should find SAFE crypto in fixtures."""
        source_findings = scan_source_files(FIXTURES)
        deps_findings = scan_dependencies(FIXTURES)
        classified = classify(source_findings + deps_findings)
        safe = [c for c in classified if c.quantum_risk == QuantumRisk.SAFE]
        assert len(safe) > 0

    def test_pipeline_json_output_is_valid(self) -> None:
        """JSON output should be valid and contain expected fields."""
        source_findings = scan_source_files(FIXTURES)
        deps_findings = scan_dependencies(FIXTURES)
        classified = classify(source_findings + deps_findings)
        result = ScanResult(
            path=FIXTURES,
            findings=classified,
            total_files_scanned=3,
            scan_duration_seconds=0.01,
        )
        json_str = render_json(result)
        data = json.loads(json_str)
        assert "version" in data
        assert "summary" in data
        assert "findings" in data
        assert data["summary"]["total_findings"] == len(classified)

    def test_pipeline_text_output_not_empty(self) -> None:
        """Text output should contain meaningful content."""
        source_findings = scan_source_files(FIXTURES)
        classified = classify(source_findings)
        result = ScanResult(
            path=FIXTURES,
            findings=classified,
            total_files_scanned=3,
            scan_duration_seconds=0.01,
        )
        text = render_text(result)
        assert "qproof" in text
        assert "Quantum" in text or "VULNERABLE" in text or "SAFE" in text

    def test_quantum_ready_score_in_range(self) -> None:
        """Quantum-ready score should be between 0 and 100."""
        source_findings = scan_source_files(FIXTURES)
        deps_findings = scan_dependencies(FIXTURES)
        classified = classify(source_findings + deps_findings)
        result = ScanResult(
            path=FIXTURES,
            findings=classified,
            total_files_scanned=3,
            scan_duration_seconds=0.01,
        )
        assert 0.0 <= result.quantum_ready_score <= 100.0


class TestCLIIntegration:
    """Test the CLI as a subprocess — like a real user."""

    def test_cli_scan_text_output(self) -> None:
        """CLI text output should contain risk levels."""
        result = subprocess.run(
            [sys.executable, "-m", "qproof", "scan", str(FIXTURES)],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0
        has_risk = "VULNERABLE" in result.stdout or "SAFE" in result.stdout
        assert has_risk or "PARTIAL" in result.stdout

    def test_cli_scan_json_output(self) -> None:
        """CLI JSON output should be valid JSON with findings."""
        result = subprocess.run(
            [sys.executable, "-m", "qproof", "scan", str(FIXTURES), "--format", "json"],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert "findings" in data
        assert len(data["findings"]) > 0

    def test_cli_scan_json_to_file(self, tmp_path: Path) -> None:
        """CLI should write JSON report to file."""
        out_file = tmp_path / "report.json"
        result = subprocess.run(
            [sys.executable, "-m", "qproof", "scan", str(FIXTURES),
             "--format", "json", "--output", str(out_file)],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0
        assert out_file.exists()
        data = json.loads(out_file.read_text())
        assert "findings" in data

    def test_cli_scan_empty_dir(self, tmp_path: Path) -> None:
        """Scanning an empty directory should not crash."""
        result = subprocess.run(
            [sys.executable, "-m", "qproof", "scan", str(tmp_path)],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0

    def test_cli_version(self) -> None:
        """CLI --version should print the version."""
        result = subprocess.run(
            [sys.executable, "-m", "qproof", "--version"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0
        assert "0.1.0" in result.stdout

    def test_cli_scan_nonexistent_path(self) -> None:
        """CLI with nonexistent path should fail gracefully."""
        result = subprocess.run(
            [sys.executable, "-m", "qproof", "scan", "/nonexistent/path/xyz"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode != 0


class TestDatabaseIntegrity:
    """Verify database consistency end-to-end."""

    def test_all_algorithms_have_compilable_patterns(self) -> None:
        """Every algorithm should have at least one pattern that compiles."""
        db = load_algorithms()
        compiled = compile_patterns(db)
        algo_ids_with_patterns = {cp.algorithm_id for cp in compiled}
        for algo_id in db:
            assert algo_id in algo_ids_with_patterns, (
                f"{algo_id} has no compilable patterns"
            )

    def test_findings_reference_real_algorithms(self) -> None:
        """All findings from the scanner should reference known algorithms."""
        db = load_algorithms()
        source_findings = scan_source_files(FIXTURES)
        for f in source_findings:
            assert f.algorithm_id in db, (
                f"Finding references unknown algorithm: {f.algorithm_id}"
            )
