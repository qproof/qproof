"""Tests for the source code regex scanner (QP-003)."""

from __future__ import annotations

from pathlib import Path

from qproof.models import AlgorithmInfo, Finding, QuantumRisk
from qproof.scanner.source import (
    _CompiledPattern,
    _is_binary,
    _read_file_lines,
    compile_patterns,
    scan_file,
    scan_source_files,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).parent / "fixtures"
SAMPLE_PROJECT = FIXTURES_DIR / "sample_project"


def _make_algo(
    algo_id: str,
    patterns: list[str],
    risk: QuantumRisk = QuantumRisk.VULNERABLE,
) -> AlgorithmInfo:
    """Create a minimal AlgorithmInfo for testing."""
    return AlgorithmInfo(
        id=algo_id,
        name=algo_id,
        type="symmetric",
        quantum_risk=risk,
        reason="test",
        replacement="test",
        patterns=patterns,
    )


def _write_file(tmp_path: Path, name: str, content: str) -> Path:
    """Write a temporary source file and return its path."""
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Pattern compilation
# ---------------------------------------------------------------------------


class TestCompilePatterns:
    """Tests for compile_patterns and boundary logic."""

    def test_loads_from_real_db(self) -> None:
        """compile_patterns with no args loads the real algorithm database."""
        compiled = compile_patterns()
        assert len(compiled) > 0
        algo_ids = {cp.algorithm_id for cp in compiled}
        assert "RSA" in algo_ids
        assert "SHA-256" in algo_ids

    def test_custom_algorithms(self) -> None:
        """compile_patterns accepts a custom algorithm dict."""
        db = {"TEST": _make_algo("TEST", ["test_pattern"])}
        compiled = compile_patterns(db)
        assert len(compiled) == 1
        assert compiled[0].algorithm_id == "TEST"

    def test_malformed_regex_skipped(self) -> None:
        """Malformed regex patterns are silently skipped."""
        # "[invalid" without .* metachar gets re.escaped, so it compiles fine.
        # Use a pattern with .* to bypass escaping — triggers real re.error.
        db = {"BAD": _make_algo("BAD", ["(?P<open"])}
        compiled = compile_patterns(db)
        assert len(compiled) == 0


# ---------------------------------------------------------------------------
# Smart word boundaries (short patterns)
# ---------------------------------------------------------------------------


class TestSmartBoundaries:
    """Short patterns must NOT match inside common words."""

    def _match(self, pattern: str, text: str) -> bool:
        """Compile a single pattern and test if it matches text."""
        db = {"X": _make_algo("X", [pattern])}
        compiled = compile_patterns(db)
        assert len(compiled) == 1
        return compiled[0].regex.search(text) is not None

    # --- RSA ---
    def test_rsa_standalone(self) -> None:
        assert self._match("RSA", "RSA key generation")

    def test_rsa_in_function(self) -> None:
        assert self._match("RSA", "use RSA_OAEP for encryption")

    def test_rsa_not_in_word(self) -> None:
        # Should not match inside longer alphanumeric tokens
        # But RSA is a short pattern with smart boundaries, so
        # "RSA" won't match inside "xRSAy" due to lookbehind/lookahead
        assert not self._match("RSA", "0RSA1")

    # --- DES ---
    def test_des_standalone(self) -> None:
        # DES is in the DB as DES_MODE, DES_CBC, etc. — not bare "DES".
        # But let's test the boundary logic on a hypothetical bare pattern.
        assert self._match("DES", "uses DES encryption")

    def test_des_not_in_description(self) -> None:
        assert not self._match("DES", "description of the project")

    def test_des_not_in_desktop(self) -> None:
        assert not self._match("DES", "run on desktop")

    def test_des_not_in_design(self) -> None:
        assert not self._match("DES", "software design document")

    def test_des_not_in_desire(self) -> None:
        assert not self._match("DES", "desire for speed")

    def test_des_not_in_deserialized(self) -> None:
        assert not self._match("DES", "deserialized object")

    # --- DH ---
    def test_dh_not_in_dhtml(self) -> None:
        assert not self._match("DH", "DHTML page")

    # --- RC4 ---
    def test_rc4_standalone(self) -> None:
        assert self._match("RC4", "RC4 cipher")

    def test_rc4_not_in_src4(self) -> None:
        assert not self._match("RC4", "SRC4 variable")

    # --- MD5 ---
    def test_md5_standalone(self) -> None:
        assert self._match("MD5", "MD5 hash")

    def test_md5_not_in_cmd5(self) -> None:
        assert not self._match("MD5", "CMD5something")


# ---------------------------------------------------------------------------
# Version / separator flexibility
# ---------------------------------------------------------------------------


class TestFlexibleSeparators:
    """Patterns with hyphens/underscores match flexible separators."""

    def _match(self, pattern: str, text: str) -> bool:
        db = {"X": _make_algo("X", [pattern])}
        compiled = compile_patterns(db)
        return compiled[0].regex.search(text) is not None

    def test_sha_256_hyphen(self) -> None:
        assert self._match("SHA-256", "SHA-256 hash")

    def test_sha_256_underscore(self) -> None:
        assert self._match("SHA-256", "SHA_256 hash")

    def test_sha_256_no_separator(self) -> None:
        assert self._match("SHA-256", "SHA256 hash")

    def test_sha_256_space(self) -> None:
        assert self._match("SHA-256", "SHA 256 hash")

    def test_aes_128_cbc_hyphen(self) -> None:
        assert self._match("AES-128-CBC", "aes-128-cbc mode")

    def test_aes_128_cbc_underscore(self) -> None:
        assert self._match("AES-128-CBC", "AES_128_CBC mode")


# ---------------------------------------------------------------------------
# Binary file detection
# ---------------------------------------------------------------------------


class TestBinaryDetection:
    def test_text_not_binary(self) -> None:
        assert not _is_binary(b"hello world\n")

    def test_binary_with_null(self) -> None:
        assert _is_binary(b"hello\x00world")

    def test_empty_not_binary(self) -> None:
        assert not _is_binary(b"")


# ---------------------------------------------------------------------------
# File reading
# ---------------------------------------------------------------------------


class TestReadFileLines:
    def test_reads_utf8(self, tmp_path: Path) -> None:
        p = _write_file(tmp_path, "test.py", "line1\nline2\n")
        lines = _read_file_lines(p)
        assert lines is not None
        assert lines == ["line1", "line2"]

    def test_skips_binary(self, tmp_path: Path) -> None:
        p = tmp_path / "binary.py"
        p.write_bytes(b"header\x00\x01\x02binary data")
        assert _read_file_lines(p) is None

    def test_nonexistent_returns_none(self, tmp_path: Path) -> None:
        p = tmp_path / "nope.py"
        assert _read_file_lines(p) is None

    def test_utf8_replace_mode(self, tmp_path: Path) -> None:
        """Files with invalid UTF-8 are read with replacement characters."""
        p = tmp_path / "bad.py"
        p.write_bytes(b"RSA key \xff\xfe generation\n")
        lines = _read_file_lines(p)
        assert lines is not None
        assert len(lines) >= 1


# ---------------------------------------------------------------------------
# Single file scanning
# ---------------------------------------------------------------------------


class TestScanFile:
    def _patterns(self) -> list[_CompiledPattern]:
        db = {
            "RSA": _make_algo("RSA", ["RSA"]),
            "SHA-256": _make_algo("SHA-256", ["SHA-256", "SHA256", "sha256"]),
        }
        return compile_patterns(db)

    def test_finds_rsa(self, tmp_path: Path) -> None:
        p = _write_file(tmp_path, "crypto.py", "key = RSA.generate(2048)\n")
        findings = scan_file(p, self._patterns())
        algo_ids = [f.algorithm_id for f in findings]
        assert "RSA" in algo_ids

    def test_finds_sha256(self, tmp_path: Path) -> None:
        p = _write_file(tmp_path, "hash.py", "h = hashlib.sha256(data)\n")
        findings = scan_file(p, self._patterns())
        algo_ids = [f.algorithm_id for f in findings]
        assert "SHA-256" in algo_ids

    def test_dedup_same_line_same_algo(self, tmp_path: Path) -> None:
        """Multiple pattern matches for same algo on same line => 1 finding."""
        # "SHA256" and "sha256" both match the SHA-256 algo.
        p = _write_file(tmp_path, "dup.py", "use SHA256 or sha256\n")
        findings = scan_file(p, self._patterns())
        sha_findings = [f for f in findings if f.algorithm_id == "SHA-256"]
        assert len(sha_findings) == 1

    def test_different_algos_same_line(self, tmp_path: Path) -> None:
        """Different algos on the same line produce separate findings."""
        p = _write_file(tmp_path, "multi.py", "RSA key with SHA256 hash\n")
        findings = scan_file(p, self._patterns())
        algo_ids = {f.algorithm_id for f in findings}
        assert "RSA" in algo_ids
        assert "SHA-256" in algo_ids

    def test_finding_fields(self, tmp_path: Path) -> None:
        """Verify all Finding fields are populated correctly."""
        p = _write_file(tmp_path, "check.py", "  key = RSA.generate(2048)\n")
        findings = scan_file(p, self._patterns())
        rsa = [f for f in findings if f.algorithm_id == "RSA"][0]
        assert rsa.file_path == p
        assert rsa.line_number == 1
        assert rsa.matched_text == "RSA"
        assert rsa.source == "source_code"
        assert rsa.context == "key = RSA.generate(2048)"

    def test_empty_file(self, tmp_path: Path) -> None:
        p = _write_file(tmp_path, "empty.py", "")
        findings = scan_file(p, self._patterns())
        assert findings == []

    def test_no_matches(self, tmp_path: Path) -> None:
        p = _write_file(tmp_path, "clean.py", "x = 1 + 2\n")
        findings = scan_file(p, self._patterns())
        assert findings == []


# ---------------------------------------------------------------------------
# Directory scanning
# ---------------------------------------------------------------------------


class TestScanSourceFiles:
    def test_scans_sample_project(self) -> None:
        """Scan the sample_project fixture and find known crypto usage."""
        findings = scan_source_files(SAMPLE_PROJECT)
        algo_ids = {f.algorithm_id for f in findings}
        # app.py uses sha256, sha1; index.ts uses sha256, aes-128-cbc, rsa
        assert "SHA-256" in algo_ids
        assert "SHA-1" in algo_ids
        assert "RSA" in algo_ids

    def test_sorted_output(self) -> None:
        """Findings are sorted by (file_path, line_number)."""
        findings = scan_source_files(SAMPLE_PROJECT)
        pairs = [(str(f.file_path), f.line_number or 0) for f in findings]
        assert pairs == sorted(pairs)

    def test_nonexistent_dir(self) -> None:
        """Non-existent directory returns empty list."""
        findings = scan_source_files(Path("/tmp/qproof_nonexistent_dir"))
        assert findings == []

    def test_empty_project(self) -> None:
        """Empty project directory returns empty list."""
        empty = FIXTURES_DIR / "empty_project"
        findings = scan_source_files(empty)
        assert findings == []

    def test_custom_algorithms(self, tmp_path: Path) -> None:
        """Passing a custom algorithm DB limits detection to those algos."""
        src = tmp_path / "code.py"
        src.write_text("use RSA and SHA256\n", encoding="utf-8")
        db = {"CUSTOM": _make_algo("CUSTOM", ["RSA"])}
        findings = scan_source_files(tmp_path, algorithms=db)
        assert len(findings) == 1
        assert findings[0].algorithm_id == "CUSTOM"

    def test_skips_node_modules(self) -> None:
        """Files inside node_modules are not scanned."""
        findings = scan_source_files(SAMPLE_PROJECT)
        for f in findings:
            assert "node_modules" not in str(f.file_path)


# ---------------------------------------------------------------------------
# False positive tests
# ---------------------------------------------------------------------------


class TestFalsePositives:
    """Ensure common English words do not produce false positives."""

    def _scan_text(self, text: str) -> list[Finding]:
        """Helper: write text to a temp-like in-memory approach via scan_file."""
        import tempfile

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as f:
            f.write(text)
            p = Path(f.name)
        try:
            compiled = compile_patterns()
            return scan_file(p, compiled)
        finally:
            p.unlink(missing_ok=True)

    def test_description_no_des(self) -> None:
        findings = self._scan_text("This is a description of the system.\n")
        algo_ids = {f.algorithm_id for f in findings}
        assert "DES" not in algo_ids

    def test_desktop_no_des(self) -> None:
        findings = self._scan_text("Running on a desktop environment.\n")
        algo_ids = {f.algorithm_id for f in findings}
        assert "DES" not in algo_ids

    def test_archive_no_rc4(self) -> None:
        findings = self._scan_text("Extract the archive file.\n")
        algo_ids = {f.algorithm_id for f in findings}
        assert "RC4" not in algo_ids

    def test_address_no_rsa(self) -> None:
        """'address' should not match RSA (no RSA substring anyway)."""
        findings = self._scan_text("The email address is foo@bar.com\n")
        algo_ids = {f.algorithm_id for f in findings}
        assert "RSA" not in algo_ids

    def test_case_insensitive_match(self) -> None:
        """Patterns match case-insensitively."""
        findings = self._scan_text("using rsa_generate for keys\n")
        algo_ids = {f.algorithm_id for f in findings}
        assert "RSA" in algo_ids
