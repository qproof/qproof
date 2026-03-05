"""Tests for the dependency scanner (QP-004)."""

from pathlib import Path

from qproof.scanner.deps import (
    _parse_build_gradle,
    _parse_cargo_toml,
    _parse_go_mod,
    _parse_package_json,
    _parse_pipfile,
    _parse_pom_xml,
    _parse_pyproject_toml,
    _parse_requirements_txt,
    scan_dependencies,
)

# ---------------------------------------------------------------------------
# Parser unit tests
# ---------------------------------------------------------------------------


class TestParseRequirementsTxt:
    """Tests for requirements.txt parsing."""

    def test_basic_packages(self) -> None:
        """Extracts packages with version specifiers."""
        content = "cryptography==42.0.0\nrequests>=2.31\nflask\n"
        result = _parse_requirements_txt(content)
        names = [pkg for pkg, _line in result]
        assert "cryptography" in names
        assert "requests" in names
        assert "flask" in names

    def test_line_numbers(self) -> None:
        """Returns correct 1-based line numbers."""
        content = "cryptography==42.0.0\nrequests>=2.31\n"
        result = _parse_requirements_txt(content)
        assert result[0] == ("cryptography", 1)
        assert result[1] == ("requests", 2)

    def test_comments_and_blanks_skipped(self) -> None:
        """Comments and blank lines are ignored."""
        content = "# comment\n\ncryptography==42.0\n  # another\n"
        result = _parse_requirements_txt(content)
        assert len(result) == 1
        assert result[0][0] == "cryptography"

    def test_dash_flags_skipped(self) -> None:
        """Lines starting with - (like -r, -e) are skipped."""
        content = "-r base.txt\n-e .\ncryptography\n"
        result = _parse_requirements_txt(content)
        assert len(result) == 1

    def test_inline_comment(self) -> None:
        """Inline comments are stripped."""
        content = "cryptography>=42.0 # security\n"
        result = _parse_requirements_txt(content)
        assert result[0][0] == "cryptography"

    def test_extras_bracket(self) -> None:
        """Package with extras bracket is handled."""
        content = "bcrypt[speedup]>=4.0\n"
        result = _parse_requirements_txt(content)
        assert result[0][0] == "bcrypt"

    def test_tilde_specifier(self) -> None:
        """Tilde version specifier is split correctly."""
        content = "pycryptodome~=3.20\n"
        result = _parse_requirements_txt(content)
        assert result[0][0] == "pycryptodome"

    def test_empty_file(self) -> None:
        """Empty file returns no packages."""
        assert _parse_requirements_txt("") == []


class TestParsePipfile:
    """Tests for Pipfile parsing."""

    def test_packages_section(self) -> None:
        """Extracts packages from [packages] section."""
        content = (
            "[packages]\n"
            'cryptography = ">=42.0"\n'
            'requests = "*"\n'
            "\n"
            "[dev-packages]\n"
            'pytest = ">=7.0"\n'
        )
        result = _parse_pipfile(content)
        names = [pkg for pkg, _line in result]
        assert "cryptography" in names
        assert "requests" in names
        assert "pytest" in names

    def test_ignores_other_sections(self) -> None:
        """Packages from non-dependency sections are ignored."""
        content = (
            "[source]\n"
            'url = "https://pypi.org/simple"\n'
            "\n"
            "[packages]\n"
            'cryptography = "*"\n'
        )
        result = _parse_pipfile(content)
        names = [pkg for pkg, _line in result]
        assert "url" not in names
        assert "cryptography" in names

    def test_empty_file(self) -> None:
        """Empty Pipfile returns nothing."""
        assert _parse_pipfile("") == []


class TestParsePyprojectToml:
    """Tests for pyproject.toml parsing."""

    def test_project_dependencies(self) -> None:
        """Extracts from [project] dependencies list."""
        content = (
            "[project]\n"
            "name = 'myapp'\n"
            "dependencies = [\n"
            '    "cryptography>=42.0",\n'
            '    "requests>=2.31",\n'
            "]\n"
        )
        result = _parse_pyproject_toml(content)
        names = [pkg for pkg, _line in result]
        assert "cryptography" in names
        assert "requests" in names

    def test_poetry_dependencies(self) -> None:
        """Extracts from [tool.poetry.dependencies]."""
        content = (
            "[tool.poetry.dependencies]\n"
            "python = \"^3.10\"\n"
            "cryptography = \"^42.0\"\n"
        )
        result = _parse_pyproject_toml(content)
        names = [pkg for pkg, _line in result]
        assert "cryptography" in names
        # python should be excluded
        assert "python" not in names

    def test_empty(self) -> None:
        """Empty file returns nothing."""
        assert _parse_pyproject_toml("") == []


class TestParsePackageJson:
    """Tests for package.json parsing."""

    def test_dependencies_and_devdependencies(self) -> None:
        """Extracts from both dependencies and devDependencies."""
        content = '{"dependencies":{"jsonwebtoken":"^9.0"},"devDependencies":{"jest":"^29"}}'
        result = _parse_package_json(content)
        names = [pkg for pkg, _line in result]
        assert "jsonwebtoken" in names
        assert "jest" in names

    def test_line_numbers(self) -> None:
        """Returns correct line numbers for packages."""
        content = (
            '{\n'
            '  "dependencies": {\n'
            '    "jsonwebtoken": "^9.0"\n'
            '  }\n'
            '}\n'
        )
        result = _parse_package_json(content)
        assert result[0] == ("jsonwebtoken", 3)

    def test_invalid_json(self) -> None:
        """Invalid JSON returns empty list."""
        assert _parse_package_json("{invalid") == []

    def test_no_dependencies(self) -> None:
        """package.json without dependency keys returns nothing."""
        assert _parse_package_json('{"name":"foo"}') == []

    def test_empty(self) -> None:
        """Empty string returns nothing."""
        assert _parse_package_json("") == []


class TestParseGoMod:
    """Tests for go.mod parsing."""

    def test_require_block(self) -> None:
        """Extracts modules from require ( ... ) block."""
        content = (
            "module example.com/myapp\n"
            "\n"
            "go 1.21\n"
            "\n"
            "require (\n"
            "\tgolang.org/x/crypto v0.17.0\n"
            "\tgithub.com/gin-gonic/gin v1.9.0\n"
            ")\n"
        )
        result = _parse_go_mod(content)
        names = [pkg for pkg, _line in result]
        assert "crypto" in names
        assert "gin" in names

    def test_single_line_require(self) -> None:
        """Extracts from single-line require statement."""
        content = "require golang.org/x/crypto v0.17.0\n"
        result = _parse_go_mod(content)
        names = [pkg for pkg, _line in result]
        assert "crypto" in names

    def test_empty(self) -> None:
        """Empty file returns nothing."""
        assert _parse_go_mod("") == []


class TestParseCargoToml:
    """Tests for Cargo.toml parsing."""

    def test_dependencies_section(self) -> None:
        """Extracts crates from [dependencies]."""
        content = (
            "[package]\n"
            'name = "myapp"\n'
            "\n"
            "[dependencies]\n"
            'ring = "0.17"\n'
            'serde = { version = "1.0", features = ["derive"] }\n'
        )
        result = _parse_cargo_toml(content)
        names = [pkg for pkg, _line in result]
        assert "ring" in names
        assert "serde" in names

    def test_dev_dependencies(self) -> None:
        """Extracts from [dev-dependencies]."""
        content = "[dev-dependencies]\ntokio = \"1.0\"\n"
        result = _parse_cargo_toml(content)
        names = [pkg for pkg, _line in result]
        assert "tokio" in names

    def test_stops_at_non_dep_section(self) -> None:
        """Stops extracting when a non-dependency section is reached."""
        content = (
            "[dependencies]\n"
            'ring = "0.17"\n'
            "\n"
            "[profile.release]\n"
            "opt-level = 3\n"
        )
        result = _parse_cargo_toml(content)
        names = [pkg for pkg, _line in result]
        assert "ring" in names
        assert "opt-level" not in names

    def test_empty(self) -> None:
        """Empty file returns nothing."""
        assert _parse_cargo_toml("") == []


class TestParsePomXml:
    """Tests for pom.xml parsing."""

    def test_extracts_artifact_ids(self) -> None:
        """Extracts artifactId values."""
        content = (
            "<dependency>\n"
            "  <groupId>org.bouncycastle</groupId>\n"
            "  <artifactId>bcprov-jdk18on</artifactId>\n"
            "  <version>1.77</version>\n"
            "</dependency>\n"
        )
        result = _parse_pom_xml(content)
        names = [pkg for pkg, _line in result]
        assert "bcprov-jdk18on" in names

    def test_line_number(self) -> None:
        """Returns correct line number for artifactId."""
        content = "<dependency>\n<artifactId>bcprov</artifactId>\n</dependency>\n"
        result = _parse_pom_xml(content)
        assert result[0] == ("bcprov", 2)

    def test_empty(self) -> None:
        """Empty file returns nothing."""
        assert _parse_pom_xml("") == []


class TestParseBuildGradle:
    """Tests for build.gradle parsing."""

    def test_implementation_dependency(self) -> None:
        """Extracts artifact from implementation declaration."""
        content = "implementation 'org.bouncycastle:bcprov-jdk18on:1.77'\n"
        result = _parse_build_gradle(content)
        names = [pkg for pkg, _line in result]
        assert "bcprov-jdk18on" in names

    def test_double_quoted(self) -> None:
        """Handles double-quoted dependencies."""
        content = 'compile "org.bouncycastle:bcprov-jdk18on:1.77"\n'
        result = _parse_build_gradle(content)
        names = [pkg for pkg, _line in result]
        assert "bcprov-jdk18on" in names

    def test_empty(self) -> None:
        """Empty file returns nothing."""
        assert _parse_build_gradle("") == []


# ---------------------------------------------------------------------------
# Integration tests: scan_dependencies on real fixture
# ---------------------------------------------------------------------------


class TestScanDependenciesFixture:
    """Integration tests using the sample_project fixture."""

    FIXTURE_DIR = Path(__file__).parent / "fixtures" / "sample_project"

    def test_finds_python_dependencies(self) -> None:
        """Detects crypto libraries in requirements.txt."""
        findings = scan_dependencies(self.FIXTURE_DIR)
        # requirements.txt has cryptography and pycryptodome
        crypto_findings = [f for f in findings if f.matched_text == "cryptography"]
        assert len(crypto_findings) > 0
        pycryptodome_findings = [f for f in findings if f.matched_text == "pycryptodome"]
        assert len(pycryptodome_findings) > 0

    def test_finds_npm_dependencies(self) -> None:
        """Detects crypto libraries in package.json."""
        findings = scan_dependencies(self.FIXTURE_DIR)
        jwt_findings = [f for f in findings if f.matched_text == "jsonwebtoken"]
        assert len(jwt_findings) > 0

    def test_all_findings_are_dependency_source(self) -> None:
        """All findings from dep scanner have source='dependency'."""
        findings = scan_dependencies(self.FIXTURE_DIR)
        for f in findings:
            assert f.source == "dependency"

    def test_findings_have_algorithm_ids(self) -> None:
        """Each finding has a non-empty algorithm_id."""
        findings = scan_dependencies(self.FIXTURE_DIR)
        for f in findings:
            assert f.algorithm_id, f"Finding for {f.matched_text} has empty algorithm_id"

    def test_findings_have_context(self) -> None:
        """Each finding has a context (library description)."""
        findings = scan_dependencies(self.FIXTURE_DIR)
        for f in findings:
            assert f.context, f"Finding for {f.matched_text} has empty context"

    def test_cryptography_exposes_rsa(self) -> None:
        """cryptography library should produce a finding for RSA."""
        findings = scan_dependencies(self.FIXTURE_DIR)
        rsa_from_crypto = [
            f for f in findings
            if f.matched_text == "cryptography" and f.algorithm_id == "RSA"
        ]
        assert len(rsa_from_crypto) == 1

    def test_line_numbers_present(self) -> None:
        """Findings from requirements.txt should have line numbers."""
        findings = scan_dependencies(self.FIXTURE_DIR)
        req_findings = [f for f in findings if f.file_path.name == "requirements.txt"]
        for f in req_findings:
            assert f.line_number is not None, f"Missing line number for {f.matched_text}"


class TestScanDependenciesEdgeCases:
    """Edge case tests for scan_dependencies."""

    def test_nonexistent_directory(self) -> None:
        """Non-existent directory returns empty list."""
        result = scan_dependencies(Path("/nonexistent/path"))
        assert result == []

    def test_empty_directory(self, tmp_path: Path) -> None:
        """Empty directory returns empty list."""
        result = scan_dependencies(tmp_path)
        assert result == []

    def test_file_instead_of_directory(self, tmp_path: Path) -> None:
        """Passing a file path returns empty list."""
        f = tmp_path / "file.txt"
        f.write_text("hello")
        result = scan_dependencies(f)
        assert result == []

    def test_requirements_with_no_crypto_libs(self, tmp_path: Path) -> None:
        """requirements.txt without crypto libs yields no findings."""
        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.31\nflask==3.0\n")
        result = scan_dependencies(tmp_path)
        assert result == []

    def test_package_json_with_crypto_lib(self, tmp_path: Path) -> None:
        """package.json with a known crypto library produces findings."""
        pkg = tmp_path / "package.json"
        pkg.write_text('{"dependencies":{"jsonwebtoken":"^9.0"}}')
        result = scan_dependencies(tmp_path)
        assert len(result) > 0
        assert all(f.matched_text == "jsonwebtoken" for f in result)
        assert all(f.source == "dependency" for f in result)

    def test_excluded_directories_skipped(self, tmp_path: Path) -> None:
        """Dependency files inside excluded dirs (node_modules) are skipped."""
        nm = tmp_path / "node_modules"
        nm.mkdir()
        req = nm / "requirements.txt"
        req.write_text("cryptography==42.0\n")
        result = scan_dependencies(tmp_path)
        assert result == []

    def test_dedup_same_file_line_algo(self, tmp_path: Path) -> None:
        """No duplicate findings for same file + line + algorithm."""
        req = tmp_path / "requirements.txt"
        req.write_text("cryptography==42.0\n")
        result = scan_dependencies(tmp_path)
        keys = [(str(f.file_path), f.line_number, f.algorithm_id) for f in result]
        assert len(keys) == len(set(keys))

    def test_pipfile_scanning(self, tmp_path: Path) -> None:
        """Pipfile with crypto library produces findings."""
        pf = tmp_path / "Pipfile"
        pf.write_text('[packages]\ncryptography = ">=42.0"\n')
        result = scan_dependencies(tmp_path)
        assert len(result) > 0
        assert result[0].matched_text == "cryptography"

    def test_cargo_toml_scanning(self, tmp_path: Path) -> None:
        """Cargo.toml is parsed (no matching libs in DB means no findings)."""
        cargo = tmp_path / "Cargo.toml"
        cargo.write_text('[dependencies]\nserde = "1.0"\n')
        result = scan_dependencies(tmp_path)
        # serde is not a crypto lib, so no findings expected
        assert result == []

    def test_unreadable_file_no_crash(self, tmp_path: Path) -> None:
        """Unreadable file doesn't cause a crash."""
        req = tmp_path / "requirements.txt"
        req.write_text("cryptography==42.0\n")
        req.chmod(0o000)
        try:
            result = scan_dependencies(tmp_path)
            # May return empty or findings depending on platform permissions
            assert isinstance(result, list)
        finally:
            req.chmod(0o644)
