"""Dependency scanner — detects cryptographic libraries in project dependencies."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from qproof.data.loader import load_libraries
from qproof.models import Finding
from qproof.utils.file_walker import EXCLUDED_DIRS, MAX_FILE_SIZE

# Dependency file names we look for (mapped to parser functions later).
DEPENDENCY_FILENAMES: set[str] = {
    "requirements.txt",
    "Pipfile",
    "pyproject.toml",
    "package.json",
    "go.mod",
    "Cargo.toml",
    "pom.xml",
    "build.gradle",
}

# Version specifier separators for requirements.txt-style files.
_REQ_SPLIT_RE = re.compile(r"[><=!~;@\[]")


def scan_dependencies(root: Path) -> list[Finding]:
    """Scan dependency files for cryptographic library usage.

    Walks the directory tree looking for known dependency file names,
    parses each to extract package names, and matches them against the
    library database to produce findings.

    Args:
        root: Root directory to scan.

    Returns:
        List of findings from dependency analysis. Never raises on
        file errors — returns empty list instead.
    """
    root = root.resolve()
    if not root.is_dir():
        return []

    libraries = _load_library_lookup()
    if not libraries:
        return []

    dep_files = _find_dependency_files(root)
    findings: list[Finding] = []

    for dep_file in dep_files:
        try:
            file_findings = _scan_single_file(dep_file, libraries)
            findings.extend(file_findings)
        except Exception:
            # Never raise on file errors per project convention.
            continue

    return findings


# ---------------------------------------------------------------------------
# Library lookup building
# ---------------------------------------------------------------------------


def _load_library_lookup() -> dict[str, dict[str, Any]]:
    """Build a lookup from package_name to library data.

    Returns:
        Dictionary mapping (lowercase) package_name to library metadata.
        Empty dict if the database cannot be loaded.
    """
    try:
        libs = load_libraries()
    except (FileNotFoundError, ValueError):
        return {}

    lookup: dict[str, dict[str, Any]] = {}
    for _lib_id, data in libs.items():
        pkg_name: str = data["package_name"].lower()
        lookup[pkg_name] = data
    return lookup


# ---------------------------------------------------------------------------
# Dependency file discovery
# ---------------------------------------------------------------------------


def _find_dependency_files(root: Path) -> list[Path]:
    """Find all dependency files under root, respecting exclusion rules.

    Args:
        root: Root directory to search.

    Returns:
        Sorted list of dependency file paths found.
    """
    results: list[Path] = []

    for item in sorted(root.rglob("*")):
        if item.is_symlink():
            continue
        if item.is_dir():
            continue
        if _is_excluded(item, root):
            continue
        if item.name not in DEPENDENCY_FILENAMES:
            continue
        try:
            if item.stat().st_size > MAX_FILE_SIZE:
                continue
        except OSError:
            continue
        results.append(item)

    return results


def _is_excluded(path: Path, root: Path) -> bool:
    """Check if any path component is in the excluded directories set."""
    try:
        rel = path.relative_to(root)
    except ValueError:
        return True
    for part in rel.parts:
        if part in EXCLUDED_DIRS or part.endswith(".egg-info"):
            return True
    return False


# ---------------------------------------------------------------------------
# Single-file scanning
# ---------------------------------------------------------------------------


def _scan_single_file(
    file_path: Path,
    libraries: dict[str, dict[str, Any]],
) -> list[Finding]:
    """Parse one dependency file and match packages against library DB.

    Args:
        file_path: Path to the dependency file.
        libraries: Package-name-to-library lookup.

    Returns:
        List of findings. Empty on any error.
    """
    name = file_path.name

    parsers: dict[str, _ParserFn] = {
        "requirements.txt": _parse_requirements_txt,
        "Pipfile": _parse_pipfile,
        "pyproject.toml": _parse_pyproject_toml,
        "package.json": _parse_package_json,
        "go.mod": _parse_go_mod,
        "Cargo.toml": _parse_cargo_toml,
        "pom.xml": _parse_pom_xml,
        "build.gradle": _parse_build_gradle,
    }

    parser = parsers.get(name)
    if parser is None:
        return []

    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    packages = parser(content)
    return _match_packages(file_path, packages, libraries)


# Type alias for parser functions: content -> list[(package_name, line_number | None)]
_ParserFn = Callable[[str], list[tuple[str, int | None]]]


def _match_packages(
    file_path: Path,
    packages: list[tuple[str, int | None]],
    libraries: dict[str, dict[str, Any]],
) -> list[Finding]:
    """Match extracted package names against the library database.

    For each matched library, creates one Finding per algorithm it exposes.

    Args:
        file_path: The dependency file path.
        packages: List of (package_name, line_number) tuples.
        libraries: Package-name-to-library lookup.

    Returns:
        List of findings.
    """
    findings: list[Finding] = []
    seen: set[tuple[str, int | None, str]] = set()

    for pkg_name, line_number in packages:
        normalized = pkg_name.strip().lower()
        if not normalized:
            continue

        lib_data = libraries.get(normalized)
        if lib_data is None:
            continue

        exposes: list[str] = lib_data.get("exposes", [])
        description: str = lib_data.get("description", "")

        for algo_id in exposes:
            key = (str(file_path), line_number, algo_id)
            if key in seen:
                continue
            seen.add(key)

            findings.append(
                Finding(
                    file_path=file_path,
                    line_number=line_number,
                    matched_text=lib_data.get("package_name", pkg_name),
                    algorithm_id=algo_id,
                    source="dependency",
                    context=description,
                )
            )

    return findings


# ---------------------------------------------------------------------------
# File-type parsers
# ---------------------------------------------------------------------------


def _parse_requirements_txt(content: str) -> list[tuple[str, int | None]]:
    """Parse requirements.txt to extract package names with line numbers.

    Handles formats: ``package==1.0``, ``package>=1.0``, ``package``,
    and ignores comments, blank lines, and ``-r``/``-e`` directives.

    Args:
        content: Full file content.

    Returns:
        List of (package_name, line_number) tuples.
    """
    packages: list[tuple[str, int | None]] = []

    for line_num, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue

        # Strip inline comments
        if " #" in line:
            line = line[: line.index(" #")]

        # Split on version specifiers
        match = _REQ_SPLIT_RE.search(line)
        if match:
            pkg = line[: match.start()].strip()
        else:
            pkg = line.strip()

        # Normalize underscores/hyphens (pip treats them as equivalent)
        if pkg:
            packages.append((pkg, line_num))

    return packages


def _parse_pipfile(content: str) -> list[tuple[str, int | None]]:
    """Parse Pipfile to extract package names from [packages] and [dev-packages].

    Uses a simple line-by-line parser (no TOML dependency required).

    Args:
        content: Full file content.

    Returns:
        List of (package_name, line_number) tuples.
    """
    packages: list[tuple[str, int | None]] = []
    in_packages_section = False

    for line_num, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()

        # Section headers
        if line.startswith("["):
            section = line.lower()
            in_packages_section = section in ("[packages]", "[dev-packages]")
            continue

        if not in_packages_section:
            continue

        if not line or line.startswith("#"):
            continue

        # Pipfile format: package_name = "version"
        if "=" in line:
            pkg = line.split("=", 1)[0].strip().strip('"').strip("'")
            if pkg:
                packages.append((pkg, line_num))

    return packages


def _parse_pyproject_toml(content: str) -> list[tuple[str, int | None]]:
    """Parse pyproject.toml to extract dependency package names.

    Looks for entries in ``dependencies`` and ``optional-dependencies`` lists
    under ``[project]``, as well as ``[tool.poetry.dependencies]``.

    Simple line-based parsing — no TOML library required.

    Args:
        content: Full file content.

    Returns:
        List of (package_name, line_number) tuples.
    """
    packages: list[tuple[str, int | None]] = []
    # Patterns to extract package name from dependency strings like:
    #   "cryptography>=42.0"  or  "requests"  or  'bcrypt[speedup]>=4.0'
    _dep_string_re = re.compile(r"""['"]([A-Za-z0-9_][A-Za-z0-9._-]*)""")

    in_deps = False
    in_poetry_deps = False

    for line_num, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()

        # Detect section headers
        if line.startswith("["):
            section = line.lower()
            in_deps = section in (
                "[project]",
            ) and False  # project section itself isn't deps
            # Direct dependency list sections
            if "dependencies" in section:
                in_deps = True
            if "tool.poetry.dependencies" in section:
                in_poetry_deps = True
                in_deps = False
            elif line.startswith("["):
                in_poetry_deps = "[tool.poetry.dependencies]" in line.lower()
                if not in_poetry_deps and "dependencies" not in section:
                    in_deps = False
            continue

        # In a [project] dependencies = [...] style list
        if "dependencies" in raw_line and "=" in raw_line and not in_poetry_deps:
            in_deps = True
            # Check if the line itself has entries
            m = _dep_string_re.findall(line)
            for pkg in m:
                packages.append((pkg, line_num))
            continue

        if in_deps:
            if not line or line.startswith("#"):
                continue
            if line == "]":
                in_deps = False
                continue
            m = _dep_string_re.findall(line)
            for pkg in m:
                packages.append((pkg, line_num))

        if in_poetry_deps:
            if not line or line.startswith("#"):
                continue
            if line.startswith("[") and "poetry.dependencies" not in line.lower():
                in_poetry_deps = False
                continue
            # Poetry: package_name = "^1.0"
            if "=" in line:
                pkg = line.split("=", 1)[0].strip()
                if pkg and not pkg.startswith("#") and pkg != "python":
                    packages.append((pkg, line_num))

    return packages


def _parse_package_json(content: str) -> list[tuple[str, int | None]]:
    """Parse package.json to extract dependency names with line numbers.

    Uses json.loads for reliable parsing, then scans the raw text for
    line numbers of each dependency name.

    Args:
        content: Full file content.

    Returns:
        List of (package_name, line_number) tuples.
    """
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return []

    if not isinstance(data, dict):
        return []

    packages: list[tuple[str, int | None]] = []
    dep_sections = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]

    lines = content.splitlines()

    for section in dep_sections:
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        for pkg_name in deps:
            line_number = _find_line_number(lines, pkg_name)
            packages.append((pkg_name, line_number))

    return packages


def _find_line_number(lines: list[str], pkg_name: str) -> int | None:
    """Find the line number where a package name appears in file lines.

    Args:
        lines: List of file lines.
        pkg_name: Package name to locate.

    Returns:
        1-based line number, or None if not found.
    """
    needle = f'"{pkg_name}"'
    for idx, line in enumerate(lines):
        if needle in line:
            return idx + 1
    return None


def _parse_go_mod(content: str) -> list[tuple[str, int | None]]:
    """Parse go.mod to extract module paths from require blocks.

    Handles both single-line ``require path v1.0`` and block
    ``require ( ... )`` syntax. Matches the last path segment against
    the library database.

    Args:
        content: Full file content.

    Returns:
        List of (package_name, line_number) tuples. Package name is
        the last segment of the module path (e.g., ``crypto`` from
        ``golang.org/x/crypto``).
    """
    packages: list[tuple[str, int | None]] = []
    in_require = False

    for line_num, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()

        if line.startswith("require ("):
            in_require = True
            continue
        if line == ")" and in_require:
            in_require = False
            continue

        # Single-line require
        if line.startswith("require ") and "(" not in line:
            parts = line.split()
            if len(parts) >= 2:
                module_path = parts[1]
                pkg = module_path.rsplit("/", 1)[-1]
                packages.append((pkg, line_num))
                # Also add the full path for matching
                packages.append((module_path, line_num))
            continue

        if in_require:
            if not line or line.startswith("//"):
                continue
            parts = line.split()
            if len(parts) >= 1:
                module_path = parts[0]
                pkg = module_path.rsplit("/", 1)[-1]
                packages.append((pkg, line_num))
                packages.append((module_path, line_num))

    return packages


def _parse_cargo_toml(content: str) -> list[tuple[str, int | None]]:
    """Parse Cargo.toml to extract crate names from dependency sections.

    Handles ``[dependencies]``, ``[dev-dependencies]``, and
    ``[build-dependencies]`` sections.

    Args:
        content: Full file content.

    Returns:
        List of (package_name, line_number) tuples.
    """
    packages: list[tuple[str, int | None]] = []
    in_deps = False

    for line_num, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()

        if line.startswith("["):
            section = line.lower()
            in_deps = any(
                kw in section
                for kw in ("dependencies]", "dev-dependencies]", "build-dependencies]")
            )
            # Skip compound section headers like [dependencies.serde]
            if in_deps and section.count(".") > 0 and "dependencies]" not in section:
                in_deps = False
            continue

        if not in_deps:
            continue
        if not line or line.startswith("#"):
            continue

        # Format: crate_name = "version" or crate_name = { version = "..." }
        if "=" in line:
            pkg = line.split("=", 1)[0].strip()
            if pkg:
                packages.append((pkg, line_num))

    return packages


def _parse_pom_xml(content: str) -> list[tuple[str, int | None]]:
    """Parse pom.xml to extract Maven artifactIds.

    Simple regex-based extraction — no XML parser needed for this scope.

    Args:
        content: Full file content.

    Returns:
        List of (package_name, line_number) tuples.
    """
    packages: list[tuple[str, int | None]] = []
    artifact_re = re.compile(r"<artifactId>\s*([^<]+?)\s*</artifactId>")

    for line_num, raw_line in enumerate(content.splitlines(), start=1):
        match = artifact_re.search(raw_line)
        if match:
            packages.append((match.group(1), line_num))

    return packages


def _parse_build_gradle(content: str) -> list[tuple[str, int | None]]:
    """Parse build.gradle to extract dependency artifact names.

    Matches common Gradle dependency formats:
    - ``implementation 'group:artifact:version'``
    - ``implementation "group:artifact:version"``
    - ``compile 'group:artifact:version'``

    Args:
        content: Full file content.

    Returns:
        List of (package_name, line_number) tuples.
    """
    packages: list[tuple[str, int | None]] = []
    # Match group:artifact:version in quotes
    dep_re = re.compile(r"""['"]([^'"]+):([^'"]+):([^'"]+)['"]""")

    for line_num, raw_line in enumerate(content.splitlines(), start=1):
        match = dep_re.search(raw_line)
        if match:
            artifact = match.group(2)
            packages.append((artifact, line_num))
            # Also add group:artifact for matching
            group_artifact = f"{match.group(1)}:{match.group(2)}"
            packages.append((group_artifact, line_num))

    return packages
