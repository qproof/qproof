"""File system walker for qproof. Traverses directories finding scannable files."""

from pathlib import Path

EXCLUDED_DIRS: set[str] = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    ".env",
    "dist",
    "build",
    ".next",
    ".nuxt",
    ".svelte-kit",
    ".tox",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    "vendor",
    "target",
    ".cargo",
    ".eggs",
    "*.egg-info",
}

SOURCE_EXTENSIONS: set[str] = {
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".mjs",
    ".cjs",
    ".go",
    ".java",
    ".rs",
    ".rb",
    ".php",
    ".cs",
    ".swift",
}

CONFIG_EXTENSIONS: set[str] = {
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".cfg",
    ".ini",
    ".conf",
    ".env",
    ".sh",
    ".bash",
}

ALL_EXTENSIONS: set[str] = SOURCE_EXTENSIONS | CONFIG_EXTENSIONS

MAX_FILE_SIZE: int = 1_000_000  # 1MB


def walk_files(root: Path, extensions: set[str] | None = None) -> list[Path]:
    """Walk directory tree, returning files relevant for crypto scanning.

    Args:
        root: Root directory to scan.
        extensions: Set of file extensions to include. Defaults to ALL_EXTENSIONS.

    Returns:
        Sorted list of file paths matching the criteria.
    """
    if extensions is None:
        extensions = ALL_EXTENSIONS

    root = root.resolve()
    if not root.is_dir():
        return []

    results: list[Path] = []

    for item in sorted(root.rglob("*")):
        # Skip symlinks
        if item.is_symlink():
            continue

        # Skip directories
        if item.is_dir():
            continue

        # Check if any parent directory is excluded
        if _is_excluded(item, root):
            continue

        # Check extension
        if item.suffix.lower() not in extensions:
            continue

        # Check file size
        try:
            if item.stat().st_size > MAX_FILE_SIZE:
                continue
        except OSError:
            continue

        results.append(item)

    return results


def _is_excluded(path: Path, root: Path) -> bool:
    """Check if any component of the path relative to root is in EXCLUDED_DIRS."""
    try:
        rel = path.relative_to(root)
    except ValueError:
        return True

    for part in rel.parts:
        if part in EXCLUDED_DIRS or part.endswith(".egg-info"):
            return True
    return False
