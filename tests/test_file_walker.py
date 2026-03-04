"""Tests for the file walker utility."""

from pathlib import Path

from qproof.utils.file_walker import walk_files


def test_walk_excludes_node_modules(sample_project: Path) -> None:
    """Files inside node_modules are excluded."""
    files = walk_files(sample_project)
    for f in files:
        assert "node_modules" not in f.parts


def test_walk_includes_python_files(sample_project: Path) -> None:
    """Python source files are included in results."""
    files = walk_files(sample_project)
    names = [f.name for f in files]
    assert "app.py" in names


def test_walk_includes_typescript_files(sample_project: Path) -> None:
    """TypeScript source files are included in results."""
    files = walk_files(sample_project)
    names = [f.name for f in files]
    assert "index.ts" in names


def test_walk_empty_directory(empty_project: Path) -> None:
    """Walking an empty directory does not crash."""
    files = walk_files(empty_project)
    # .gitkeep has no recognized extension, so list should be empty
    assert isinstance(files, list)


def test_walk_ignores_large_files(tmp_path: Path) -> None:
    """Files larger than MAX_FILE_SIZE are excluded."""
    large_file = tmp_path / "big.py"
    large_file.write_bytes(b"x" * 1_100_000)
    files = walk_files(tmp_path, extensions={".py"})
    assert large_file.resolve() not in files
