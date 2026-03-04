"""Tests for the qproof CLI."""

from click.testing import CliRunner

from qproof.cli import main


def test_cli_version() -> None:
    """CLI --version outputs the correct version string."""
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0-dev" in result.output


def test_cli_scan_default() -> None:
    """CLI scan . runs without error."""
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "."])
    assert result.exit_code == 0
    assert "Scanning" in result.output


def test_cli_scan_nonexistent() -> None:
    """CLI scan with nonexistent path fails."""
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "/tmp/nonexistent_qproof_path"])
    assert result.exit_code != 0
