"""CLI interface for qproof."""

from pathlib import Path

import click

from qproof import __version__


@click.group()
@click.version_option(version=__version__, prog_name="qproof")
def main() -> None:
    """qproof — Find quantum-vulnerable cryptography in your codebase."""


@main.command()
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format.",
)
@click.option("--output", "-o", type=click.Path(), default=None, help="Write output to file.")
def scan(path: str, output_format: str, output: str | None) -> None:
    """Scan a directory for quantum-vulnerable cryptography."""
    target = Path(path).resolve()
    click.echo(f"Scanning {target}...")
    click.echo(f"   Format: {output_format}")
    if output:
        click.echo(f"   Output: {output}")
    click.echo()
    click.echo("Scanner not yet implemented. Coming in QP-002 through QP-007.")
    click.echo("   Install the latest version: pip install --upgrade qproof")
