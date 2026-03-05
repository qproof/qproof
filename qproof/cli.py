"""CLI interface for qproof."""

import time
from pathlib import Path

import click

from qproof import __version__
from qproof.classifier.quantum_risk import classify
from qproof.models import ScanResult
from qproof.output.json_out import render_json
from qproof.output.text import render_text
from qproof.scanner.deps import scan_dependencies
from qproof.scanner.source import scan_source_files
from qproof.utils.file_walker import walk_files


@click.group()
@click.version_option(version=__version__, prog_name="qproof")
def main() -> None:
    """qproof — Find quantum-vulnerable cryptography in your codebase."""


@main.command()
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json", "sarif"]),
    default="text",
    help="Output format.",
)
@click.option("--output", "-o", type=click.Path(), default=None, help="Write output to file.")
def scan(path: str, output_format: str, output: str | None) -> None:
    """Scan a directory for quantum-vulnerable cryptography."""
    target = Path(path).resolve()
    start = time.monotonic()

    # Count files
    files = walk_files(target)
    total_files = len(files)

    # Scan source code and dependencies
    source_findings = scan_source_files(target)
    dep_findings = scan_dependencies(target)
    all_findings = source_findings + dep_findings

    # Classify findings
    classified = classify(all_findings)

    duration = time.monotonic() - start

    # Build result
    result = ScanResult(
        path=target,
        findings=classified,
        total_files_scanned=total_files,
        scan_duration_seconds=round(duration, 2),
    )

    # Render output
    if output_format == "json":
        rendered = render_json(result)
    elif output_format == "sarif":
        from qproof.output.sarif import findings_to_sarif

        rendered = findings_to_sarif(
            classified, str(target), result.scan_duration_seconds,
        )
    else:
        rendered = render_text(result)

    # Write or print
    if output:
        output_path = Path(output)
        output_path.write_text(rendered, encoding="utf-8")
        click.echo(f"Report written to {output_path}")
    else:
        click.echo(rendered)
