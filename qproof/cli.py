"""CLI interface for qproof."""

import json
import sys
import time
from pathlib import Path

import click

from qproof import __version__
from qproof.baseline import diff_findings, generate_baseline, load_baseline
from qproof.classifier.context import enrich_findings
from qproof.classifier.quantum_risk import classify
from qproof.classifier.severity import enrich_severity
from qproof.models import ScanResult
from qproof.output.json_out import render_json
from qproof.output.text import render_text
from qproof.policy import (
    PolicyValidationError,
    apply_severity_overrides,
    check_fail_conditions,
    load_policy,
    load_policy_from_file,
    should_ignore_finding,
    should_ignore_path,
)
from qproof.scanner.config import scan_configs
from qproof.scanner.deps import scan_dependencies
from qproof.scanner.source import scan_source_files
from qproof.utils.file_walker import walk_files


@click.group()
@click.version_option(version=__version__, prog_name="qproof")
def main() -> None:
    """qproof — Find quantum-vulnerable cryptography in your codebase."""


@main.group()
def policy() -> None:
    """Manage qproof policy files."""


@policy.command()
@click.option(
    "--file",
    "policy_file",
    type=click.Path(),
    default="qproof.yml",
    help="Path to qproof.yml policy file.",
)
def validate(policy_file: str) -> None:
    """Validate a qproof.yml policy file."""
    try:
        p = load_policy_from_file(policy_file)
    except (FileNotFoundError, PolicyValidationError) as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(2)

    click.echo(
        f"Policy valid: version={p.version}, "
        f"{len(p.ignore.paths)} ignore paths, "
        f"{len(p.ignore.algorithms)} ignored algorithms, "
        f"{len(p.allow)} allow rules, "
        f"fail on_severity={p.fail.on_severity}, "
        f"{len(p.severity_overrides)} severity overrides"
    )


@main.command()
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json", "sarif", "cbom"]),
    default="text",
    help="Output format.",
)
@click.option("--output", "-o", type=click.Path(), default=None, help="Write output to file.")
@click.option(
    "--baseline",
    type=click.Path(),
    default=None,
    help="Generate baseline snapshot file.",
)
@click.option(
    "--diff",
    "diff_baseline",
    type=click.Path(exists=True),
    default=None,
    help="Compare against baseline file and report only new/worsened findings.",
)
def scan(
    path: str,
    output_format: str,
    output: str | None,
    baseline: str | None,
    diff_baseline: str | None,
) -> None:
    """Scan a directory for quantum-vulnerable cryptography."""
    if baseline and diff_baseline:
        click.echo("Error: --baseline and --diff are mutually exclusive.", err=True)
        sys.exit(2)

    target = Path(path).resolve()
    start = time.monotonic()

    # Load policy if present
    policy_cfg = load_policy(target)
    if policy_cfg:
        click.echo(
            f"Policy loaded: qproof.yml "
            f"({len(policy_cfg.ignore.paths)} ignore paths, "
            f"{len(policy_cfg.allow)} allow rules)",
            err=True,
        )

    # Count files
    files = walk_files(target)
    total_files = len(files)

    # Scan source code, dependencies, and configurations
    source_findings = scan_source_files(target)
    dep_findings = scan_dependencies(target)
    config_findings = scan_configs(target)
    all_findings = source_findings + dep_findings + config_findings

    # Classify findings
    classified = classify(all_findings)

    # Enrich with context and confidence scoring
    enrich_findings(classified)

    # Enrich with severity, category, and remediation
    enrich_severity(classified)

    # Apply policy: severity overrides, then filter
    if policy_cfg:
        apply_severity_overrides(classified, policy_cfg)

        classified = [
            cf for cf in classified
            if not should_ignore_path(str(cf.finding.file_path), policy_cfg)
            and not should_ignore_finding(cf, policy_cfg)
        ]

    duration = time.monotonic() - start

    # Baseline mode: generate snapshot and exit
    if baseline:
        baseline_data = generate_baseline(classified, __version__)
        baseline_path = Path(baseline)
        baseline_path.write_text(
            json.dumps(baseline_data, indent=2) + "\n",
            encoding="utf-8",
        )
        click.echo(
            f"Baseline generated: {baseline_path} "
            f"({baseline_data['findings_count']} findings)",
            err=True,
        )
        sys.exit(0)

    # Diff mode: compare against baseline
    if diff_baseline:
        bl_data = load_baseline(diff_baseline)
        diff_result = diff_findings(classified, bl_data)

        # Summary to stderr
        click.echo(
            f"Diff: {len(diff_result.new)} new, "
            f"{len(diff_result.worsened)} worsened, "
            f"{len(diff_result.resolved)} resolved",
            err=True,
        )

        # Only report new + worsened findings
        diff_findings_list = diff_result.new + diff_result.worsened

        result = ScanResult(
            path=target,
            findings=diff_findings_list,
            total_files_scanned=total_files,
            scan_duration_seconds=round(duration, 2),
        )

        # Render output
        if output_format == "json":
            rendered = render_json(result, diff_result=diff_result)
        elif output_format == "sarif":
            from qproof.output.sarif import findings_to_sarif

            rendered = findings_to_sarif(
                diff_findings_list, str(target), result.scan_duration_seconds,
            )
        elif output_format == "cbom":
            from qproof.output.cbom import findings_to_cbom

            rendered = findings_to_cbom(
                diff_findings_list, str(target), result.scan_duration_seconds,
            )
        else:
            rendered = render_text(result, diff_result=diff_result)

        if output:
            output_path = Path(output)
            output_path.write_text(rendered, encoding="utf-8")
            click.echo(f"Report written to {output_path}")
        else:
            click.echo(rendered)

        # Exit code: policy fail check overrides default diff logic
        if policy_cfg:
            sys.exit(1 if check_fail_conditions(
                diff_findings_list, policy_cfg, is_diff_mode=True,
            ) else 0)
        sys.exit(1 if diff_result.has_new_debt else 0)

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
    elif output_format == "cbom":
        from qproof.output.cbom import findings_to_cbom

        rendered = findings_to_cbom(
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

    # Policy fail check (normal scan mode)
    if policy_cfg and check_fail_conditions(classified, policy_cfg):
        sys.exit(1)
