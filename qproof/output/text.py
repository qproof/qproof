"""Text output renderer for scan results using Rich."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from qproof.models import ClassifiedFinding, QuantumRisk, ScanResult

_RISK_STYLES: dict[QuantumRisk, str] = {
    QuantumRisk.VULNERABLE: "bold red",
    QuantumRisk.PARTIAL: "bold yellow",
    QuantumRisk.SAFE: "bold green",
    QuantumRisk.UNKNOWN: "dim",
}

_RISK_ORDER: list[QuantumRisk] = [
    QuantumRisk.VULNERABLE,
    QuantumRisk.PARTIAL,
    QuantumRisk.SAFE,
    QuantumRisk.UNKNOWN,
]


def _risk_sort_key(finding: ClassifiedFinding) -> int:
    """Return sort index so VULNERABLE appears first."""
    try:
        return _RISK_ORDER.index(finding.quantum_risk)
    except ValueError:
        return len(_RISK_ORDER)


def _format_file_line(finding: ClassifiedFinding, scan_path: str) -> str:
    """Format file path and line number for display.

    Attempts to show a relative path from the scan root. Falls back to the
    full path if the finding is outside the scan root.
    """
    file_str = str(finding.finding.file_path)
    try:
        file_str = str(finding.finding.file_path.relative_to(scan_path))
    except ValueError:
        pass
    if finding.finding.line_number is not None:
        return f"{file_str}:{finding.finding.line_number}"
    return file_str


def render_text(result: ScanResult) -> str:
    """Render scan results as human-readable Rich terminal output.

    Creates a formatted report with a header panel, summary statistics,
    and a findings table grouped by risk level.

    Args:
        result: The scan result to render.

    Returns:
        Formatted text output captured from the Rich console.
    """
    console = Console(record=True, width=120)

    # Header
    console.print()
    console.print(
        Panel(
            Text("qproof Quantum Risk Report", justify="center", style="bold cyan"),
            border_style="cyan",
        )
    )
    console.print()

    # Summary
    score = result.quantum_ready_score
    if score >= 80.0:
        score_style = "bold green"
    elif score >= 50.0:
        score_style = "bold yellow"
    else:
        score_style = "bold red"

    summary = Table.grid(padding=(0, 2))
    summary.add_column(style="bold")
    summary.add_column()
    summary.add_row("Scanned path:", str(result.path))
    summary.add_row("Total files scanned:", str(result.total_files_scanned))
    summary.add_row("Scan duration:", f"{result.scan_duration_seconds:.2f}s")
    summary.add_row("Total findings:", str(len(result.findings)))
    summary.add_row(
        "Vulnerable:", Text(str(result.vulnerable_count), style="bold red")
    )
    summary.add_row(
        "Partial:", Text(str(result.partial_count), style="bold yellow")
    )
    summary.add_row("Safe:", Text(str(result.safe_count), style="bold green"))
    summary.add_row(
        "Quantum-ready score:", Text(f"{score:.1f}%", style=score_style)
    )
    console.print(summary)
    console.print()

    # Findings table
    if not result.findings:
        console.print(
            Panel(
                Text(
                    "No quantum-vulnerable cryptography found!",
                    justify="center",
                    style="bold green",
                ),
                border_style="green",
            )
        )
    else:
        table = Table(
            title="Findings",
            show_lines=True,
            title_style="bold",
        )
        table.add_column("Risk", width=12)
        table.add_column("Algorithm", width=18)
        table.add_column("File:Line", min_width=30)
        table.add_column("Source", width=14)
        table.add_column("Replacement", min_width=20)

        sorted_findings = sorted(result.findings, key=_risk_sort_key)

        for cf in sorted_findings:
            risk_style = _RISK_STYLES.get(cf.quantum_risk, "dim")
            table.add_row(
                Text(cf.quantum_risk.value, style=risk_style),
                cf.algorithm.name,
                _format_file_line(cf, str(result.path)),
                cf.finding.source,
                cf.replacement or "-",
            )

        console.print(table)

    console.print()
    return console.export_text()
