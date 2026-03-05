"""Baseline snapshot generation and loading for diff mode.

Generates a deterministic JSON snapshot of all findings in a scan.
The baseline file is committed to the repo and used by --diff (QP-014)
to report only new or worsened findings.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from qproof.models import ClassifiedFinding

_REQUIRED_BASELINE_KEYS = {
    "baseline_version",
    "qproof_version",
    "generated_at",
    "findings_count",
    "findings",
}


def finding_hash(cf: ClassifiedFinding) -> str:
    """Compute a deterministic hash for a classified finding.

    Uses only stable fields: file path, line number, algorithm ID, and
    scanner source. Does not include line content or timestamps.

    Args:
        cf: The classified finding to hash.

    Returns:
        First 16 hex characters of the SHA-256 digest.
    """
    raw = (
        f"{cf.finding.file_path}:{cf.finding.line_number}"
        f":{cf.finding.algorithm_id}:{cf.finding.source}"
    )
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def git_commit_or_null() -> str | None:
    """Try to get the current git HEAD commit hash.

    Returns:
        The commit hash string, or None if not in a git repo or git fails.
    """
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


def generate_baseline(
    findings: list[ClassifiedFinding],
    qproof_version: str,
) -> dict[str, Any]:
    """Generate a baseline snapshot dict from classified findings.

    Findings are sorted by hash for deterministic output. The timestamp
    is always UTC ISO format.

    Args:
        findings: Classified findings from a scan.
        qproof_version: Current qproof version string.

    Returns:
        Baseline dict ready to be serialised as JSON.
    """
    entries: list[dict[str, Any]] = []
    for cf in findings:
        entries.append({
            "hash": finding_hash(cf),
            "file": str(cf.finding.file_path),
            "line": cf.finding.line_number,
            "algorithm": cf.finding.algorithm_id,
            "risk": cf.quantum_risk.value,
            "severity": cf.severity,
            "source": cf.finding.source,
        })

    # Sort by hash for determinism regardless of scan order
    entries.sort(key=lambda e: e["hash"])

    return {
        "baseline_version": "1.0",
        "qproof_version": qproof_version,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "commit": git_commit_or_null(),
        "findings_count": len(entries),
        "findings": entries,
    }


def load_baseline(path: str | Path) -> dict[str, Any]:
    """Load and validate a baseline file.

    Args:
        path: Path to the baseline JSON file.

    Returns:
        Parsed baseline dict.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the JSON is invalid or missing required keys.
    """
    baseline_path = Path(path)

    if not baseline_path.exists():
        raise FileNotFoundError(f"Baseline file not found: {baseline_path}")

    try:
        raw = baseline_path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in baseline file: {e}") from e

    if not isinstance(data, dict):
        raise ValueError("Baseline file must contain a JSON object")

    missing = _REQUIRED_BASELINE_KEYS - set(data.keys())
    if missing:
        raise ValueError(f"Baseline file missing required keys: {sorted(missing)}")

    return data


# Severity ordering for worsened detection (lower index = more severe).
_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _severity_index(severity: str) -> int:
    """Return severity index (0 = most severe). Unknown defaults to middle."""
    try:
        return _SEVERITY_ORDER.index(severity)
    except ValueError:
        return 2


@dataclass
class DiffResult:
    """Result of diffing current findings against a baseline.

    Attributes:
        new: Findings not present in the baseline.
        worsened: Findings present in the baseline but with higher severity now.
        resolved: Baseline entries that no longer appear in the current scan.
        unchanged: Current findings that match the baseline exactly.
    """

    new: list[ClassifiedFinding] = field(default_factory=list)
    worsened: list[ClassifiedFinding] = field(default_factory=list)
    resolved: list[dict[str, Any]] = field(default_factory=list)
    unchanged: list[ClassifiedFinding] = field(default_factory=list)

    @property
    def has_new_debt(self) -> bool:
        """True if there are new or worsened findings (CI should fail)."""
        return len(self.new) > 0 or len(self.worsened) > 0


def diff_findings(
    current: list[ClassifiedFinding],
    baseline: dict[str, Any],
) -> DiffResult:
    """Compare current findings against a baseline snapshot.

    Each finding is identified by its deterministic hash. A finding is:
    - **new** if its hash does not appear in the baseline.
    - **worsened** if its hash exists but severity increased.
    - **resolved** if a baseline hash no longer appears in the current scan.
    - **unchanged** otherwise.

    Side effect: sets ``diff_status`` on each ClassifiedFinding in *current*.

    Args:
        current: Classified findings from the current scan.
        baseline: Parsed baseline dict (from ``load_baseline``).

    Returns:
        DiffResult with categorised findings.
    """
    # Build lookup from baseline: hash → entry dict
    baseline_by_hash: dict[str, dict[str, Any]] = {
        entry["hash"]: entry for entry in baseline.get("findings", [])
    }

    result = DiffResult()
    seen_hashes: set[str] = set()

    for cf in current:
        h = finding_hash(cf)
        seen_hashes.add(h)
        baseline_entry = baseline_by_hash.get(h)

        if baseline_entry is None:
            cf.diff_status = "new"
            result.new.append(cf)
        elif _severity_index(cf.severity) < _severity_index(
            baseline_entry.get("severity", "medium"),
        ):
            cf.diff_status = "worsened"
            result.worsened.append(cf)
        else:
            cf.diff_status = None
            result.unchanged.append(cf)

    # Resolved: baseline hashes not seen in current scan
    for h, entry in baseline_by_hash.items():
        if h not in seen_hashes:
            result.resolved.append(entry)

    return result
