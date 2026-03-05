"""Baseline snapshot generation and loading for diff mode.

Generates a deterministic JSON snapshot of all findings in a scan.
The baseline file is committed to the repo and used by --diff (QP-014)
to report only new or worsened findings.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
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
