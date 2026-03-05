"""Severity model — calculates 5-level severity from quantum_risk + confidence + context.

Also enriches findings with category and remediation from algorithms.yaml.
"""

from __future__ import annotations

from typing import Any, Literal

import yaml

from qproof.models import ClassifiedFinding

SeverityLevel = Literal["critical", "high", "medium", "low", "info"]

# Non-runtime contexts where findings are less impactful.
_NON_RUNTIME = {"test", "docs", "comment", "build"}

# ---------- severity mapping ----------

_SEVERITY_MAP: dict[tuple[str, str, bool], SeverityLevel] = {
    # (quantum_risk, confidence, is_runtime) → severity
    ("VULNERABLE", "high", True): "critical",
    ("VULNERABLE", "high", False): "low",
    ("VULNERABLE", "medium", True): "high",
    ("VULNERABLE", "medium", False): "medium",
    ("VULNERABLE", "low", True): "medium",
    ("VULNERABLE", "low", False): "medium",
    ("PARTIAL", "high", True): "high",
    ("PARTIAL", "high", False): "info",
    ("PARTIAL", "medium", True): "medium",
    ("PARTIAL", "medium", False): "low",
    ("PARTIAL", "low", True): "low",
    ("PARTIAL", "low", False): "low",
}


def calculate_severity(
    quantum_risk: str,
    confidence: str,
    context: str,
) -> SeverityLevel:
    """Calculate 5-level severity from quantum_risk, confidence, and context.

    Args:
        quantum_risk: The quantum risk level (VULNERABLE/PARTIAL/SAFE/UNKNOWN).
        confidence: The confidence level (low/medium/high).
        context: The finding context (runtime/test/docs/comment/build).

    Returns:
        Severity level: critical, high, medium, low, or info.
    """
    if quantum_risk == "SAFE":
        return "info"

    is_runtime = context not in _NON_RUNTIME
    key = (quantum_risk, confidence, is_runtime)
    return _SEVERITY_MAP.get(key, "medium")


# ---------- SARIF level mapping ----------

_SEVERITY_TO_SARIF: dict[SeverityLevel, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def severity_to_sarif_level(severity: SeverityLevel) -> str:
    """Map severity to SARIF level (error/warning/note)."""
    return _SEVERITY_TO_SARIF.get(severity, "warning")


# ---------- enrichment from YAML ----------

_yaml_cache: dict[str, dict[str, Any]] | None = None


def _load_algo_yaml_raw() -> dict[str, dict[str, Any]]:
    """Load raw algorithm YAML data for category/remediation lookup."""
    global _yaml_cache
    if _yaml_cache is not None:
        return _yaml_cache

    from pathlib import Path

    yaml_path = Path(__file__).parent.parent / "data" / "algorithms.yaml"
    with open(yaml_path) as f:
        raw = yaml.safe_load(f)

    _yaml_cache = raw.get("algorithms", {})
    return _yaml_cache


def enrich_severity(findings: list[ClassifiedFinding]) -> None:
    """Enrich findings with severity, category, and remediation in-place.

    Must be called AFTER enrich_findings (QP-016) so that confidence and
    context are already set.

    Args:
        findings: Classified findings to enrich.
    """
    algo_data = _load_algo_yaml_raw()

    for cf in findings:
        # Calculate severity
        cf.severity = calculate_severity(
            cf.quantum_risk.value,
            cf.confidence,
            cf.context,
        )

        # Load category and remediation from YAML
        raw = algo_data.get(cf.algorithm.id, {})
        cf.category = raw.get("category")
        cf.remediation = raw.get("remediation")
