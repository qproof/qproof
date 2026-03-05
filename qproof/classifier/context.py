"""Context and confidence scoring for classified findings.

Assigns context (runtime/test/docs/comment/build) and confidence
(low/medium/high) to each finding using path and content heuristics.
AST-based analysis is planned for Fase 1 — these heuristics cover ~70%.
"""

from __future__ import annotations

import re
from fnmatch import fnmatch
from typing import Literal

from qproof.models import ClassifiedFinding

ContextType = Literal["runtime", "test", "docs", "comment", "build"]
ConfidenceLevel = Literal["low", "medium", "high"]

# ---------- context patterns ----------

_TEST_PATTERNS: list[str] = [
    "test_*",
    "*_test.py",
    "tests/*",
    "__tests__/*",
    "spec/*",
    "*_spec.*",
    "test/*",
]

_DOCS_PATTERNS: list[str] = [
    "docs/*",
    "*.md",
    "*.rst",
    "README*",
    "CHANGELOG*",
]

_BUILD_PATTERNS: list[str] = [
    "build/*",
    "dist/*",
    "*.min.js",
    "*.min.css",
    "Makefile",
    "Dockerfile",
]

_COMMENT_PREFIXES: tuple[str, ...] = ("#", "//", "/*", "*", '"""', "'''")

# ---------- confidence patterns ----------

_IMPORT_RE = re.compile(
    r"(?:^\s*(?:import\s+\S|from\s+\S+\s+import\s|use\s+\S)|require\s*\()",
)

_FUNCTION_CALL_RE = re.compile(
    r"(?:\.\s*(?:generate|encrypt|decrypt|sign|verify|digest|update|new|create)"
    r"\s*\(|new\s+\w+\s*\()",
)


def _match_any_pattern(path: str, patterns: list[str]) -> bool:
    """Check if path matches any of the glob patterns.

    Normalises the path to forward-slashes and checks each segment so that
    a pattern like ``tests/*`` also matches ``tests/sub/file.py``.
    """
    normalised = path.replace("\\", "/")
    for pattern in patterns:
        if fnmatch(normalised, pattern):
            return True
        # Also check individual path components for directory patterns
        parts = normalised.split("/")
        for i in range(len(parts)):
            sub = "/".join(parts[i:])
            if fnmatch(sub, pattern):
                return True
    return False


def _classify_context(file_path: str, line_content: str) -> ContextType:
    """Determine the context of a finding based on file path and line content."""
    if _match_any_pattern(file_path, _TEST_PATTERNS):
        return "test"
    if _match_any_pattern(file_path, _DOCS_PATTERNS):
        return "docs"
    if _match_any_pattern(file_path, _BUILD_PATTERNS):
        return "build"

    stripped = line_content.lstrip()
    if stripped and any(stripped.startswith(prefix) for prefix in _COMMENT_PREFIXES):
        return "comment"

    return "runtime"


def _classify_confidence(
    line_content: str,
    source: str,
    context: ContextType,
) -> ConfidenceLevel:
    """Determine the confidence level of a finding."""
    # HIGH: dependency/config scanners are inherently high confidence
    if source in ("dependency", "config"):
        return "high"

    # HIGH: import statements or function calls with crypto args
    if _IMPORT_RE.search(line_content):
        return "high"
    if _FUNCTION_CALL_RE.search(line_content):
        return "high"

    # LOW: comments or docs
    if context in ("comment", "docs"):
        return "low"

    # Default
    return "medium"


def classify_context(
    file_path: str,
    line_content: str,
    source: str,
) -> tuple[ContextType, ConfidenceLevel]:
    """Classify the context and confidence of a finding.

    Args:
        file_path: Path to the file where the finding was detected.
        line_content: The source line that triggered the finding.
        source: The scanner source (``source_code``, ``dependency``, ``config``).

    Returns:
        Tuple of (context, confidence).
    """
    context = _classify_context(file_path, line_content)
    confidence = _classify_confidence(line_content, source, context)
    return context, confidence


def enrich_findings(findings: list[ClassifiedFinding]) -> None:
    """Enrich a list of classified findings with context and confidence in-place.

    Args:
        findings: Classified findings to enrich.
    """
    for cf in findings:
        ctx, conf = classify_context(
            str(cf.finding.file_path),
            cf.finding.context,
            cf.finding.source,
        )
        cf.context = ctx
        cf.confidence = conf
