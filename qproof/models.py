"""Data models for qproof scan results."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Literal


class QuantumRisk(Enum):
    """Quantum computing risk level for a cryptographic algorithm."""

    VULNERABLE = "VULNERABLE"
    PARTIAL = "PARTIAL"
    SAFE = "SAFE"
    UNKNOWN = "UNKNOWN"


@dataclass
class Finding:
    """A single cryptographic finding in the codebase."""

    file_path: Path
    line_number: int | None
    matched_text: str
    algorithm_id: str
    source: str  # "source_code" | "dependency" | "config"
    context: str = ""


@dataclass
class AlgorithmInfo:
    """Information about a cryptographic algorithm from the database."""

    id: str
    name: str
    type: str  # "asymmetric" | "symmetric" | "hash" | "kdf" | "protocol"
    quantum_risk: QuantumRisk
    reason: str
    replacement: str
    patterns: list[str] = field(default_factory=list)


@dataclass
class ClassifiedFinding:
    """A finding enriched with quantum risk classification."""

    finding: Finding
    algorithm: AlgorithmInfo
    quantum_risk: QuantumRisk
    replacement: str
    reason: str
    confidence: Literal["low", "medium", "high"] = "medium"
    context: Literal["runtime", "test", "docs", "comment", "build"] = "runtime"


@dataclass
class ScanResult:
    """Complete result of a qproof scan."""

    path: Path
    findings: list[ClassifiedFinding] = field(default_factory=list)
    total_files_scanned: int = 0
    scan_duration_seconds: float = 0.0

    @property
    def vulnerable_count(self) -> int:
        """Count of findings classified as VULNERABLE."""
        return sum(1 for f in self.findings if f.quantum_risk == QuantumRisk.VULNERABLE)

    @property
    def partial_count(self) -> int:
        """Count of findings classified as PARTIAL risk."""
        return sum(1 for f in self.findings if f.quantum_risk == QuantumRisk.PARTIAL)

    @property
    def safe_count(self) -> int:
        """Count of findings classified as SAFE."""
        return sum(1 for f in self.findings if f.quantum_risk == QuantumRisk.SAFE)

    @property
    def quantum_ready_score(self) -> float:
        """Percentage of findings that are quantum-safe. 100 = fully ready."""
        total = len(self.findings)
        if total == 0:
            return 100.0
        return (self.safe_count / total) * 100
