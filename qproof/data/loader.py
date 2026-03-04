"""Load and validate qproof's algorithm and library databases."""

from pathlib import Path
from typing import Any

import yaml

from qproof.models import AlgorithmInfo, QuantumRisk

_DATA_DIR = Path(__file__).parent
_algorithms_cache: dict[str, AlgorithmInfo] | None = None
_libraries_cache: dict[str, dict[str, Any]] | None = None


def load_algorithms(path: Path | None = None) -> dict[str, AlgorithmInfo]:
    """Load the algorithm database from YAML.

    Args:
        path: Path to algorithms.yaml. Defaults to bundled database.

    Returns:
        Dictionary mapping algorithm ID to AlgorithmInfo.

    Raises:
        FileNotFoundError: If the YAML file doesn't exist.
        ValueError: If the YAML structure is invalid.
    """
    global _algorithms_cache
    if _algorithms_cache is not None and path is None:
        return _algorithms_cache

    yaml_path = path or (_DATA_DIR / "algorithms.yaml")

    if not yaml_path.exists():
        raise FileNotFoundError(f"Algorithm database not found: {yaml_path}")

    with open(yaml_path) as f:
        raw = yaml.safe_load(f)

    if not isinstance(raw, dict) or "algorithms" not in raw:
        raise ValueError("Invalid algorithms.yaml: must have top-level 'algorithms' key")

    result: dict[str, AlgorithmInfo] = {}

    for algo_id, data in raw["algorithms"].items():
        required = ["name", "type", "quantum_risk", "reason", "replacement", "patterns"]
        missing = [f for f in required if f not in data]
        if missing:
            raise ValueError(f"Algorithm '{algo_id}' missing required fields: {missing}")

        try:
            risk = QuantumRisk(data["quantum_risk"])
        except ValueError as e:
            valid = [r.value for r in QuantumRisk]
            raise ValueError(
                f"Algorithm '{algo_id}' has invalid quantum_risk: "
                f"'{data['quantum_risk']}'. Must be one of: {valid}"
            ) from e

        result[algo_id] = AlgorithmInfo(
            id=algo_id,
            name=data["name"],
            type=data["type"],
            quantum_risk=risk,
            reason=data["reason"],
            replacement=data["replacement"],
            patterns=data["patterns"],
        )

    if path is None:
        _algorithms_cache = result
    return result


def load_libraries(path: Path | None = None) -> dict[str, dict[str, Any]]:
    """Load the library-to-algorithm mapping from YAML.

    Args:
        path: Path to libraries.yaml. Defaults to bundled database.

    Returns:
        Dictionary mapping library name to its metadata.

    Raises:
        FileNotFoundError: If the YAML file doesn't exist.
        ValueError: If the YAML structure is invalid.
    """
    global _libraries_cache
    if _libraries_cache is not None and path is None:
        return _libraries_cache

    yaml_path = path or (_DATA_DIR / "libraries.yaml")

    if not yaml_path.exists():
        raise FileNotFoundError(f"Library database not found: {yaml_path}")

    with open(yaml_path) as f:
        raw = yaml.safe_load(f)

    if not isinstance(raw, dict) or "libraries" not in raw:
        raise ValueError("Invalid libraries.yaml: must have top-level 'libraries' key")

    required = ["ecosystem", "package_name", "description", "exposes", "default_risk"]
    for lib_id, data in raw["libraries"].items():
        missing = [f for f in required if f not in data]
        if missing:
            raise ValueError(f"Library '{lib_id}' missing required fields: {missing}")

    result = raw["libraries"]
    if path is None:
        _libraries_cache = result
    return result


def get_patterns_for_algorithm(
    algo_id: str, db: dict[str, AlgorithmInfo] | None = None
) -> list[str]:
    """Get regex patterns for a specific algorithm.

    Args:
        algo_id: Algorithm identifier (e.g., "RSA", "AES-256").
        db: Pre-loaded algorithm database. Loads default if None.

    Returns:
        List of string patterns for matching.
    """
    db = db or load_algorithms()
    if algo_id not in db:
        return []
    return db[algo_id].patterns


def get_all_patterns(
    db: dict[str, AlgorithmInfo] | None = None,
) -> dict[str, list[str]]:
    """Get all patterns grouped by algorithm ID.

    Args:
        db: Pre-loaded algorithm database. Loads default if None.

    Returns:
        Dictionary mapping algo ID to its patterns.
    """
    db = db or load_algorithms()
    return {algo_id: info.patterns for algo_id, info in db.items()}
