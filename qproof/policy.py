"""Policy-as-Code engine — loads and enforces qproof.yml rules.

Supports ignore paths/algorithms, allow rules with expiry, fail conditions
by severity threshold, and severity overrides per algorithm.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

import yaml

from qproof.models import ClassifiedFinding

# Severity ordering: lower index = more severe.
_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_VALID_SEVERITIES = set(_SEVERITY_ORDER)


class PolicyValidationError(Exception):
    """Raised when qproof.yml has invalid schema or values."""


# ---------- dataclasses ----------


@dataclass
class AllowRule:
    """Allow a specific algorithm in specific paths."""

    algorithm: str
    paths: list[str]
    reason: str
    expires: date | None = None


@dataclass
class SeverityOverride:
    """Override calculated severity for a specific algorithm."""

    algorithm: str
    severity: str
    reason: str


@dataclass
class FailConfig:
    """Conditions that cause qproof to exit with failure."""

    on_severity: str = "high"
    max_new_findings: int = 0


@dataclass
class IgnoreConfig:
    """Paths and algorithms to ignore entirely."""

    paths: list[str] = field(default_factory=list)
    algorithms: list[str] = field(default_factory=list)


@dataclass
class PolicyConfig:
    """Parsed qproof.yml policy."""

    version: str
    ignore: IgnoreConfig
    allow: list[AllowRule]
    fail: FailConfig
    severity_overrides: list[SeverityOverride]


# ---------- loading ----------

_KNOWN_TOP_KEYS = {"version", "ignore", "allow", "fail", "severity_overrides"}
_KNOWN_IGNORE_KEYS = {"paths", "algorithms"}
_KNOWN_ALLOW_KEYS = {"algorithm", "paths", "reason", "expires"}
_KNOWN_FAIL_KEYS = {"on_severity", "max_new_findings"}
_KNOWN_OVERRIDE_KEYS = {"algorithm", "severity", "reason"}


def _check_unknown_keys(
    data: dict[str, Any],
    known: set[str],
    context: str,
) -> None:
    """Raise PolicyValidationError if data contains unknown keys."""
    unknown = set(data.keys()) - known
    if unknown:
        raise PolicyValidationError(
            f"{context}: unknown keys {sorted(unknown)}"
        )


def _parse_allow_rules(raw_list: list[Any]) -> list[AllowRule]:
    """Parse allow rules from YAML data."""
    rules: list[AllowRule] = []
    for i, entry in enumerate(raw_list):
        if not isinstance(entry, dict):
            raise PolicyValidationError(
                f"allow[{i}]: expected a mapping, got {type(entry).__name__}"
            )
        _check_unknown_keys(entry, _KNOWN_ALLOW_KEYS, f"allow[{i}]")

        if "algorithm" not in entry:
            raise PolicyValidationError(f"allow[{i}]: missing required key 'algorithm'")
        if "reason" not in entry:
            raise PolicyValidationError(f"allow[{i}]: missing required key 'reason'")

        expires = None
        if "expires" in entry:
            raw_expires = entry["expires"]
            if isinstance(raw_expires, date):
                expires = raw_expires
            elif isinstance(raw_expires, str):
                try:
                    expires = date.fromisoformat(raw_expires)
                except ValueError as e:
                    raise PolicyValidationError(
                        f"allow[{i}].expires: invalid date format '{raw_expires}' — {e}"
                    ) from e
            else:
                raise PolicyValidationError(
                    f"allow[{i}].expires: expected date string, got {type(raw_expires).__name__}"
                )

        paths = entry.get("paths", [])
        if not isinstance(paths, list):
            raise PolicyValidationError(
                f"allow[{i}].paths: expected a list, got {type(paths).__name__}"
            )

        rules.append(AllowRule(
            algorithm=str(entry["algorithm"]),
            paths=[str(p) for p in paths],
            reason=str(entry["reason"]),
            expires=expires,
        ))
    return rules


def _parse_severity_overrides(raw_list: list[Any]) -> list[SeverityOverride]:
    """Parse severity overrides from YAML data."""
    overrides: list[SeverityOverride] = []
    for i, entry in enumerate(raw_list):
        if not isinstance(entry, dict):
            raise PolicyValidationError(
                f"severity_overrides[{i}]: expected a mapping, got {type(entry).__name__}"
            )
        _check_unknown_keys(entry, _KNOWN_OVERRIDE_KEYS, f"severity_overrides[{i}]")

        for key in ("algorithm", "severity", "reason"):
            if key not in entry:
                raise PolicyValidationError(
                    f"severity_overrides[{i}]: missing required key '{key}'"
                )

        sev = str(entry["severity"])
        if sev not in _VALID_SEVERITIES:
            raise PolicyValidationError(
                f"severity_overrides[{i}].severity: invalid value '{sev}', "
                f"must be one of {_SEVERITY_ORDER}"
            )

        overrides.append(SeverityOverride(
            algorithm=str(entry["algorithm"]),
            severity=sev,
            reason=str(entry["reason"]),
        ))
    return overrides


def _parse_policy_yaml(raw: dict[str, Any], context: str) -> PolicyConfig:
    """Parse and validate a raw YAML dict into a PolicyConfig.

    Args:
        raw: Parsed YAML dictionary.
        context: Label for error messages (e.g. "qproof.yml").

    Returns:
        Validated PolicyConfig.

    Raises:
        PolicyValidationError: If the data is invalid.
    """
    _check_unknown_keys(raw, _KNOWN_TOP_KEYS, context)

    # version (required)
    if "version" not in raw:
        raise PolicyValidationError(f"{context}: missing required key 'version'")
    version = str(raw["version"])

    # ignore
    ignore_raw = raw.get("ignore", {})
    if not isinstance(ignore_raw, dict):
        raise PolicyValidationError(
            f"ignore: expected a mapping, got {type(ignore_raw).__name__}"
        )
    _check_unknown_keys(ignore_raw, _KNOWN_IGNORE_KEYS, "ignore")
    ignore_paths = ignore_raw.get("paths", [])
    ignore_algos = ignore_raw.get("algorithms", [])
    if not isinstance(ignore_paths, list):
        raise PolicyValidationError("ignore.paths: expected a list")
    if not isinstance(ignore_algos, list):
        raise PolicyValidationError("ignore.algorithms: expected a list")
    ignore = IgnoreConfig(
        paths=[str(p) for p in ignore_paths],
        algorithms=[str(a) for a in ignore_algos],
    )

    # allow
    allow_raw = raw.get("allow", [])
    if not isinstance(allow_raw, list):
        raise PolicyValidationError(
            f"allow: expected a list, got {type(allow_raw).__name__}"
        )
    allow = _parse_allow_rules(allow_raw)

    # fail
    fail_raw = raw.get("fail", {})
    if not isinstance(fail_raw, dict):
        raise PolicyValidationError(
            f"fail: expected a mapping, got {type(fail_raw).__name__}"
        )
    _check_unknown_keys(fail_raw, _KNOWN_FAIL_KEYS, "fail")
    on_severity = str(fail_raw.get("on_severity", "high"))
    if on_severity not in _VALID_SEVERITIES:
        raise PolicyValidationError(
            f"fail.on_severity: invalid value '{on_severity}', "
            f"must be one of {_SEVERITY_ORDER}"
        )
    max_new = fail_raw.get("max_new_findings", 0)
    if not isinstance(max_new, int):
        raise PolicyValidationError(
            f"fail.max_new_findings: expected an integer, got {type(max_new).__name__}"
        )
    fail_config = FailConfig(on_severity=on_severity, max_new_findings=max_new)

    # severity_overrides
    overrides_raw = raw.get("severity_overrides", [])
    if not isinstance(overrides_raw, list):
        raise PolicyValidationError(
            f"severity_overrides: expected a list, got {type(overrides_raw).__name__}"
        )
    overrides = _parse_severity_overrides(overrides_raw)

    return PolicyConfig(
        version=version,
        ignore=ignore,
        allow=allow,
        fail=fail_config,
        severity_overrides=overrides,
    )


def _load_yaml_file(path: Path) -> dict[str, Any]:
    """Load and validate basic YAML structure from a file.

    Args:
        path: Path to the YAML file.

    Returns:
        Parsed dict.

    Raises:
        PolicyValidationError: If the YAML is invalid or not a mapping.
    """
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise PolicyValidationError(f"Invalid YAML syntax: {e}") from e

    if not isinstance(raw, dict):
        raise PolicyValidationError("Policy file must contain a YAML mapping")

    return raw


def load_policy(scan_path: str | Path) -> PolicyConfig | None:
    """Load qproof.yml from the scan root directory.

    Args:
        scan_path: Root directory being scanned.

    Returns:
        PolicyConfig if qproof.yml exists, None otherwise.

    Raises:
        PolicyValidationError: If the file exists but is invalid.
    """
    policy_path = Path(scan_path) / "qproof.yml"
    if not policy_path.exists():
        return None

    raw = _load_yaml_file(policy_path)
    return _parse_policy_yaml(raw, "qproof.yml")


def load_policy_from_file(path: str | Path) -> PolicyConfig:
    """Load and validate a policy file from an explicit path.

    Unlike load_policy(), this raises if the file does not exist.

    Args:
        path: Path to the qproof.yml file.

    Returns:
        PolicyConfig.

    Raises:
        FileNotFoundError: If the file does not exist.
        PolicyValidationError: If the file is invalid.
    """
    policy_path = Path(path)
    if not policy_path.exists():
        raise FileNotFoundError(f"Policy file not found: {policy_path}")

    raw = _load_yaml_file(policy_path)
    return _parse_policy_yaml(raw, str(policy_path))


# ---------- filtering ----------


def should_ignore_path(file_path: str, policy: PolicyConfig) -> bool:
    """Check if a file path should be ignored by policy.

    Args:
        file_path: Relative file path to check.
        policy: Active policy config.

    Returns:
        True if the path matches any ignore.paths pattern.
    """
    for pattern in policy.ignore.paths:
        if fnmatch.fnmatch(file_path, pattern):
            return True
    return False


def should_ignore_finding(
    finding: ClassifiedFinding,
    policy: PolicyConfig,
) -> bool:
    """Check if a finding should be suppressed by policy.

    A finding is ignored if:
    - Its algorithm_id matches ignore.algorithms (case-insensitive), OR
    - It matches an active (non-expired) allow rule for its algorithm and path.

    Args:
        finding: The classified finding to check.
        policy: Active policy config.

    Returns:
        True if the finding should be suppressed.
    """
    algo_id = finding.finding.algorithm_id

    # Check ignore.algorithms (case-insensitive)
    for ignored_algo in policy.ignore.algorithms:
        if algo_id.upper() == ignored_algo.upper():
            return True

    # Check allow rules
    file_str = str(finding.finding.file_path)
    for rule in policy.allow:
        if algo_id.upper() != rule.algorithm.upper():
            continue

        # Check expiry
        if rule.expires is not None and rule.expires < date.today():
            continue  # expired — do not ignore

        # Check path match
        for pattern in rule.paths:
            if fnmatch.fnmatch(file_str, pattern):
                return True

    return False


# ---------- severity overrides ----------


def apply_severity_overrides(
    findings: list[ClassifiedFinding],
    policy: PolicyConfig,
) -> None:
    """Apply severity overrides from policy to findings in-place.

    Must be called AFTER enrich_severity so it overrides the calculated value.

    Args:
        findings: Classified findings to modify.
        policy: Active policy config.
    """
    for override in policy.severity_overrides:
        for cf in findings:
            if cf.finding.algorithm_id.upper() == override.algorithm.upper():
                cf.severity = override.severity


# ---------- fail conditions ----------


def _severity_index(severity: str) -> int:
    """Return severity index (0 = most severe)."""
    try:
        return _SEVERITY_ORDER.index(severity)
    except ValueError:
        return 2


def check_fail_conditions(
    findings: list[ClassifiedFinding],
    policy: PolicyConfig,
    is_diff_mode: bool = False,
) -> bool:
    """Check if the scan should fail based on policy rules.

    Args:
        findings: Classified findings (after filtering and overrides).
        policy: Active policy config.
        is_diff_mode: True if --diff is active.

    Returns:
        True if should fail (exit 1).
    """
    threshold_idx = _severity_index(policy.fail.on_severity)

    # Check severity threshold
    for cf in findings:
        if _severity_index(cf.severity) <= threshold_idx:
            return True

    # Check max_new_findings (only in diff mode)
    if is_diff_mode:
        new_count = sum(
            1 for cf in findings if cf.diff_status in ("new", "worsened")
        )
        if new_count > policy.fail.max_new_findings:
            return True

    return False
