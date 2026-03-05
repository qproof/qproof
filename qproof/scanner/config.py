"""Configuration file scanner for cryptographic settings.

Detects cryptographic configurations in server configs (nginx, Apache, HAProxy),
SSH configs, OpenSSL configs, JWT configs, PEM/certificate files, and
environment files.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from qproof.models import Finding
from qproof.utils.file_walker import EXCLUDED_DIRS

# Maximum file size to scan (1 MB).
_MAX_FILE_SIZE: int = 1_000_000

# Config files matched by exact name (case-sensitive).
_CONFIG_NAMES: set[str] = {
    "nginx.conf",
    "httpd.conf",
    "apache2.conf",
    "haproxy.cfg",
    "Caddyfile",
    "sshd_config",
    "ssh_config",
    "openssl.cnf",
    "settings.py",
    "docker-compose.yml",
    "docker-compose.yaml",
}

# Config files matched by extension.
_CONFIG_EXTENSIONS: set[str] = {
    ".conf",
    ".cfg",
    ".cnf",
    ".ini",
    ".pub",
    ".pem",
    ".crt",
    ".key",
}

# Extensions that are scanned for JWT patterns.
_JWT_EXTENSIONS: set[str] = {
    ".json",
    ".yaml",
    ".yml",
}


@dataclass(frozen=True)
class _ConfigPattern:
    """A compiled regex pattern for detecting cryptographic config settings."""

    algorithm_id: str
    regex: re.Pattern[str]
    context_template: str
    file_filter: frozenset[str] | None  # extensions/names this applies to, None = all


def _ext_filter(*exts: str) -> frozenset[str]:
    """Build a frozenset of extensions/names for file filtering."""
    return frozenset(exts)


# ---------------------------------------------------------------------------
# Pattern definitions — compiled once at module import
# ---------------------------------------------------------------------------

# TLS version patterns (conf, cfg, env, cnf, yaml, json, ini files)
_TLS_CONF_FILTER = _ext_filter(
    ".conf", ".cfg", ".cnf", ".ini", ".yaml", ".yml", ".json",
)

_TLS_PATTERNS: list[_ConfigPattern] = [
    # nginx: ssl_protocols TLSv1 (not TLSv1.2 or TLSv1.3)
    _ConfigPattern(
        algorithm_id="TLS-1.0",
        regex=re.compile(r"ssl_protocols\s+.*\bTLSv1\b(?!\.)", re.IGNORECASE),
        context_template="nginx TLS 1.0 enabled",
        file_filter=_TLS_CONF_FILTER,
    ),
    _ConfigPattern(
        algorithm_id="TLS-1.1",
        regex=re.compile(r"ssl_protocols\s+.*\bTLSv1\.1\b", re.IGNORECASE),
        context_template="nginx TLS 1.1 enabled",
        file_filter=_TLS_CONF_FILTER,
    ),
    # Apache: SSLProtocol
    _ConfigPattern(
        algorithm_id="TLS-1.0",
        regex=re.compile(r"SSLProtocol\s+.*\+?TLSv1\b(?!\.)", re.IGNORECASE),
        context_template="Apache TLS 1.0 enabled",
        file_filter=_TLS_CONF_FILTER,
    ),
    # HAProxy: ssl-min-ver
    _ConfigPattern(
        algorithm_id="TLS-1.0",
        regex=re.compile(r"ssl-min-ver\s+TLSv1\.0", re.IGNORECASE),
        context_template="HAProxy TLS 1.0 minimum version",
        file_filter=_TLS_CONF_FILTER,
    ),
    # OpenSSL: MinProtocol
    _ConfigPattern(
        algorithm_id="TLS-1.0",
        regex=re.compile(r"MinProtocol\s*=\s*TLSv1\b(?!\.)", re.IGNORECASE),
        context_template="OpenSSL TLS 1.0 minimum protocol",
        file_filter=_TLS_CONF_FILTER,
    ),
    # .env: TLS_VERSION=1.0
    _ConfigPattern(
        algorithm_id="TLS-1.0",
        regex=re.compile(r"TLS_VERSION\s*=\s*1\.0\b"),
        context_template="TLS 1.0 configured in environment",
        file_filter=None,  # applies to .env* files
    ),
]

# SSH public key patterns (.pub files)
_SSH_PUB_FILTER = _ext_filter(".pub")

_SSH_KEY_PATTERNS: list[_ConfigPattern] = [
    _ConfigPattern(
        algorithm_id="SSH-RSA",
        regex=re.compile(r"^ssh-rsa\s"),
        context_template="SSH RSA public key",
        file_filter=_SSH_PUB_FILTER,
    ),
    _ConfigPattern(
        algorithm_id="DSA",
        regex=re.compile(r"^ssh-dss\s"),
        context_template="SSH DSA public key",
        file_filter=_SSH_PUB_FILTER,
    ),
    _ConfigPattern(
        algorithm_id="ECDSA",
        regex=re.compile(r"^ecdsa-sha2-nistp\d+\s"),
        context_template="SSH ECDSA public key",
        file_filter=_SSH_PUB_FILTER,
    ),
    _ConfigPattern(
        algorithm_id="Ed25519",
        regex=re.compile(r"^ssh-ed25519\s"),
        context_template="SSH Ed25519 public key",
        file_filter=_SSH_PUB_FILTER,
    ),
]

# SSH config patterns (sshd_config, ssh_config)
_SSH_CONFIG_FILTER = _ext_filter("sshd_config", "ssh_config")

_SSH_CONFIG_PATTERNS: list[_ConfigPattern] = [
    _ConfigPattern(
        algorithm_id="3DES",
        regex=re.compile(r"Ciphers\s+.*3des", re.IGNORECASE),
        context_template="3DES cipher enabled in SSH config",
        file_filter=_SSH_CONFIG_FILTER,
    ),
    _ConfigPattern(
        algorithm_id="AES-128",
        regex=re.compile(r"Ciphers\s+.*aes128", re.IGNORECASE),
        context_template="AES-128 cipher enabled in SSH config",
        file_filter=_SSH_CONFIG_FILTER,
    ),
    _ConfigPattern(
        algorithm_id="HMAC-SHA1",
        regex=re.compile(r"MACs\s+.*hmac-sha1\b", re.IGNORECASE),
        context_template="HMAC-SHA1 MAC enabled in SSH config",
        file_filter=_SSH_CONFIG_FILTER,
    ),
    _ConfigPattern(
        algorithm_id="DH",
        regex=re.compile(r"KexAlgorithms\s+.*diffie-hellman", re.IGNORECASE),
        context_template="Diffie-Hellman key exchange in SSH config",
        file_filter=_SSH_CONFIG_FILTER,
    ),
]

# JWT patterns (.json, .yaml, .env files)
_JWT_FILTER = _ext_filter(".json", ".yaml", ".yml")

_JWT_PATTERNS: list[_ConfigPattern] = [
    _ConfigPattern(
        algorithm_id="JWT-RS256",
        regex=re.compile(r"""(?:algorithm|alg)["'\s:=]+RS256""", re.IGNORECASE),
        context_template="JWT RS256 algorithm configured",
        file_filter=_JWT_FILTER,
    ),
    _ConfigPattern(
        algorithm_id="JWT-ES256",
        regex=re.compile(r"""(?:algorithm|alg)["'\s:=]+ES256""", re.IGNORECASE),
        context_template="JWT ES256 algorithm configured",
        file_filter=_JWT_FILTER,
    ),
    # .env-specific JWT pattern
    _ConfigPattern(
        algorithm_id="JWT-RS256",
        regex=re.compile(r"JWT_ALGORITHM\s*=\s*RS256\b"),
        context_template="JWT RS256 algorithm in environment",
        file_filter=None,  # applies to .env* files
    ),
]

# OpenSSL config patterns (.cnf files)
_OPENSSL_FILTER = _ext_filter(".cnf")

_OPENSSL_PATTERNS: list[_ConfigPattern] = [
    _ConfigPattern(
        algorithm_id="SHA-1",
        regex=re.compile(r"default_md\s*=\s*sha1\b", re.IGNORECASE),
        context_template="OpenSSL default digest set to SHA-1",
        file_filter=_OPENSSL_FILTER,
    ),
    _ConfigPattern(
        algorithm_id="MD5",
        regex=re.compile(r"default_md\s*=\s*md5\b", re.IGNORECASE),
        context_template="OpenSSL default digest set to MD5",
        file_filter=_OPENSSL_FILTER,
    ),
    _ConfigPattern(
        algorithm_id="RSA",
        regex=re.compile(r"default_bits\s*=\s*(?:512|1024|2048)\b"),
        context_template="RSA key size configured in OpenSSL",
        file_filter=_OPENSSL_FILTER,
    ),
]

# PEM header patterns (.pem, .crt, .key files)
_PEM_FILTER = _ext_filter(".pem", ".crt", ".key")

_PEM_PATTERNS: list[_ConfigPattern] = [
    _ConfigPattern(
        algorithm_id="RSA",
        regex=re.compile(r"-----BEGIN RSA PRIVATE KEY-----"),
        context_template="RSA private key in PEM format",
        file_filter=_PEM_FILTER,
    ),
    _ConfigPattern(
        algorithm_id="DSA",
        regex=re.compile(r"-----BEGIN DSA PRIVATE KEY-----"),
        context_template="DSA private key in PEM format",
        file_filter=_PEM_FILTER,
    ),
    _ConfigPattern(
        algorithm_id="ECDSA",
        regex=re.compile(r"-----BEGIN EC PRIVATE KEY-----"),
        context_template="ECDSA private key in PEM format",
        file_filter=_PEM_FILTER,
    ),
]

# All patterns combined.
_ALL_PATTERNS: list[_ConfigPattern] = (
    _TLS_PATTERNS
    + _SSH_KEY_PATTERNS
    + _SSH_CONFIG_PATTERNS
    + _JWT_PATTERNS
    + _OPENSSL_PATTERNS
    + _PEM_PATTERNS
)


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------


def _is_excluded(path: Path, root: Path) -> bool:
    """Check if any path component is in the excluded directories set."""
    try:
        rel = path.relative_to(root)
    except ValueError:
        return True
    for part in rel.parts[:-1]:  # Check parent dirs only, not the file itself
        if part in EXCLUDED_DIRS or part.endswith(".egg-info"):
            return True
    return False


def _is_env_file(name: str) -> bool:
    """Check if a filename is a .env variant (e.g. .env, .env.local, .env.production).

    Args:
        name: Filename to check.

    Returns:
        True if the filename matches a .env pattern.
    """
    return name == ".env" or name.startswith(".env.")


def _is_config_file(path: Path) -> bool:
    """Determine if a file is a config file we should scan.

    Matches by exact name, extension, .env* pattern, or JWT-scannable extension.

    Args:
        path: File path to check.

    Returns:
        True if the file should be scanned for config patterns.
    """
    name = path.name
    suffix = path.suffix.lower()

    # Exact name matches
    if name in _CONFIG_NAMES:
        return True

    # .env* files
    if _is_env_file(name):
        return True

    # Extension matches
    if suffix in _CONFIG_EXTENSIONS:
        return True

    # JWT-scannable files
    if suffix in _JWT_EXTENSIONS:
        return True

    return False


def _find_config_files(root: Path) -> list[Path]:
    """Find all config files under root, respecting exclusion rules.

    Args:
        root: Root directory to search.

    Returns:
        Sorted list of config file paths found.
    """
    results: list[Path] = []

    for item in sorted(root.rglob("*")):
        if item.is_symlink():
            continue
        if item.is_dir():
            continue
        if _is_excluded(item, root):
            continue
        if not _is_config_file(item):
            continue
        try:
            if item.stat().st_size > _MAX_FILE_SIZE:
                continue
        except OSError:
            continue
        results.append(item)

    return results


# ---------------------------------------------------------------------------
# Pattern matching
# ---------------------------------------------------------------------------


def _matches_file_filter(
    path: Path,
    file_filter: frozenset[str] | None,
) -> bool:
    """Check if a file matches a pattern's file filter.

    The filter can contain extensions (starting with '.') or exact filenames.
    A None filter means the pattern is env-specific (only matches .env* files).

    Args:
        path: File path to check.
        file_filter: Set of extensions/names, or None for .env* patterns.

    Returns:
        True if the file matches the filter.
    """
    name = path.name
    suffix = path.suffix.lower()

    if file_filter is None:
        # None filter means this pattern is env-specific
        return _is_env_file(name)

    # Check by extension or exact name
    if suffix in file_filter:
        return True
    if name in file_filter:
        return True

    return False


def _read_file_lines(path: Path) -> list[str] | None:
    """Read a file and return its lines, or None if unreadable.

    Uses utf-8 with errors='replace' as fallback.

    Args:
        path: Path to the file.

    Returns:
        List of lines (with newlines stripped), or None if skipped.
    """
    try:
        raw = path.read_bytes()
    except OSError:
        return None

    try:
        text = raw.decode("utf-8", errors="replace")
    except (UnicodeDecodeError, ValueError):
        return None

    return text.splitlines()


def _scan_single_file(path: Path) -> list[Finding]:
    """Scan a single config file for cryptographic patterns.

    Args:
        path: Path to the config file.

    Returns:
        Deduplicated list of findings from this file.
    """
    lines = _read_file_lines(path)
    if lines is None:
        return []

    findings: list[Finding] = []
    seen: set[tuple[str, int, str]] = set()  # (file_str, line_no, algo_id)
    file_str = str(path)

    for line_idx, line in enumerate(lines, start=1):
        for pattern in _ALL_PATTERNS:
            if not _matches_file_filter(path, pattern.file_filter):
                continue

            match = pattern.regex.search(line)
            if match is None:
                continue

            dedup_key = (file_str, line_idx, pattern.algorithm_id)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            findings.append(
                Finding(
                    file_path=path,
                    line_number=line_idx,
                    matched_text=match.group(0),
                    algorithm_id=pattern.algorithm_id,
                    source="config",
                    context=pattern.context_template,
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan_configs(root: Path) -> list[Finding]:
    """Scan configuration files for cryptographic settings.

    Walks the directory tree looking for configuration files (server configs,
    SSH configs, OpenSSL configs, JWT configs, PEM/certificate files, and
    environment files), then applies config-specific regex patterns to detect
    cryptographic settings.

    Args:
        root: Root directory to scan.

    Returns:
        List of findings from configuration analysis, sorted by
        (file_path, line_number). Never raises on file errors --
        returns empty list instead.
    """
    root = root.resolve()
    if not root.is_dir():
        return []

    config_files = _find_config_files(root)
    all_findings: list[Finding] = []

    for file_path in config_files:
        try:
            file_findings = _scan_single_file(file_path)
            all_findings.extend(file_findings)
        except Exception:
            # Never raise on individual file errors -- skip and continue.
            continue

    # Sort by file path, then line number.
    all_findings.sort(key=lambda f: (str(f.file_path), f.line_number or 0))
    return all_findings
