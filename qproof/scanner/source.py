"""Source code scanner — detects cryptographic patterns in source files."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from qproof.data.loader import load_algorithms
from qproof.models import AlgorithmInfo, Finding
from qproof.utils.file_walker import SOURCE_EXTENSIONS, walk_files

# Threshold for "short" patterns that need smart word boundaries.
# Patterns at or below this length (that are purely alphabetic) get
# negative lookbehind/lookahead to prevent matching inside words like
# "description", "desktop", "design", "archive", etc.
_SHORT_ALPHA_PATTERN_MAX_LEN = 4

# Null byte used to detect binary files.
_NULL_BYTE = b"\x00"

# Number of bytes to sample when checking for binary content.
_BINARY_CHECK_SIZE = 8192


@dataclass(frozen=True)
class _CompiledPattern:
    """A pre-compiled regex pattern mapped to its algorithm ID."""

    algorithm_id: str
    regex: re.Pattern[str]
    raw_pattern: str


def _needs_smart_boundaries(pattern: str) -> bool:
    """Determine if a pattern needs smart word boundaries.

    Short, purely alphabetic patterns (e.g. RSA, DES, DH, MD5, RC4, DSA)
    match too aggressively without boundaries because they appear as
    substrings in common English words.

    Patterns that already contain regex metacharacters (like ``.*``) or
    non-alphanumeric characters are left untouched.
    """
    if len(pattern) > _SHORT_ALPHA_PATTERN_MAX_LEN:
        return False
    # Only apply to purely alphanumeric patterns (letters + digits).
    # Patterns like "P-256" or "3DES" or "sha1" are handled differently.
    return pattern.isalnum()


def _compile_pattern(pattern: str) -> re.Pattern[str]:
    """Compile a single pattern string into a regex.

    Rules:
    - Short alphanumeric patterns get negative lookbehind/lookahead to
      prevent matching inside longer words.
    - Version patterns with hyphens/underscores (SHA-256, AES_128) allow
      flexible separators: hyphen, underscore, space, or nothing.
    - All patterns are case-insensitive.
    """
    escaped = pattern

    # For patterns that contain a regex metacharacter already (e.g. "hmac.*sha1"),
    # compile them as-is (they are intentional regexes).
    if any(ch in pattern for ch in (".*", ".+", "\\", "[", "]", "(", ")", "|")):
        return re.compile(escaped, re.IGNORECASE)

    # Flexible separators: if the pattern contains hyphens or underscores
    # between meaningful parts, allow [-_ ]? as separator.
    # Example: "SHA-256" -> "SHA[-_ ]?256", "AES_128" -> "AES[-_ ]?128"
    if "-" in pattern or "_" in pattern:
        # Replace hyphens and underscores with a flexible separator group.
        flexible = re.sub(r"[-_]", r"[-_ ]?", pattern)
        # Escape any remaining regex-special chars (like dots in "TLSv1.0").
        # But we already inserted our regex group, so escape carefully.
        # Since we only replaced - and _, the rest should be literal.
        # Add word boundaries for these version-style patterns.
        return re.compile(r"(?<![a-zA-Z0-9])" + flexible + r"(?![a-zA-Z0-9])", re.IGNORECASE)

    # Short alphanumeric patterns: add smart boundaries.
    if _needs_smart_boundaries(pattern):
        return re.compile(
            r"(?<![a-zA-Z0-9])" + re.escape(pattern) + r"(?![a-zA-Z0-9])",
            re.IGNORECASE,
        )

    # Longer literal patterns: escape and use word boundaries.
    escaped = re.escape(pattern)
    return re.compile(r"(?<![a-zA-Z0-9])" + escaped + r"(?![a-zA-Z0-9])", re.IGNORECASE)


def compile_patterns(
    algorithms: dict[str, AlgorithmInfo] | None = None,
) -> list[_CompiledPattern]:
    """Compile all algorithm patterns into ready-to-use regexes.

    Patterns are compiled once and reused across all files for performance.

    Args:
        algorithms: Pre-loaded algorithm database. Loads default if None.

    Returns:
        List of compiled pattern objects with their algorithm IDs.
    """
    db = algorithms or load_algorithms()
    compiled: list[_CompiledPattern] = []

    for algo_id, info in db.items():
        for pattern in info.patterns:
            try:
                regex = _compile_pattern(pattern)
                compiled.append(
                    _CompiledPattern(
                        algorithm_id=algo_id,
                        regex=regex,
                        raw_pattern=pattern,
                    )
                )
            except re.error:
                # Skip malformed patterns — never raise on bad data.
                continue

    return compiled


def _is_binary(data: bytes) -> bool:
    """Detect binary content by checking for null bytes in the first chunk."""
    return _NULL_BYTE in data[:_BINARY_CHECK_SIZE]


def _read_file_lines(path: Path) -> list[str] | None:
    """Read a file and return its lines, or None if unreadable/binary.

    Skips binary files (null byte detection) and files that cannot be
    decoded. Uses utf-8 with errors='replace' as fallback.

    Args:
        path: Path to the file.

    Returns:
        List of lines (with newlines stripped), or None if skipped.
    """
    try:
        raw = path.read_bytes()
    except OSError:
        return None

    if _is_binary(raw):
        return None

    try:
        text = raw.decode("utf-8", errors="replace")
    except (UnicodeDecodeError, ValueError):
        return None

    return text.splitlines()


def scan_file(
    path: Path,
    compiled_patterns: list[_CompiledPattern],
) -> list[Finding]:
    """Scan a single file for cryptographic pattern matches.

    Args:
        path: Path to the source file.
        compiled_patterns: Pre-compiled regex patterns.

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
        for cp in compiled_patterns:
            match = cp.regex.search(line)
            if match is None:
                continue

            dedup_key = (file_str, line_idx, cp.algorithm_id)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            findings.append(
                Finding(
                    file_path=path,
                    line_number=line_idx,
                    matched_text=match.group(0),
                    algorithm_id=cp.algorithm_id,
                    source="source_code",
                    context=line.strip(),
                )
            )

    return findings


def scan_source_files(
    root: Path,
    algorithms: dict[str, AlgorithmInfo] | None = None,
) -> list[Finding]:
    """Scan source code files for cryptographic algorithm usage.

    Walks the directory tree, reads each source file, and matches
    pre-compiled regex patterns from the algorithm database.

    Args:
        root: Root directory to scan.
        algorithms: Pre-loaded algorithm database. Loads default if None.

    Returns:
        List of findings from source code analysis, sorted by
        (file_path, line_number).
    """
    root = root.resolve()
    compiled = compile_patterns(algorithms)

    files = walk_files(root, extensions=SOURCE_EXTENSIONS)
    all_findings: list[Finding] = []

    for file_path in files:
        try:
            file_findings = scan_file(file_path, compiled)
            all_findings.extend(file_findings)
        except Exception:
            # Never raise on individual file errors — skip and continue.
            continue

    # Sort by file path, then line number (None sorts first).
    all_findings.sort(key=lambda f: (str(f.file_path), f.line_number or 0))
    return all_findings
