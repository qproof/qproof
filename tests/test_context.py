"""Tests for context and confidence scoring (QP-016)."""

from pathlib import Path

from qproof.classifier.context import classify_context, enrich_findings
from qproof.models import (
    AlgorithmInfo,
    ClassifiedFinding,
    Finding,
    QuantumRisk,
)


def _make_classified(
    file_path: str = "src/auth.py",
    line_content: str = "key = RSA.generate(2048)",
    source: str = "source_code",
    algorithm_id: str = "RSA",
) -> ClassifiedFinding:
    """Create a ClassifiedFinding for testing."""
    finding = Finding(
        file_path=Path(file_path),
        line_number=10,
        matched_text="RSA",
        algorithm_id=algorithm_id,
        source=source,
        context=line_content,
    )
    algo = AlgorithmInfo(
        id=algorithm_id,
        name=algorithm_id,
        type="asymmetric",
        quantum_risk=QuantumRisk.VULNERABLE,
        reason="Broken by Shor's algorithm",
        replacement="ML-KEM",
    )
    return ClassifiedFinding(
        finding=finding,
        algorithm=algo,
        quantum_risk=QuantumRisk.VULNERABLE,
        replacement="ML-KEM",
        reason="Broken by Shor's algorithm",
    )


# ---------- context tests ----------


def test_context_test_file() -> None:
    """File under tests/ directory gets context 'test'."""
    ctx, _ = classify_context("tests/test_crypto.py", "import RSA", "source_code")
    assert ctx == "test"


def test_context_test_file_pattern() -> None:
    """File matching test_* pattern gets context 'test'."""
    ctx, _ = classify_context("test_auth.py", "RSA key", "source_code")
    assert ctx == "test"


def test_context_test_suffix() -> None:
    """File matching *_test.py pattern gets context 'test'."""
    ctx, _ = classify_context("crypto_test.py", "RSA key", "source_code")
    assert ctx == "test"


def test_context_docs() -> None:
    """README.md gets context 'docs'."""
    ctx, _ = classify_context("README.md", "RSA is used here", "source_code")
    assert ctx == "docs"


def test_context_docs_directory() -> None:
    """Files under docs/ get context 'docs'."""
    ctx, _ = classify_context("docs/security.rst", "RSA", "source_code")
    assert ctx == "docs"


def test_context_build() -> None:
    """Dockerfile gets context 'build'."""
    ctx, _ = classify_context("Dockerfile", "RUN openssl", "source_code")
    assert ctx == "build"


def test_context_build_makefile() -> None:
    """Makefile gets context 'build'."""
    ctx, _ = classify_context("Makefile", "openssl", "source_code")
    assert ctx == "build"


def test_context_comment_hash() -> None:
    """Line starting with # gets context 'comment'."""
    ctx, _ = classify_context("src/auth.py", "# RSA is deprecated", "source_code")
    assert ctx == "comment"


def test_context_comment_double_slash() -> None:
    """Line starting with // gets context 'comment'."""
    ctx, _ = classify_context("src/auth.js", "// use RSA-2048", "source_code")
    assert ctx == "comment"


def test_context_comment_block() -> None:
    """Line starting with /* gets context 'comment'."""
    ctx, _ = classify_context("src/auth.c", "/* RSA encryption */", "source_code")
    assert ctx == "comment"


def test_context_runtime() -> None:
    """Normal source file gets context 'runtime'."""
    ctx, _ = classify_context("src/auth.py", "key = RSA.generate(2048)", "source_code")
    assert ctx == "runtime"


# ---------- confidence tests ----------


def test_confidence_import() -> None:
    """Import statement gets confidence 'high'."""
    _, conf = classify_context("src/auth.py", "from cryptography.hazmat import RSA", "source_code")
    assert conf == "high"


def test_confidence_import_require() -> None:
    """require() statement gets confidence 'high'."""
    _, conf = classify_context("src/auth.js", "const crypto = require('crypto')", "source_code")
    assert conf == "high"


def test_confidence_function_call() -> None:
    """Function call with crypto method gets confidence 'high'."""
    _, conf = classify_context("src/auth.py", "key = RSA.generate(2048)", "source_code")
    assert conf == "high"


def test_confidence_encrypt_call() -> None:
    """Encrypt call gets confidence 'high'."""
    _, conf = classify_context("src/auth.py", "cipher.encrypt(data)", "source_code")
    assert conf == "high"


def test_confidence_dependency() -> None:
    """Dependency scanner source gets confidence 'high'."""
    _, conf = classify_context("requirements.txt", "cryptography==3.4", "dependency")
    assert conf == "high"


def test_confidence_config() -> None:
    """Config scanner source gets confidence 'high'."""
    _, conf = classify_context("nginx.conf", "ssl_protocols TLSv1.2", "config")
    assert conf == "high"


def test_confidence_comment_low() -> None:
    """Comment context gets confidence 'low'."""
    _, conf = classify_context("src/auth.py", "# RSA is deprecated", "source_code")
    assert conf == "low"


def test_confidence_docs_low() -> None:
    """Docs context gets confidence 'low'."""
    _, conf = classify_context("README.md", "We use RSA for encryption", "source_code")
    assert conf == "low"


def test_confidence_string_literal() -> None:
    """Plain string reference gets confidence 'medium'."""
    _, conf = classify_context("src/auth.py", 'algo = "RSA-OAEP"', "source_code")
    assert conf == "medium"


# ---------- enrich_findings ----------


def test_enrich_findings_sets_fields() -> None:
    """enrich_findings sets context and confidence on ClassifiedFinding."""
    cf = _make_classified(
        file_path="tests/test_crypto.py",
        line_content="from cryptography import RSA",
        source="source_code",
    )
    enrich_findings([cf])
    assert cf.context == "test"
    # Test context overrides to low even though import pattern matches
    # because test + comment/docs → low confidence
    # Actually: test context doesn't force low. Only comment/docs do.
    # Import pattern → high confidence, test context stays.
    assert cf.confidence == "high"


def test_enrich_findings_runtime_medium() -> None:
    """Runtime finding without special patterns gets medium confidence."""
    cf = _make_classified(
        file_path="src/auth.py",
        line_content='algo = "RSA-OAEP"',
        source="source_code",
    )
    enrich_findings([cf])
    assert cf.context == "runtime"
    assert cf.confidence == "medium"


def test_enrich_findings_dependency() -> None:
    """Dependency finding gets high confidence."""
    cf = _make_classified(
        file_path="requirements.txt",
        line_content="cryptography==3.4",
        source="dependency",
    )
    enrich_findings([cf])
    assert cf.confidence == "high"


def test_default_values_before_enrichment() -> None:
    """ClassifiedFinding defaults to medium/runtime before enrichment."""
    cf = _make_classified()
    assert cf.confidence == "medium"
    assert cf.context == "runtime"
