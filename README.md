# qproof

**Find quantum-vulnerable cryptography in your codebase.**

qproof scans source code and dependencies for cryptographic algorithms, classifies their quantum risk, and recommends post-quantum replacements — with references to NIST, CNSA 2.0, ENISA, and EU standards.

[![CI](https://github.com/qproof/qproof/actions/workflows/ci.yml/badge.svg)](https://github.com/qproof/qproof/actions)
[![PyPI](https://img.shields.io/pypi/v/qproof)](https://pypi.org/project/qproof/)
[![Python](https://img.shields.io/pypi/pyversions/qproof)](https://pypi.org/project/qproof/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

<!-- ![qproof demo](docs/demo.gif) -->

## Why qproof?

Quantum computers will break RSA, ECDSA, and Diffie-Hellman. The EU requires full PQC migration by 2035 (high-risk systems by 2030). NSA's CNSA 2.0 mandates transition starting now.

**qproof tells you exactly where you're exposed and what to do about it.**

- Scans Python, JavaScript/TypeScript, Go, Java, Rust source code
- Detects crypto dependencies in package.json, requirements.txt, go.mod, and more
- Classifies each finding: **VULNERABLE**, **PARTIAL**, or **SAFE**
- Recommends post-quantum replacements (ML-KEM, ML-DSA per FIPS 203/204)
- References NIST, CNSA 2.0, ENISA, EU 2024/1101, CCN-STIC 221/807
- Outputs Rich terminal tables or JSON for CI/CD integration

## Quick start

```bash
pip install qproof
qproof scan .
```

## Installation

```bash
# From PyPI
pip install qproof

# From source
git clone https://github.com/qproof/qproof.git
cd qproof
pip install -e ".[dev]"
```

Requires Python 3.10+.

## Usage

```bash
# Scan current directory — Rich terminal output
qproof scan .

# Scan a specific path
qproof scan /path/to/project

# JSON output (for CI/CD)
qproof scan . --format json

# Save JSON report to file
qproof scan . --format json --output report.json
```

## What it detects

| Category | Examples | Risk |
|----------|----------|------|
| Asymmetric crypto | RSA, ECDSA, ECDH, Ed25519, DH | VULNERABLE |
| Broken hashes | MD5, SHA-1 | VULNERABLE |
| Deprecated ciphers | DES, 3DES, RC4 | VULNERABLE |
| Partial-risk symmetric | AES-128, Blowfish | PARTIAL |
| Quantum-safe | AES-256, SHA-256, SHA-3, ChaCha20 | SAFE |

43 algorithms classified. 13 libraries mapped (Python + npm).

## Output example

```
+------------+------------------+----------+------------------+
| Risk       | Algorithm        | File     | Replacement      |
+------------+------------------+----------+------------------+
| VULNERABLE | RSA              | app.py:5 | ML-KEM (FIPS 203)|
| VULNERABLE | SHA-1            | app.py:9 | SHA-256          |
| SAFE       | AES-256          | app.py:12| No change needed |
+------------+------------------+----------+------------------+

Quantum Ready Score: 33.3% — 1 SAFE / 3 total
```

## Standards referenced

qproof maps every algorithm to formal standards for compliance reporting:

- **NIST**: SP 800-131A Rev.2, FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 180-4, FIPS 197
- **NSA CNSA 2.0**: Transition timeline 2025-2035
- **ENISA**: PQC Integration Study, ECCG Agreed Cryptographic Mechanisms v2
- **EU**: Recommendation 2024/1101, Coordinated PQC Roadmap (2030/2035)
- **CCN (Spain)**: CCN-STIC 221, CCN-STIC 807 (ENS compliance)

## Supported dependency files

| File | Ecosystem |
|------|-----------|
| requirements.txt | Python |
| Pipfile | Python |
| pyproject.toml | Python |
| package.json | npm |
| go.mod | Go |
| Cargo.toml | Rust |
| pom.xml | Java/Maven |
| build.gradle | Java/Gradle |

## Roadmap

- [x] v0.1 — Regex source scanner, dependency scanner, Rich/JSON output
- [ ] v0.2 — AST scanner (tree-sitter), SARIF output, GitHub Action
- [ ] v0.3 — CBOM CycloneDX, config scanner (TLS/JWT/SSH), Go/Java source support
- [ ] v1.0 — SaaS dashboard, compliance PDF reports

## Contributing

Contributions welcome. Please open an issue first to discuss changes.

```bash
git clone https://github.com/qproof/qproof.git
cd qproof
pip install -e ".[dev]"
pytest -v
ruff check qproof/ tests/
```

## License

MIT — see [LICENSE](LICENSE).

---

Built by the [EYES](https://github.com/eyes) team. Scanning the quantum horizon.
