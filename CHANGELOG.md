# Changelog

All notable changes to qproof will be documented in this file.

## [0.3.0] — 2026-03-05

### Added
- CBOM CycloneDX v1.6 output format (`--format cbom`) for cryptographic asset inventory
- OID mapping for 12 algorithms (ITU-T X.660)
- CycloneDX primitive classification (pke, signature, blockcipher, hash, kdf, mac)
- Deduplication: same algorithm grouped into single component with multiple occurrences
- Config scanner for server/infrastructure crypto settings
- TLS version detection (nginx, Apache, HAProxy, OpenSSL, .env)
- SSH key type detection (.pub files) and SSH config cipher/MAC/KEX analysis
- JWT algorithm detection (RS256, ES256) in JSON, YAML, and .env files
- OpenSSL config scanning (default_md, default_bits)
- PEM/certificate header detection (RSA, DSA, ECDSA private keys)

### Changed
- CLI `--format` now accepts `text`, `json`, `sarif`, `cbom`
- Scan pipeline now includes config scanner (source + deps + config)

## [0.2.0] — 2026-03-05

### Added
- SARIF v2.1.0 output format (`--format sarif`) for GitHub Security tab integration
- GitHub Actions workflow example in README
- Rules per unique algorithm in SARIF (deduplication)
- Severity mapping: VULNERABLE→error, PARTIAL→warning, SAFE→note

### Changed
- CLI `--format` now accepts `text`, `json`, `sarif`

## [0.1.0] — 2026-03-05

### Added
- Source code scanner with regex detection and smart word boundaries
- Dependency scanner supporting 8 manifest formats (requirements.txt, package.json, go.mod, Cargo.toml, pom.xml, build.gradle, Pipfile, pyproject.toml)
- Algorithm database with 43 algorithms classified by quantum risk
- Formal references to NIST SP 800-131A, CNSA 2.0, ENISA PQC, EU 2024/1101, CCN-STIC 221/807
- EU/US transition deadlines per algorithm
- Library database mapping 13 crypto libraries (Python + npm)
- Classifier enriching findings with quantum risk and replacement recommendations
- Migration advisor with severity-prefixed recommendations
- Rich terminal output with color-coded risk table and quantum-ready score
- JSON output for CI/CD integration
- CLI: `qproof scan <path> [--format text|json] [--output file]`

### Known limitations
- Source scanner includes comments (no AST filtering yet)
- Dependency parsers for pyproject.toml/Cargo.toml are line-based
- No CBOM output yet
