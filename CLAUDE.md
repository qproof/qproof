# CLAUDE.md — qproof

## What is qproof
Open source Python CLI tool that scans codebases for quantum-vulnerable cryptography. Detects algorithms, classifies quantum risk (VULNERABLE/PARTIAL/SAFE), and recommends post-quantum replacements with formal references to NIST, CNSA 2.0, ENISA, CCN-STIC, and EU standards.

qproof is a node/vertical of EYES, not a separate company. MIT license. Solo project by the CTO until traction is validated.

## Stack
- **Language**: Python 3.10+ (strict typing, no `any`)
- **CLI**: Click
- **Output**: Rich (terminal), JSON, SARIF v2.1.0
- **Data**: PyYAML (algorithm/library databases)
- **Testing**: pytest + ruff (linter)
- **Package**: pyproject.toml (PEP 621), editable install via `pip install -e ".[dev]"`
- **Distribution**: PyPI (`pip install qproof`)
- **License**: MIT

## Architecture

```
qproof/
├── qproof/
│   ├── __init__.py          # __version__
│   ├── cli.py               # Click CLI — full pipeline wired
│   ├── models.py            # QuantumRisk, Finding, AlgorithmInfo, ClassifiedFinding, ScanResult
│   ├── scanner/
│   │   ├── source.py        # Regex scanner — smart word boundaries, dedup, binary skip
│   │   ├── deps.py          # Dependency scanner — 8 manifest formats
│   │   └── config.py        # Config scanner (TLS, JWT, SSH) — future
│   ├── classifier/
│   │   └── quantum_risk.py  # Enriches findings with risk + replacement + reason
│   ├── advisor/
│   │   └── migration.py     # CRITICAL/WARNING/INFO migration recommendations
│   ├── data/
│   │   ├── algorithms.yaml  # 43 algorithms with quantum risk + formal references + deadlines
│   │   ├── libraries.yaml   # 13 libraries mapped to algorithms
│   │   └── loader.py        # YAML loader with caching and validation
│   ├── output/
│   │   ├── text.py          # Rich terminal — color-coded table, summary panel, score
│   │   ├── json_out.py      # Structured JSON with metadata, summary, findings
│   │   └── sarif.py         # SARIF v2.1.0 for GitHub Security tab
│   └── utils/
│       └── file_walker.py   # Directory traversal with exclusions
├── tests/
│   ├── fixtures/            # Sample projects + false positives
│   ├── test_cli.py
│   ├── test_models.py
│   ├── test_file_walker.py
│   ├── test_algorithms_db.py
│   ├── test_source_scanner.py
│   ├── test_deps_scanner.py
│   ├── test_classifier.py
│   ├── test_advisor.py
│   ├── test_text_output.py
│   ├── test_json_output.py
│   └── test_sarif_output.py
├── pyproject.toml
├── .github/workflows/ci.yml
├── CLAUDE.md
└── README.md
```

## Working pipeline

```bash
qproof scan <path>                          # Rich terminal output
qproof scan <path> --format json            # JSON to stdout
qproof scan <path> --format json -o out.json # JSON to file
qproof scan <path> --format sarif -o out.sarif # SARIF for GitHub Security
```

Pipeline flow:
```
file_walker.walk_files()
    → scanner/source.py (regex on source code)
    → scanner/deps.py (package.json, requirements.txt, go.mod, etc.)
    → classifier/quantum_risk.py (enrich with risk/replacement)
    → advisor/migration.py (generate migration messages)
    → output/text.py or output/json_out.py or output/sarif.py (render)
```

## Key models (models.py)

- `QuantumRisk`: Enum — VULNERABLE | PARTIAL | SAFE | UNKNOWN
- `Finding`: file_path, line_number, matched_text, algorithm_id, source ("source" | "dependency" | "config"), context
- `AlgorithmInfo`: id, name, type, quantum_risk, reason, replacement, patterns
- `ClassifiedFinding`: finding + algorithm + quantum_risk + replacement + reason
- `ScanResult`: path, findings, total_files_scanned, scan_duration_seconds
  - Properties: vulnerable_count, partial_count, safe_count, quantum_ready_score

## Data layer

- `algorithms.yaml`: 43 algorithms — each has name, type, quantum_risk, reason, replacement, patterns, references (nist/cnsa/enisa/eu/ccn), deadlines
- `libraries.yaml`: 13 libraries — each has ecosystem, package_name, description, exposes (list of algorithm IDs), default_risk
- `loader.py`: `load_algorithms()` and `load_libraries()` with global caching. Raises FileNotFoundError or ValueError on bad data.
- **Cross-reference rule**: libraries.yaml `exposes` must only reference algorithm IDs that exist in algorithms.yaml

## Scanner rules

### Source scanner (source.py)
- Patterns compiled once at scan start, not per file
- Case-insensitive matching
- Smart word boundaries: short patterns (DES, DH, RC4, DSA) use negative lookbehind/lookahead to avoid matching inside common words (description, desktop, design)
- Version patterns (SHA-1, AES-256) allow flexible separators: hyphen, underscore, space, or none
- Dedup: max 1 Finding per (file_path, line_number, algorithm_id)
- Binary files skipped (null byte detection or encoding error)
- Encoding: utf-8 with errors='replace'
- v0.1 does NOT filter comments — scans everything. AST scanner (v0.2) will refine.
- source field: "source"

### Deps scanner (deps.py)
- Formats supported: requirements.txt, Pipfile, pyproject.toml, package.json, go.mod, Cargo.toml, pom.xml, build.gradle
- Matches package names against libraries.yaml
- Emits one Finding per exposed algorithm per matched library
- pyproject.toml/Cargo.toml parsers are line-based, not full TOML parsers
- source field: "dependency"

### Classifier (quantum_risk.py)
- Looks up each Finding's algorithm_id in algorithms.yaml
- Returns ClassifiedFinding with quantum_risk, replacement, reason

### Advisor (migration.py)
- Generates severity-prefixed messages: CRITICAL (VULNERABLE), WARNING (PARTIAL), INFO (SAFE)

## Formal references in algorithms.yaml

Each algorithm has a `references` dict grouped by standards body:
- `nist`: NIST SP 800-131A Rev.2/Rev.3, FIPS 203/204/180-4/197, SP 800-208
- `cnsa`: NSA CNSA 2.0 (Sep 2022, updated May 2025)
- `enisa`: ENISA PQC reports, ECCG ACM v2 (May 2025)
- `eu`: EU Recommendation 2024/1101, Coordinated Implementation Roadmap (Jun 2025)
- `ccn`: CCN-STIC 221 (mecanismos autorizados), CCN-STIC 807 (criptología ENS)
- `ietf`: RFCs for protocols (TLS, SSH, JWT)

VULNERABLE asymmetric algorithms have `deadlines`:
- `eu_high_risk`: "2030-12-31"
- `eu_full_transition`: "2035-12-31"
- `cnsa_prefer` / `cnsa_mandatory` / `cnsa_exclusive`

## Commands

```bash
# Install (development)
pip install -e ".[dev]"

# Run scan
qproof scan .
qproof scan . --format json
qproof scan . --format json -o report.json

# Tests (194 passing)
pytest -v
pytest -v tests/test_source_scanner.py  # specific module

# Lint
ruff check qproof/ tests/

# Validate data layer
python -c "from qproof.data.loader import load_algorithms, load_libraries; a=load_algorithms(); l=load_libraries(); print(f'{len(a)} algos, {len(l)} libs')"

# Smoke test
qproof scan tests/fixtures/sample_project
```

## Coding conventions

- Type hints on all functions (return types included)
- Docstrings on all public functions
- No `any` — use explicit types
- Use `pathlib.Path` not string paths
- Scanner functions return `list[Finding]`, never raise on file errors — return empty list
- Use `from __future__ import annotations` if needed for forward refs
- No `print()` for output — use Rich console or return data structures

## Ticket execution rules

- Do not expand scope beyond what the ticket specifies
- If the ticket is too large, say so and propose a split
- If requirements are ambiguous, state assumptions explicitly
- Prefer the smallest safe implementation
- Avoid touching unrelated files
- Preserve existing architecture

## Validation before commit

- `pytest -v` — all tests pass
- `ruff check qproof/ tests/` — no lint errors
- Manual smoke test if scanner behavior changed
- No files outside scope modified

## Response format

1. Summary of changes
2. Files created/modified with full paths
3. Commands executed and results
4. Risks or known limitations
5. Suggested commit message

## Git conventions

```bash
# Ticket commits
git commit -m "QP-XXX: short description"

# Checkpoint commits (mid-ticket)
git commit -m "checkpoint(QP-XXX): what was done — state: lint PASS, test PASS/FAIL"
```

## Security rules

- Never include real secrets, API keys, or tokens in code or tests
- Never hardcode credentials — use environment variables
- algorithms.yaml references are public standards — no proprietary data
- Test fixtures use fake/dummy crypto keys only

## What NOT to do

- Do not add dependencies without explicit approval in the ticket
- Do not refactor modules outside the ticket scope
- Do not change models.py unless the ticket explicitly says so
- Do not add AST/tree-sitter scanning (reserved for v0.2)
- Do not implement CBOM output (separate ticket)
- Do not connect to external APIs or services

## MVP ticket sequence

```
QP-001 ✅ Scaffolding (CLI, models, file_walker, tests)
QP-002 ✅ Algorithm database (43 algos + formal refs + 13 libs + loader)
QP-003 ✅ Source scanner (regex detection, smart word boundaries)
QP-004 ✅ Deps scanner (8 manifest formats)
QP-005 ✅ Classifier + Advisor (risk enrichment + migration messages)
QP-006 ✅ Rich terminal output (color-coded table + score)
QP-007 ✅ JSON output (structured with metadata)
QP-008 ✅ Integration tests + README + PyPI prep
QP-009 ✅ SARIF output (GitHub Security tab integration)
QP-010 ⬜ GitHub Action (action.yml for CI/CD)
```

## Known limitations (v0.1)

- Source scanner scans all text including comments — AST filtering in v0.2
- createCipheriv pattern may trigger without explicit AES-128 context
- pyproject.toml/Cargo.toml dependency parsers are line-based, not full TOML
- Loader caching uses module globals — may need reset in future integration tests
- bcrypt classified as PARTIAL (uses Blowfish internally)

## Post-MVP roadmap (not in scope for current tickets)

- v0.2: AST scanner (tree-sitter), GitHub Action marketplace
- v0.3: CBOM CycloneDX output, config scanner (TLS/JWT/SSH), Go/Java support
- v1.0: Dashboard SaaS (Next.js + Supabase), GitHub OAuth, compliance PDF reports

## Agent delegation rules

- architect: design decisions, trade-offs, new module planning
- builder: implementation (default for all QP tickets)
- tester: validation after implementation
- researcher: investigate external APIs, standards updates
- security-auditor: review patterns, false positives, data integrity