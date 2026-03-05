# CLAUDE.md — qproof

## What is qproof
Open source Python CLI tool that scans codebases for quantum-vulnerable cryptography. Detects algorithms, classifies quantum risk (VULNERABLE/PARTIAL/SAFE), and recommends post-quantum replacements with formal references to NIST, CNSA 2.0, ENISA, CCN-STIC, and EU standards.

qproof is a node/vertical of EYES, not a separate company. MIT license. Solo project by the CTO until traction is validated.

## Stack
- **Language**: Python 3.10+ (strict typing, no `any`)
- **CLI**: Click
- **Output**: Rich (terminal), JSON, SARIF v2.1.0, CBOM CycloneDX v1.6
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
│   │   └── config.py        # Config scanner (TLS, JWT, SSH, OpenSSL, PEM)
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
│   │   ├── sarif.py         # SARIF v2.1.0 for GitHub Security tab
│   │   └── cbom.py          # CycloneDX v1.6 CBOM for EU compliance
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
│   ├── test_sarif_output.py
│   ├── test_cbom_output.py
│   └── test_config_scanner.py
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
qproof scan <path> --format cbom -o cbom.json  # CycloneDX CBOM for compliance
```

Pipeline flow:
```
file_walker.walk_files()
    → scanner/source.py (regex on source code)
    → scanner/deps.py (package.json, requirements.txt, go.mod, etc.)
    → scanner/config.py (nginx, SSH, OpenSSL, JWT, PEM configs)
    → classifier/quantum_risk.py (enrich with risk/replacement)
    → advisor/migration.py (generate migration messages)
    → output/text.py or json_out.py or sarif.py or cbom.py (render)
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

# Tests (228 passing)
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
- Do not add new output formats without a ticket
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
QP-010 ✅ GitHub Action (action.yml for CI/CD) + PyPI v0.2.0
QP-011 ✅ CBOM CycloneDX v1.6 (cryptographic asset inventory)
QP-012 ✅ Config scanner (TLS, SSH, JWT, OpenSSL, PEM)
```

## Known limitations (v0.1)

- Source scanner scans all text including comments — AST filtering in v0.2
- createCipheriv pattern may trigger without explicit AES-128 context
- pyproject.toml/Cargo.toml dependency parsers are line-based, not full TOML
- Loader caching uses module globals — may need reset in future integration tests
- bcrypt classified as PARTIAL (uses Blowfish internally)

## Post-MVP roadmap (not in scope for current tickets)

- v0.3: AST scanner (tree-sitter), GitHub Action marketplace, Go/Java source support
- v1.0: Dashboard SaaS (Next.js + Supabase), GitHub OAuth, compliance PDF reports

## Agent delegation rules

- architect: design decisions, trade-offs, new module planning
- builder: implementation (default for all QP tickets)
- tester: validation after implementation
- researcher: investigate external APIs, standards updates
- security-auditor: review patterns, false positives, data integrity


# qproof — Fase 0: Credibilidad + Adopción CI/CD

> **Meta**: Convertir qproof de "scanner que lista algoritmos" a "guardrail CI/CD que bloquea deuda criptográfica nueva en PRs".
> **Base**: v0.3.0 (3 scanners, 4 outputs, 43 algos, 228 tests, GitHub Action)
> **Timeline**: ~2 semanas, 2-3h/día
> **Release target**: v0.4.0
> **Repo**: github.com/qproof/qproof

---

## Mapa de tickets

| ID | Título | Depende de | Estimación | Riesgo |
|---|---|---|---|---|
| QP-013 | Baseline snapshot | — | 2-3h | BAJO |
| QP-014 | Diff mode (solo findings nuevos) | QP-013 | 3-4h | MEDIO |
| QP-015 | Policy-as-code (qproof.yml) | — | 3-4h | MEDIO |
| QP-016 | Confidence + Context scoring | — | 2-3h | BAJO |
| QP-017 | Severity model + finding enrichment | QP-016 | 2-3h | BAJO |
| QP-018 | Integration tests + example repo + Action update | QP-013→017 | 3-4h | BAJO |

**Orden de ejecución recomendado**:
- Día 1-2: QP-016 (confidence/context) → QP-017 (severity) — independientes, enriquecen el modelo de datos
- Día 3-4: QP-013 (baseline) → QP-014 (diff) — la feature nuclear de Fase 0
- Día 5-6: QP-015 (policy-as-code) — la que convierte qproof en guardrail real
- Día 7: QP-018 (integration + example repo) — cierre, release v0.4.0

**Paralelismo posible**: QP-016/017 y QP-013 son independientes. Si quieres acelerar, lanza QP-013 y QP-016 en paralelo.

---

## QP-013 — Baseline Snapshot

### Objetivo
Implementar `qproof scan --baseline <file>` que genera un snapshot JSON de todos los findings actuales de un repo. Este snapshot es la referencia para el diff mode.

### Contexto
Sin baseline, qproof reporta TODO lo que encuentra — útil para auditorías, inútil para CI/CD en PRs. Nadie quiere 400 findings de legacy en cada PR. El baseline captura el estado actual ("esto ya lo sabemos") y permite que el diff mode (QP-014) reporte solo lo nuevo.

### Alcance
- Nuevo flag `--baseline <output-file>` en `qproof scan`
- Genera un archivo JSON con: metadata (timestamp, commit hash si disponible, qproof version) + lista de findings hasheados
- Cada finding tiene un hash determinista basado en: file + line + algorithm + source_type (para dedup estable)
- El baseline es un archivo que se commitea al repo (como un lockfile)

### Archivos / zona afectada
- `qproof/cli.py` — nuevo flag `--baseline`
- `qproof/models.py` — método `finding_hash()` en Finding o ClassifiedFinding
- `qproof/baseline.py` (NUEVO) — lógica de generación y carga de baseline
- `tests/test_baseline.py` (NUEVO)

### Restricciones
- El hash debe ser determinista: mismo file + line + algorithm = mismo hash siempre
- No depender de ordering de findings (sort antes de hashear)
- El baseline file debe ser human-readable (JSON indentado)
- No romper el pipeline actual de scan → classify → advise → output
- El flag `--baseline` es MUTUAMENTE EXCLUYENTE con `--diff` (que viene en QP-014)

### Criterios de aceptación
1. `qproof scan . --baseline baseline.json` genera archivo válido
2. El JSON contiene: `version`, `generated_at`, `commit` (o null), `findings_count`, `findings` (lista de hashes + metadata mínima)
3. Ejecutar dos veces sobre el mismo código produce el mismo output (determinismo)
4. `--baseline` funciona con todos los scanners (source, deps, config)
5. Tests: mínimo 10 tests cubriendo generación, determinismo, edge cases (repo vacío, archivo no escribible)

### Prompt para Claude Code

```
TICKET: QP-013 — Baseline Snapshot

OBJETIVO: Implementar `qproof scan --baseline <output-file>` que genera un snapshot JSON de findings actuales para usar como referencia en diff mode futuro.

CONTEXTO:
- Repo: qproof (Python CLI, Click, Rich)
- v0.3.0 tiene: source scanner, deps scanner, config scanner, classifier, advisor
- Pipeline actual: walk_files → scan → classify → advise → output
- El baseline se inserta DESPUÉS de classify (usa ClassifiedFinding)

IMPLEMENTACIÓN:

1. Crear qproof/baseline.py:
   - FindingHash: dataclass con campos para hash determinista
   - generate_baseline(findings: list[ClassifiedFinding]) -> dict
     - Para cada finding: hash = sha256(f"{file}:{line}:{algorithm}:{source}")
     - Sort por hash para determinismo
     - Return: {"version": "1.0", "qproof_version": __version__, "generated_at": ISO timestamp, "commit": git_commit_or_null(), "findings_count": N, "findings": [{"hash": ..., "file": ..., "line": ..., "algorithm": ..., "risk": ..., "source": ...}]}
   - load_baseline(path: str) -> dict (para QP-014)
   - git_commit_or_null(): intenta `git rev-parse HEAD`, retorna None si falla

2. Modificar qproof/cli.py:
   - Añadir option: @click.option('--baseline', type=click.Path(), default=None, help='Generate baseline snapshot file')
   - Si --baseline: después de classify, llamar generate_baseline() y escribir JSON
   - Si --baseline: NO generar output normal (rich/json/sarif/cbom), solo el baseline
   - Validar que --baseline y --diff no se usen juntos (QP-014 añadirá --diff)

3. Crear tests/test_baseline.py:
   - test_baseline_generation: fixture con findings conocidos → genera baseline → verifica estructura
   - test_baseline_determinism: mismos findings dos veces → mismo output
   - test_baseline_different_order: findings en orden distinto → mismo output (sorted)
   - test_baseline_empty: sin findings → baseline válido con findings_count: 0
   - test_baseline_hash_uniqueness: findings diferentes → hashes diferentes
   - test_baseline_includes_all_scanners: source + deps + config findings todos presentes
   - test_baseline_git_commit: mock git → commit aparece
   - test_baseline_no_git: mock git fail → commit es null
   - test_baseline_file_write: verifica que el archivo se escribe correctamente
   - test_baseline_mutual_exclusion: --baseline + --diff → error (preparar para QP-014)

4. Validación:
   ruff check qproof/ tests/
   python -m pytest tests/ -v
   python -m qproof scan . --baseline /tmp/test-baseline.json
   cat /tmp/test-baseline.json | python -m json.tool

RESTRICCIONES:
- No romper tests existentes (228 tests deben seguir pasando)
- No modificar models.py más allá de añadir finding_hash() si es necesario
- No añadir dependencias nuevas (hashlib es stdlib)
- Mantener typing estricto

FORMATO DE RESPUESTA:
1. Resumen de cambios
2. Archivos creados/modificados
3. Comandos ejecutados
4. Resultado de tests (total pass/fail)
5. Output de ejemplo del baseline JSON
6. Riesgos pendientes

CHECKPOINT: commit después de que tests pasen:
checkpoint(QP-013): baseline snapshot generation
```

---

## QP-014 — Diff Mode (Solo Findings Nuevos)

### Objetivo
Implementar `qproof scan --diff <baseline-file>` que compara el scan actual contra un baseline existente y reporta SOLO findings nuevos o empeorados. Esta es la feature nuclear para CI/CD en PRs.

### Contexto
Con baseline (QP-013), qproof sabe "qué ya existía". El diff mode filtra el ruido del legacy y solo muestra lo que se introdujo en el PR. Esto es lo que hace que un equipo acepte qproof como check obligatorio en CI: no castiga el pasado, bloquea el futuro.

### Alcance
- Nuevo flag `--diff <baseline-file>` en `qproof scan`
- Carga el baseline, ejecuta scan normal, compara hashes
- Reporta: findings NUEVOS (no estaban en baseline), findings EMPEORADOS (mismo hash pero risk subió)
- Opcionalmente reporta findings RESUELTOS (estaban en baseline, ya no están)
- Output en cualquier formato existente (rich/json/sarif/cbom) pero solo con los findings diferenciados
- Exit code: 0 si no hay nuevos VULNERABLE/PARTIAL, 1 si hay → para CI gates

### Archivos / zona afectada
- `qproof/cli.py` — nuevo flag `--diff`
- `qproof/baseline.py` — función `diff_findings(baseline, current)`
- `qproof/models.py` — posible campo `diff_status` en ClassifiedFinding (NEW/WORSENED/RESOLVED/UNCHANGED)
- `qproof/output/*.py` — respetar filtrado por diff_status
- `tests/test_diff.py` (NUEVO)

### Restricciones
- `--diff` y `--baseline` son mutuamente excluyentes
- `--diff` sin archivo existente → error claro, no crash
- El diff NUNCA modifica el baseline file — es read-only
- Exit codes: 0 = no new debt, 1 = new debt found (para CI `set -e`)
- El diff debe funcionar aunque el baseline fue generado con una versión anterior de qproof (forward-compatible)

### Criterios de aceptación
1. `qproof scan . --diff baseline.json` muestra solo findings nuevos
2. Finding existente en baseline → no aparece en output
3. Finding nuevo (no en baseline) → aparece como NEW
4. Finding con risk escalado → aparece como WORSENED
5. Exit code 1 si hay findings NEW con risk VULNERABLE o PARTIAL
6. Exit code 0 si solo hay findings SAFE nuevos o ninguno nuevo
7. Todos los formatos de output (rich/json/sarif/cbom) respetan el filtro diff
8. Rich output muestra banner: "Comparing against baseline: <file> (N findings baselined)"
9. Tests: mínimo 12 tests

### Prompt para Claude Code

```
TICKET: QP-014 — Diff Mode

DEPENDE DE: QP-013 (baseline.py debe existir y funcionar)

OBJETIVO: Implementar `qproof scan --diff <baseline-file>` que compara scan actual contra baseline y reporta SOLO findings nuevos o empeorados. Exit code 1 si hay nueva deuda vulnerable.

CONTEXTO:
- QP-013 ya implementó baseline.py con generate_baseline() y load_baseline()
- Cada finding tiene un hash determinista (file:line:algorithm:source)
- Pipeline: walk → scan → classify → [DIFF FILTER HERE] → advise → output

IMPLEMENTACIÓN:

1. Extender qproof/baseline.py:
   - diff_findings(baseline: dict, current: list[ClassifiedFinding]) -> DiffResult
   - DiffResult: dataclass con: new_findings, worsened_findings, resolved_findings, unchanged_count
   - "new": hash no existe en baseline
   - "worsened": hash existe pero risk actual > risk baseline (SAFE→PARTIAL, PARTIAL→VULNERABLE, etc.)
   - "resolved": hash en baseline pero no en current scan
   - Comparar por hash, no por posición

2. Extender qproof/models.py:
   - Añadir campo opcional diff_status: Optional[Literal["new", "worsened", "resolved"]] = None en ClassifiedFinding
   - O crear DiffClassifiedFinding que wrappea ClassifiedFinding + status

3. Modificar qproof/cli.py:
   - Añadir option: @click.option('--diff', type=click.Path(exists=True), default=None, help='Compare against baseline file')
   - Validar: --diff y --baseline mutuamente excluyentes
   - Si --diff:
     a. Load baseline
     b. Run normal scan + classify
     c. diff_findings(baseline, classified)
     d. Filtrar: solo pasar new + worsened al advisor + output
     e. Print banner: "Comparing against baseline: {file} ({N} findings baselined)"
     f. Print summary: "{X} new, {Y} worsened, {Z} resolved"
   - Exit code: sys.exit(1) si cualquier new/worsened tiene risk VULNERABLE o PARTIAL
   - Exit code: sys.exit(0) si todos son SAFE o no hay nuevos

4. Modificar outputs para respetar diff:
   - qproof/output/text.py: añadir columna/badge [NEW] [WORSENED] si diff activo
   - qproof/output/json_out.py: añadir campo "diff_status" por finding + "diff_summary" en metadata
   - qproof/output/sarif.py: findings filtrados, añadir property "diff_status"
   - qproof/output/cbom.py: findings filtrados

5. Crear tests/test_diff.py:
   - test_diff_no_new_findings: baseline == current → exit 0, output vacío
   - test_diff_new_vulnerable: nuevo RSA → exit 1, aparece como NEW
   - test_diff_new_safe: nuevo AES-256 → exit 0 (SAFE no bloquea)
   - test_diff_worsened: SAFE→VULNERABLE → exit 1, aparece como WORSENED
   - test_diff_resolved: finding desapareció → reporta RESOLVED en summary
   - test_diff_mixed: new + unchanged → solo new en output
   - test_diff_baseline_not_found: archivo no existe → error claro
   - test_diff_baseline_invalid_json: JSON corrupto → error claro
   - test_diff_baseline_old_version: baseline v1.0 con qproof v0.4+ → funciona
   - test_diff_exit_code_zero: solo SAFE nuevos → exit 0
   - test_diff_exit_code_one: VULNERABLE nuevo → exit 1
   - test_diff_rich_output: [NEW] badge aparece en rich output

6. Validación:
   ruff check qproof/ tests/
   python -m pytest tests/ -v
   # Test funcional:
   python -m qproof scan . --baseline /tmp/baseline.json
   # Añadir un finding fake (echo "import RSA" >> /tmp/test.py)
   python -m qproof scan . --diff /tmp/baseline.json
   echo "Exit code: $?"

RESTRICCIONES:
- No romper tests existentes
- No modificar el formato del baseline file (backward compatible)
- Exit codes son la API para CI — deben ser consistentes
- El diff NO modifica el baseline (read-only)

FORMATO DE RESPUESTA:
1. Resumen de cambios
2. Archivos creados/modificados
3. Tests: total pass/fail + lista de nuevos tests
4. Output de ejemplo: scan --diff con findings nuevos
5. Exit codes verificados
6. Riesgos pendientes

CHECKPOINT: commit después de tests:
checkpoint(QP-014): diff mode — new/worsened finding detection with exit codes
```

---

## QP-015 — Policy-as-Code (qproof.yml)

### Objetivo
Implementar soporte para `qproof.yml` como archivo de configuración de políticas: ignore paths, allowlist de algoritmos, fail rules por severity, y severity overrides. Esto convierte qproof en un guardrail configurable por equipo.

### Contexto
Sin policy file, qproof es "todo o nada": o escanea todo y reporta todo, o no lo usas. Los equipos reales necesitan: ignorar vendors/tests, permitir ciertos algoritmos en contextos específicos, y decidir qué severity bloquea un PR. `qproof.yml` es el equivalente de `.eslintrc` para crypto policy.

### Alcance
- Nuevo archivo de config: `qproof.yml` en raíz del repo escaneado
- Secciones: `ignore` (paths/patterns), `allow` (algorithm allowlist por path), `fail` (conditions para exit 1), `severity_overrides`
- `qproof policy validate` — nuevo subcomando que valida el yml
- El scan respeta el policy file si existe

### Archivos / zona afectada
- `qproof/policy.py` (NUEVO) — parsing, validación, aplicación
- `qproof/cli.py` — nuevo subcomando `policy`, integración con scan
- `qproof/scanner/*.py` — respetar ignore paths
- `qproof/classifier/quantum_risk.py` — respetar severity_overrides
- `tests/test_policy.py` (NUEVO)
- `tests/fixtures/` — sample qproof.yml files

### Ejemplo de qproof.yml

```yaml
# qproof.yml
version: "1"

ignore:
  paths:
    - "vendor/**"
    - "node_modules/**"
    - "**/test_*"
    - "docs/**"
  algorithms:
    - MD5  # accepted in non-crypto contexts

allow:
  # Allow specific algorithms in specific paths
  - algorithm: RSA
    paths: ["legacy/auth/**"]
    reason: "Migration planned for Q3 2026"
    expires: "2026-09-30"

fail:
  # Exit 1 if any of these conditions are true
  on_vulnerable: true       # any VULNERABLE finding
  on_partial: false          # PARTIAL findings don't block
  min_score: 0               # 0-100, fail if quantum readiness score below this
  max_new_findings: 0        # with --diff: max new findings before fail

severity_overrides:
  # Override default severity for specific algorithms
  - algorithm: SHA-1
    severity: critical       # escalate from default
    reason: "Company policy: no SHA-1 anywhere"
```

### Restricciones
- Si `qproof.yml` no existe, scan funciona exactamente igual que antes (backward compatible)
- El policy file es YAML, no JSON (human-editable)
- Validar con schema estricto — typos en el yml deben dar error claro, no silencio
- `allow` con `expires` pasado → el allow se ignora (vuelve a reportar)
- No añadir dependencias más allá de PyYAML (ya está en el stack)

### Criterios de aceptación
1. `qproof scan .` con `qproof.yml` presente respeta ignore paths
2. `qproof scan .` con allow rules no reporta findings permitidos
3. `qproof scan .` con allow expired → reporta el finding normalmente
4. `qproof policy validate` con yml válido → exit 0
5. `qproof policy validate` con yml inválido → error claro con línea/campo
6. Fail rules controlan exit code correctamente
7. severity_overrides se aplican en el classifier
8. Sin qproof.yml → comportamiento idéntico a v0.3.0
9. Tests: mínimo 15 tests

### Prompt para Claude Code

```
TICKET: QP-015 — Policy-as-Code (qproof.yml)

OBJETIVO: Implementar soporte para qproof.yml como archivo de política de escaneo: ignore paths, allowlist, fail rules, severity overrides.

CONTEXTO:
- qproof v0.3.0 escanea todo sin filtros configurables
- Los equipos necesitan: ignorar vendors, permitir ciertos algos, configurar qué bloquea CI
- qproof.yml es el equivalente de .eslintrc para crypto policy
- PyYAML ya está en el stack

IMPLEMENTACIÓN:

1. Crear qproof/policy.py:
   - PolicyConfig dataclass:
     - version: str
     - ignore: IgnoreConfig (paths: list[str], algorithms: list[str])
     - allow: list[AllowRule] (algorithm, paths, reason, expires: Optional[date])
     - fail: FailConfig (on_vulnerable: bool, on_partial: bool, min_score: int, max_new_findings: int)
     - severity_overrides: list[SeverityOverride] (algorithm, severity, reason)
   - load_policy(scan_path: str) -> Optional[PolicyConfig]
     - Busca qproof.yml en scan_path
     - Si no existe, retorna None (backward compatible)
     - Si existe, parsea con PyYAML + valida schema
     - Si inválido, raise PolicyValidationError con mensaje claro
   - should_ignore_path(path: str, policy: PolicyConfig) -> bool
     - Usa fnmatch para glob patterns
   - should_ignore_finding(finding, policy: PolicyConfig) -> bool
     - Check ignore.algorithms + allow rules (con expires check)
   - apply_severity_overrides(finding, policy: PolicyConfig) -> finding
   - check_fail_conditions(findings, policy: PolicyConfig, diff_mode: bool) -> bool
     - Retorna True si debe fallar (exit 1)

2. Integrar en qproof/cli.py:
   - En scan command: cargar policy al inicio
   - Pasar policy a file_walker (para ignore paths)
   - Pasar policy a classifier (para severity_overrides)
   - Post-classify: filtrar por should_ignore_finding
   - Post-output: check_fail_conditions para exit code
   - Nuevo subcomando: @cli.command() def policy(): pass
   - Sub-subcomando: qproof policy validate [--file qproof.yml]

3. Integrar en qproof/utils/file_walker.py:
   - Aceptar ignore_patterns opcional
   - Añadir patterns del policy a los exclusions existentes

4. Crear tests/test_policy.py:
   - test_policy_load_valid: yml válido → PolicyConfig correcto
   - test_policy_load_missing: sin yml → None
   - test_policy_load_invalid_yaml: YAML roto → error claro
   - test_policy_load_invalid_schema: campo incorrecto → error con detalle
   - test_policy_ignore_paths: vendor/** ignorado
   - test_policy_ignore_algorithms: MD5 ignorado
   - test_policy_allow_with_path: RSA permitido solo en legacy/
   - test_policy_allow_expired: allow expirado → finding reportado
   - test_policy_allow_not_expired: allow vigente → finding ignorado
   - test_policy_severity_override: SHA-1 escalado a critical
   - test_policy_fail_on_vulnerable: exit 1 con VULNERABLE
   - test_policy_fail_on_partial_disabled: PARTIAL con on_partial:false → exit 0
   - test_policy_fail_min_score: score bajo → exit 1
   - test_policy_fail_max_new_findings: con diff, N+1 nuevos → exit 1
   - test_policy_validate_command: qproof policy validate → exit 0

5. Crear tests/fixtures/qproof_valid.yml y qproof_invalid.yml

6. Validación:
   ruff check qproof/ tests/
   python -m pytest tests/ -v
   # Test funcional con policy:
   echo 'version: "1"\nignore:\n  paths:\n    - "tests/**"' > /tmp/qproof.yml
   cd <test-repo> && python -m qproof scan .

RESTRICCIONES:
- Backward compatible: sin qproof.yml = comportamiento v0.3.0 exacto
- No añadir deps nuevas
- YAML schema strict: typos → error, no silencio
- allow.expires usa date ISO (YYYY-MM-DD), comparar contra date.today()

FORMATO DE RESPUESTA:
1. Resumen de cambios
2. Archivos creados/modificados
3. Schema completo del qproof.yml documentado
4. Tests: total pass/fail
5. Output de ejemplo con policy activa vs sin policy
6. Riesgos pendientes

CHECKPOINT: commit después de tests:
checkpoint(QP-015): policy-as-code qproof.yml — ignore, allow, fail rules, severity overrides
```

---

## QP-016 — Confidence + Context Scoring

### Objetivo
Añadir `confidence` (low/med/high) y `context` (runtime/test/docs/comment/build) a cada finding. Reduce falsos positivos y permite al usuario filtrar por confianza.

### Contexto
El source scanner actual usa regex — encuentra "RSA" en un comentario, en un test fixture, y en código real. Los tres tienen el mismo peso. Esto genera ruido. El confidence score dice "qué tan seguro estoy de que esto es uso real de criptografía" y el context dice "dónde se usa".

### Alcance
- Enriquecer ClassifiedFinding con campos `confidence` y `context`
- Heurísticas para determinar ambos (no AST — eso es Fase 1)
- Integrar en todos los outputs

### Archivos / zona afectada
- `qproof/models.py` — campos confidence, context en ClassifiedFinding
- `qproof/classifier/context.py` (NUEVO) — heurísticas de contexto
- `qproof/output/*.py` — mostrar confidence/context
- `tests/test_context.py` (NUEVO)

### Heurísticas (v0 — sin AST)

**Context** (por path + filename):
- `test_*`, `*_test.py`, `tests/`, `__tests__/`, `spec/` → "test"
- `docs/`, `*.md`, `*.rst`, `README*` → "docs"
- `build/`, `dist/`, `*.min.js`, `Makefile` → "build"
- Comentario (línea empieza con #, //, /* detectado por scanner) → "comment"
- Todo lo demás → "runtime"

**Confidence**:
- HIGH: import statement (`from cryptography import`), function call con argumento (`RSA.generate(2048)`), dependency manifest
- MEDIUM: string literal que contiene nombre de algo (`"RSA-OAEP"`), config file key-value
- LOW: comentario, docstring, README, nombre de variable suelto

### Criterios de aceptación
1. Cada ClassifiedFinding tiene confidence (low/med/high) y context
2. Rich output muestra ambos campos
3. JSON output incluye ambos campos por finding
4. SARIF incluye confidence como property
5. Finding en tests/ → context: "test"
6. Finding en import statement → confidence: "high"
7. Finding en comentario → confidence: "low", context: "comment"
8. Tests: mínimo 10 tests

### Prompt para Claude Code

```
TICKET: QP-016 — Confidence + Context Scoring

OBJETIVO: Añadir confidence (low/med/high) y context (runtime/test/docs/comment/build) a cada finding mediante heurísticas de path y contenido.

CONTEXTO:
- v0.3.0 trata todos los findings como iguales — un RSA en un comentario pesa igual que un RSA en un import
- Esto genera ruido y falsos positivos
- La solución definitiva es AST (Fase 1), pero heurísticas cubren ~70% de los casos

IMPLEMENTACIÓN:

1. Extender qproof/models.py:
   - Añadir a ClassifiedFinding:
     confidence: Literal["low", "medium", "high"] = "medium"
     context: Literal["runtime", "test", "docs", "comment", "build"] = "runtime"

2. Crear qproof/classifier/context.py:
   - classify_context(file_path: str, line_content: str, finding: Finding) -> tuple[str, str]
     Returns (context, confidence)
   
   Context rules (by path, in order):
   - path matches test patterns (test_*, *_test.py, tests/, __tests__/, spec/, *_spec.*) → "test"
   - path matches docs patterns (docs/, *.md, *.rst, README*, CHANGELOG*) → "docs"
   - path matches build patterns (build/, dist/, *.min.js, *.min.css, Makefile, Dockerfile) → "build"
   - line_content stripped starts with #, //, /*, *, """ → "comment"
   - else → "runtime"
   
   Confidence rules (by content pattern):
   - HIGH: line matches import pattern (import X, from X import, require(X), use X)
     OR line matches function call with crypto arg (X.generate, X.encrypt, X.sign, new X())
     OR source == "dependency" (from deps scanner)
     OR source == "config" (from config scanner)
   - LOW: context is "comment" or "docs"
     OR line is just a variable name or string without function call
   - MEDIUM: everything else

3. Integrar en pipeline (qproof/cli.py o qproof/classifier/quantum_risk.py):
   - Después de classify, antes de advise:
     for finding in classified_findings:
       finding.context, finding.confidence = classify_context(finding.file, finding.line_content, finding)

4. Actualizar outputs:
   - text.py: añadir columnas [HIGH] [MED] [LOW] coloreadas + context
   - json_out.py: campos confidence, context por finding
   - sarif.py: properties confidence, context por result
   - cbom.py: properties si el schema lo permite, o skip

5. Crear tests/test_context.py:
   - test_context_test_file: tests/test_crypto.py → context: "test"
   - test_context_docs: README.md → context: "docs"
   - test_context_build: Dockerfile → context: "build"
   - test_context_comment: "# RSA is..." → context: "comment"
   - test_context_runtime: src/auth.py → context: "runtime"
   - test_confidence_import: "from cryptography import" → confidence: "high"
   - test_confidence_function_call: "RSA.generate(2048)" → confidence: "high"
   - test_confidence_dependency: source=dependency → confidence: "high"
   - test_confidence_comment: comment context → confidence: "low"
   - test_confidence_string_literal: "using RSA-OAEP" → confidence: "medium"

6. Validación:
   ruff check qproof/ tests/
   python -m pytest tests/ -v
   python -m qproof scan <test-repo> --format text  # verify columns

RESTRICCIONES:
- No romper tests existentes — confidence/context son campos con defaults
- No añadir dependencias
- Heurísticas son "good enough" — AST viene en Fase 1
- Si no se puede determinar, default a medium/runtime (safe defaults)

FORMATO DE RESPUESTA:
1. Resumen de cambios
2. Archivos creados/modificados
3. Tests nuevos: lista + pass/fail
4. Output ejemplo mostrando confidence/context
5. Riesgos: edge cases no cubiertos por heurísticas

CHECKPOINT: commit después de tests:
checkpoint(QP-016): confidence + context scoring heuristics
```

---

## QP-017 — Severity Model + Finding Enrichment

### Objetivo
Reemplazar el modelo de severity actual (quantum_risk: VULNERABLE/PARTIAL/SAFE) con un modelo de 5 niveles (critical/high/medium/low/info) y enriquecer cada finding con remediation concreta y category.

### Contexto
El modelo actual de 3 niveles es demasiado grueso para CI/CD. Un equipo necesita distinguir entre "RSA-1024 en producción" (critical) y "SHA-1 en test fixture" (info). El modelo de 5 niveles alineado con SARIF (que usa level: error/warning/note) permite granularidad real.

### Alcance
- Nuevo campo `severity` (critical/high/medium/low/info) en ClassifiedFinding
- Mantener `quantum_risk` existente (VULNERABLE/PARTIAL/SAFE) como campo separado — no romper backward compatibility
- Añadir `category` (tls/jwt/pki/at-rest/kdf/hash/random/protocol)
- Añadir `remediation` (string con recomendación concreta)
- Mapping: quantum_risk + confidence + context → severity

### Mapping de severity

```
quantum_risk=VULNERABLE + confidence=high + context=runtime → critical
quantum_risk=VULNERABLE + confidence=high + context=test   → low
quantum_risk=VULNERABLE + confidence=medium                → high
quantum_risk=VULNERABLE + confidence=low                   → medium
quantum_risk=PARTIAL + confidence=high + context=runtime   → high
quantum_risk=PARTIAL + confidence=high + context=test      → info
quantum_risk=PARTIAL + confidence=medium                   → medium
quantum_risk=PARTIAL + confidence=low                      → low
quantum_risk=SAFE                                          → info
```

### Criterios de aceptación
1. Cada ClassifiedFinding tiene severity, category, remediation
2. severity se calcula automáticamente del mapping
3. quantum_risk sigue existiendo (backward compatible)
4. SARIF output mapea severity → SARIF level (critical/high → error, medium → warning, low/info → note)
5. Rich output usa colores por severity
6. JSON incluye todos los campos nuevos
7. Tests: mínimo 8 tests

### Prompt para Claude Code

```
TICKET: QP-017 — Severity Model + Finding Enrichment

DEPENDE DE: QP-016 (confidence + context deben existir)

OBJETIVO: Añadir severity (5 niveles), category, y remediation a cada finding. El severity se calcula combinando quantum_risk + confidence + context.

CONTEXTO:
- v0.3.0 tiene quantum_risk: VULNERABLE/PARTIAL/SAFE — demasiado grueso para CI/CD
- QP-016 añadió confidence (low/med/high) y context (runtime/test/docs/comment/build)
- Ahora combinamos los tres para generar severity: critical/high/medium/low/info
- También añadimos category y remediation por finding

IMPLEMENTACIÓN:

1. Extender qproof/models.py:
   - ClassifiedFinding nuevos campos:
     severity: Literal["critical", "high", "medium", "low", "info"] = "medium"
     category: Optional[str] = None  # tls/jwt/pki/at-rest/kdf/hash/random/protocol
     remediation: Optional[str] = None

2. Crear qproof/classifier/severity.py:
   - calculate_severity(quantum_risk, confidence, context) -> str
     Mapping:
     VULNERABLE + high + runtime → critical
     VULNERABLE + high + test/docs/comment → low
     VULNERABLE + medium + runtime → high
     VULNERABLE + medium + test/docs → medium
     VULNERABLE + low → medium
     PARTIAL + high + runtime → high
     PARTIAL + high + test/docs → info
     PARTIAL + medium → medium
     PARTIAL + low → low
     SAFE → info

3. Extender qproof/data/algorithms.yaml:
   - Añadir campo category por algoritmo:
     RSA: category: pki
     ECDSA: category: pki
     AES-*: category: at-rest
     SHA-*: category: hash
     TLS*: category: tls
     JWT*: category: jwt
     bcrypt/argon2/scrypt: category: kdf
     HMAC*: category: mac
   - Añadir campo remediation por algoritmo:
     RSA: "Migrate to ML-KEM (FIPS 203) or ML-DSA (FIPS 204)"
     ECDSA: "Migrate to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205)"
     SHA-1: "Replace with SHA-256 or SHA-3"
     MD5: "Replace with SHA-256 or SHA-3. Never use for security."
     TLS 1.0/1.1: "Upgrade to TLS 1.3"
     etc.

4. Integrar en pipeline:
   - Después de context scoring (QP-016), calcular severity
   - Cargar category + remediation desde algorithms.yaml

5. Actualizar outputs:
   - text.py: severity con colores (critical=rojo bold, high=rojo, medium=amarillo, low=cyan, info=gris)
   - json_out.py: campos severity, category, remediation
   - sarif.py: mapear severity → level (critical/high→error, medium→warning, low/info→note)
   - cbom.py: category si el schema lo permite

6. Crear tests/test_severity.py:
   - test_severity_critical: VULNERABLE + high + runtime → critical
   - test_severity_downgrade_test: VULNERABLE + high + test → low
   - test_severity_partial_runtime: PARTIAL + high + runtime → high
   - test_severity_safe_always_info: SAFE + any → info
   - test_severity_low_confidence: VULNERABLE + low → medium
   - test_category_from_yaml: RSA → pki, AES → at-rest, etc.
   - test_remediation_from_yaml: RSA → includes "ML-KEM"
   - test_sarif_level_mapping: critical → error, medium → warning

7. Validación:
   ruff check qproof/ tests/
   python -m pytest tests/ -v
   python -m qproof scan <test-repo> --format text  # severity colors
   python -m qproof scan <test-repo> --format sarif | python -m json.tool | grep level

RESTRICCIONES:
- quantum_risk field SIGUE EXISTIENDO — no romper backward compat
- No modificar algorithms.yaml structure de forma que rompa el loader existente
- Remediation text debe ser conciso (1 línea) y citar estándares donde aplique

FORMATO DE RESPUESTA:
1. Resumen de cambios
2. Archivos creados/modificados
3. algorithms.yaml: cuántos algos con category + remediation
4. Tests nuevos + total pass/fail
5. Output ejemplo con severity colors
6. Riesgos pendientes

CHECKPOINT: commit después de tests:
checkpoint(QP-017): severity model (5 levels) + category + remediation enrichment
```

---

## QP-018 — Integration Tests + Example Repo + Action Update + Release v0.4.0

### Objetivo
Cierre de Fase 0: tests de integración end-to-end, ejemplo de repo con GitHub Action configurado, actualización de la Action para soportar los nuevos features, y release v0.4.0 en PyPI.

### Contexto
QP-013 a QP-017 añaden features individuales. Este ticket verifica que todo funciona junto, prepara un repo de ejemplo que cualquier equipo puede copiar, y publica la release.

### Alcance
- Tests de integración end-to-end (scan real con baseline → diff → policy)
- Actualizar README.md con docs de los nuevos features
- Crear repo de ejemplo (o directorio examples/) con qproof.yml + baseline + GitHub Action workflow
- Actualizar qproof-action para pasar --diff y --baseline
- Bump version a 0.4.0, update CHANGELOG, release PyPI

### Archivos / zona afectada
- `tests/test_integration_fase0.py` (NUEVO)
- `examples/` (NUEVO) — repo de ejemplo
- `README.md` — docs actualizados
- `CHANGELOG.md` — v0.4.0 entry
- `qproof/__init__.py` — version bump
- `pyproject.toml` — version bump
- `qproof-action/` — action.yml update (repo separado)

### Criterios de aceptación
1. Test E2E: scan → baseline → add finding → diff → policy fail → exit 1 (toda la cadena)
2. Test E2E: scan → baseline → no changes → diff → exit 0
3. Test E2E: scan con qproof.yml ignore → finding ignorado
4. README tiene sección "Quick Start" con baseline/diff/policy
5. examples/ contiene qproof.yml + .github/workflows/qproof.yml funcional
6. CHANGELOG documenta todos los features de Fase 0
7. Version 0.4.0 en __init__.py y pyproject.toml
8. All tests pass (existentes + nuevos, estimado 270+)

### Prompt para Claude Code

```
TICKET: QP-018 — Integration + Example Repo + Release v0.4.0

DEPENDE DE: QP-013, QP-014, QP-015, QP-016, QP-017 (todos completados)

OBJETIVO: Tests de integración end-to-end para toda la cadena Fase 0, repo de ejemplo, docs actualizados, release v0.4.0.

IMPLEMENTACIÓN:

1. Crear tests/test_integration_fase0.py:
   - test_e2e_baseline_diff_no_change:
     a. Crear temp dir con fixtures (Python files con crypto)
     b. qproof scan . --baseline baseline.json
     c. qproof scan . --diff baseline.json
     d. Assert exit code 0, assert no new findings
   
   - test_e2e_baseline_diff_new_finding:
     a. Crear baseline
     b. Añadir archivo con "import RSA" al temp dir
     c. qproof scan . --diff baseline.json
     d. Assert exit code 1, assert finding marked as NEW
   
   - test_e2e_policy_ignore:
     a. Crear temp dir con vendor/crypto.py (has RSA)
     b. Crear qproof.yml con ignore paths: ["vendor/**"]
     c. qproof scan .
     d. Assert vendor file NOT in findings
   
   - test_e2e_policy_fail_rules:
     a. Crear temp dir con VULNERABLE finding
     b. Crear qproof.yml con fail.on_vulnerable: true
     c. qproof scan .
     d. Assert exit code 1
   
   - test_e2e_full_pipeline:
     a. Crear temp dir con mixed findings (runtime + test + docs)
     b. Crear qproof.yml con ignores + allows
     c. Generate baseline
     d. Add new crypto
     e. Diff → only new shown
     f. Verify confidence/context/severity correct
     g. Verify SARIF output valid
     h. Verify JSON has all enrichment fields

2. Actualizar README.md:
   - Quick Start section con baseline/diff/policy
   - Table of features: scanners, outputs, policy, baseline/diff
   - Example qproof.yml
   - CI/CD section: GitHub Action workflow example
   - Badges: version, python versions, license, tests

3. Crear examples/:
   - examples/qproof.yml — sample policy file comentado
   - examples/github-action.yml — workflow listo para copiar:
     ```yaml
     name: QProof Crypto Scan
     on: [pull_request]
     jobs:
       qproof:
         runs-on: ubuntu-latest
         steps:
           - uses: actions/checkout@v4
           - uses: qproof/qproof-action@v1
             with:
               format: sarif
               diff: true
               baseline: qproof-baseline.json
           - uses: github/codeql-action/upload-sarif@v3
             with:
               sarif_file: qproof-results.sarif
     ```

4. Actualizar CHANGELOG.md:
   ## v0.4.0 — Fase 0: CI/CD Credibility
   - Baseline snapshot generation (--baseline)
   - Diff mode: only new/worsened findings (--diff)
   - Policy-as-code: qproof.yml (ignore, allow, fail rules, severity overrides)
   - Confidence scoring (low/medium/high) per finding
   - Context classification (runtime/test/docs/comment/build)
   - 5-level severity model (critical/high/medium/low/info)
   - Category + remediation per finding
   - Example repo with GitHub Action workflow

5. Version bump:
   - qproof/__init__.py: __version__ = "0.4.0"
   - pyproject.toml: version = "0.4.0"

6. Validación final:
   ruff check qproof/ tests/
   python -m pytest tests/ -v --tb=short
   python -m pytest tests/ -v --tb=short 2>&1 | tail -5  # summary
   python -m qproof scan . --format text
   python -m qproof scan . --format json | python -m json.tool | head -30
   python -m qproof scan . --baseline /tmp/bl.json && cat /tmp/bl.json | python -m json.tool | head -20

NO PUBLICAR EN PYPI EN ESTE TICKET — eso lo hace el CTO manualmente después de revisión.

FORMATO DE RESPUESTA:
1. Resumen de cambios
2. Total tests: existentes + nuevos + pass/fail
3. Features verificados end-to-end
4. README sections added
5. CHANGELOG entry
6. Riesgos pendientes antes de release

COMMIT FINAL:
feat(v0.4.0): Fase 0 — baseline/diff, policy-as-code, confidence/context/severity enrichment
```

---

## Resumen de ejecución

```
Día 1-2:  QP-016 (confidence/context) → QP-017 (severity)
Día 3-4:  QP-013 (baseline) → QP-014 (diff mode)
Día 5-6:  QP-015 (policy-as-code)
Día 7:    QP-018 (integration + release v0.4.0)
```

**Release v0.4.0 = qproof pasa de "scanner" a "CI/CD guardrail creíble".**

Después de Fase 0, el producto tiene todo lo necesario para:
- Bloquear deuda criptográfica nueva en PRs (diff-first)
- Configurar políticas por equipo (qproof.yml)
- Generar evidencia (SARIF + CBOM + JSON enriquecido)
- Integrar en GitHub Actions con una línea

---

*Generado por CTO Planning System — qproof Fase 0 — 2026-03-05*