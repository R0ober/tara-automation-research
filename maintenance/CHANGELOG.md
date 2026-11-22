# Changelog

All notable changes to the maintenance subproject are documented here. The
repository identifies experiment code by Git commit rather than release
version.

## Unreleased

### Added

- Deterministic vulnerability and component-change triage baseline.
- Component-ID and exact-CPE matching against the reference architecture.
- Existing-CVE detection and related TARA attack-tree evidence.
- Three-way decisions: `review_required`, `no_review`, and `unresolved`.
- Machine-readable JSON reports with stable ordering and summary counts.
- Standalone command-line interface and Python API with input validation.
- Pi 1.5.2 extension with a typed `tara_maintenance` custom tool, safe Python
  subprocess adapter, report truncation, and reusable `/tara-maintenance`
  prompt template.
- Editable-install Python environment, idempotent bootstrap script, and Pi
  launcher that loads local shell configuration.
- Tracked example configuration and synthetic inputs, separated from ignored
  local configuration, credentials, working data, reports, and `.venv/`.
- Configuration precedence across CLI arguments, `--config`,
  `TARA_MAINTENANCE_CONFIG`, and local defaults.
- Synthetic BBW change set demonstrating all decision outcomes.
- Python unit/reference-data/CLI tests and Node tests for the real Pi runner.
- Usage, evaluation, limitations, and agent development documentation.
- ADR 0001 for the deterministic baseline and ADR 0002 for the Pi extension.

- Twelve-case labeled synthetic benchmark with decision accuracy, detection
  recall, false-positive rate, unresolved counts, and structural evidence
  support metrics.
- Repeatable DeepSeek/Pi experiment runner and response quality gates.
- Four real NVD snapshots with public-domain provenance, SHA-256 manifest,
  offline converter, converted changes, and manually reviewed labels.
- CPE wildcard/product matching, numeric version ranges, matched-rule evidence,
  unaffected-version handling, and existing-TARA conflict review.
- Repeatable DeepSeek/Pi NVD scenario and roadmap for NVD Boolean semantics,
  incremental updates, independent datasets, and OpenCTI integration.
- Eight-record real NVD evaluation, including unaffected versions, N/A CPE
  conflicts, and feature-specific Mosquitto preconditions.
- Optional `--tara-output` writer carrying `maintenance_review` in a complete
  TARA copy with real-file round-trip and in-place-write protection.
- Scenario coverage matrix and measured iteration log.
- Draft NVD configuration-semantics specification with official-schema data
  shape, three-valued logic, evidence contract, and 28 acceptance tests.

### Changed

- Separate `/tara-maintenance` actual analysis from
  `/tara-maintenance-example` synthetic evaluation.
- Simplify CPE `matched_by` evidence to `affected_cpes`.
- Constrain model summaries to compact, row-verifiable evidence tables.

### Fixed

- Explicit DeepSeek provider selection avoids ambiguous model resolution.
- Session-level guards prevent duplicate identical Pi tool executions while
  allowing different inputs and failure retries.
- Regression gates detect corrected CVE IDs, incomplete CPEs, false CPE
  matching claims, and unsupported truncation statements.
- Range-only vulnerability inputs are now evaluated without requiring a
  duplicate `affected_cpes` entry.
- Unknown applicability now blocks version-exclusion `no_review` decisions.
- NVD records without CPE configurations become explicitly unresolved, and
  malformed NVD entries raise controlled input errors.
- Explicit unknown flags now block exclusion-based negative decisions, and the
  evidence metric recognizes unresolved-source evidence.
- External evaluation inputs reject duplicate IDs; Pi response validation
  accepts unresolved CPEs and sentence punctuation.
- Reports and TARA overlays reject overwriting any input artifact; Pi capability
  text now describes wildcard and numeric-range matching.
