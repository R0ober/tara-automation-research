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
