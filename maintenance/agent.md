# Maintenance agent guide

## Scope

Work in `maintenance/`. Shared reference artifacts under `shared/` are inputs,
not fixtures to edit for a maintenance feature. Request cross-team review for
any separately proposed shared-data change.

## Commands

Run from `maintenance/`. Create missing local environments without overwriting
configuration with `./scripts/bootstrap.sh`.

```bash
.venv/bin/python -m unittest discover -s tests -v
node --test tests/test_pi_runner.mjs
```

Smoke-test the explicit synthetic example:

```bash
.venv/bin/tara-maintenance \
  --config config/maintenance.example.json \
  --changes examples/changes.json \
  --output /tmp/tara-maintenance-report.json
```

Expected example counts: 4 total, 2 `review_required`, 1 `no_review`, and 1
`unresolved`. The synthetic CVEs are not real vulnerability claims.


Check Pi resource loading without a model:

```bash
./scripts/pi.sh --no-session --help
```

With a valid model provider, run both agent experiments:

```bash
.venv/bin/python experiments/pi_smoke.py --scenario synthetic --runs 3
.venv/bin/python experiments/pi_smoke.py --scenario nvd --runs 3
```

Use `/tara-maintenance-example` for synthetic data,
`/tara-maintenance-nvd-example` for tracked real NVD snapshots, and
`/tara-maintenance` for the ignored local change set. Do not pass example paths
to the actual command.

## Structure

- `.pi/extensions/tara-maintenance/index.ts`: Pi tool registration, duplicate
  invocation guard, output truncation, and queued report writes.
- `.pi/extensions/tara-maintenance/runner.ts`: argument-array Python subprocess
  adapter. It must not contain maintenance decision rules.
- `.pi/prompts/`: separate actual and synthetic agent entry points.
- `src/tara_maintenance/baseline.py`: input validation, reference indexes,
  deterministic rules, and report construction.
- `src/tara_maintenance/cli.py`: configuration precedence, argument parsing,
  JSON rendering, and exit behavior.
- `src/tara_maintenance/evaluate.py`: labeled decision and evidence metrics.
- `src/tara_maintenance/cpe.py`: CPE product and numeric range comparisons.
- `src/tara_maintenance/nvd.py`: offline NVD snapshot conversion.
- `src/tara_maintenance/review.py`: TARA-preserving maintenance review overlay.
- `tests/test_baseline.py`: decision boundaries and shared-data integration.
- `tests/test_cli.py`: real subprocess CLI behavior.
- `tests/test_configuration.py`: config precedence and example/local separation.
- `tests/test_pi_runner.mjs`: real Python execution through the Pi adapter.
- `tests/test_pi_smoke.py`: tool arguments and final-response quality gates.
- `tests/test_cpe.py`: numeric range and wildcard boundaries.
- `tests/test_nvd.py`: real NVD snapshots, ranges, and conflict decisions.
- `tests/test_review.py`: TARA round-trip, identity, and overlay safety.
- `docs/decisions/`: meaningful architectural decisions.
- `README.md`: public input/output contract and operating instructions.
- `CHANGELOG.md`: user-visible changes.

## Invariants

- Keep the Python core and its tests independent of LLMs, networks, GPUs,
  Minerva, and third-party Python packages. Pi and Node.js 22.18+ are explicitly
  adopted only for the optional agent interface.
- Never turn missing applicability evidence into `no_review`; use `unresolved`.
- Preserve one output recommendation per input change and preserve input order.
- Require unique change IDs and reject the whole invalid change document before
  writing a report.
- Keep reports deterministic: no timestamps, random IDs, or unordered evidence.
- Include evidence that points back to the change source and matched reference
  artifacts.
- Do not silently reinterpret `unresolved` as a negative label in evaluation.
- Do not modify caller-owned input dictionaries.
- Keep a single decision implementation in Python. Pi may format or explain a
  report but must never reclassify its decisions or duplicate matching rules.
- Normalize Pi `@` path prefixes and spawn Python with an argument array, never
  a shell command string.
- Never commit `.env`, `config/maintenance.json`, `data/*.json`, `output/`, or
  `.venv/`. Keep their tracked examples free of real credentials and data.
- The actual default input is `data/changes.json`; synthetic data must be
  selected explicitly as `examples/changes.json`.
- Keep model credentials only in ignored `.env` or Pi's external auth store.
  Set both provider and model to avoid ambiguous model resolution.
- Run `experiments/pi_smoke.py` after changing Pi prompts or invocation guards;
  inspect final responses manually as well as relying on automatic gates.
- Preserve raw NVD snapshots, source URLs, hashes, and the NVD non-endorsement
  notice. Use offline snapshots in tests; do not require network access.
- Review `ROADMAP.md` before expanding applicability, NVD Boolean semantics,
  incremental feeds, or OpenCTI integration.
- Before implementing full NVD applicability, read
  `docs/specs/nvd-configuration-semantics.md`. Do not introduce a `children`
  field or other semantics absent from the official API 2.0 schema.

## Change checklist

1. Read the README contract and relevant ADR before changing decision behavior.
2. Add a regression test for each changed decision, parsing boundary, or error.
3. Run both test commands, the reference-data smoke command, and Pi resource
   loading. Run the model-backed agent smoke test when valid credentials exist;
   otherwise report that specific limitation.
4. Update the README when input, output, commands, agent behavior, or
   limitations change.
5. Add user-visible changes to `CHANGELOG.md` under `Unreleased`.
6. Add an ADR for a new matching strategy or decision model; do not add ADRs for
   routine bug fixes.
7. Do not commit generated reports, caches, credentials, or real feed data
   unless the repository explicitly defines a dataset location and license.
