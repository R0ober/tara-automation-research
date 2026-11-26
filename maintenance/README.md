# Maintenance

Contributors: Hongbin, Zeren

## Scope

This subproject keeps an existing TARA under review when new vulnerability
reports or component information becomes available. The current implementation
is a deterministic baseline for change triage. It does not call an LLM or an
external vulnerability service.

The baseline:

- matches vulnerabilities to architecture components by component ID or exact
  CPE;
- finds related threat scenarios, attack-tree steps, and existing CVE
  references;
- compares before/after component states;
- emits review recommendations with source and architecture/TARA evidence;
- uses `unresolved` when applicability cannot be established.

## Requirements

- Python 3.10 or newer for the deterministic core; no third-party Python
  runtime dependencies.
- Node.js 22.18 or newer and Pi for the agent interface. Pi 1.5.2 is the tested
  version. A configured model provider is required only for model-generated
  explanations and follow-up.

Run all commands from `maintenance/`.

## Local setup

Initialize a fresh clone or recreate the environment without overwriting
existing local configuration:

```bash
./scripts/bootstrap.sh
```

The script creates `.venv/`, installs this package in editable mode, creates
missing local files, and creates `output/`. Pip may download the
`setuptools>=68` build backend, so the first setup requires network access
unless that backend is already cached. The installed CLI is
`.venv/bin/tara-maintenance`. Optional shell activation:

```bash
source .venv/bin/activate
```

## Configuration: examples versus local work

| File or directory | Purpose | Git status |
| --- | --- | --- |
| `.env.example` | Shell-environment template | Tracked |
| `config/maintenance.example.json` | Path-configuration template | Tracked |
| `examples/changes.json` | Synthetic demonstration input | Tracked |
| `.env` | Current shell configuration and optional secrets | Ignored |
| `config/maintenance.json` | Current artifact and working-file paths | Ignored |
| `data/changes.json` | Current working change set | Ignored |
| `.venv/` | Editable Python environment | Ignored |
| `output/` | Generated local reports | Ignored |

Edit `.env`, `config/maintenance.json`, and `data/changes.json` directly for
local work. Put API keys only in `.env` or Pi's external credential store;
never put real credentials in tracked examples. `scripts/pi.sh` loads `.env`,
including `TARA_MAINTENANCE_PROVIDER`, `TARA_MAINTENANCE_MODEL`, and provider
credentials such as `DEEPSEEK_API_KEY`.

Pi receives these provider settings, but the deterministic Python subprocess
uses an allowlisted environment and does not inherit provider credentials.

Configuration paths are resolved relative to `maintenance/`. Explicit CLI paths
are resolved relative to the caller's working directory. Precedence is:

1. `--tara`, `--architecture`, `--changes`, and `--output`;
2. `--config` or `TARA_MAINTENANCE_CONFIG`;
3. `config/maintenance.json` when it exists.

The versioned configuration schema rejects unknown keys instead of silently
ignoring misspellings.

For the standalone CLI, use `--stdout`, `--output -`, or `output_path: "-"`.

For Pi tool calls, `output_path` must resolve within `maintenance/`; absolute
or relative paths that escape that directory are rejected before Python runs.
The standalone Python CLI does not impose this agent-specific restriction.

## Pi agent (recommended)

The agent uses a Pi extension and custom `tara_maintenance` tool rather than a
fixed workflow. One typed tool calls the Python implementation; the prompt
template reads the local configuration. This supports analyst follow-up without
duplicating decision logic in TypeScript or an LLM prompt.

Start Pi through the local launcher:

```bash
./scripts/pi.sh
```

Run the actual configured change file or the separate synthetic example:

```text
/tara-maintenance
/tara-maintenance-example
```

Pi loads `.pi/extensions/tara-maintenance/` and `.pi/prompts/` automatically
after project trust. The runner auto-detects `.venv`. Only identical calls
still running are deduplicated; completed calls can be repeated after inputs
change or at the user's request. Large results are truncated in model context,
with a complete-report path returned. Temporary complete reports are removed
on session shutdown. Review project-local extensions before trusting them: Pi
extensions execute with the user's operating-system permissions.

## Python CLI

Run the actual local configuration (the initial local change set is empty):

```bash
.venv/bin/tara-maintenance
```

This reads `data/changes.json` and writes `output/report.json` by default. Run
the synthetic example explicitly:

```bash
.venv/bin/tara-maintenance \
  --config config/maintenance.example.json \
  --changes examples/changes.json \
  --output output/example-report.json
```

To carry the review in a complete TARA document, add:

```bash
  --tara-output output/TARA-reviewed.json
```

This option preserves every original field and adds `maintenance_review` with
the summary and recommendations. It refuses to overwrite any input file or
stack an existing overlay. Removing that top-level member reconstructs the input
TARA exactly.
It does not create attack steps or update risk ratings; those changes still
require analyst-approved methods.

See [docs/COVERAGE_MATRIX.md](docs/COVERAGE_MATRIX.md) and
[docs/ITERATION_LOG.md](docs/ITERATION_LOG.md) for covered scenarios and measured
improvements.

The example's two `CVE-2026-9xxxx` identifiers are placeholders, not claims
about real vulnerabilities. Its expected summary is:

```json
{
  "total": 4,
  "review_required": 3,
  "no_review": 0,
  "unresolved": 1
}
```

Invalid input produces a diagnostic on standard error and exit status 2. A
report is written only after all inputs pass validation.

## Open vulnerability data

The project includes eight real NVD CVE API 2.0 snapshots, provenance hashes,
converted changes, and manually reviewed labels under `experiments/datasets/nvd-bbw/`.
The NVD adapter preserves vulnerable CPEs, numeric version ranges, timestamps,
descriptions, and available CISA fields.

The draft [NVD configuration-semantics specification](docs/specs/nvd-configuration-semantics.md)
defines the next implementation contract and acceptance tests; full
configuration evaluation is not implemented yet.

**NVD notice:** This product uses data from the NVD API but is not endorsed or
certified by the NVD.

Use `tara-maintenance-nvd` to convert offline snapshots. Fetching, evaluation,
and DeepSeek/Pi commands are documented in [experiments/README.md](experiments/README.md).
Known limitations and planned OpenCTI integration are tracked in
[ROADMAP.md](ROADMAP.md).

## Input contract

The TARA and architecture must describe the same non-empty
`tara_metadata.item_id` / `item_definition.item_id` when both fields are
present. The change file is a JSON object with a `changes` array. Every change
requires a unique `change_id`, a `type`, and a non-empty `source`. `source_url`
is optional.

### Vulnerability

```json
{
  "change_id": "VULN-001",
  "type": "vulnerability",
  "cve_id": "CVE-2026-0001",
  "affected_components": ["COMP-VDCM"],
  "affected_cpes": [],
  "source": "internal vulnerability feed",
  "source_url": "https://example.invalid/CVE-2026-0001",
  "summary": "Optional human-readable context"
}
```

A vulnerability requires a valid `cve_id`. `affected_components` and
`affected_cpes` are optional string arrays.
`affected_cpe_ranges` optionally adds rules with `cpe`, optional
`match_criteria_id`, and the four snake-case version bounds. At least one
applicability identifier or range is required unless `applicability_unknown` is
explicitly `true`. Such explicitly unknown records produce `unresolved`.
Matching supports exact CPEs, part/vendor/product wildcard matching, and
numeric/dotted version ranges. Nonnumeric comparisons remain unresolved. The
baseline does not infer applicability from `summary`.

### Component change

```json
{
  "change_id": "COMPONENT-001",
  "type": "component_change",
  "component_id": "COMP-VDCM",
  "before": {"security_configuration": {"secoc_enabled": false}},
  "after": {"security_configuration": {"secoc_enabled": true}},
  "source": "component snapshot 2026-11-20"
}
```

A component change requires a non-empty `component_id`. `before` and `after`
are required and may contain any JSON values. For objects,
the report lists changed top-level fields, including fields added or removed
with a `null` value. Nested differences are reported under their top-level
field. Non-object differences use the field name `value`.

## Decision rules

| Input condition | Decision | Reason |
| --- | --- | --- |
| New CVE matches at least one known component | `review_required` | The item is affected and the TARA does not reference the CVE. |
| Existing TARA CVE references the same matched component | `no_review` | The baseline suppresses only CVE coverage for the affected component. |
| Same-product installed version is outside all supplied vulnerable ranges | `no_review` | A new CVE has positive version-exclusion evidence. |
| Existing TARA CVE conflicts with same-product version exclusion | `review_required` | Current evidence and the attack reference need analyst reconciliation. |
| No supplied component ID or CPE rule matches the architecture | `unresolved` | Item applicability is unknown. |
| Known component has different before/after states | `review_required` | Existing and missing attack chains may need review. |
| Known component has identical before/after states | `no_review` | There is no effective state change. |
| Changed component is absent from the architecture | `unresolved` | Its relationship to the item is unknown. |

A known match still controls the decision when other supplied identifiers are
unknown. Those unresolved identifiers remain in the evidence instead of being
silently discarded.

## Output contract

The report contains:

- `schema_version`: currently `1.0`;
- `tara`: source document ID, version, and item ID;
- `summary`: total and per-decision counts;
- `recommendations`: one entry per input change, in input order.

Each recommendation includes `decision`, `rationale`, and `evidence`. Evidence
can include the source, matched components/software, matched range rules,
same-product exclusions, unresolved identifiers, related threat scenarios and
attack steps, existing CVE references, and before/after component states.
Output has no timestamp or random field, so identical inputs produce identical
JSON.

## Python API

```python
from tara_maintenance import evaluate_changes, load_json

report = evaluate_changes(
    load_json("tara.json"),
    load_json("architecture.json"),
    load_json("changes.json"),
)
```

`InputError` reports unreadable, malformed, or contract-violating input.

## Tests

```bash
.venv/bin/python -m unittest discover -s tests -v
node --test tests/test_pi_runner.mjs tests/test_pi_index.mjs
```

The Python suite covers decision rules, malformed input, strict configuration
loading and precedence, labeled evaluation, explicit example-data selection,
shared BBW integration, and Pi response quality gates. The Node suites execute
the real Python CLI through the Pi runner and exercise extension invocation
guards, attachment aliases, truncation cleanup, configured paths, and errors.

To check Pi resource loading without a model call:

```bash
./scripts/pi.sh --no-session --help
```

For a model-backed smoke test, configure a valid provider and run:

```bash
.venv/bin/python experiments/pi_smoke.py --runs 3
```

See [experiments/README.md](experiments/README.md) for DeepSeek configuration,
the iteration record, and metric definitions.

## Project layout

```text
.pi/extensions/tara-maintenance/  Pi custom tool and Python runner
.pi/prompts/                     Reusable /tara-maintenance command
config/maintenance.example.json  Tracked configuration template
experiments/                    Synthetic datasets, metrics, and Pi smoke runner
examples/changes.json            Tracked synthetic change set
scripts/                         Bootstrap and Pi launchers
src/tara_maintenance/            Decision engine, configuration, and CLI
tests/                           Python unit/config/CLI and Node runner tests
data/                            Ignored local working changes
output/                          Ignored generated reports
docs/decisions/                  Architecture Decision Records
CHANGELOG.md                     Notable changes
agent.md                         Development conventions for coding agents
```

## Evaluation use

Run the labeled synthetic baseline experiment:

```bash
.venv/bin/tara-maintenance-evaluate \
  --config config/maintenance.example.json \
  --dataset experiments/datasets/synthetic-maintenance.json \
  --output output/synthetic-baseline-evaluation.json
```

Treat `unresolved` separately rather than silently counting it as either review
outcome. The automatic evidence metric is structural; semantic evidence support
still requires analyst review. Record the Git commit, artifact versions,
configuration, and ignored result location with each experiment.

## Known limitations

- CPE range matching supports numeric/dotted versions only; nonnumeric versions
  and product aliases require further handling.
- NVD configurations are flattened for extraction; nested AND/OR, negation, and
  platform prerequisites are not yet evaluated as Boolean expressions.
- Existing-CVE suppression ignores new severity, exploitability, patch, and
  description information unless a version-applicability conflict is detected.
- Any effective change to a known component is flagged; the baseline does not
  prove that risk changed.
- New components and unmapped vulnerabilities remain unresolved until the
  architecture or mapping data is extended.
- Incremental NVD synchronization, OpenCTI ingestion, and natural-language
  threat-intelligence parsing are not implemented.
- Recommendations are triage decisions, not updated risk ratings or proof that
  an attack is feasible.

See [ADR 0001](docs/decisions/0001-deterministic-maintenance-baseline.md),
[ADR 0002](docs/decisions/0002-pi-extension-for-maintenance-agent.md), and
[ADR 0003](docs/decisions/0003-nvd-version-aware-applicability.md) for the
baseline, agent interface, and NVD applicability rationale.

See [ROADMAP.md](ROADMAP.md) for prioritized follow-up work.
