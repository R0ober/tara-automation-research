# Maintenance experiments

## Scope and data classification

The tracked experiments include synthetic smoke cases and a small set of real
NVD snapshots for the BBW reference case. Neither is an independent benchmark
or evidence of broad real-world performance. Local model events, generated
reports, credentials, and working data remain under ignored `output/`, `data/`,
and `.env` paths. Selected raw NVD records are tracked with their public-domain
provenance; see the NVD notice below.

Reference artifacts:

- TARA: `TARA-AUTO-BBW-01`, version `1.0.0`, item `AUTO-BBW-01`.
- Architecture and TARA files: the paths in `config/maintenance.example.json`.
- Code revision: use the Git commit that contains this document and the selected
  experiment code. Record `git rev-parse HEAD` with any copied results.

## Labeled rule-baseline experiment

`datasets/synthetic-maintenance.json` contains 12 labeled cases: 6 expected
`review_required`, 4 expected `no_review`, and 2 expected `unresolved`. Cases
cover component and exact-CPE matching, existing CVEs, mixed known/unknown
identifiers, component changes, and identical states.

Run:

```bash
.venv/bin/tara-maintenance-evaluate \
  --config config/maintenance.example.json \
  --dataset experiments/datasets/synthetic-maintenance.json \
  --output output/synthetic-baseline-evaluation.json
```

Metric definitions:

- `decision_accuracy`: exact decision agreement over all cases.
- `detection_recall`: `TP / (TP + FN)` over expected `review_required` cases;
  unresolved predictions are reported separately.
- `false_positive_rate`: `FP / (FP + TN)` over expected `no_review` cases;
  unresolved predictions are reported separately.
- `evidence_support_rate`: fraction with the required source and structural
  evidence for the predicted decision. This is an automatic structural proxy,
  not a substitute for analyst review of semantic evidence quality.
- `unresolved`: number of predictions labeled unresolved, regardless of the
  expected class. Per-case results preserve the expected/actual confusion.

Observed result on 2026-11-20 with Python 3.14.10:

| Total | Correct | Accuracy | Detection recall | False-positive rate | Evidence support | Unresolved |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 12 | 12 | 1.0 | 1.0 | 0.0 | 1.0 | 2 |

These values demonstrate agreement with the rule-derived labels only.

## Real NVD snapshot experiment

`datasets/nvd-bbw/` contains raw NVD API 2.0 responses for CVE-2020-12351,
CVE-2022-0847, CVE-2021-34434, and CVE-2020-22284, plus `manifest.json` source
URLs, timestamps, and SHA-256 hashes. `changes.json` is the converted input and
`labels.json` records this iteration's manual review. Labels are not
independent.

**NVD notice:** This product uses data from the NVD API but is not endorsed or
certified by the NVD. NIST publications are in the public domain under Title
17 U.S.C.

Refresh selected snapshots (network access, sequential requests, six-second
default delay):

```bash
.venv/bin/python experiments/nvd_fetch.py \
  --output-directory experiments/datasets/nvd-bbw \
  CVE-2020-12351 CVE-2022-0847 CVE-2021-34434 CVE-2020-22284
```

Convert and evaluate entirely offline:

```bash
.venv/bin/tara-maintenance-nvd \
  experiments/datasets/nvd-bbw/CVE-2020-12351.json \
  experiments/datasets/nvd-bbw/CVE-2022-0847.json \
  experiments/datasets/nvd-bbw/CVE-2021-34434.json \
  experiments/datasets/nvd-bbw/CVE-2020-22284.json \
  --output experiments/datasets/nvd-bbw/changes.json

.venv/bin/tara-maintenance-evaluate \
  --config config/maintenance.example.json \
  --dataset experiments/datasets/nvd-bbw/labels.json \
  --changes experiments/datasets/nvd-bbw/changes.json \
  --output output/nvd-evaluation.json
```

The initial exact-CPE-only run produced 1 `review_required` and 3 `unresolved`.
After version-aware matching and existing-TARA conflict handling, the observed
result on 2026-11-22 is:

| Total | Correct | Accuracy | Detection recall | False-positive rate | Evidence support | Unresolved |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 4 | 4 | 1.0 | 1.0 | 0.0 | 1.0 | 0 |

CVE-2020-12351 requires review because its TARA references conflict with the
current same-product version exclusion. This is not a claim that the whole item
is unaffected.

## DeepSeek + Pi agent experiment

Local `.env` configuration uses an explicit provider to avoid ambiguous model
resolution:

```bash
export TARA_MAINTENANCE_PROVIDER="deepseek"
export TARA_MAINTENANCE_MODEL="deepseek-flash"
export DEEPSEEK_API_KEY="local-secret-only"
```

Never commit the real key. `scripts/pi.sh` loads these values and selects Pi
1.5.2. Run independent synthetic or real-NVD sessions:

```bash
.venv/bin/python experiments/pi_smoke.py --scenario synthetic --runs 3
.venv/bin/python experiments/pi_smoke.py --scenario nvd --runs 3
```

The scenarios invoke `/tara-maintenance-example` or
`/tara-maintenance-nvd-example` with literal tracked paths.
`/tara-maintenance` is a separate command for the actual ignored local change
set. Generated event streams, responses, and summaries are written under
ignored `output/pi-example-experiment/` or `output/pi-nvd-experiment/`.

Agent quality gates check:

- exactly one completed `tara_maintenance` execution with the required paths;
- the scenario-specific report summary;
- one final-response row per change, with its own subject and decision;
- no questioned/corrected CVE identifiers;
- complete, supported CPE evidence and no false CPE-matching claims;
- no unsupported output-truncation claims.

The extension also blocks duplicate in-flight or successfully completed calls
with identical arguments in one Pi session. Different inputs remain allowed,
and failed invocations can be retried.

### Iteration record

| Observed failure | Correction | Regression coverage |
| --- | --- | --- |
| Model ID resolved to the wrong provider | Explicit provider and catalog model ID | Live DeepSeek call |
| Conditional prompt arguments selected local empty data | Separate actual and example commands | Literal tool-argument gate |
| Model repeated an identical tool call | Session-level invocation guard | Repeated independent Pi runs |
| CVE editorial self-correction appeared | Constrained table and identifier rules | Questioned-CVE gate |
| Unsupported truncation descriptions appeared | Return explicit report path and constrain wording | Truncation-claim gate |
| CPE wildcards were omitted | Require complete CPE evidence | CPE-membership gate |
| Component matching was described as CPE matching | Simplified `matched_by` and row-specific checks | False-CPE-claim gate |
| NVD gate rejected valid wildcard range CPEs | Include matched and excluded rule evidence in the CPE allowlist | Range-CPE gate test |

Final observed synthetic run on 2026-11-20: **3/3 sessions passed all gates**,
with manual review of all three responses. The actual `/tara-maintenance`
command also completed one model-driven tool call and reported the configured
empty set without substituting example data.

Final observed NVD run on 2026-11-22: **3/3 sessions passed all gates**, with
manual review of all three responses.

## Remaining validity limits

- Three successful sessions are a smoke result, not a statistical guarantee of
  stable model wording.
- The labels and structural evidence checks are aligned with the implemented
  rules; independent analyst-labeled cases are still required.
- NVD ingestion and numeric CPE ranges are covered; Boolean NVD configuration
  semantics, nonnumeric versions, new attack-chain reasoning, and risk
  recalculation remain unevaluated.
- Model responses remain explanatory views of the JSON report. The deterministic
  report is authoritative.
