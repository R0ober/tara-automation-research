# Iteration log

## Iteration 0: deterministic synthetic baseline

- Delivered component and vulnerability triage with three decisions and
  evidence.
- Established 12 synthetic labeled cases and configuration isolation.
- Initial result: 12/12 agreement with rule-derived synthetic labels.
- Limitation: labels and data did not exercise real NVD version ranges.

## Iteration 1: reliable Pi/DeepSeek tool use

- Separated actual and example commands and fixed provider resolution.
- Added duplicate-call prevention and response quality gates.
- Final observed result: 3/3 synthetic agent sessions passed.
- Improvement evidence: literal paths, one tool execution, and row-level
  identifier/decision/evidence checks.

## Iteration 2: real NVD applicability

- Added four public-domain NVD snapshots with hashes and manual labels.
- Initial exact-CPE result: 1 `review_required`, 3 `unresolved`.
- Added wildcard product matching, numeric version ranges, version exclusions,
  and existing-TARA conflict review.
- Final result: 4/4 manual-label agreement; 3 `review_required`, 1 `no_review`,
  0 `unresolved`; 3/3 NVD agent sessions passed.
- Main improvement: applicable range-based records no longer remain unresolved,
  and existing references are not blindly suppressed when evidence conflicts.

## Iteration 3: expanded scenarios and TARA review output

### Goals

- Add real unaffected-version, N/A-CPE, and feature-specific vulnerability
  scenarios.
- Expand the NVD set from four to eight records and publish per-case decisions.
- Add an optional TARA review-overlay writer that preserves every original TARA
  field instead of returning only a side-channel maintenance report.
- Verify that removing the overlay from the output exactly reconstructs the
  input TARA; do not invent attack steps or risk ratings.

### Results

- Expanded from 4 to 8 real NVD records. The 8-case evaluation produced 8/8
  agreement with this iteration's manual labels: 6 `review_required`, 2
  `no_review`, and 0 `unresolved`.
- Added real coverage for an unaffected version (CVE-2014-4883), an N/A CPE
  conflict (CVE-2020-22283), and feature-specific Mosquitto preconditions
  (CVE-2024-3935 and CVE-2024-10525).
- DeepSeek/Pi passed 3/8-record sessions with all automatic gates; all three
  responses were manually reviewed.
- Added `--tara-output`. Removing `maintenance_review` from the real generated
  BBW output exactly reconstructed the original TARA JSON. Unit and CLI tests
  also cover mutable-data isolation, identity mismatch, overlay stacking, and
  in-place-write refusal.
- Improvement over the previous deliverable: maintenance decisions can now be
  carried in a complete TARA document while preserving all original analysis.
  The overlay is review evidence, not an invented attack-tree or risk update.
