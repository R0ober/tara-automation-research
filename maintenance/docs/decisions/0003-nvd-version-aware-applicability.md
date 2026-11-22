# 0003: NVD snapshots and version-aware applicability

Status: Proposed

## The problem

Real NVD vulnerability records commonly use wildcard CPEs and version ranges.
Exact CPE matching leaves applicable records unresolved. An existing CVE in the
TARA can also conflict with current version-applicability evidence.

## Options considered

- **Selected option: offline NVD snapshots and deterministic numeric range rules.**
- Continue exact CPE matching and require analysts to expand every version.
- Send raw NVD records directly to an LLM without deterministic applicability
  rules.

## Rationale

NVD provides public-domain CVE records with CPE configurations and provenance.
Offline snapshots make experiments reproducible and tests independent of network
availability. Deterministic product and version-range checks provide auditable
evidence and leave ambiguous comparisons unresolved.

An existing TARA reference and a same-product version exclusion represent a
conflict that needs analyst review. This does not prove that the entire item is
unaffected.

## Consequences

The implementation compares CPE part, vendor, and product and supports numeric
or dotted versions, including equivalent trailing zero components. All four
start/end inclusive/exclusive bounds are supported. Nonnumeric versions remain
unresolved. Product aliases and complete NVD AND/OR/negation semantics are not
implemented.

The adapter extracts vulnerable CPEs but currently flattens configurations.
Large records can produce many irrelevant product rules; source evidence is
retained for later configuration-aware evaluation.

NVD data requires the notice: "This product uses data from the NVD API but is
not endorsed or certified by the NVD."

## Validation

Unit tests cover range boundaries, numeric ordering, wildcards, escaped CPE
characters, and unsupported versions. Offline integration tests use eight real
NVD snapshots and manual labels. DeepSeek/Pi experiments validate tool
arguments, decisions, and response evidence. Remaining work is in `ROADMAP.md`.

The full configuration follow-up is specified in
`../specs/nvd-configuration-semantics.md`; it remains unimplemented.
