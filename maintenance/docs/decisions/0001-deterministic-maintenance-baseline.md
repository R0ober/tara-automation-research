# 0001: Deterministic maintenance baseline

Status: Proposed

## The problem

The maintenance subproject needs a reproducible baseline that decides when
vulnerability reports and component changes require review of an existing TARA.
The baseline must distinguish irrelevant or already covered changes from cases
with insufficient evidence.

## Options considered

- **Selected option: exact component and CPE matching with deterministic rules.**
- Fuzzy product-name matching without a reference architecture mapping.
- An LLM-only reviewer without a deterministic comparison baseline.

## Rationale

The shared architecture contains stable component identifiers and software CPEs.
The reference TARA contains component targets and CVE references. Exact links
between these fields provide inspectable evidence and repeatable output. A
separate `unresolved` decision prevents missing mappings from becoming false
`no_review` decisions.

Update: ADR 0003 extends exact CPE matching with wildcard products, numeric
version ranges, and existing-TARA conflict review.

## Consequences

The baseline requires affected component identifiers or exact CPE strings. It
does not evaluate CPE version ranges, CVSS changes, exploit maturity, natural
language descriptions, or risk acceptance. A CVE already present in the TARA
produces `no_review` after item applicability is established. New components
outside the reference architecture are `unresolved`.

Component changes are supported only for components already in the reference
architecture. The baseline flags any effective state difference for analyst
review; it does not claim that every such change alters risk.

## Validation

Unit tests cover decision boundaries, CPE matching, existing CVE suppression,
missing mappings, component diffs, malformed inputs, and deterministic output.
The CLI is also exercised against the shared BBW reference artifacts and the
synthetic change set in `examples/changes.json`.
