# Maintenance roadmap

## Current baseline

The repository contains a deterministic component-change and vulnerability
review baseline, a Pi/DeepSeek agent interface, local configuration isolation,
and synthetic smoke experiments. The first open-data experiment uses four raw
NVD CVE API 2.0 snapshots with source URLs, timestamps, and SHA-256 hashes.

NVD notice: this product uses data from the NVD API but is not endorsed or
certified by the NVD.

## Findings from the initial NVD experiment

The initial exact-CPE-only pipeline produced one `review_required` and three
`unresolved` decisions:

- CVE-2020-22284 exactly matches lwIP 2.1.2 and is not in the TARA.
- CVE-2022-0847 uses a wildcard Linux-kernel CPE and version ranges. NVD's
  `5.8 <= version < 5.10.102` range includes the reference kernel 5.10.70.
- CVE-2021-34434 uses a wildcard Mosquitto CPE and an inclusive range that
  includes the reference Mosquitto 2.0.10.
- CVE-2020-12351 is already referenced by the TARA, but NVD's current listed
  ranges do not include kernel 5.10.70. This is a reference-data/applicability
  conflict that needs review, not silent suppression or a claim that NVD proves
  the whole item is unaffected.

The initial adapter preserved vulnerable CPE rules but did not evaluate version
ranges. It also flattened NVD configurations, which is insufficient for full
Boolean applicability semantics.

## Iteration status: P0 implemented and verified

The current implementation now supports CPE part/vendor/product matching,
wildcard versions, all four numeric range boundaries, matched-rule evidence,
same-product version exclusions, and existing-TARA conflict review. Nonnumeric
comparisons remain unresolved. The four NVD records produce three
`review_required` and one `no_review`, with zero unresolved decisions.

The real-data evaluation agrees with all four manually reviewed labels. The
DeepSeek/Pi NVD scenario also passed three independent sessions after the
quality gate was corrected to accept wildcard CPEs from range evidence. These
results do not close the P1/P2 items below.

## P0: Correct vulnerability applicability

### Version-aware matching

- Match CPE part, vendor, and product independently of a wildcard version.
- Evaluate start/end including/excluding ranges for numeric and dotted versions.
- Keep nonnumeric or ambiguous version comparisons unresolved rather than
  guessing.
- Return the exact matched range and `matchCriteriaId` as evidence.
- Distinguish a positive match, a same-product version exclusion, and an unknown
  product mapping.

Acceptance: real NVD regression tests cover CVE-2022-0847, CVE-2021-34434,
CVE-2020-22284, and the CVE-2020-12351 range conflict; boundary tests cover all
four range operators.

Status: implemented for numeric/dotted versions and verified by unit tests plus
the four offline NVD snapshots. Full NVD Boolean configuration semantics remain
open under P1.

### Existing-TARA conflicts

- Do not suppress an existing CVE when current applicability evidence conflicts
  with the existing attack reference.
- Require analyst review for that conflict and include both NVD and TARA
  evidence.
- Do not treat a missing product mapping as proof that a component is patched.

Acceptance: a CVE already in the TARA can produce `review_required` when the
same product's installed version is outside all supplied vulnerable ranges.

Status: implemented for same-product version exclusion conflicts and verified
with CVE-2020-12351. Content-update detection remains open.

## P1: Trustworthy open-data maintenance

### Preserve NVD configuration semantics

- Represent nested nodes, AND/OR operators, and negation instead of flattening
  all vulnerable CPEs into one list.
- Separate vulnerable products from platform/environment requirements.
- Add adversarial fixtures where flattening creates a false applicability match.

### Detect updates to existing CVEs

- Store previous NVD snapshots and compare `lastModified`, status, CVSS, CISA
  fields, descriptions, and applicability rules.
- Define review policy for each changed field; do not automatically recalculate
  ISO/SAE 21434 risk from CVSS.
- Keep source and before/after evidence for every review recommendation.

### Independent evaluation data

- Expand beyond four selected records with stratified component, version,
  existing-CVE, unaffected-version, and unknown-product cases.
- Obtain independent analyst labels; do not derive expected labels solely from
  the implementation rules.
- Report unresolved separately and publish per-case errors with metrics.

## P1: Reproducible ingestion

- Support offline raw snapshots as the default test input.
- Add incremental NVD retrieval using `lastModStartDate` and `lastModEndDate`.
- Keep sequential requests, configurable delays, optional `NVD_API_KEY`, response
  hashes, and API timestamps. Follow NVD's published rate-limit guidance.
- Validate snapshots against the official NVD JSON schema in a separate schema
  test workflow.

## P2: OpenCTI and threat-intelligence context

- Add an optional OpenCTI GraphQL/STIX adapter after a test instance is
  available. OpenCTI is an integration platform, not a static public CVE file.
- Configure `OPENCTI_URL` and `OPENCTI_TOKEN` only in ignored local config or an
  external secret store.
- Map vulnerability objects to the same maintenance change contract and retain
  OpenCTI IDs, STIX IDs, markings, sources, and relationships as evidence.
- Deduplicate NVD and OpenCTI records by CVE without discarding provenance.
- Evaluate whether relationship/context data changes review decisions; do not
  assume that aggregation alone improves accuracy.

## P2: Enrichment and reasoning

- Add CISA KEV and EPSS snapshots as separate evidence sources.
- Investigate existing attack-path impact and previously unidentified
  cross-component chains.
- Keep deterministic applicability results separate from LLM interpretation.
- Require human approval for any actual TARA rewrite or risk-rating change.

## Engineering gates for each iteration

1. Preserve raw source evidence and provenance.
2. Add consumer-visible regression tests before closing a discovered failure.
3. Run all Python and Node tests plus offline synthetic and NVD experiments.
4. Update `README.md`, `experiments/README.md`, and `CHANGELOG.md` when behavior
   or commands change.
5. Keep credentials, local configuration, generated reports, and model event
   streams out of Git.
