# NVD configuration semantics specification

Status: Draft for implementation

Date: 2026-11-22

## 1. Purpose

This specification defines how the maintenance subproject must interpret NVD
CVE API 2.0 applicability configurations. Its goal is to decide whether a
vulnerability applies to software in the reference item without discarding
configuration structure or treating missing evidence as a negative result.

This document is a specification, not an implementation claim. The current
implementation remains the flattened exact/range matcher described in ADR 0003.

## 2. Normative language

The words MUST, MUST NOT, SHOULD, MAY, and OPTIONAL are interpreted according to
RFC 2119. `UNKNOWN` is a semantic result, not an exception.

## 3. Normative sources

- [NVD CVE API 2.0 JSON schema](https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema),
  definitions `config`, `node`, and `cpe_match`.
- [NVD vulnerability detail-page documentation](https://nvd.nist.gov/vuln/vulnerability-detail-pages),
  section "Known Affected Software Configurations".
- [NVD API guidance](https://nvd.nist.gov/developers/start-here).
- ADR 0003 for the existing numeric CPE range rules.

NVD notice: this product uses data from the NVD API but is not endorsed or
certified by the NVD.

## 4. Official data shape

The current official schema defines:

```text
vulnerabilities[]
  cve
    configurations[]       configuration alternatives
      operator?            relation between nodes: AND | OR
      negate?              negation of the configuration result
      nodes[]
        operator           relation between cpeMatch entries: AND | OR
        negate?            negation of the node result
        cpeMatch[]
          vulnerable       whether matching CPE Names are vulnerable
          criteria         CPE 2.3 match string
          matchCriteriaId  stable identifier for the match rule
          versionStartIncluding?
          versionStartExcluding?
          versionEndIncluding?
          versionEndExcluding?
```

The official API 2.0 schema does NOT define `children` on `node`.
Implementations MUST NOT invent child-node semantics. Unknown extension fields
MAY be preserved in raw evidence but MUST NOT affect applicability unless a
future specification defines them.

`vulnerable: false` identifies a non-vulnerable/platform match in the NVD
applicability statement. It is NOT equivalent to `negate: true`.

## 5. Scope

In scope:

- Configuration-level and node-level AND, OR, and negation.
- Multiple configuration alternatives.
- Vulnerable products and non-vulnerable platform requirements.
- Exact CPEs, wildcard CPEs, and the four numeric version bounds.
- Open and closed architecture-inventory assumptions.
- Three-valued evaluation, deterministic evidence, and review-decision mapping.
- Offline schema-valid NVD snapshots.

Out of scope:

- CVSS-to-ISO/SAE-21434 risk conversion.
- Exploitability or attack-feasibility proof.
- Online CPE Dictionary lookups during deterministic evaluation.
- OpenCTI relationship reasoning.
- Automatic TARA attack-tree or risk-rating modification.

## 6. Required internal representation

The adapter MUST preserve the configuration tree as data. It MUST NOT flatten
`configurations`, `nodes`, or `cpeMatch` into one undifferentiated list.

A normalized configuration document SHOULD preserve source indices and contain
at least:

```json
{
  "configurations": [
    {
      "config_index": 0,
      "operator": "AND",
      "negate": false,
      "nodes": [
        {
          "node_index": 0,
          "operator": "OR",
          "negate": false,
          "cpe_match": [
            {
              "vulnerable": true,
              "criteria": "cpe:2.3:a:eclipse:mosquitto:*:*:*:*:*:*:*:*",
              "match_criteria_id": "07853BAC-AF86-4FF4-B0DB-FC0B91EE1E28",
              "version_start_including": "2.0.0",
              "version_end_including": "2.0.11"
            }
          ]
        }
      ]
    }
  ]
}
```

The original NVD field names MAY be retained instead. Normalization MUST NOT
change values, discard source order, or replace `matchCriteriaId`.

When a full `configurations` field is present, the evaluator MUST use it as the
authoritative applicability expression for that NVD record. It MUST NOT also
run the legacy flattened matcher over the same record. Legacy inputs without
`configurations` MAY continue to use the existing matcher.

## 7. Rule-level matching

### 7.1 Match results

Each CPE rule evaluated against one architecture software entry returns:

- `TRUE`: product and version criteria match.
- `FALSE`: the product is known not to match, or its version is outside the rule.
- `UNKNOWN`: product identity or version cannot be compared safely.

The existing CPE product comparison and numeric/dotted range behavior SHOULD be
reused. All four range operators MUST retain their inclusive/exclusive meaning.
Non-numeric versions and malformed CPEs MUST produce `UNKNOWN`, never a guessed
version match.

A rule with `vulnerable: false` uses the same product/version matcher as a
vulnerable rule. The flag controls evidence interpretation, not rule matching.

### 7.2 Inventory modes

The evaluator MUST support an explicit inventory mode:

- `open`: absence of a compatible product in the architecture produces
  `UNKNOWN`. This is the safe default for an incomplete item inventory.
- `closed`: absence produces `FALSE` only when the architecture is declared
  complete for the evaluation boundary and product aliases have been resolved.

Implementations MUST NOT silently select `closed`. The reference architecture
MUST NOT be declared complete merely because it is the current shared example.

## 8. Three-valued operators

Evaluation uses Kleene three-valued logic.

### AND

| Inputs | Result |
| --- | --- |
| Any `FALSE` | `FALSE` |
| All `TRUE` | `TRUE` |
| Otherwise | `UNKNOWN` |

### OR

| Inputs | Result |
| --- | --- |
| Any `TRUE` | `TRUE` |
| All `FALSE` | `FALSE` |
| Otherwise | `UNKNOWN` |

### NOT

| Input | Result |
| --- | --- |
| `TRUE` | `FALSE` |
| `FALSE` | `TRUE` |
| `UNKNOWN` | `UNKNOWN` |

`negate` absent means `false`. Node `operator` is REQUIRED by the official
schema. Configuration `operator` is OPTIONAL; when multiple nodes are present
and no configuration operator is available, the result MUST be `UNKNOWN` unless
another normative NVD source defines the relation. A single-node configuration
does not require an operator.

## 9. Evaluation procedure

For each configuration, in source order:

1. Evaluate every `cpeMatch` against the selected architecture inventory.
2. Combine CPE results using the node operator.
3. Apply node negation, when present.
4. Combine node results using the configuration operator.
5. Apply configuration negation, when present.
6. Record the result and evidence for every node and rule.

Combine configuration results using OR. Evaluation MUST be bottom-up and MUST
NOT require exponential path enumeration or network access.

The evaluator MUST separately track positively matched vulnerable CPE rules.
A rule that contributes to applicability only by being absent, negated, or
marked `vulnerable: false` MUST NOT be reported as a positively affected
software component.

## 10. Aggregate applicability

After all configurations are evaluated:

- `APPLICABLE`: at least one configuration is `TRUE` with at least one positive
  vulnerable-product match.
- `NOT_APPLICABLE`: no configuration is `UNKNOWN`, and every configuration is
  either `FALSE` or matches only non-vulnerable platform rules.
- `UNKNOWN`: all other cases.

A platform-only match with `vulnerable: false` MUST NOT make a CVE
`APPLICABLE` by itself. A negated match that is true because a vulnerable product
is absent MUST NOT make the item `APPLICABLE`.

The aggregate result and all contributing configuration results MUST be
available in evidence.

## 11. Maintenance-decision mapping

| Prior TARA state | Aggregate applicability | Decision |
| --- | --- | --- |
| CVE absent | `APPLICABLE` | `review_required` |
| CVE present | `APPLICABLE` | `no_review`, unless another update policy requires review |
| CVE absent | `NOT_APPLICABLE` | `no_review` with exclusion evidence |
| CVE present | `NOT_APPLICABLE` | `review_required` for TARA/source conflict |
| Any | `UNKNOWN` | `unresolved` |

A `NOT_APPLICABLE` result applies only to the supplied architecture and NVD
snapshot. It MUST NOT be presented as proof that the whole vehicle or item is
permanently unaffected.

Malformed schema input MUST produce `InputError`. It MUST NOT be converted to
`unresolved`, because malformed data and valid-but-incomplete data are different
failure modes.

## 12. Evidence contract

Each evaluation MUST include:

- CVE ID, source URL, snapshot identifier/hash, and last-modified value when
  available;
- inventory mode;
- aggregate applicability and final maintenance decision;
- configuration and node source indices, operators, negation, and results;
- `matchCriteriaId`, criteria, vulnerable flag, installed product/version, rule
  result, and range bounds for each evaluated rule;
- positively matched vulnerable rules separately from matched platform rules;
- excluded and unknown rules with machine-readable reasons.

Evidence arrays MUST be sorted by configuration index, node index, and source
CPE order. Repeated evaluation with identical inputs MUST produce byte-identical
JSON after formatting. No evaluation timestamp or random identifier is REQUIRED.

## 13. Errors and limits

- Missing required `nodes`, `operator`, `cpeMatch`, `vulnerable`, `criteria`, or
  `matchCriteriaId` MUST be an input error.
- An operator outside `AND`/`OR` MUST be an input error.
- A non-boolean `vulnerable` or `negate` MUST be an input error.
- Empty `nodes` or `cpeMatch` SHOULD be an input error because the official
  schema does not give them a useful applicability meaning.
- Missing configurations MUST produce `UNKNOWN` for an otherwise valid CVE.
- Unknown extension fields MUST NOT change the result.
- An open inventory MUST remain the default.

## 14. Acceptance-test matrix

An implementation is complete for this specification only when all following
consumer-visible tests pass.

### Rule and operator tests

1. Exact vulnerable CPE match produces `APPLICABLE`.
2. Wildcard product with an inclusive range produces `APPLICABLE`.
3. Each exclusive boundary rejects equality.
4. A nonnumeric version produces `UNKNOWN`.
5. `AND(TRUE, FALSE)` is `FALSE`.
6. `AND(FALSE, UNKNOWN)` is `FALSE`.
7. `AND(TRUE, UNKNOWN)` is `UNKNOWN`.
8. `OR(TRUE, UNKNOWN)` is `TRUE`.
9. `OR(FALSE, UNKNOWN)` is `UNKNOWN`.
10. `NOT(UNKNOWN)` is `UNKNOWN`.
11. Double negation preserves the original result.

### Configuration tests

12. Configuration AND combines vulnerable product and required platform.
13. Node OR permits alternative vulnerable products.
14. Multiple configurations act as alternatives.
15. Configuration negation and node negation are applied at the correct level.
16. A platform-only match does not create vulnerable-component evidence.
17. A negated absent vulnerable product does not create positive evidence.
18. Open inventory absence produces `UNKNOWN`; declared closed inventory absence
    produces `FALSE`.
19. Missing configuration operator with multiple nodes produces `UNKNOWN`.
20. Missing configurations produce `UNKNOWN`.

### Maintenance and regression tests

21. New applicable CVE requires review.
22. New not-applicable CVE produces evidence-based `no_review`.
23. Existing not-applicable CVE produces conflict review.
24. Any unknown applicability produces `unresolved`.
25. Malformed input produces `InputError` and no partial report.
26. The eight existing real NVD cases retain their expected decisions after
    migration to full configuration evaluation.
27. Repeated input produces deterministic evidence ordering.
28. Flat legacy inputs retain their existing behavior when no full configuration
    field is present.

## 15. Implementation and documentation gates

Before the roadmap item can be marked complete:

- Update ADR 0003 or add a superseding ADR for full configuration evaluation.
- Keep raw NVD snapshots and add focused synthetic configuration fixtures.
- Run all existing Python and Node tests and both Pi experiment scenarios.
- Update the coverage matrix from "specified" to "covered" only after all
  acceptance tests pass.
- Record before/after metrics and any changed real-CVE decisions in the
  iteration log.
- Preserve unresolved as a separate result and do not claim real-world validity
  from synthetic operator tests alone.
