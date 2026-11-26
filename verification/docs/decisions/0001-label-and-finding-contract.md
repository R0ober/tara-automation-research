# 0001: Label and finding contract

Status: Proposed

## The problem

The injector writes ground-truth labels. Each reviewer (rule-based and
LLM-based) writes findings. Evaluation must match findings to labels. All
three parts need one stable format for locations, evidence and edits. The
reference TARA has no IDs for some objects, for example summary rows.

## Options considered

- **Typed contract in `src/tara_verification/contract/` with JSON Schemas.
  Locations use IDs and field paths, never list indices.**
- Locations as JSON pointers with list indices.
- Free-form locations and fuzzy matching in evaluation.

## Rationale

IDs are stable when lists are reordered or when the injector inserts a node.
A reviewer cannot know the internal list indices, so a pointer location would
measure formatting skill, not review skill. A typed contract lets tests check
every label before it is written.

## Decisions

- `location` is `{scenario_id, object_id, field}`.
  - `object_id` is the ID of the nearest object that has its own ID: an
    attack-tree node, a requirement, a goal.
  - Scenario-level fields and summary-table rows have no own ID. For them
    `object_id` is the scenario ID and `field` is the full path from the
    scenario object, for example `risk_determination.inherent_risk_value`.
    Summary fields use the prefix `traceability_and_risk_summary.`, for
    example `traceability_and_risk_summary.inherent_risk`.
  - `field` is a dotted path without list indices.
- `edits[].path` is an RFC 6901 JSON pointer into the TARA. It may contain
  list indices. It exists only in labels, which reviewers never see.
- `evidence[]` is `{document, object_id, field, quote, relation}`.
  - `document` is `tara`, `item_definition` or `functional_specification`.
  - `relation: "quote"` means that `quote` occurs in the resolved field.
  - `relation: "absent"` means that `quote` is an ID that the document does
    not define. Operator C1a uses this, because its evidence is the absence of
    an ID. `object_id` and `field` can be null for this relation.
- `base` records `system`, `tag`, `tara_sha256` and `item_sha256`. During
  development `tag` can be a commit. Dataset v1 must use a tag.
- `effect` records `band_changed` and `risk_changed`. The injector computes
  them from the methodology tables. It does not use the validator.
  - `band_changed` is true if the edit changes a feasibility band at the
    edited node. The band can be stated (a C4 band edit) or implied by the
    edited numbers (a C3 factor edit that moves the total into another band).
  - `risk_changed` is true if a correct propagation of the edit would change
    the inherent risk value. A null risk value never changes.
  - Values per operator in milestone 1:

    | Operator and site | `band_changed` | `risk_changed` |
    |---|---|---|
    | C1a, C1b | false | false |
    | C3 factor score | band of the new total differs from the stated band | matrix value for the implied root band differs from the stated risk |
    | C3 total score | false (the offset keeps the band) | false |
    | C4 leaf band | true | false (a leaf band is not an input of the risk lookup) |
    | C4 root band, `risk_determination` band | true | matrix value for the new band differs from the stated risk |
    | C4 risk value and level | false | true |
- A finding has `category`, `location`, `claim` and `evidence`. It uses the
  same location and evidence types as a label.

## Consequences

- Evaluation matches on category plus `scenario_id` and `object_id`. `field`
  is reported but is not a match condition. This makes the scenario-ID
  convention for summary rows coarse: any finding on another scenario-level
  field of the same scenario matches. `accepted_locations` must list the
  other objects that also show the defect, for example the root node for a
  changed leaf total.
- A contract change requires an update of this ADR first.
- The JSON Schemas document the format for other tools. The runtime uses only
  the standard library, so it checks enumerated values with `check_label` and
  `check_finding`, not with a JSON Schema validator.

## Validation

`tests/test_contract.py` checks that the dataclass fields equal the schema
properties, that labels survive a round trip, and that `check_label` rejects
unknown values.
