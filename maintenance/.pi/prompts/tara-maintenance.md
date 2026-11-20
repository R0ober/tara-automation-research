---
description: Triage the actual change set from local maintenance configuration
---
Call the `tara_maintenance` tool exactly once with no path arguments. It must
read `config/maintenance.json` or `TARA_MAINTENANCE_CONFIG` and use the actual
configured local change set. Do not substitute any file from `examples/`.

After the tool returns:

1. Give one small table with the total and each decision count.
2. If there are no changes, state that the configured change set is empty and
   stop. Do not speculate about why it is empty.
3. Otherwise, give exactly one Markdown table containing all changes, with
   columns `change_id`, `subject`, `decision`, and `key_evidence`. Copy
   identifiers, decisions, and `matched_by` values verbatim. Include complete
   CPE strings or omit them. Never convert `unresolved` into `no_review`.
4. State a report path only when the tool returns one. Do not discuss output
   truncation unless the tool explicitly reports that truncation occurred.
5. Do not add other sections, corrections, alternatives, editorial comments,
   risk ratings, or unsupported claims.
