---
description: Run the real NVD snapshot maintenance experiment
---
Call the `tara_maintenance` tool exactly once with these literal arguments:

- `config_path`: `config/maintenance.example.json`
- `changes_path`: `experiments/datasets/nvd-bbw/changes.json`
- `output_path`: `output/nvd-pi-report.json`

These are real NVD records, not the synthetic `examples/changes.json` file. Do
not use `config/maintenance.json` or `data/changes.json` for this command.

After the tool returns:

2. Give exactly one Markdown table containing all eight CVEs, with columns
   `change_id`, `subject`, `decision`, and `key_evidence`. Copy identifiers,
   decisions, and `matched_by` values verbatim. Include complete CPE strings or
   omit them. Never convert `unresolved` into `no_review`.
3. Do not claim that a CVE has an existing TARA reference unless that evidence
   is present. Describe version exclusions as applying to the supplied software
   version, not as proof that the entire item is unaffected.
4. State the complete report path returned by the tool. Do not discuss output
   truncation unless the tool explicitly reports that truncation occurred.
5. Do not add other sections, corrections, alternatives, editorial comments,
   risk ratings, or unsupported claims.
