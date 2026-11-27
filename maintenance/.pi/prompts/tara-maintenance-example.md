---
description: Run the synthetic maintenance example with explicit example inputs
---
Call the `tara_maintenance` tool exactly once with these literal arguments:

- `config_path`: `config/maintenance.example.json`
- `changes_path`: `examples/changes.json`
- `output_path`: `output/example-pi-report.json`

Do not use `config/maintenance.json` or `data/changes.json` for this command.
Do not replace the tool with a shell script or a second implementation of the
rules. After the tool returns:

1. Give one small table with the total and each decision count.
2. Give exactly one Markdown table containing all four changes, with columns
   `change_id`, `subject`, `decision`, and `key_evidence`. Copy identifiers and
   decisions verbatim from the report. Keep only the strongest evidence in the
   last column. Use each item's `matched_by` field faithfully: never claim CPE
   matching when it contains only `affected_components`. If a CPE is included,
   copy its complete string including every wildcard. Never convert
   `unresolved` into `no_review`.
3. State the complete report path returned by the tool. Do not discuss output
   truncation unless the tool explicitly reports that truncation occurred.
4. Do not add any other sections, corrections, alternatives, question marks,
   editorial comments, risk ratings, or claims that the synthetic CVEs are real.
