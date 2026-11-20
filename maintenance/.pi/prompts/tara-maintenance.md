---
description: Triage changes using the local maintenance configuration
argument-hint: "[changes.json] [report.json]"
---
Use the `tara_maintenance` tool once. Let it read `config/maintenance.json`
(or `TARA_MAINTENANCE_CONFIG`) for the TARA and architecture paths. Do not
replace those configured paths with the shared examples unless the user asks.

- When `$1` is supplied, set `changes_path` to `$1`. Otherwise omit it and use
  the configured local change file.
- When `$2` is supplied, set `output_path` to `$2`; otherwise omit it.
- Set `config_path`, `tara_path`, or `architecture_path` only when the user
  explicitly requests an override.

Do not replace the tool with a shell script or a second implementation of the
rules. After the tool returns:

1. State the total and the count for each decision.
2. List every `review_required` and `unresolved` change with its rationale and
   the most relevant evidence. Include `no_review` items in a compact list.
3. Never convert `unresolved` into `no_review`. Explain which component ID or
   CPE mapping is missing.
4. Preserve the tool's decisions. Do not infer new risk ratings or claim that
   the synthetic example CVEs are real vulnerabilities.
5. When an output path was supplied, confirm the actual path returned by the
   tool. If output was truncated, point to the complete report path.
