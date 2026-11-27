# tarav

Validates, lints and renders TARA item-definition JSON (ISO/SAE 21434 style):
components, connections, entry points, assets and damage scenarios. Findings point
at the offending value with an RFC 6901 JSON pointer, and `tarav render` produces
one offline HTML page showing the architecture with each edge coloured by its
derived protection level.

It also works as a pipeline step: `tarav check` gives a machine-readable pass or
fail under a policy file, `tarav serve --review` lets a person review and approve,
and `tarav gate` tells the pipeline when the next step may run. Design decisions
(cited in code as SPEC Dn and plan §n) are in `docs/DESIGN.md`.

## Build

```
go build -o bin/tarav ./cmd/tarav
```

Requires Go 1.22+. The schemas, the viewer and its pinned libraries are embedded in
the binary; nothing is fetched at build or run time.

## Usage

```
tarav validate FILE...                    check FILE against the item-definition schema
tarav lint [--format text|json] FILE...   validate, then run lint rules
tarav render FILE -o OUT.html             validate, lint, write the offline viewer page ("-o -" for stdout)
tarav serve FILE [--addr HOST:PORT] [--open]
                                          serve the viewer locally; reloads when FILE changes

pipeline (JSON on stdout, messages on stderr):
tarav check FILE [--policy P] [--format text|json]
tarav serve FILE --review [--stage S] [--reviewer NAME] [--policy P] [--approvals A]
tarav approve FILE --reviewer NAME [--stage S] [--comment C] [--policy P] [--approvals A]
tarav gate FILE [--stage S] [--approvals A]
```

Flags may come before or after file names.

```
$ tarav validate testdata/bbw/item-definition.json
testdata/bbw/item-definition.json: note: no "$schema" in input; validating against https://tarav.local/schema/item-definition/1.1.0
testdata/bbw/item-definition.json: valid

$ tarav lint testdata/lint/L003-no-damage-scenario.json
testdata/lint/L003-no-damage-scenario.json:/assets/1: error L003 [ASSET-MISSING] asset ASSET-MISSING has no damage_scenarios; every asset needs at least one damage scenario
...
```

Input without `$schema` is validated against the latest schema (1.1.0), with a
one-line notice on stderr. Inputs naming 1.0.0 keep validating against it. An
unknown `$schema` URI is a schema error.

### Output

Text output prints one line per finding:

```
file:json_path: severity rule [element_id] message
```

`--format json` prints a JSON array of findings and takes exactly one file
(findings carry no file name). Schema errors go to stderr in this mode, so stdout
is always valid JSON:

```json
[
  {
    "rule": "L001",
    "severity": "error",
    "message": "connection CONN-1: source_component \"COMP-X\" is not a defined component",
    "json_path": "/connections/0/source_component",
    "element_id": "CONN-1"
  }
]
```

Findings are sorted by `json_path` (array indices numerically), then rule, then
message, so output is byte-identical across runs.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | valid, no error-severity findings |
| 1 | schema errors, or at least one error-severity finding |
| 2 | usage error, or a file could not be read |
| 3 | not approved: `gate` found no approval for the file's current content, or a `serve --review` was rejected or interrupted |

`render` writes no page when the input has schema errors (exit 1). Otherwise it
always writes the page, so reviewers see the findings, and exits as above.

### Pipeline gate

For running tarav as a step in another pipeline (`docs/DESIGN.md`, D21–D25):

```
1. tarav check item.json --policy policy.json --format json
       exit 1 → report the findings to the user and stop
2. tarav serve item.json --review --stage item-definition --open
       the reviewer opens the page, may edit item.json (the page reloads and
       re-checks), then clicks Review and chooses Approve or Reject
       exit 0 → stdout is the approval record; exit 3 → rejected or interrupted
3. tarav gate item.json --stage item-definition
       exit 0 → this exact file content is approved: run the next step
       exit 3 → not approved (never, or the file changed since)
```

The Review button opens a dialog with an Approve / Reject toggle, the
reviewer's name and a comment (a reason is required to reject). Approve is
disabled while the file fails the checks, and the server re-checks
the file when Approve is clicked. The approval is bound to the SHA-256 of the
file at that moment, so any later edit closes the gate. Records are appended to
`item.json.approvals.json` (`--approvals` to change):

```json
{
  "approved": true,
  "stage": "item-definition",
  "file": "item.json",
  "sha256": "9f2c…",
  "reviewer": "Ada Lovelace",
  "approved_at": "2026-11-26T12:00:00Z",
  "comment": "zones and protection reviewed",
  "tarav_version": "M4",
  "findings": { "error": 0, "warning": 3, "info": 0 }
}
```

`gate` and a rejected review print `{"approved": false, "stage", "file",
"sha256", "reason"}` instead. Stages are free names (`[a-z0-9-]`), so later
human-reviewed steps such as `attack-path-analysis` can use `approve` and `gate`
on their own files. `tarav approve FILE --reviewer NAME` records an approval
without the page.

The reviewer name is typed, not authenticated, and anyone who can write the
approvals file can add a record: it is an audit trail, not a signature.

A policy file decides what blocks `check`, `approve` and the Approve button:

```json
{ "fail_on": "warning", "rules": { "L017": "error", "L003": "off" } }
```

`fail_on` is `error` (the default), `warning`, `info` or `never`; a rule can be
re-graded to `error`, `warning` or `info`, or turned `off`. Unknown fields or
rule IDs are errors (exit 2). See `testdata/policy/`.

### Viewer

`tarav render` writes one self-contained HTML file (about 2 MB) that works offline
and can be archived as review evidence: the viewer, cytoscape and elkjs are
inlined, and the graph, findings and the raw item JSON are embedded. A Content
Security Policy forbids any network load. The page shows trust zones, component
cards with ASIL badges, entry points, orthogonally routed edges coloured by
protection level, dashed physical-access and diagnostic paths, and multi-instance
components collapsed as `×N` (double-click to expand).

- **Drawer:** click any element for its details: hardware, OS, software with
  versions and CPEs, security configuration as green/red/amber chips, diagnostic
  services, assets with damage scenarios and SFOP ratings, messages and receiver
  behaviour, the flags behind an edge's protection level, its findings and its raw
  JSON. Cross-references in the drawer are links.
- **Focus and reachability:** selecting a component dims everything but its
  neighbours. Selecting an entry point dims everything it cannot reach following
  declared directions; this is topology, not attack feasibility. Esc, a click on
  empty canvas or the pane's close button clears the selection and keeps your zoom;
  the Fit button (or F) brings the whole graph back into view. The mouse wheel
  zooms smoothly, about 7% per notch.
- **Findings:** the lint badge opens the findings panel; each row selects the
  element it concerns, unfolding zones and expanding groups as needed. Cards and
  edge labels with findings are marked.
- **Search, layers, zones:** search by name, ID, software or CPE; toggle zones,
  entry points, protection colouring, assets, ASIL badges, diagnostic routes and
  labels; double-click a zone to fold it into one box (edges crossing it merge and
  show their weakest protection level).

Reachability and the finding-to-element links are computed in Go and embedded,
so they are deterministic and covered by golden tests.

`tarav serve` serves the same page on `127.0.0.1:8000` and reloads it within a
second of the file being saved. Schema errors are shown in the page.

### Protection levels

Each connection, message and entry-point edge gets a level, strongest first:
encrypted, MAC + freshness, MAC, CRC only, none, or unknown. Derivation is
strict: a flag that is not stated is unknown, never false, so an edge is only
"none" when encryption, MAC and CRC are all stated false (SPEC D12). Flags come
from, in order:

1. an explicit `protection` object on the message or connection (schema 1.1.0):

   ```json
   "protection": { "e2e_crc": true, "mac": true, "freshness": false }
   ```

2. a fixed table of `security_configuration` keys on the receiver, then the
   sender (component or hosted software): `e2e_crc_enabled`; `secoc_mac_enabled`,
   `secoc_mac_verification`, `secoc_mac_verification_enabled`,
   `command_authentication_mac`; `secoc_freshness_counter_enabled`,
   `secoc_freshness_counter_verification_enabled`. Message-prefixed keys such as
   `pedal_demand_mac_verification_enabled` are not matched to messages; state
   those with `protection`.

Encryption is `connections[].encrypted` (or `entry_points[].encrypted`). Edges
with unstated flags raise L017.
## Rules

| Rule | Severity | Checks |
|---|---|---|
| L001 | error | A reference names an undefined component, instance, connection or interface. Covers connection endpoints, `target_instances`, `adjacent_components`, `interface_id`, entry points, physical access, messages and payload fields, diagnostic access and downstream routes, diagnostic services, forwarding rules, and asset references. `EXTERNAL_*` component IDs count as defined. |
| L002 | error | An ID is used twice. Component, instance, connection, asset and damage-scenario IDs share one namespace; interface IDs are excluded. |
| L003 | error | An asset has a missing or empty `damage_scenarios` list. |
| L017 | warning | A drawn edge's protection is unknown, or could be higher if a missing flag were stated. |

Interfaces have no definition list: an interface is defined if any component lists
it in `interfaces`. A connection without `interface_id` gets its interface inferred
from the one interface both endpoints share (SPEC D10).

## Development

```
go test ./... -race -count=1             # all tests
go vet ./... && gofmt -l .               # must print nothing
go test ./cmd/tarav -update              # regenerate lint goldens, review the diff
go test ./internal/graph -update         # regenerate graph goldens, review the diff
go test -cover ./internal/...            # target: ≥80%
go test -short ./...                     # skip the headless-Chrome tests
```

The browser tests in `internal/render` load rendered pages in headless Chrome
with networking blocked and drive them through `window.__tarav`: no console
errors, edge routing (on node sides, orthogonal, not crossing nodes), a stable
layout, live reload under `serve`, drawer sections for every element, exact
reach sets, every findings row selecting its element, search, each layer, and
folding each zone. They skip when no Chrome/Chromium is found; set
`TARAV_CHROME` to point at one.

- `internal/schema`: embedded JSON Schemas (`schema/`, one file per version) and validation.
- `internal/model`: typed item definition, ID lookups, entry-point normalization.
- `internal/lint`: rule registry and rules, one file per rule (`l0NN_*.go`).
- `internal/protect`: protection-level derivation and the list of drawn edges.
- `internal/graph`: item → graph (nodes, edges, zones, assets) for the viewer.
- `internal/render`: page assembly, the `serve` handler and the review endpoints; `web/` holds the viewer.
- `internal/check`: schema + lint + policy into the pipeline report (`tarav check`).
- `internal/policy`: the policy file. `internal/approval`: approval records, the log and the gate lookup.
- `testdata/lint/`: a positive and a negative fixture per rule; `testdata/golden/`
  holds the expected `lint --format json` output for every fixture and sample,
  and `testdata/golden/graph/` the graph JSON. `testdata/policy/` has example policies.

To add a rule, add `internal/lint/lNNN_name.go` that calls `Register` from `init`,
add fixtures under `testdata/lint/`, run `-update`, and review the golden diff.
