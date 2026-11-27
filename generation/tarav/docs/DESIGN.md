# tarav design notes

Comments in the code cite **SPEC Dn** (a decision below) and **plan §n** (a section of the original design, reproduced at the end).
This file is extracted from the development repo's `SPEC.md` and `plan.md`; milestone plans, checklists and the M0 prototype stayed there.

## Decisions

### D1–D6 (plan §11 open questions)

| # | Question | Decision | Affects |
|---|---|---|---|
| D1 | Schema ownership & versioning | **tarav owns** `schema/item-definition.schema.json`, written from the two samples. Versioned by semver in its `$id` (`https://tarav.local/schema/item-definition/1.0.0`). Inputs *may* carry a top-level `"$schema"` with that URI; if absent, validate against the latest bundled version and emit a one-line notice to stderr (not a finding, not a failure). Unknown `$schema` URI → validation error. | M1 |
| D2 | Multi-instance default | **Collapsed with a `×N` badge**; click toggles expansion. While collapsed, edges to `target_instances[]` are aggregated onto the group node. | M0 |
| D3 | Entry-point normalization | **Tool-only.** Source format unchanged. `internal/model` exposes one normalized `EntryPoints []EntryPoint` collected from all locations in plan §5, plus (amended 2026-11-25) any connection with an `EXTERNAL_*` end and no `entry_points[]`, which is itself the entry point. That is how OTA-ADAS declares its attack surface; without it OTA has none. Entries merge by ID (interface ID, `<conn>#physical_access`, or the connection ID), so one port declared towards several components is one entry point reaching all of them; every declaration keeps its JSON pointer. | M1 |
| D4 | Offline reviewers | **Offline. Vendor from M0.** Pinned copies of cytoscape and elkjs are committed under `web/vendor/` and inlined (elkjs is called directly; the cytoscape-elk adapter was dropped 2026-11-25 because it cannot hand ELK's orthogonal bend points to Cytoscape); no network requests from any HTML we produce, including the spike. | M0, M1 |
| D5 | Blocking findings | **Hardcoded until M4:** exit `1` on any schema error or any error-severity finding (L001–L003); exit `0` otherwise; exit `2` on usage/IO errors (missing file, unparseable JSON is a schema error → `1`). Policy file replaces this in M4. | M1 |

### D7–D10

| # | Decision |
|---|---|
| D6 | Component IDs matching `EXTERNAL_*` (e.g. `EXTERNAL_ATTACKER_SURFACE`) are reserved sentinels for "outside the item". L001 treats them as defined; the viewer renders them as entry-point nodes. |
| D7 | Schema v1.0.0 requires a common core (`item_definition`, `components`, `connections`, `assets` and their ID/name/reference fields); everything else optional, `additionalProperties: true`. |
| D8 | L002 uses one global ID namespace: component, instance, connection, asset and damage-scenario IDs must be unique across all of them, so `element_id` is unambiguous. Interface IDs are excluded (they are references listed per component and legitimately repeat). |
| D9 | `plan.md` §12 is left as is; a truncated copy of the BBW sample is kept as `testdata/schema/truncated-bbw.json`. |
| D10 | A connection's interface is `connections[].interface_id` when present (optional in the schema; OTA-ADAS sets it, BBW does not). When absent it is **inferred** as the single interface both endpoint components list. If they share none or several, nothing is inferred and lint warns (L016) instead of guessing. L001 checks `interface_id` only where present; L010 counts explicit and inferred interfaces, entry points, physical access and diagnostic `entry_interfaces` as use. (L010 and L016 are not implemented yet.) (Decided 2026-11-25; revisit if inference proves surprising.) |

### D11–D16 (M2: protection, render, serve)

| # | Decision |
|---|---|
| D11 | **Protection source: explicit field first, then a key table.** Schema 1.1.0 adds an optional `protection: {e2e_crc, mac, freshness}` on connections and messages. When a flag is absent there, it is read from a fixed table of exact, unprefixed `security_configuration` keys on the sender's and receiver's component or hosted software: CRC ← `e2e_crc_enabled`; MAC ← `secoc_mac_enabled`, `secoc_mac_verification`, `secoc_mac_verification_enabled`, `command_authentication_mac`; freshness ← `secoc_freshness_counter_enabled`, `secoc_freshness_counter_verification_enabled`. Message-prefixed keys (`pedal_demand_mac_verification_enabled`) are **not** matched to messages, because the prefixes don't match message names; state those through `protection`. Encryption is `connections[].encrypted` (entry-point edges: `entry_points[].encrypted` when stated). The receiver's value wins over the sender's (plan §6). |
| D12 | **Strict unknown.** Levels follow plan §6, first match wins: encrypted → MAC + freshness → MAC → CRC → none. A flag that is missing is never assumed false: the edge is `unknown` unless a stated `true` already proves a level above none. So CONN-BRK-04 (MAC false, CRC not stated) is `unknown`, not `none`. |
| D13 | Message edges take their own `protection`, then the connection's, then the key table for the message's own source and target components; encryption comes from the connection. Physical-access edges have no protection level (neutral, as in M0). Which edges are drawn (`protect.Edges`, shared by the graph and L017): every connection, except one with an `EXTERNAL_*` end that declares `entry_points` (its entry-point edges stand in for it); a message only when its endpoints differ from the connection's or it states its own `protection`; one edge per declared entry point. |
| D14 | L017 is the plan §6 lint warning for missing protection flags. One finding per edge, `element_id` the connection ID, `json_path` the connection (or message) object. |
| D15 | **Render exit codes:** schema error → no HTML written, exit 1. Otherwise the HTML is always written (reviewers need to see the findings) and the exit code follows D5: 1 if any error-severity finding, else 0. |
| D16 | **Viewer scope:** static view per plan §10 M2, with a read-only details pane instead of the M3 drawer. `serve` uses mtime/content-hash polling, no file-watcher dependency. |

### D17–D20 (M3: interactive review)

| # | Decision |
|---|---|
| D17 | **Reachability follows declared direction** over all drawn edges (connection, message, entry, physical, diagnostic), computed in Go and embedded per entry node. Entering a component reaches its instances. It is topology, not feasibility, and the UI says so. |
| D18 | **Finding links are computed in Go** by longest JSON-pointer prefix over graph elements, with owner fallbacks (component, connection edge or its entry edges, asset's parent component). Embedded as `links` parallel to `findings`; the plan §7 finding shape is unchanged. |
| D19 | **Zone collapse** merges border-crossing edges per (outside end, direction). The viewer shows the selected property and member counts. Different member states produce a mixed edge. Physical and diagnostic edges merge separately and stay dashed. |
| D20 | **UI tests extend the headless-Chrome driver** through `window.__tarav` hooks; no Playwright or other JS dependency. UI/UX reviewer suggestions on M2 are deferred and will be folded in when collected. |

### D21–D25 (M4: pipeline gate)

| # | Decision |
|---|---|
| D21 | **Pipeline contract.** The pipeline commands (`check`, `approve`, `gate`, `serve --review`) print exactly one JSON document on stdout and human messages on stderr. Exit 0 passed/approved, 1 schema errors or blocking findings, 2 usage/IO, 3 not approved (gate closed, rejected, interrupted). Code 3 is new and used only by these commands; `validate`, `lint` and `render` keep D5. |
| D22 | **Policy file** as in M4 scope; strict parsing so a typo cannot loosen the gate; its SHA-256 is recorded in the report and in approvals. |
| D23 | **Approval record** `{approved, stage, file, sha256, reviewer, approved_at, comment, tarav_version, policy_sha256, findings}` appended to an approvals log `{"approvals": [...]}`, default `FILE.approvals.json`, written via temp file + rename. The hash is of the exact bytes the server re-checked at approval time. The reviewer name is typed, not authenticated; the log can be forged by anyone who can write it. |
| D24 | **Review in serve.** Approve/Reject POST JSON with a per-run random token and the page's version; the server refuses other content types, cross-origin requests, a version that no longer matches the file (409), a file that fails the checks (422) and anything after the first decision (410). Review mode serves only to IP-literal or `localhost` Host headers (DNS rebinding). |
| D25 | **Gate** matches any approved record with the stage and current SHA-256 (newest first); with none, the reason names the last approval of that stage if the file changed since. Stage names are `[a-z0-9][a-z0-9-]*`, default `item-definition`. |

## Code Style

Standard Go: `gofmt`, `go vet` clean, errors wrapped with `%w`, no panics outside `main`. Rules are self-registering and data-only at the boundary:

```go
// internal/lint/l001_dangling_ref.go
func init() { Register(Rule{ID: "L001", Severity: Error, Check: checkDanglingRefs}) }

func checkDanglingRefs(it *model.Item) []Finding {
	var out []Finding
	for i, c := range it.Connections {
		if !it.HasComponent(c.Source) {
			out = append(out, Finding{
				Rule: "L001", Severity: Error,
				Message:   fmt.Sprintf("connection %s: source_component %q is not defined", c.ID, c.Source),
				JSONPath:  fmt.Sprintf("/connections/%d/source_component", i),
				ElementID: c.ID,
			})
		}
	}
	return out
}
```
- `json_path` is an RFC 6901 JSON Pointer into the input file.
- Findings sorted by (`json_path`, `rule`) before output — determinism.
- JSON output keys are `snake_case`; Go fields `CamelCase` with tags.

## Testing Strategy

- **Schema:** both `testdata/{bbw,ota-adas}/item-definition.json` pass; each file in `testdata/schema/` fails with an expected pointer.
- **Model:** table tests for entry-point normalization: each source location from plan §5 contributes; duplicates across locations collapse to one entry.
- **Lint:** per rule, one minimal fixture that triggers it and one that doesn't; golden JSON output per fixture; `-update` flag to regenerate.
- **CLI:** exit-code tests for D5 (0 / 1 / 2) via `exec` of the built binary or a `run(args, stdout, stderr) int` seam.
- **Determinism:** running `lint --format json` twice on each sample yields byte-identical output.
- **Protection (M2):** table tests for every plan §6 rule and D12 case; flag-gathering tests for each source and precedence; expected level per sample edge.
- **Graph (M2):** golden JSON per sample and `testdata/graph/edge-cases.json`; structure (unique IDs, edges join nodes) and pointer-resolution tests.
- **Render/serve (M2):** byte-identical output, network-free page (CSP + no external loads), escaping, D15 exit codes; `serve` handler tests via `httptest`.
- **Browser (M2):** headless Chrome with networking blocked loads each rendered sample: zero console errors, `routeCheck` clean (also expanded), identical layout across loads, and live reload under `serve`. Skipped without Chrome or with `-short`.
- **Graph (M3):** reach per entry point in goldens, pinned BBW/OTA sets, closure test; `Locate` table tests for prefix, ties and every fallback; every fixture finding links to a drawable element.
- **Browser (M3):** scenarios through `window.__tarav` (D20): drawer sections per element kind, exact undimmed set per entry point, every findings row (also with zones folded), search by CPE and ID, each layer toggle, folding each zone and all zones with `routeCheck` clean and merged edges summarised by property.
- **Pipeline (M4):** policy parse errors and grading table tests; check report per fixture and policy; approval log append/find (stale, other stage); review endpoints refuse wrong token, form content type, cross origin, stale version, failing file, second decision and foreign Host names; CLI approve → gate → edit → gate closed; `serve --review` run end to end for approve and reject; browser tests drive the real Approve form and a blocked page.
- Coverage target: ≥80% statements on `internal/...` (M1–M4).

## Boundaries

- **Always:** keep output deterministic; keep every HTML artefact network-free; pin and checksum vendored JS; add a fixture with every new rule; run `go test ./...` and `go vet` before declaring a task done.
- **Ask first:** adding any Go or JS dependency; changing the finding shape; changing exit-code semantics; bumping the schema major version; SARIF; any M5+ work.
- **Never:** call an LLM or any network service from tarav; load assets from a CDN; delete or weaken a failing test to get green; commit generated golden files without reviewing the diff.

## Out of Scope (Deferred)

- SARIF output — after M4 (needs JSON-pointer → line mapping).
- Signed approvals, reviewer authentication — the approvals log is an audit trail, not proof.
- L010–L021 — after M1 (L010–L015 likely M2/M3 as the model firms up).
- Canonical entry-point list in the source format (D3) — revisit after M3 if normalization proves lossy.
- Signal-flow tab, control matrix, diff view, SVG/PNG export — M5.
- Playwright smoke test — replaced in M2 by a headless-Chrome smoke test (no JS dependency); revisit Playwright in M3 when interactions need driving.

## Original design (plan.md excerpts)

### plan §3. UI concept

The look follows Floorplan's flat, quiet style: lots of whitespace, thin borders, color only where it means something.

**Layout**

- **Canvas (center):** trust zones drawn as labeled containers, with components as cards inside them. Entry points are distinct external nodes.
- **Side drawer (right):** opens when you click anything.
- **Top bar:** item name and ID, search, layer toggles, a lint badge ("3 errors · 12 warnings"), and export.
- **Bottom drawer:** the lint findings list. Clicking a finding focuses its node.

**Interactions**

- **Click a component.** The drawer shows hardware, OS, software (version, CPE, listening ports), security config as green/red/amber chips, diagnostic services, hosted assets with CIA tags, and damage scenarios with SFOP ratings.
- **Click an edge.** The drawer shows the medium and protocol, messages and payload fields, protections (E2E, MAC, freshness, encryption), and receiver timeout, invalid-input and recovery behavior.
- **Click an entry point.** Everything reachable from it is highlighted and the rest is dimmed. This is topology reachability, not attack feasibility.
- **Focus mode.** Selecting a node dims everything except its direct neighbors.
- **Semantic zoom.** Zones can collapse into a single box, and multi-instance components (EMBA ×4) collapse or expand.
- **Layer toggles:** zones, entry points, protection coloring, assets overlay, ASIL badges.

**Visual encoding**

- In the architecture overview, stated encryption sets the line color and the label lists all stated controls. Without an encryption setting, the first enabled control in MAC, freshness, E2E CRC order sets the color. Selecting a property colors the edges by that property. The viewer labels enabled, disabled, unstated and mixed states with distinct symbols.
- Dashed edges are physical-access paths (SWD, wheel harness).
- Components get an ASIL badge, and a red dot when the lint has findings for them.

**Better than Floorplan for this use case**

- Reachability highlighting from entry points.
- The lint panel is tied to graph elements, like Floorplan's Health check but specific to item definitions.
- Optional tabs reuse the same data: a **signal flow strip** for the braking chain and a **control matrix** of components × controls.

### plan §5. Mapping: JSON to graph

| Graph element | Source |
|---|---|
| Zone (compound parent) | distinct `components[].trust_zone` |
| Component node | `components[]`. Expand `instances[]` into child nodes, or a collapsible group |
| Entry point node | `connections[].entry_points[]`, `components[].physical_access`, `connections[].physical_access`, and connections with an `EXTERNAL_*` end that declare no `entry_points[]` (OTA-ADAS style) |
| Edge | `connections[]` source → target, plus `target_instances[]` |
| Message-level edge | `connections[].messages[]` source → target. This catches RIC → VDCM, which is only listed under `adjacent_components` |
| Diagnostic route | `diagnostic_access.downstream_routes[]`, drawn as a dashed overlay |
| Asset overlay | `assets[].parent_component` and `associated_connections` |

**Normalization step:** entry points and physical access currently appear in several places in the JSON. Collect them into one internal list before building the graph.

### plan §6. Protection-level derivation

L017 uses the first matching rule to derive a level:

1. `encrypted: true` → **encrypted**
2. MAC enabled and freshness enabled → **MAC + freshness**
3. MAC enabled → **MAC only**
4. E2E CRC enabled → **CRC**
5. Encryption, MAC and E2E CRC explicitly disabled → **none**
6. Otherwise → **unknown**

L017 warns when an unstated flag could change the derived level.

Flags are read from both the sender's and the receiver's `security_configuration`. Where they disagree, the receiver-side verification wins.

### plan §7. Lint rules (initial set)

- **Errors**
  - **L001** Dangling reference: an ID used but never defined (component, interface, connection, instance).
  - **L002** Duplicate IDs.
  - **L003** Asset with no damage scenario.
- **Warnings**
  - **L010** An interface listed on a component but used nowhere: not a connection's explicit or inferred interface (SPEC D10), not an entry point, not physical access, not a diagnostic route (for example `INT-UART-DEBUG` in `testdata/lint/L010-unused-interface.json`; BBW's `INT-SWD-HEADER` is *not* a finding, because `physical_access` uses it).
  - **L011** A message with no receiver timeout behavior defined (for example SOME/IP 0x1020).
  - **L012** A value of "Not specified" or "Configured …" with no number (seed-key algorithm, timeouts).
  - **L013** A security config field present on one component but missing on its peer.
  - **L014** An asset's parent component doesn't cover every component the asset is about (for example `ASSET-BRK-04` covering EMBA firmware).
  - **L015** A component with a CPE missing the version, or software missing a CPE.
  - **L016** A connection without `interface_id` whose endpoints share no interface or several, so the interface can't be inferred (SPEC D10).
- **Info**
  - **L020** Diagnostic services allowed while driving.
  - **L021** Unauthenticated diagnostic services.

Each finding carries `rule`, `severity`, `message`, `json_path` and `element_id`, so the viewer can link it to the graph. SARIF output lets findings show up in GitLab or GitHub code review.

### plan §8. Pipeline integration

```
item.json ──► tarav validate ──► tarav lint ──► tarav render
                 (fail)          (warn/fail      (artifact:
                                  by policy)      preview.html)
                                       │
                                manual approval gate
                                       │
                                 TARA pipeline
```

- The policy file sets which lint severities fail the build.
- Approval records `sha256(item.json)` and the reviewer's name. The TARA step refuses to run if the hash doesn't match an approved review.
