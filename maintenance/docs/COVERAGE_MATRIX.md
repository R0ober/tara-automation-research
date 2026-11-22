# Maintenance scenario coverage

This matrix distinguishes implemented behavior from planned roadmap items. Real
CVE labels refer to the tracked NVD snapshots and the reference BBW
architecture. Synthetic cases provide controlled boundaries that the selected
real records do not cover.

| Scenario | Data | Expected behavior | Status |
| --- | --- | --- | --- |
| New CVE, exact CPE | CVE-2020-22284 | Match COMP-EBCM; review | Covered |
| New CVE, inclusive range | CVE-2021-34434 | Match Mosquitto 2.0.10; review | Covered |
| Existing CVE, applicable range | CVE-2022-0847 | Match kernel 5.10.70; no duplicate review | Covered |
| Existing CVE, version conflict | CVE-2020-12351 | Review TARA/NVD conflict | Covered |
| New CVE, unaffected older range | CVE-2014-4883 | lwIP 2.1.2 excluded; no review | Covered |
| Existing CVE, N/A/git-head CPE | CVE-2020-22283 | Do not interpret `-` as all versions; review conflict | Covered |
| New CVE with feature-specific description | CVE-2024-3935 | Version match triggers review, not exploit confirmation | Covered |
| Additional real configuration record | CVE-2024-10525 | Exercise client/callback precondition and range | Covered |
| Unknown component/product | Synthetic | Unresolved | Covered |
| Nonnumeric version comparison | Synthetic | Unresolved, never guessed | Covered |
| All range boundaries | Synthetic | Inclusive/exclusive comparisons | Covered |
| Same nested component state | Synthetic | No review | Covered |
| Effective component state change | Synthetic | Review with changed fields | Covered |
| Added/removed null field | Synthetic | Detected as a real diff | Covered |
| Invalid JSON/config/CVE | Synthetic | Input error, no partial report | Covered |
| Repeated identical Pi call | Agent event stream | Block duplicate execution | Covered |
| Wrong agent input substitution | Agent event stream | Fail experiment | Covered |
| Incomplete/misattributed CPE summary | Agent event stream | Fail experiment | Covered |
| TARA output preserves original content | Real BBW round-trip comparison | Original JSON unchanged outside review overlay | Covered |
| Nested NVD AND/OR/negation applicability | Dedicated NVD fixtures | Full Boolean evaluation | Roadmap, not covered |
| Existing CVE description/CVSS update | Snapshot pairs | Policy-based review | Roadmap, not covered |
| OpenCTI relationship context | OpenCTI test instance | Provenance-preserving adapter evaluation | Roadmap, not covered |
