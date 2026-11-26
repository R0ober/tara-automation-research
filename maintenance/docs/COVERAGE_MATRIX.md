# Maintenance scenario coverage

This matrix distinguishes implemented behavior from planned roadmap items. Real
CVE labels refer to the tracked NVD snapshots and the reference BBW
architecture. Synthetic cases provide controlled boundaries that the selected
real records do not cover.

| Scenario | Data | Expected behavior | Status |
| --- | --- | --- | --- |
| New CVE, exact CPE | CVE-2020-22284 | Match COMP-EBCM; review | Covered |
| New CVE, inclusive range | CVE-2021-34434 | Match Mosquitto 2.0.10; review | Covered |
| New CVE, applicable range | CVE-2022-0847 | Match kernel 5.10.70; review | Covered |
| New CVE, version exclusion | CVE-2020-12351 | Kernel 5.10.70 excluded; no review | Covered |
| New CVE, unaffected older range | CVE-2014-4883 | lwIP 2.1.2 excluded; no review | Covered |
| New CVE, N/A/git-head CPE | CVE-2020-22283 | Do not interpret `-` as all versions; no matching installed version | Covered |
| Existing CVE, version conflict | Synthetic TARA | Review TARA/NVD conflict | Covered |
| New CVE with feature-specific description | CVE-2024-3935 | Version match triggers review, not exploit confirmation | Covered |
| Additional real configuration record | CVE-2024-10525 | Exercise client/callback precondition and range | Covered |
| Unknown component/product | Synthetic | Unresolved | Covered |
| Range supplied without duplicate CPE list | Audit fixture | Evaluate range and match component | Covered |
| Unknown component plus excluded known version | Audit fixture | Unresolved, never no_review | Covered |
| NVD record without CPE configurations | Awaiting-analysis fixture | Explicit applicability unknown; unresolved | Covered |
| Malformed NVD vulnerability entry | Invalid fixture | InputError instead of attribute exception | Covered |
| Explicit unknown flag plus version exclusion | Audit fixture | Unresolved, never no_review | Covered |
| External evaluation data with duplicate IDs | Evaluation fixture | Reject before indexing | Covered |
| Unresolved CPE cited with punctuation | Pi response fixture | Accepted as valid source evidence | Covered |
| Report/TARA output targeting any input | CLI fixtures | Reject without modifying input | Covered |
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
| Configuration/node AND/OR/negation applicability | Spec fixtures + real NVD regression | Full three-valued evaluation | Specified; implementation open |
| Existing CVE description/CVSS update | Snapshot pairs | Policy-based review | Roadmap, not covered |
| OpenCTI relationship context | OpenCTI test instance | Provenance-preserving adapter evaluation | Roadmap, not covered |
