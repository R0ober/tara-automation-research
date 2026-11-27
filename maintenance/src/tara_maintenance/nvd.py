"""Convert NVD CVE API 2.0 snapshots into maintenance change documents."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterator, Sequence
from pathlib import Path

from .baseline import InputError, JsonObject, load_json

RANGE_FIELDS = {
    "versionStartIncluding": "version_start_including",
    "versionEndIncluding": "version_end_including",
    "versionStartExcluding": "version_start_excluding",
    "versionEndExcluding": "version_end_excluding",
}


def nvd_to_changes(document: JsonObject) -> list[JsonObject]:
    """Convert all CVEs in one NVD response, preserving vulnerable CPE rules."""

    vulnerabilities = document.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise InputError("NVD document requires a 'vulnerabilities' array")
    changes = []
    for item in vulnerabilities:
        if not isinstance(item, dict) or not isinstance(item.get("cve"), dict):
            raise InputError("Each NVD vulnerability requires a cve object")
        changes.append(_convert_cve(item["cve"]))
    return changes


def _convert_cve(cve: JsonObject) -> JsonObject:
    cve_id = cve.get("id")
    if not isinstance(cve_id, str):
        raise InputError("NVD vulnerability is missing cve.id")
    matches = list(_vulnerable_cpe_matches(cve.get("configurations", [])))
    ranges = []
    for match in matches:
        converted = {"cpe": match["criteria"], "match_criteria_id": match.get("matchCriteriaId")}
        for source, target in RANGE_FIELDS.items():
            if source in match:
                converted[target] = match[source]
        if len(converted) > 2:
            ranges.append(converted)

    change: JsonObject = {
        "change_id": f"NVD-{cve_id}",
        "type": "vulnerability",
        "cve_id": cve_id,
        "affected_components": [],
        "affected_cpes": sorted({match["criteria"] for match in matches}),
        "affected_cpe_ranges": ranges,
        "applicability_unknown": not matches,
        "source": "NVD",
        "source_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "summary": _english_description(cve),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "vulnerability_status": cve.get("vulnStatus"),
    }
    if cve.get("cisaExploitAdd"):
        change["cisa"] = {
            "exploit_added": cve["cisaExploitAdd"],
            "action_due": cve.get("cisaActionDue"),
            "required_action": cve.get("cisaRequiredAction"),
            "vulnerability_name": cve.get("cisaVulnerabilityName"),
        }
    return change


def _vulnerable_cpe_matches(configurations: object) -> Iterator[JsonObject]:
    if not isinstance(configurations, list):
        return
    for configuration in configurations:
        if not isinstance(configuration, dict):
            continue
        for node in configuration.get("nodes", []):
            if not isinstance(node, dict):
                continue
            for match in node.get("cpeMatch", []):
                if (
                    isinstance(match, dict)
                    and match.get("vulnerable") is True
                    and isinstance(match.get("criteria"), str)
                ):
                    yield match
            children = node.get("children")
            if isinstance(children, list):
                yield from _vulnerable_cpe_matches([{"nodes": children}])


def _english_description(cve: JsonObject) -> str:
    for description in cve.get("descriptions", []):
        if isinstance(description, dict) and description.get("lang") == "en":
            return str(description.get("value", ""))
    return ""


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="tara-maintenance-nvd")
    parser.add_argument("inputs", nargs="+", help="NVD API 2.0 JSON snapshots")
    parser.add_argument("--output", help="Write converted changes to this JSON file")
    args = parser.parse_args(argv)
    try:
        changes = [
            change
            for path in args.inputs
            for change in nvd_to_changes(load_json(Path(path)))
        ]
        rendered = json.dumps({"changes": changes}, indent=2, ensure_ascii=False) + "\n"
        if args.output:
            output = Path(args.output)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
    except (InputError, OSError, UnicodeError) as exc:
        print(f"tara-maintenance-nvd: {exc}", file=sys.stderr)
        return 2
    return 0


def entrypoint() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    entrypoint()
